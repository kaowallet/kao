//! Two-screen onboarding flow for adding a Safe to the wallet.
//!
//! The screen is one `Phase` enum so each phase carries exactly the data
//! it needs:
//!
//! 1. `Find` — paste a hex address or a name (`.eth` / `.gwei` / `.wei` /
//!    `@xns`; names resolve on mainnet via the same helper
//!    `ImportAddressScreen` uses), then `safe::scan_across_chains` runs
//!    in place on the same card. A scan that finds no Safe on any chain
//!    stays here and shows the per-chain reason.
//! 2. `Review` — one wide card holding everything that used to be five
//!    separate steps (chain chooser, inspect, role selection, signer
//!    picker, label):
//!    - a chain strip with one row per scanned chain — Safe hits can be
//!      included / excluded and focused, misses say why;
//!    - a Security column for the focused chain: trust, threshold,
//!      owners, modules / guard / fallback handler (each with its
//!      `safe::classify_module` label);
//!    - a Setup column: name, which wallet accounts to link as signers,
//!      the inline "Add a new signer" sub-flow, the Advanced transaction
//!      service override, and a per-chain role summary above the
//!      confirm button.
//!
//! Signer links are worked out **per chain** on confirm: each included
//! chain links exactly the ticked, signing-capable accounts that are an
//! owner on THAT chain (owner sets can diverge across chains). A chain
//! none of them own is saved watch-only — and the role summary says so
//! before the user confirms.
//!
//! Re-adding a Safe the wallet already holds (`with_existing_safes`) folds
//! each saved chain into its saved entry, which keeps its links, and the
//! name applies to every chain of the address. So Review starts from the
//! saved name (left as is, nothing is renamed), hints when the field would
//! rename it, and the role summary counts a saved chain's kept links.
//!
//! "Add a new signer" emits `Outcome::RequestAddSigner`; the parent
//! stashes this screen (still in `Review`) while it runs the import,
//! then resumes it via `apply_added_signer` / `apply_added_nested_safe`
//! / `apply_signer_import_error`.
//!
//! On confirm the screen emits `Outcome::Done { primary, siblings }` so
//! the parent can add the descriptors to the wallet and persist.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{
    Scrollable, Space, column, container, responsive, row, scrollable, text, text_input,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use crate::chain::Chain;
use crate::names;
use crate::net::BalanceFetcher;
use crate::safe::{self, SafeMetadata, ScanResult};
use crate::settings;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    auth_background, auth_card, black, colored_address, error_text, ghost_button, hint_pill,
    kao_checkbox, kao_hero, kao_scrollable_style, link_button, method_card, mono, mono_bold,
    primary_button, screen_subtitle, screen_title, section_card, text_input_style, vspace,
};
use crate::wallet::{SafeDescriptor, SafeKey, SafeTrust, short_address};

pub const ADDRESS_INPUT_ID: &str = "safe_onboarding_address";
pub const NAME_INPUT_ID: &str = "safe_onboarding_name";

/// Review card cap. The card is `Fill` up to this so it shrinks with a
/// narrow window instead of overflowing it (the default window is
/// 1024 px wide).
const REVIEW_CARD_MAX_W: f32 = 920.0;
/// Review card height cap — the card fills the window height (so the two
/// columns get a bounded height to scroll within) but doesn't turn into a
/// wall on a tall monitor.
const REVIEW_CARD_MAX_H: f32 = 860.0;
/// Below this content width the Review card stacks Security above Setup
/// in one scrollable. Each column must fit a full 42-char
/// `colored_address` (~355 px at size 14) plus `section_card` padding and
/// the scrollbar gutter (fits at ~820; the rest is margin); an address
/// row that doesn't fit overlaps its own chunks rather than wrapping.
const REVIEW_TWO_COLUMN_MIN_W: f32 = 840.0;

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Message {
    // Find
    AddressInput(String),
    AddressSubmit,
    EnsResolved {
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    },
    ScanCompleted {
        seq: u64,
        address: Address,
        results: Vec<(Chain, ScanResult)>,
    },

    // Review — chain strip
    /// Include / exclude a chain the scan found the Safe on. The last
    /// included chain can't be excluded.
    ChainIncludeToggled(Chain),
    /// Show this chain's details in the Security column.
    ChainFocused(Chain),

    // Review — Setup column
    NameInput(String),
    SignerToggled(u32),
    /// Expand / collapse the inline "Add a new signer" section.
    AddSignerToggled,
    SignerMethodPicked(SignerMethod),
    /// Expand/collapse the Advanced section (custom transaction
    /// service).
    AdvancedToggled,
    /// Custom Safe Transaction Service base URL input.
    ServiceUrlInput(String),
    Confirm,

    // Both phases
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

/// What the parent learns when this screen finishes.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The user completed onboarding. The parent should append
    /// `primary` to `wallet.safes`, plus one `SafeDescriptor` per
    /// entry in `siblings` (each is its own (address, chain_id)
    /// record per the storage design), then persist with
    /// `save_descriptor`.
    Done {
        // Boxed to keep `Outcome`'s size down — `SafeDescriptor` is
        // ~256 bytes, and clippy's large_enum_variant lint flags
        // shoveling that around every message hop.
        primary: Box<SafeDescriptor>,
        siblings: Vec<SafeDescriptor>,
    },
    /// User backed out. Parent decides what to do (return to setup
    /// picker for fresh wallets, return to dashboard for add-account).
    Back,
    /// User picked an import method for a new signer. The parent
    /// runs the corresponding import sub-screen, then must call
    /// `apply_added_signer` (success) or `apply_signer_import_error`
    /// (rejected) on this screen to resume. While the parent owns
    /// the sub-screen, this `SafeOnboardingScreen` instance is parked
    /// in `Review` and must be kept alive (stashed).
    RequestAddSigner {
        method: SignerMethod,
        /// Owners of the Safe — across every chain the user is adding —
        /// whose key isn't already represented by an account in the
        /// wallet. The parent enforces this set on the imported address;
        /// anything outside is rejected.
        allowed_owners: Vec<Address>,
    },
}

impl Outcome {
    /// Variant name for the GUI state trace — the payloads (descriptors,
    /// owner lists) stay out of the log.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Done { .. } => "Done",
            Outcome::Back => "Back",
            Outcome::RequestAddSigner { .. } => "RequestAddSigner",
        }
    }
}

/// Import method the user picked for the add-signer sub-flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerMethod {
    SeedPhrase,
    PrivateKey,
    Hardware,
    /// The owner of this Safe is itself a Safe — open a nested
    /// onboarding flow to add it as its own `SafeDescriptor`.
    NestedSafe,
}

// ── State ───────────────────────────────────────────────────────────────────

/// One wallet account, pre-computed by the parent so we don't have to
/// repeat the keccak-derived address calculation on every view.
/// `account_idx` indexes into the wallet's `accounts` Vec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAccount {
    pub account_idx: u32,
    pub address: Address,
    /// Display name as the dashboard would render it — passed in so we
    /// don't re-derive `display_name(idx)` here.
    pub label: String,
    /// Watch-only account (no key). Listed when it owns the Safe so the
    /// user isn't confused about where it went, but it can't sign, so
    /// it is never linked.
    pub view_only: bool,
}

/// One Safe entry already in the wallet, pre-computed by the parent like
/// `ExistingAccount`. Review uses it to flag a chain that's already saved,
/// to prefill the name the Safe already goes by, and to say what such a
/// chain ends up as — confirming folds into the saved entry
/// (`WalletDescriptor::upsert_safe`), which keeps its links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingSafe {
    /// `(address, chain_id)` — the entry's identity.
    pub key: SafeKey,
    /// User-assigned name (`SafeDescriptor::name`); `None` = unnamed.
    pub name: Option<String>,
    /// Saved signer links. Older wallets can hold indices that dangle or
    /// point at a view-only account, so Review only counts the ones that
    /// can actually sign.
    pub linked_signer_indices: Vec<u32>,
}

impl From<&SafeDescriptor> for ExistingSafe {
    fn from(safe: &SafeDescriptor) -> Self {
        Self {
            key: safe.key(),
            name: safe.name().map(str::to_owned),
            linked_signer_indices: safe.linked_signer_indices.clone(),
        }
    }
}

#[derive(Debug)]
enum Phase {
    Find(FindState),
    // Boxed: the Review state is several times the size of Find's.
    Review(Box<ReviewState>),
}

impl Phase {
    /// Coarse phase for the GUI state trace. Find's in-place sub-states
    /// get their own names so the trace still reads like the flow does.
    fn name(&self) -> &'static str {
        match self {
            Phase::Find(f) if f.scanning.is_some() => "Scanning",
            Phase::Find(f) if f.ens_resolving.is_some() => "ResolvingName",
            Phase::Find(f) if f.no_safe.is_some() => "NoSafe",
            Phase::Find(_) => "Find",
            Phase::Review(r) if r.awaiting_signer => "AwaitingSigner",
            Phase::Review(_) => "Review",
        }
    }
}

#[derive(Debug, Default)]
struct FindState {
    input: String,
    error: Option<String>,
    /// `Some(seq)` while a name lookup is in flight.
    ens_resolving: Option<u64>,
    /// `Some` while a scan is in flight. The button reads "Scanning…"
    /// and the scanned string is shown so the user can confirm the
    /// right target is being checked.
    scanning: Option<ScanTarget>,
    /// The last scan found no Safe on any chain — the per-chain
    /// breakdown of *why*. Cleared by editing the input or rescanning.
    no_safe: Option<NoSafe>,
}

#[derive(Debug)]
struct ScanTarget {
    address: Address,
    /// The string the user submitted (address or name).
    what: String,
    /// `what` is a name the user typed rather than a hex address — it
    /// becomes the default label on Review.
    from_name: bool,
}

#[derive(Debug)]
struct NoSafe {
    address: Address,
    results: Vec<(Chain, ScanResult)>,
}

#[derive(Debug)]
struct ReviewState {
    address: Address,
    /// What was in the Find input, restored on Back so the user can
    /// rescan with Enter.
    find_input: String,
    /// The name the user typed (ENS etc.) when it wasn't a hex address.
    typed_name: Option<String>,
    /// Every chain's scan result — hits and misses — in `Chain::ALL`
    /// order.
    results: Vec<(Chain, ScanResult)>,
    /// Hit chains the user unticked. Every hit starts included.
    excluded: Vec<Chain>,
    /// Chain shown in the Security column. Always a hit; may be excluded.
    focused: Chain,
    /// Accounts the user has ticked as signers (by `account_idx`).
    /// Starts as every signing-capable account that owns the Safe on any
    /// chain. View-only accounts are never in here.
    selected: BTreeSet<u32>,
    /// Owners that are themselves Safes the user has onboarded during
    /// this session via the nested-Safe sub-flow. Informational — the
    /// parent→child link is derived from the owner-set intersection at
    /// signing time, not persisted on `SafeDescriptor`.
    linked_nested_safes: Vec<Address>,
    /// Error from the last add-signer attempt. Cleared on any signer
    /// toggle or a successful import.
    signer_error: Option<String>,
    /// The inline "Add a new signer" section is expanded.
    add_signer_open: bool,
    /// `RequestAddSigner` was emitted and the parent hasn't resumed us
    /// yet. Trace-only: the screen is parked in Review either way, and
    /// the next message it handles clears it.
    awaiting_signer: bool,
    name: String,
    /// Advanced section expanded. Collapsed by default — almost
    /// everyone wants the public service.
    advanced: bool,
    /// Custom Transaction Service base URL, raw as typed. Validated
    /// through `service::normalize_service_base` on confirm; blank means
    /// the public default.
    service_url: String,
    /// Validation error from the last confirm attempt.
    service_url_error: Option<String>,
}

impl ReviewState {
    fn new(
        address: Address,
        find_input: String,
        target: ScanTarget,
        results: Vec<(Chain, ScanResult)>,
        existing: &[ExistingAccount],
        existing_safes: &[ExistingSafe],
    ) -> Self {
        let focused = results
            .iter()
            .find_map(|(c, r)| hit_of(r).map(|_| *c))
            .unwrap_or_default();
        let owners: BTreeSet<Address> = results
            .iter()
            .filter_map(|(_, r)| hit_of(r))
            .flat_map(|(md, _)| md.owners.iter().copied())
            .collect();
        // Default-check every signing-capable owner — the user opts
        // out rather than in, and still has to confirm the screen.
        let selected = existing
            .iter()
            .filter(|e| !e.view_only && owners.contains(&e.address))
            .map(|e| e.account_idx)
            .collect();
        let typed_name = target.from_name.then_some(target.what);
        // A Safe that's already saved starts from the name it already goes
        // by — even when it was found by ENS: confirming applies the field
        // to every chain, and a name typed into the finder is a lookup, not
        // a rename. Untouched, it renames nothing. Otherwise the typed name
        // (ENS etc.) is the label the user reached for.
        let name = saved_name(existing_safes, address)
            .map(str::to_owned)
            .or_else(|| typed_name.clone())
            .unwrap_or_default();
        Self {
            address,
            find_input,
            name,
            typed_name,
            results,
            excluded: Vec::new(),
            focused,
            selected,
            linked_nested_safes: Vec::new(),
            signer_error: None,
            add_signer_open: false,
            awaiting_signer: false,
            advanced: false,
            service_url: String::new(),
            service_url_error: None,
        }
    }

    /// Chains the address is a Safe on, in `Chain::ALL` order.
    fn hits(&self) -> impl Iterator<Item = (Chain, &SafeMetadata, SafeTrust)> + '_ {
        self.results
            .iter()
            .filter_map(|(c, r)| hit_of(r).map(|(md, trust)| (*c, md, trust)))
    }

    fn hit(&self, chain: Chain) -> Option<(&SafeMetadata, SafeTrust)> {
        self.hits()
            .find(|(c, _, _)| *c == chain)
            .map(|(_, md, trust)| (md, trust))
    }

    /// Hits the user is adding, in `Chain::ALL` order.
    fn included(&self) -> impl Iterator<Item = (Chain, &SafeMetadata, SafeTrust)> + '_ {
        self.hits().filter(|(c, _, _)| !self.excluded.contains(c))
    }

    fn is_included(&self, chain: Chain) -> bool {
        self.hit(chain).is_some() && !self.excluded.contains(&chain)
    }

    /// The descriptor emitted as `primary`: the focused chain if it's
    /// included, otherwise the first included chain.
    fn primary_chain(&self) -> Option<Chain> {
        if self.is_included(self.focused) {
            return Some(self.focused);
        }
        self.included().next().map(|(c, _, _)| c)
    }

    /// Accounts to link on a chain whose owner set is `owners`: the
    /// ticked, signing-capable accounts that are an owner THERE. Owner
    /// sets diverge across chains, and linking a non-owner would offer
    /// signing that reverts on-chain. Sorted and deduplicated.
    fn links_on(&self, existing: &[ExistingAccount], owners: &[Address]) -> Vec<u32> {
        existing
            .iter()
            .filter(|e| {
                !e.view_only
                    && self.selected.contains(&e.account_idx)
                    && owners.contains(&e.address)
            })
            .map(|e| e.account_idx)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// What each included chain ends up as once confirmed — the role
    /// summary above the confirm button.
    ///
    /// A chain that isn't saved yet gets exactly the ticked links. One that
    /// is folds into its saved entry, which never unlinks, so it ends up
    /// with the ticked links ∪ the saved ones. Either way only accounts
    /// that can sign there count: signing-capable and an owner on this
    /// scan — an older wallet's saved links can dangle, point at a
    /// view-only account, or name an owner removed on-chain since.
    fn chain_roles(
        &self,
        existing: &[ExistingAccount],
        existing_safes: &[ExistingSafe],
    ) -> Vec<ChainRole> {
        self.included()
            .map(|(chain, md, _)| {
                let ticked = self.links_on(existing, &md.owners);
                let saved = saved_entry(existing_safes, self.address, chain);
                let mut signers: BTreeSet<u32> = ticked.iter().copied().collect();
                if let Some(s) = saved {
                    signers.extend(s.linked_signer_indices.iter().copied().filter(|idx| {
                        existing.iter().any(|e| {
                            e.account_idx == *idx && !e.view_only && md.owners.contains(&e.address)
                        })
                    }));
                }
                // `ticked` is deduplicated and a subset of `signers`.
                let kept = signers.len() - ticked.len();
                ChainRole {
                    chain,
                    saved: saved.is_some(),
                    signers: signers.into_iter().collect(),
                    kept,
                }
            })
            .collect()
    }

    /// Included chains on which `address` is an owner.
    fn owned_chains(&self, address: Address) -> Vec<Chain> {
        self.included()
            .filter(|(_, md, _)| md.owners.contains(&address))
            .map(|(c, _, _)| c)
            .collect()
    }

    /// Owners across every included chain whose key isn't already an
    /// account in the wallet — the allow-list for an add-signer import.
    /// First-seen order, deduplicated.
    fn unclaimed_owners(&self, existing: &[ExistingAccount]) -> Vec<Address> {
        let claimed: BTreeSet<Address> = existing.iter().map(|e| e.address).collect();
        let mut out: Vec<Address> = Vec::new();
        for (_, md, _) in self.included() {
            for owner in &md.owners {
                if !claimed.contains(owner) && !out.contains(owner) {
                    out.push(*owner);
                }
            }
        }
        out
    }

    /// Some included chain's `key` differs from the focused chain's — i.e.
    /// the Security column isn't showing everything that will be added.
    fn differs_from_focused<K: PartialEq>(&self, key: impl Fn(&SafeMetadata) -> K) -> bool {
        let Some((focused, _)) = self.hit(self.focused) else {
            return false;
        };
        let shown = key(focused);
        self.included().any(|(_, md, _)| key(md) != shown)
    }

    /// An included chain has a different owner set or threshold than the
    /// one on screen.
    fn owners_differ(&self) -> bool {
        self.differs_from_focused(|md| {
            let owners: BTreeSet<Address> = md.owners.iter().copied().collect();
            (owners, md.threshold)
        })
    }

    /// An included chain has different modules / guard / module guard /
    /// fallback handler than the one on screen.
    fn danger_surfaces_differ(&self) -> bool {
        self.differs_from_focused(|md| {
            let modules: BTreeSet<Address> = md.modules.iter().copied().collect();
            (modules, md.guard, md.module_guard, md.fallback_handler)
        })
    }
}

/// One included chain's line in the role summary (`ReviewState::chain_roles`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainRole {
    chain: Chain,
    /// `(address, chain)` is already in the wallet; confirm merges into it.
    saved: bool,
    /// Accounts that can sign there once confirmed, sorted. Empty =
    /// watch-only.
    signers: Vec<u32>,
    /// How many of `signers` stay only because the saved entry already
    /// links them — unticked here, but a merge never unlinks.
    kept: usize,
}

impl ChainRole {
    /// "Mainnet — signer · 1 key", "Base — already in your wallet ·
    /// watch-only (…)", plus " · owner Safe linked" when a nested Safe
    /// onboarded in this session owns it there.
    fn line(&self, owner_safe: bool) -> String {
        let mut line = format!("{} — ", self.chain.label());
        if self.saved {
            line.push_str("already in your wallet · ");
        }
        if self.signers.is_empty() {
            line.push_str("watch-only (none of your selected keys own it here)");
        } else {
            let n = self.signers.len();
            line.push_str(&format!("signer · {n} key{}", plural(n)));
            if self.kept > 0 {
                line.push_str(&format!(" ({} already linked — kept)", self.kept));
            }
        }
        if owner_safe {
            line.push_str(" · owner Safe linked");
        }
        line
    }
}

/// The confirm button: "Add as watch-only →" only when no included chain
/// ends up with a key that can sign.
fn confirm_label(roles: &[ChainRole]) -> &'static str {
    if roles.iter().any(|r| !r.signers.is_empty()) {
        "Add to wallet →"
    } else {
        "Add as watch-only →"
    }
}

pub struct SafeOnboardingScreen {
    network: Arc<dyn BalanceFetcher>,
    /// Snapshot of every account in the wallet right before the screen
    /// opened (plus any added through the add-signer sub-flow) — used in
    /// Review to intersect with each chain's owner set.
    existing: Vec<ExistingAccount>,
    /// Every Safe entry already in the wallet, so Review can say "Already
    /// in your wallet", prefill the saved name and show what a saved chain
    /// ends up as.
    existing_safes: Vec<ExistingSafe>,
    phase: Phase,
    /// Monotonic counter bumped on every address input change (and on
    /// a cancelled scan); ENS and scan tasks stamp results with the
    /// value they were spawned at and the screen drops stale results.
    /// Without this, a user who typed fast could race a stale scan into
    /// Review.
    input_seq: u64,
}

impl std::fmt::Debug for SafeOnboardingScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeOnboardingScreen")
            .field("existing_count", &self.existing.len())
            .field("existing_safes_count", &self.existing_safes.len())
            .field("phase", &self.phase)
            .field("input_seq", &self.input_seq)
            .finish()
    }
}

impl SafeOnboardingScreen {
    pub fn new(network: Arc<dyn BalanceFetcher>, existing: Vec<ExistingAccount>) -> Self {
        Self {
            network,
            existing,
            existing_safes: Vec::new(),
            phase: Phase::Find(FindState::default()),
            input_seq: 0,
        }
    }

    /// The Safes already in the wallet (one entry per `(address,
    /// chain_id)`), so Review can flag a chain that's already saved, start
    /// from the Safe's saved name and count its saved links.
    pub fn with_existing_safes(mut self, safes: Vec<ExistingSafe>) -> Self {
        self.existing_safes = safes;
        self
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("safe_onboarding", &message);
        let phase_before = self.phase.name();
        let (task, outcome) = self.update_inner(message);
        let phase_after = self.phase.name();
        if phase_before != phase_after {
            crate::trace::state("safe_onboarding", "phase", phase_before, phase_after);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("safe_onboarding", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        // Handling a message means the parent has resumed us, whether or
        // not it called an `apply_*` (Back out of an import sub-screen
        // restores the stash as-is).
        if let Phase::Review(r) = &mut self.phase {
            r.awaiting_signer = false;
        }
        match message {
            Message::BackPressed => self.handle_back(),
            Message::KeyboardEvent(keyboard::Event::KeyPressed { key, .. }) => {
                if matches!(key, keyboard::Key::Named(keyboard::key::Named::Escape)) {
                    self.handle_back()
                } else {
                    (Task::none(), None)
                }
            }
            Message::KeyboardEvent(_) => (Task::none(), None),
            Message::AddressInput(s) => self.handle_address_input(s),
            Message::AddressSubmit => self.handle_address_submit(),
            Message::EnsResolved { seq, name, result } => {
                self.handle_ens_resolved(seq, name, result)
            }
            Message::ScanCompleted {
                seq,
                address,
                results,
            } => self.handle_scan_completed(seq, address, results),
            Message::ChainIncludeToggled(chain) => self.handle_chain_include_toggled(chain),
            Message::ChainFocused(chain) => self.handle_chain_focused(chain),
            Message::NameInput(s) => self.handle_name_input(s),
            Message::SignerToggled(idx) => self.handle_signer_toggled(idx),
            Message::AddSignerToggled => self.handle_add_signer_toggled(),
            Message::SignerMethodPicked(method) => self.handle_signer_method_picked(method),
            Message::AdvancedToggled => self.handle_advanced_toggled(),
            Message::ServiceUrlInput(s) => self.handle_service_url_input(s),
            Message::Confirm => self.handle_confirm(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());
        let card = match &self.phase {
            Phase::Find(f) => auth_card(t, 560.0, view_find(t, f)),
            Phase::Review(r) => {
                let existing = self.existing.as_slice();
                let existing_safes = self.existing_safes.as_slice();
                let body = responsive(move |size| {
                    view_review(
                        t,
                        r,
                        existing,
                        existing_safes,
                        size.width >= REVIEW_TWO_COLUMN_MIN_W,
                    )
                });
                review_card(t, body.into())
            }
        };
        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);
        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);
        auth_background(t, layout.into())
    }

    // ── Find handlers ────────────────────────────────────────────────

    fn handle_back(&mut self) -> (Task<Message>, Option<Outcome>) {
        match &mut self.phase {
            // Back / Esc during a scan cancels it in place (the old
            // Scanning screen's Back did the same). Bump the seq so the
            // in-flight result is dropped when it lands.
            Phase::Find(f) if f.scanning.is_some() => {
                f.scanning = None;
                self.input_seq = self.input_seq.wrapping_add(1);
                (Task::none(), None)
            }
            Phase::Find(_) => (Task::none(), Some(Outcome::Back)),
            // First Back folds an open add-signer section away.
            Phase::Review(r) if r.add_signer_open => {
                r.add_signer_open = false;
                (Task::none(), None)
            }
            Phase::Review(r) => {
                let input = std::mem::take(&mut r.find_input);
                self.phase = Phase::Find(FindState {
                    input,
                    ..FindState::default()
                });
                (focus_widget(ADDRESS_INPUT_ID), None)
            }
        }
    }

    fn handle_address_input(&mut self, s: String) -> (Task<Message>, Option<Outcome>) {
        let Phase::Find(f) = &mut self.phase else {
            return (Task::none(), None);
        };
        // Editing abandons whatever was in flight or on display: any
        // pending name lookup or scan is dropped by the seq bump.
        f.input = s;
        f.error = None;
        f.ens_resolving = None;
        f.scanning = None;
        f.no_safe = None;
        self.input_seq = self.input_seq.wrapping_add(1);
        (Task::none(), None)
    }

    fn handle_address_submit(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Phase::Find(f) = &self.phase else {
            return (Task::none(), None);
        };
        // The button is disabled while busy, but Enter in the input
        // still submits — don't stack a second lookup/scan.
        if f.scanning.is_some() || f.ens_resolving.is_some() {
            return (Task::none(), None);
        }
        let trimmed = f.input.trim().to_string();
        if trimmed.is_empty() {
            self.set_address_error("Please enter an Ethereum address or name.");
            return (Task::none(), None);
        }
        // Try hex address first; cheaper than spawning a name-resolution task.
        if let Ok(address) = trimmed.parse::<Address>() {
            return self.kick_off_scan(address, trimmed, false);
        }
        if names::looks_like_name(&trimmed) {
            return self.kick_off_ens(trimmed);
        }
        self.set_address_error(
            "Not a valid Ethereum address or name. Expected `0x…` (40 hex chars) or a `.eth` / `.gwei` / `.wei` / `@xns` name.",
        );
        (Task::none(), None)
    }

    fn kick_off_ens(&mut self, name: String) -> (Task<Message>, Option<Outcome>) {
        let seq = self.input_seq;
        if let Phase::Find(f) = &mut self.phase {
            f.ens_resolving = Some(seq);
            f.error = None;
            f.no_safe = None;
        }
        let network = self.network.clone();
        let task = Task::perform(
            async move {
                // Name resolution rides the Helios-verified path (mainnet
                // only); a hostile exec RPC can't substitute the resolved
                // address that becomes a Safe owner.
                let result = names::resolve_name(network.as_ref(), &name).await;
                (seq, name, result)
            },
            |(seq, name, result)| Message::EnsResolved { seq, name, result },
        );
        (task, None)
    }

    fn handle_ens_resolved(
        &mut self,
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    ) -> (Task<Message>, Option<Outcome>) {
        let Phase::Find(f) = &self.phase else {
            return (Task::none(), None);
        };
        if f.ens_resolving != Some(seq) {
            return (Task::none(), None);
        }
        match result {
            Ok(Some(address)) => self.kick_off_scan(address, name, true),
            Ok(None) => {
                self.set_address_error(&format!("“{name}” has no address record."));
                (Task::none(), None)
            }
            Err(e) => {
                self.set_address_error(&format!("Name lookup failed: {e}"));
                (Task::none(), None)
            }
        }
    }

    fn kick_off_scan(
        &mut self,
        address: Address,
        what: String,
        from_name: bool,
    ) -> (Task<Message>, Option<Outcome>) {
        let Phase::Find(f) = &mut self.phase else {
            return (Task::none(), None);
        };
        let seq = self.input_seq;
        f.scanning = Some(ScanTarget {
            address,
            what,
            from_name,
        });
        f.ens_resolving = None;
        f.error = None;
        f.no_safe = None;
        let network = self.network.clone();
        let task = Task::perform(
            async move {
                let results = safe::scan_across_chains(network.as_ref(), address).await;
                (seq, address, results)
            },
            |(seq, address, results)| Message::ScanCompleted {
                seq,
                address,
                results,
            },
        );
        (task, None)
    }

    fn handle_scan_completed(
        &mut self,
        seq: u64,
        address: Address,
        mut results: Vec<(Chain, ScanResult)>,
    ) -> (Task<Message>, Option<Outcome>) {
        if seq != self.input_seq {
            // User edited the input or cancelled; drop the stale scan.
            return (Task::none(), None);
        }
        let Phase::Find(f) = &mut self.phase else {
            return (Task::none(), None);
        };
        if !matches!(&f.scanning, Some(target) if target.address == address) {
            return (Task::none(), None);
        }
        let Some(target) = f.scanning.take() else {
            return (Task::none(), None);
        };
        // `scan_across_chains` already answers in `Chain::ALL` order, but
        // the strip and the primary-chain fallback rely on it — don't
        // trust the producer.
        results.sort_by_key(|(c, _)| chain_rank(*c));
        results.dedup_by_key(|(c, _)| *c);
        if !results.iter().any(|(_, r)| hit_of(r).is_some()) {
            f.no_safe = Some(NoSafe { address, results });
            return (Task::none(), None);
        }
        let find_input = f.input.clone();
        self.phase = Phase::Review(Box::new(ReviewState::new(
            address,
            find_input,
            target,
            results,
            &self.existing,
            &self.existing_safes,
        )));
        (focus_widget(NAME_INPUT_ID), None)
    }

    fn set_address_error(&mut self, msg: &str) {
        if let Phase::Find(f) = &mut self.phase {
            f.error = Some(msg.to_string());
            f.ens_resolving = None;
        }
    }

    // ── Review handlers ──────────────────────────────────────────────

    fn handle_chain_include_toggled(&mut self, chain: Chain) -> (Task<Message>, Option<Outcome>) {
        let Phase::Review(r) = &mut self.phase else {
            return (Task::none(), None);
        };
        if r.hit(chain).is_none() {
            return (Task::none(), None);
        }
        if let Some(pos) = r.excluded.iter().position(|c| *c == chain) {
            r.excluded.remove(pos);
        } else if r.included().count() > 1 {
            // The last included chain stays — there'd be nothing to add.
            r.excluded.push(chain);
        }
        (Task::none(), None)
    }

    fn handle_chain_focused(&mut self, chain: Chain) -> (Task<Message>, Option<Outcome>) {
        if let Phase::Review(r) = &mut self.phase
            && r.hit(chain).is_some()
        {
            r.focused = chain;
        }
        (Task::none(), None)
    }

    fn handle_name_input(&mut self, s: String) -> (Task<Message>, Option<Outcome>) {
        if let Phase::Review(r) = &mut self.phase {
            r.name = s;
        }
        (Task::none(), None)
    }

    fn handle_signer_toggled(&mut self, idx: u32) -> (Task<Message>, Option<Outcome>) {
        let Phase::Review(r) = &mut self.phase else {
            return (Task::none(), None);
        };
        // Only signing-capable accounts can be ticked; a view-only row is
        // rendered disabled, this is the backstop.
        if !self
            .existing
            .iter()
            .any(|e| e.account_idx == idx && !e.view_only)
        {
            return (Task::none(), None);
        }
        if !r.selected.remove(&idx) {
            r.selected.insert(idx);
        }
        r.signer_error = None;
        (Task::none(), None)
    }

    fn handle_add_signer_toggled(&mut self) -> (Task<Message>, Option<Outcome>) {
        if let Phase::Review(r) = &mut self.phase {
            r.add_signer_open = !r.add_signer_open;
        }
        (Task::none(), None)
    }

    fn handle_signer_method_picked(
        &mut self,
        method: SignerMethod,
    ) -> (Task<Message>, Option<Outcome>) {
        let Phase::Review(r) = &mut self.phase else {
            return (Task::none(), None);
        };
        let allowed_owners = r.unclaimed_owners(&self.existing);
        if allowed_owners.is_empty() {
            r.signer_error =
                Some("Every owner of this Safe is already in your wallet.".to_string());
            return (Task::none(), None);
        }
        r.awaiting_signer = true;
        (
            Task::none(),
            Some(Outcome::RequestAddSigner {
                method,
                allowed_owners,
            }),
        )
    }

    /// Called by the parent after a successful import + owner
    /// validation. Pushes `new_account` into the screen's `existing`
    /// snapshot (so the next add-signer allow-list treats it as already
    /// claimed) and ticks it as a signer — it's then linked on every
    /// included chain it owns.
    pub fn apply_added_signer(&mut self, new_account: ExistingAccount) {
        let phase_before = self.phase.name();
        if !self
            .existing
            .iter()
            .any(|e| e.account_idx == new_account.account_idx)
        {
            self.existing.push(new_account.clone());
        }
        if let Phase::Review(r) = &mut self.phase {
            if !new_account.view_only {
                r.selected.insert(new_account.account_idx);
            }
            r.signer_error = None;
            r.add_signer_open = false;
            r.awaiting_signer = false;
        }
        if phase_before != self.phase.name() {
            crate::trace::state("safe_onboarding", "phase", phase_before, self.phase.name());
        }
    }

    /// Called by the parent on a screen that is still parked UNDER a
    /// nested-Safe sub-flow when that sub-flow imported `account`. This
    /// screen didn't ask for it, so its add-signer section, error and
    /// parked marker stay as they are (`apply_added_signer` is for the
    /// screen that did).
    ///
    /// The account joins the snapshot, so Review lists it, stops offering
    /// its address as unclaimed and a rescan sees it. A signing-capable
    /// account that owns this Safe on a scanned chain is also ticked — the
    /// default Review gives every owner it knew at scan time — so it gets
    /// linked on each included chain it owns. No-op for an account the
    /// snapshot already holds (the user's tick stays theirs).
    pub fn note_account(&mut self, account: ExistingAccount) {
        if self
            .existing
            .iter()
            .any(|e| e.account_idx == account.account_idx)
        {
            return;
        }
        if let Phase::Review(r) = &mut self.phase
            && !account.view_only
            && r.hits()
                .any(|(_, md, _)| md.owners.contains(&account.address))
        {
            r.selected.insert(account.account_idx);
        }
        self.existing.push(account);
    }

    /// Called by the parent after a nested-Safe sub-flow finished and
    /// the inner Safe was saved to the wallet. Records the nested
    /// Safe's address as a linked owner so Review can surface it as a
    /// sign-capable owner.
    pub fn apply_added_nested_safe(&mut self, address: Address) {
        let phase_before = self.phase.name();
        if let Phase::Review(r) = &mut self.phase {
            if !r.linked_nested_safes.contains(&address) {
                r.linked_nested_safes.push(address);
            }
            r.signer_error = None;
            r.add_signer_open = false;
            r.awaiting_signer = false;
        }
        if phase_before != self.phase.name() {
            crate::trace::state("safe_onboarding", "phase", phase_before, self.phase.name());
        }
    }

    /// Called by the parent when an import attempt failed validation
    /// (e.g., the derived address wasn't an owner of this Safe). Review
    /// shows the error; the add-signer section stays as it was so the
    /// user can retry.
    pub fn apply_signer_import_error(&mut self, message: String) {
        let phase_before = self.phase.name();
        if let Phase::Review(r) = &mut self.phase {
            r.signer_error = Some(message);
            r.awaiting_signer = false;
        }
        if phase_before != self.phase.name() {
            crate::trace::state("safe_onboarding", "phase", phase_before, self.phase.name());
        }
    }

    fn handle_advanced_toggled(&mut self) -> (Task<Message>, Option<Outcome>) {
        if let Phase::Review(r) = &mut self.phase {
            r.advanced = !r.advanced;
        }
        (Task::none(), None)
    }

    fn handle_service_url_input(&mut self, s: String) -> (Task<Message>, Option<Outcome>) {
        if let Phase::Review(r) = &mut self.phase {
            r.service_url = s;
            r.service_url_error = None;
        }
        (Task::none(), None)
    }

    fn handle_confirm(&mut self) -> (Task<Message>, Option<Outcome>) {
        let existing = &self.existing;
        let Phase::Review(r) = &mut self.phase else {
            return (Task::none(), None);
        };
        let Some(primary_chain) = r.primary_chain() else {
            return (Task::none(), None);
        };
        // Validate the Advanced service URL before anything is built —
        // a typo'd mirror must not get persisted and then silently
        // 404/timeout every queue fetch.
        let tx_service_url = match crate::safe::service::normalize_service_base(&r.service_url) {
            Ok(v) => v,
            Err(e) => {
                // Re-open the section so the error is visible even if
                // the user collapsed it after typing.
                r.advanced = true;
                r.service_url_error = Some(e);
                return (Task::none(), None);
            }
        };
        let now = unix_seconds();
        let clean_name = clean_label(&r.name);
        // Every included chain becomes its own (address, chain_id)
        // record (separate owner cache; the storage layer treats them
        // as independent). Primary first, then the rest in
        // `Chain::ALL` order; each lists every OTHER chosen chain as a
        // sibling so it self-describes its peer list.
        let mut chosen: Vec<(Chain, &SafeMetadata, SafeTrust)> = r.included().collect();
        chosen.sort_by_key(|(c, _, _)| *c != primary_chain);
        let all_chain_ids: Vec<u64> = chosen.iter().map(|(c, _, _)| c.chain_id()).collect();
        let mut descriptors = chosen.iter().map(|(chain, md, trust)| {
            let others: Vec<u64> = all_chain_ids
                .iter()
                .copied()
                .filter(|id| *id != chain.chain_id())
                .collect();
            descriptor_from(
                md,
                *chain,
                trust.clone(),
                clean_name.clone(),
                // Per chain: owner sets can diverge, so each descriptor
                // links only the ticked accounts that own THIS chain.
                r.links_on(existing, &md.owners),
                others,
                now,
                // A custom mirror serves the multi-chain
                // /tx-service/{chain} layout, so siblings share it.
                // Adjustable per Safe later in Settings → Safes.
                tx_service_url.clone(),
            )
        });
        let Some(primary) = descriptors.next() else {
            return (Task::none(), None);
        };
        let siblings: Vec<SafeDescriptor> = descriptors.collect();
        (
            Task::none(),
            Some(Outcome::Done {
                primary: Box::new(primary),
                siblings,
            }),
        )
    }
}

/// Hooks for App-level tests, which can't drive a scan (its result is
/// stamped with the private `input_seq`) or look inside Review.
#[cfg(test)]
impl SafeOnboardingScreen {
    /// This screen on Review for Safe `address`, as if typed in hex and
    /// scanned as a canonical Safe on each of `hits` (chain → owners).
    pub(crate) fn scanned_for_test(
        mut self,
        address: Address,
        hits: Vec<(Chain, Vec<Address>)>,
    ) -> Self {
        let results = hits
            .into_iter()
            .map(|(chain, owners)| {
                let md = SafeMetadata {
                    chain_id: chain.chain_id(),
                    address,
                    implementation: Address::ZERO,
                    version: "1.4.1".into(),
                    threshold: 1,
                    owners,
                    modules: Vec::new(),
                    guard: None,
                    fallback_handler: None,
                    module_guard: None,
                    nonce: alloy::primitives::U256::ZERO,
                };
                (chain, ScanResult::Canonical(md))
            })
            .collect();
        let what = format!("{address:?}");
        let target = ScanTarget {
            address,
            what: what.clone(),
            from_name: false,
        };
        let review = ReviewState::new(
            address,
            what,
            target,
            results,
            &self.existing,
            &self.existing_safes,
        );
        self.phase = Phase::Review(Box::new(review));
        self
    }

    /// The account snapshot holds `account_idx`.
    pub(crate) fn knows_account(&self, account_idx: u32) -> bool {
        self.existing.iter().any(|e| e.account_idx == account_idx)
    }

    /// Review has `account_idx` ticked as a signer.
    pub(crate) fn ticks_signer(&self, account_idx: u32) -> bool {
        matches!(&self.phase, Phase::Review(r) if r.selected.contains(&account_idx))
    }

    /// Review's name field.
    pub(crate) fn review_name(&self) -> Option<&str> {
        match &self.phase {
            Phase::Review(r) => Some(r.name.as_str()),
            Phase::Find(_) => None,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn clean_label(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Position in `Chain::ALL` — the display and primary-fallback order.
fn chain_rank(chain: Chain) -> usize {
    Chain::ALL
        .iter()
        .position(|c| *c == chain)
        .unwrap_or(usize::MAX)
}

/// The Safe a scan found, with the trust level its implementation earns.
/// `None` for the not-a-Safe outcomes.
fn hit_of(result: &ScanResult) -> Option<(&SafeMetadata, SafeTrust)> {
    match result {
        ScanResult::Canonical(md) => Some((md, SafeTrust::Canonical)),
        ScanResult::UnrecognizedImpl(md) => Some((md, SafeTrust::UnrecognizedImpl)),
        ScanResult::NotDeployed | ScanResult::NotASafe { .. } => None,
    }
}

/// Why a chain's scan isn't (or is) a Safe, for the Find breakdown.
fn scan_reason(result: &ScanResult) -> String {
    match result {
        ScanResult::NotDeployed => "no contract at this address".to_string(),
        ScanResult::NotASafe { reason } => format!("not a Safe: {reason}"),
        ScanResult::Canonical(_) | ScanResult::UnrecognizedImpl(_) => "Safe found".to_string(),
    }
}

/// The detail after "not a Safe on {chain}" in the Review chain strip.
fn miss_detail(result: &ScanResult) -> String {
    match result {
        ScanResult::NotDeployed => "no contract at this address".to_string(),
        ScanResult::NotASafe { reason } => reason.clone(),
        ScanResult::Canonical(_) | ScanResult::UnrecognizedImpl(_) => "Safe found".to_string(),
    }
}

/// The wallet's entry for this Safe on `chain`, if it's already saved there.
fn saved_entry(
    existing_safes: &[ExistingSafe],
    address: Address,
    chain: Chain,
) -> Option<&ExistingSafe> {
    let key = (<[u8; 20]>::from(address), chain.chain_id());
    existing_safes.iter().find(|s| s.key == key)
}

/// Every saved entry for this Safe's address, on any chain.
fn saved_peers(
    existing_safes: &[ExistingSafe],
    address: Address,
) -> impl Iterator<Item = &ExistingSafe> {
    let address = <[u8; 20]>::from(address);
    existing_safes.iter().filter(move |s| s.key.0 == address)
}

/// The name the wallet already gives this address — its first named
/// entry, the same one `WalletDescriptor::upsert_safe` hands a new chain.
fn saved_name(existing_safes: &[ExistingSafe], address: Address) -> Option<&str> {
    saved_peers(existing_safes, address).find_map(|s| s.name.as_deref())
}

/// The hint under Review's name field for a Safe that's already saved on
/// some chain: the field applies to every chain of the address
/// (`App::upsert_safes`), so say what confirming does to the saved name.
/// `(text, renames)`; `None` when the address isn't saved anywhere.
fn name_hint(
    existing_safes: &[ExistingSafe],
    address: Address,
    name: &str,
) -> Option<(String, bool)> {
    saved_peers(existing_safes, address).next()?;
    let hint = match clean_label(name) {
        // Mirrors `upsert_safes`: a given name differing from any saved
        // entry's renames them all.
        Some(name)
            if saved_peers(existing_safes, address)
                .any(|s| s.name.as_deref() != Some(name.as_str())) =>
        {
            ("Renames this Safe on every chain".to_string(), true)
        }
        Some(_) => (
            "Already saved under this name — it applies on every chain".to_string(),
            false,
        ),
        // Blank renames nothing; a new chain takes the saved name.
        None => match saved_name(existing_safes, address) {
            Some(saved) => (
                format!("Left blank, it keeps its saved name “{saved}”"),
                false,
            ),
            None => ("Applies to this Safe on every chain".to_string(), false),
        },
    };
    Some(hint)
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[allow(clippy::too_many_arguments)]
fn descriptor_from(
    md: &SafeMetadata,
    chain: Chain,
    trust: SafeTrust,
    name: Option<String>,
    linked_signer_indices: Vec<u32>,
    sibling_chains: Vec<u64>,
    cached_at: u64,
    tx_service_url: Option<String>,
) -> SafeDescriptor {
    SafeDescriptor {
        name,
        chain_id: chain.chain_id(),
        address: md.address.into(),
        version: md.version.clone(),
        trust,
        threshold: md.threshold,
        owners: md.owners.iter().map(|a| (*a).into()).collect(),
        modules: md.modules.iter().map(|a| (*a).into()).collect(),
        guard: md.guard.map(|a| a.into()),
        fallback_handler: md.fallback_handler.map(|a| a.into()),
        module_guard: md.module_guard.map(|a| a.into()),
        linked_signer_indices,
        sibling_chains,
        cached_at,
        tx_service_url,
    }
}

// ── Views: Find ─────────────────────────────────────────────────────────────

fn view_find(t: KaoTheme, f: &FindState) -> Element<'_, Message> {
    let addr_input = text_input("0x… or a name (.eth / .gwei / .wei / @xns)", &f.input)
        .id(ADDRESS_INPUT_ID)
        .on_input(Message::AddressInput)
        .on_submit(Message::AddressSubmit)
        .padding(Padding::from([12, 14]))
        .size(14)
        .font(mono())
        .style(move |_theme, status| text_input_style(t, status));

    let (btn_label, ready) = if f.scanning.is_some() {
        ("Scanning…", false)
    } else if f.ens_resolving.is_some() {
        ("Resolving name…", false)
    } else {
        ("Scan →", true)
    };
    let btn =
        primary_button(t, btn_label, ready).on_press_maybe(ready.then_some(Message::AddressSubmit));

    // While scanning, Enter does nothing and Esc cancels the scan.
    let hint_row = if f.scanning.is_some() {
        row![
            hint_pill(t, "Esc"),
            Space::new().width(6),
            text("to cancel").size(11).color(t.sub),
        ]
    } else {
        row![
            hint_pill(t, "Enter"),
            Space::new().width(6),
            text("to scan · ").size(11).color(t.sub),
            hint_pill(t, "Esc"),
            Space::new().width(6),
            text("to go back").size(11).color(t.sub),
        ]
    };
    let hint = container(hint_row.align_y(Alignment::Center))
        .width(Length::Fill)
        .center_x(Length::Fill);

    let hero = if f.scanning.is_some() {
        "ദ്ദി◝ ⩊ ◜.ᐟ"
    } else if f.no_safe.is_some() {
        "(*ᴗ͈ˬᴗ͈)ꕤ*.ﾟ"
    } else {
        "(˶>⩊<˶)"
    };

    let mut content = column![
        kao_hero(t, hero, 56.0),
        vspace(10),
        screen_title(t, "Add a Safe"),
        vspace(6),
        screen_subtitle(
            t,
            "Paste the Safe's address (or name) — Kao scans Mainnet, Optimism, and Base."
        ),
        vspace(22),
        addr_input,
        vspace(18),
        btn,
        vspace(14),
        hint,
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    if let Some(target) = &f.scanning {
        content = content
            .push(vspace(16))
            .push(
                text("Checking Mainnet, Optimism, and Base in parallel…")
                    .size(12)
                    .color(t.sub),
            )
            .push(vspace(4))
            .push(
                text(target.what.as_str())
                    .size(13)
                    .color(t.sub)
                    .font(mono()),
            );
    }
    if let Some(e) = &f.error {
        content = content.push(vspace(10)).push(error_text(t, e));
    }
    if let Some(ns) = &f.no_safe {
        content = content.push(vspace(18)).push(view_no_safe(t, ns));
    }
    content.into()
}

/// "No Safe anywhere" breakdown shown inline on Find: one row per chain
/// with the reason it isn't a Safe there.
fn view_no_safe(t: KaoTheme, ns: &NoSafe) -> Element<'_, Message> {
    let mut col = column![
        text("No Safe found at this address on Mainnet, Optimism, or Base.")
            .size(12)
            .color(t.a2)
            .font(mono_bold()),
        vspace(8),
        colored_address(t, ns.address),
        vspace(8),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);
    for (chain, result) in &ns.results {
        let line = row![
            text(chain.label()).size(12).color(t.text).font(mono_bold()),
            Space::new().width(10),
            text(scan_reason(result)).size(11).color(t.sub).font(mono()),
        ]
        .align_y(Alignment::Center);
        col = col.push(line).push(vspace(4));
    }
    col.into()
}

// ── Views: Review ───────────────────────────────────────────────────────────

/// Wide sibling of `auth_card` for Review: same chrome, but `Fill` up to
/// `REVIEW_CARD_MAX_W` so it shrinks with the window instead of
/// overflowing it, and `Fill` height (capped) so the columns below get a
/// bounded height to scroll within — a vertical scrollable hands its
/// content infinite height, so it needs a bounded parent.
fn review_card<'a>(t: KaoTheme, content: Element<'a, Message>) -> Element<'a, Message> {
    let card = container(content)
        .padding(Padding::from([24, 28]))
        .width(Length::Fill)
        .max_width(REVIEW_CARD_MAX_W)
        .height(Length::Fill)
        .max_height(REVIEW_CARD_MAX_H)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(24),
            },
            text_color: Some(t.text),
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, if t.dark { 0.45 } else { 0.10 }),
                offset: iced::Vector::new(0.0, 12.0),
                blur_radius: 36.0,
            },
            ..container::Style::default()
        });
    // `align_x`/`align_y`, not `center_x(len)` — that would SET the
    // card's width and defeat `max_width`.
    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding::from([0, 16]).bottom(16))
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .into()
}

/// The whole Review body. `wide` = two columns (Security | Setup, each
/// with its own scrollable); otherwise one stacked scrollable.
fn view_review<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing: &'a [ExistingAccount],
    existing_safes: &'a [ExistingSafe],
    wide: bool,
) -> Element<'a, Message> {
    let header = view_review_header(t, r, existing_safes, wide);
    let security = view_security(t, r, existing);
    let setup = view_setup(t, r, existing, existing_safes);
    let footer = view_review_footer(t, r, existing, existing_safes);

    let body: Element<'a, Message> = if wide {
        let left = container(review_scroll(t, security).height(Length::Shrink))
            .width(Length::FillPortion(1))
            .height(Length::Fill);
        let rule = container(Space::new().width(1).height(Length::Fill))
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.border)),
                ..container::Style::default()
            });
        // The Setup scrollable is `Fill` so the footer (role summary +
        // confirm) is laid out first and stays pinned under it — a
        // `Shrink` scrollable laid out before it could take the whole
        // height and push the button off the card.
        let right = column![
            review_scroll(t, setup).height(Length::Fill),
            vspace(12),
            footer,
        ]
        .width(Length::FillPortion(1))
        .height(Length::Fill);
        row![left, rule, right]
            .spacing(14)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        column![
            review_scroll(t, column![security, vspace(22), setup].into()).height(Length::Fill),
            vspace(12),
            footer,
        ]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    };

    column![header, vspace(14), body]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// A Review column's own scrollable. The right padding keeps the
/// (floating) scrollbar off the content.
fn review_scroll<'a>(t: KaoTheme, content: Element<'a, Message>) -> Scrollable<'a, Message> {
    scrollable(
        container(content)
            .width(Length::Fill)
            .padding(Padding::ZERO.right(12)),
    )
    .width(Length::Fill)
    .style(move |_theme, status| kao_scrollable_style(t, status))
}

fn view_review_header<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing_safes: &'a [ExistingSafe],
    wide: bool,
) -> Element<'a, Message> {
    let mut col = column![
        screen_title(t, "Review Safe"),
        vspace(8),
        colored_address(t, r.address),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);
    if let Some(name) = &r.typed_name {
        col = col.push(vspace(2)).push(
            text(format!("resolved from {name}"))
                .size(12)
                .color(t.sub)
                .font(mono()),
        );
    }
    col = col
        .push(vspace(14))
        .push(view_chain_strip(t, r, existing_safes, wide));
    col.into()
}

/// One row per scanned chain: hits get an include box, a focus target
/// and their at-a-glance numbers; misses say why they aren't a Safe.
fn view_chain_strip<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing_safes: &'a [ExistingSafe],
    wide: bool,
) -> Element<'a, Message> {
    let included_count = r.included().count();
    let mut col = column![].spacing(6).width(Length::Fill);
    for (chain, result) in &r.results {
        let chain = *chain;
        let line = match hit_of(result) {
            Some((md, trust)) => {
                let included = r.is_included(chain);
                view_chain_hit(
                    t,
                    chain,
                    md,
                    &trust,
                    ChainRowState {
                        included,
                        locked: included && included_count == 1,
                        focused: r.focused == chain,
                        saved: saved_entry(existing_safes, r.address, chain).is_some(),
                    },
                    wide,
                )
            }
            None => container(
                text(format!(
                    "not a Safe on {} — {}",
                    chain.display_name(),
                    miss_detail(result)
                ))
                .size(11)
                .color(t.sub)
                .font(mono()),
            )
            // Line up with the hit rows' chain names (row padding +
            // checkbox + gap + button padding).
            .padding(Padding::from([2, 10]).left(40))
            .width(Length::Fill)
            .into(),
        };
        col = col.push(line);
    }
    col.into()
}

#[derive(Debug, Clone, Copy)]
struct ChainRowState {
    included: bool,
    /// The last included chain: its box can't be unticked.
    locked: bool,
    focused: bool,
    saved: bool,
}

fn view_chain_hit<'a>(
    t: KaoTheme,
    chain: Chain,
    md: &'a SafeMetadata,
    trust: &SafeTrust,
    st: ChainRowState,
    wide: bool,
) -> Element<'a, Message> {
    let include = kao_checkbox(t, st.included).size(16).on_toggle_maybe(
        (!st.locked).then_some(move |_: bool| Message::ChainIncludeToggled(chain)),
    );
    let name = text(chain.display_name())
        .size(13)
        .color(t.text)
        .font(mono_bold());
    let details = text(format!(
        "threshold {} of {} · v{}",
        md.threshold,
        md.owners.len(),
        md.version
    ))
    .size(12)
    .color(t.sub)
    .font(mono());
    let saved: Element<'a, Message> = if st.saved {
        text("Already in your wallet")
            .size(11)
            .color(t.a3)
            .font(mono_bold())
            .into()
    } else {
        Space::new().into()
    };
    let info: Element<'a, Message> = if wide {
        row![
            name,
            Space::new().width(10),
            trust_badge(t, trust),
            Space::new().width(12),
            details,
            Space::new().width(Length::Fill),
            saved,
        ]
        .align_y(Alignment::Center)
        .into()
    } else {
        column![
            row![name, Space::new().width(10), trust_badge(t, trust)].align_y(Alignment::Center),
            row![details, Space::new().width(10), saved].align_y(Alignment::Center),
        ]
        .spacing(2)
        .into()
    };
    // The name/numbers are the focus target; the checkbox sits outside
    // the button so ticking it never also refocuses.
    let focus = ghost_button(
        t,
        container(info)
            .width(Length::Fill)
            .padding(Padding::from([6, 10])),
    )
    .width(Length::Fill)
    .on_press(Message::ChainFocused(chain));
    let focused = st.focused;
    container(
        row![include, Space::new().width(4), focus]
            .align_y(Alignment::Center)
            .width(Length::Fill),
    )
    .padding(Padding::from([2, 10]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(if focused {
            t.card_alt
        } else {
            Color::TRANSPARENT
        })),
        border: Border {
            color: if focused {
                with_alpha(t.a1, 0.55)
            } else {
                t.border
            },
            width: 1.0,
            radius: Radius::from(12),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    })
    .into()
}

fn trust_badge<'a>(t: KaoTheme, trust: &SafeTrust) -> Element<'a, Message> {
    match trust {
        SafeTrust::Canonical => text("✓ Canonical")
            .size(11)
            .color(t.a1)
            .font(mono_bold())
            .into(),
        SafeTrust::UnrecognizedImpl => text("⚠ Unrecognized impl")
            .size(11)
            .color(t.a2)
            .font(mono_bold())
            .into(),
    }
}

fn column_title<'a>(t: KaoTheme, label: &'a str) -> Element<'a, Message> {
    container(text(label).size(15).color(t.text).font(black()))
        .width(Length::Fill)
        .into()
}

fn field_heading<'a>(t: KaoTheme, label: &'a str) -> Element<'a, Message> {
    text(label).size(12).color(t.text).font(mono_bold()).into()
}

/// The Security column for the focused chain: version and trust,
/// threshold, owners, and the module / guard / fallback-handler surfaces.
fn view_security<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing: &'a [ExistingAccount],
) -> Element<'a, Message> {
    let mut col = column![column_title(t, "Security"), vspace(10)]
        .width(Length::Fill)
        .align_x(Alignment::Center);
    let chain = r.focused;
    let Some((md, trust)) = r.hit(chain) else {
        // `focused` is only ever set to a hit; render nothing rather
        // than panic if that stops holding.
        return col.into();
    };

    col = col.push(
        row![
            text(chain.display_name())
                .size(13)
                .color(t.text)
                .font(mono_bold()),
            Space::new().width(10),
            text(format!("v{}", md.version))
                .size(12)
                .color(t.sub)
                .font(mono()),
            Space::new().width(10),
            trust_badge(t, &trust),
        ]
        .align_y(Alignment::Center),
    );
    if let Some(reason) = trust.signing_block_reason() {
        col = col
            .push(vspace(4))
            .push(text(reason).size(11).color(t.a2).font(mono_bold()));
    }
    if !r.is_included(chain) {
        col = col.push(vspace(4)).push(
            text("Not being added — tick it above to include it.")
                .size(11)
                .color(t.sub)
                .font(mono()),
        );
    }

    col = col.push(vspace(10)).push(
        text(format!(
            "threshold {} of {} owner{}",
            md.threshold,
            md.owners.len(),
            plural(md.owners.len())
        ))
        .size(12)
        .color(t.sub)
        .font(mono()),
    );
    if md.threshold == 1 {
        col = col.push(vspace(6)).push(
            text("⚠ Threshold = 1 — any owner can act alone")
                .size(11)
                .color(t.a2)
                .font(mono_bold()),
        );
    }
    // Only the focused chain is spelled out below; flag any included
    // chain that would add something different.
    if r.owners_differ() {
        col = col.push(vspace(6)).push(
            text("⚠ Owners differ across chains — review each one")
                .size(11)
                .color(t.a2)
                .font(mono_bold()),
        );
    }
    if r.danger_surfaces_differ() {
        col = col.push(vspace(6)).push(
            text("⚠ Modules / guards / fallback handler differ across chains — review each one")
                .size(11)
                .color(t.a2)
                .font(mono_bold()),
        );
    }

    col = col.push(vspace(14)).push(field_heading(t, "Owners"));
    for owner in &md.owners {
        col = col.push(vspace(4)).push(colored_address(t, *owner));
        if let Some(acc) = existing.iter().find(|e| e.address == *owner) {
            let (label, color) = if acc.view_only {
                (format!("· {} (view-only)", acc.label), t.sub)
            } else {
                (format!("· {}", acc.label), t.a1)
            };
            col = col.push(text(label).size(11).color(color).font(mono_bold()));
        } else if r.linked_nested_safes.contains(owner) {
            col = col.push(
                text("· linked owner Safe")
                    .size(11)
                    .color(t.a1)
                    .font(mono_bold()),
            );
        }
    }

    col = col
        .push(vspace(14))
        .push(danger_block(
            t,
            "Modules",
            &md.modules,
            "no modules enabled",
        ))
        .push(vspace(10))
        .push(danger_block(
            t,
            "Guard",
            md.guard.as_slice(),
            "no guard set",
        ));
    // Only a 1.5.0+ Safe has a module guard; for an older one the row would
    // describe something the contract can't have.
    if safe::has_module_guard(&md.version) {
        col = col.push(vspace(10)).push(danger_block(
            t,
            "Module guard",
            md.module_guard.as_slice(),
            "no module guard set",
        ));
    }
    col.push(vspace(10))
        .push(danger_block(
            t,
            "Fallback handler",
            md.fallback_handler.as_slice(),
            "no fallback handler set",
        ))
        .into()
}

/// Render one of the "danger surfaces" — modules / guard / module guard /
/// fallback — with classification labels next to each address. Unknown
/// addresses get a warning-styled label since they're a standing security
/// surface that deserves attention.
fn danger_block<'a, T: AsRef<[Address]>>(
    t: KaoTheme,
    title: &str,
    addrs: T,
    empty_msg: &'a str,
) -> Element<'a, Message> {
    let mut col = column![
        text(title.to_string())
            .size(12)
            .color(t.text)
            .font(mono_bold())
    ]
    .align_x(Alignment::Center);
    let addrs = addrs.as_ref();
    if addrs.is_empty() {
        col = col
            .push(vspace(4))
            .push(text(empty_msg).size(11).color(t.sub).font(mono()));
    } else {
        for a in addrs {
            let label_text = match safe::classify_module(*a) {
                Some(label) => text(label.to_string()).size(11).color(t.sub).font(mono()),
                None => text("⚠ unknown — review before trusting")
                    .size(11)
                    .color(t.a2)
                    .font(mono_bold()),
            };
            col = col
                .push(vspace(4))
                .push(colored_address(t, *a))
                .push(label_text);
        }
    }
    col.into()
}

/// The Setup column: name, which accounts to link as signers, the inline
/// add-signer section and the Advanced transaction-service override.
fn view_setup<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing: &'a [ExistingAccount],
    existing_safes: &'a [ExistingSafe],
) -> Element<'a, Message> {
    let name_input = text_input("Treasury · Council · Personal hot…", &r.name)
        .id(NAME_INPUT_ID)
        .on_input(Message::NameInput)
        .on_submit(Message::Confirm)
        .padding(Padding::from([12, 14]))
        .size(14)
        .font(mono())
        .style(move |_theme, status| text_input_style(t, status));

    let mut col = column![
        column_title(t, "Setup"),
        vspace(10),
        field_heading(t, "Name"),
        vspace(6),
        name_input,
    ]
    .width(Length::Fill);
    if let Some((hint, renames)) = name_hint(existing_safes, r.address, &r.name) {
        col = col.push(vspace(4)).push(
            text(hint)
                .size(11)
                .color(if renames { t.a2 } else { t.sub })
                .font(mono()),
        );
    }
    col = col
        .push(vspace(18))
        .push(field_heading(t, "Your signers"))
        .push(vspace(6));

    let mut any_signer_row = false;
    for acc in existing {
        let chains = r.owned_chains(acc.address);
        if chains.is_empty() {
            continue;
        }
        any_signer_row = true;
        let idx = acc.account_idx;
        let checkbox = kao_checkbox(t, !acc.view_only && r.selected.contains(&idx))
            .label(format!("{} · {}", acc.label, short_address(acc.address)))
            .size(16)
            .spacing(10)
            .text_size(13)
            .text_line_height(1.4)
            .font(mono())
            .on_toggle_maybe(
                (!acc.view_only).then_some(move |_: bool| Message::SignerToggled(idx)),
            );
        let sub = if acc.view_only {
            "view-only — can't sign".to_string()
        } else {
            let names: Vec<&str> = chains.iter().map(|c| c.label()).collect();
            let mut sub = format!("owner on {}", names.join(" · "));
            // A saved chain already linking it keeps the link even if
            // it's unticked here — a merge never unlinks.
            let linked: Vec<&str> = chains
                .iter()
                .filter(|c| {
                    saved_entry(existing_safes, r.address, **c)
                        .is_some_and(|s| s.linked_signer_indices.contains(&idx))
                })
                .map(|c| c.label())
                .collect();
            if !linked.is_empty() {
                sub.push_str(&format!(" — already linked on {}", linked.join(" · ")));
            }
            sub
        };
        col = col
            .push(checkbox)
            .push(
                container(text(sub).size(11).color(t.sub).font(mono()))
                    .padding(Padding::ZERO.left(26)),
            )
            .push(vspace(6));
    }
    if !any_signer_row {
        col = col.push(
            text("None of your accounts own this Safe.")
                .size(12)
                .color(t.sub)
                .font(mono()),
        );
    }

    if !r.linked_nested_safes.is_empty() {
        col = col
            .push(vspace(12))
            .push(field_heading(t, "Linked owner Safes"));
        for a in &r.linked_nested_safes {
            col = col.push(vspace(6)).push(colored_address(t, *a));
        }
    }

    col = col.push(vspace(12)).push(
        link_button(
            t,
            if r.add_signer_open {
                "Add a new signer ▾"
            } else {
                "Add a new signer ▸"
            },
        )
        .on_press(Message::AddSignerToggled),
    );
    if r.add_signer_open {
        col = col.push(vspace(6)).push(view_add_signer(t, r, existing));
    }
    if let Some(err) = &r.signer_error {
        col = col.push(vspace(10)).push(error_text(t, err));
    }

    // Advanced section — collapsed by default; holds the custom
    // Transaction Service mirror. Per-Safe, validated on confirm.
    col = col.push(vspace(10)).push(
        link_button(
            t,
            if r.advanced {
                "Advanced ▾"
            } else {
                "Advanced ▸"
            },
        )
        .on_press(Message::AdvancedToggled),
    );
    if r.advanced {
        let service_input = text_input(
            crate::safe::service::DEFAULT_TX_SERVICE_BASE,
            &r.service_url,
        )
        .on_input(Message::ServiceUrlInput)
        .on_submit(Message::Confirm)
        .padding(Padding::from([10, 12]))
        .size(13)
        .font(mono())
        .style(move |_theme, status| text_input_style(t, status));
        col = col
            .push(vspace(8))
            .push(field_heading(t, "Transaction service"))
            .push(vspace(4))
            .push(service_input)
            .push(vspace(4))
            .push(
                text(
                    "Self-hosted Safe Transaction Service for this Safe. Leave blank \
                     for the public one. Must serve the /tx-service/{chain} API layout.",
                )
                .size(11)
                .color(t.sub),
            );
        if let Some(err) = &r.service_url_error {
            col = col.push(vspace(6)).push(error_text(t, err));
        }
    }
    col.push(vspace(8)).into()
}

/// The inline "Add a new signer" section: who the import must derive to,
/// then the four import methods.
fn view_add_signer<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing: &'a [ExistingAccount],
) -> Element<'a, Message> {
    let unclaimed = r.unclaimed_owners(existing);
    let mut body = column![field_heading(t, "Unclaimed owners")]
        .width(Length::Fill)
        .align_x(Alignment::Center);
    if unclaimed.is_empty() {
        body = body.push(vspace(4)).push(
            text("Every owner is already in your wallet — nothing to import.")
                .size(11)
                .color(t.sub)
                .font(mono()),
        );
    } else {
        for a in &unclaimed {
            body = body.push(vspace(4)).push(colored_address(t, *a));
        }
        body = body
            .push(vspace(10))
            .push(
                text("Pick an import method. The address it derives must be one of this Safe's owners.")
                    .size(12)
                    .color(t.sub),
            )
            .push(vspace(10))
            .push(method_card(
                t,
                t.ab1,
                t.a1,
                "1",
                "Seed phrase",
                "Restore an account from a 12 or 24-word phrase, then pick the matching HD index.",
                Message::SignerMethodPicked(SignerMethod::SeedPhrase),
            ))
            .push(vspace(8))
            .push(method_card(
                t,
                t.ab2,
                t.a2,
                "2",
                "Private key",
                "Paste a raw 32-byte hex key. Rejected if it doesn't derive to an owner.",
                Message::SignerMethodPicked(SignerMethod::PrivateKey),
            ))
            .push(vspace(8))
            .push(method_card(
                t,
                t.ab3,
                t.a3,
                "3",
                "Hardware wallet",
                "Connect a Ledger or Trezor and pick the matching account.",
                Message::SignerMethodPicked(SignerMethod::Hardware),
            ))
            .push(vspace(8))
            .push(method_card(
                t,
                t.ab1,
                t.a1,
                "4",
                "Nested Safe",
                "The owner is itself a Safe — onboard it as its own entry and link it as an owner.",
                Message::SignerMethodPicked(SignerMethod::NestedSafe),
            ));
    }
    section_card(t, "ADD A NEW SIGNER", body.into())
}

/// Pinned under the Setup column: what each included chain will be
/// saved as, then the confirm button. This is where a chain the user's
/// keys don't own shows up as watch-only BEFORE they confirm — and where a
/// chain that's already saved says it keeps its links.
fn view_review_footer<'a>(
    t: KaoTheme,
    r: &'a ReviewState,
    existing: &'a [ExistingAccount],
    existing_safes: &'a [ExistingSafe],
) -> Element<'a, Message> {
    let mut col = column![field_heading(t, "Adding as"), vspace(4)].width(Length::Fill);
    let roles = r.chain_roles(existing, existing_safes);
    for role in &roles {
        let owner_safe = r
            .hit(role.chain)
            .is_some_and(|(md, _)| r.linked_nested_safes.iter().any(|a| md.owners.contains(a)));
        let color = if role.signers.is_empty() {
            t.sub
        } else {
            t.text
        };
        col = col.push(
            text(role.line(owner_safe))
                .size(12)
                .color(color)
                .font(mono()),
        );
    }
    col.push(vspace(12))
        .push(primary_button(t, confirm_label(&roles), true).on_press(Message::Confirm))
        .into()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CallMock;
    use alloy::primitives::{U256, address};

    fn safe_addr() -> Address {
        address!("0x1111111111111111111111111111111111111111")
    }

    fn owner_a() -> Address {
        address!("0x000000000000000000000000000000000000beef")
    }
    fn owner_b() -> Address {
        address!("0x000000000000000000000000000000000000dead")
    }
    fn owner_c() -> Address {
        address!("0x0000000000000000000000000000000000000c0c")
    }
    fn owner_d() -> Address {
        address!("0x0000000000000000000000000000000000000d0d")
    }

    fn acct(idx: u32, address: Address) -> ExistingAccount {
        ExistingAccount {
            account_idx: idx,
            address,
            label: format!("Account {}", idx + 1),
            view_only: false,
        }
    }

    fn watched(idx: u32, address: Address) -> ExistingAccount {
        ExistingAccount {
            view_only: true,
            ..acct(idx, address)
        }
    }

    /// Canned `SafeMetadata`. Versioned 1.4.1 with the canonical L1
    /// singleton so it would classify as `Canonical` if it went through
    /// the registry; callers pick the `ScanResult` variant explicitly.
    fn fake_metadata_with_owners(owners: Vec<Address>, threshold: u32) -> SafeMetadata {
        SafeMetadata {
            chain_id: 1,
            address: safe_addr(),
            implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
            version: "1.4.1".into(),
            threshold,
            owners,
            modules: vec![],
            guard: None,
            fallback_handler: None,
            module_guard: None,
            nonce: U256::ZERO,
        }
    }

    fn hit_with(chain: Chain, owners: Vec<Address>, threshold: u32) -> (Chain, ScanResult) {
        (
            chain,
            ScanResult::Canonical(SafeMetadata {
                chain_id: chain.chain_id(),
                ..fake_metadata_with_owners(owners, threshold)
            }),
        )
    }

    fn canonical_hit(chain: Chain, owners: Vec<Address>) -> (Chain, ScanResult) {
        hit_with(chain, owners, 1)
    }

    fn screen(existing: Vec<ExistingAccount>) -> SafeOnboardingScreen {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        SafeOnboardingScreen::new(net, existing)
    }

    /// Type the Safe's hex address on Find and submit, so a scan is in
    /// flight (the returned task is dropped — tests inject the result).
    fn scanning(existing: Vec<ExistingAccount>) -> SafeOnboardingScreen {
        let mut s = screen(existing);
        let _ = s.update(Message::AddressInput(format!("{:?}", safe_addr())));
        let _ = s.update(Message::AddressSubmit);
        assert_eq!(s.phase.name(), "Scanning");
        s
    }

    fn complete_scan(s: &mut SafeOnboardingScreen, results: Vec<(Chain, ScanResult)>) {
        let _ = s.update(Message::ScanCompleted {
            seq: s.input_seq,
            address: safe_addr(),
            results,
        });
    }

    /// A screen on Review after a scan that returned `results`. `CallMock`
    /// ignores the chain, so per-chain owner differences are injected
    /// through `ScanCompleted` directly.
    fn reviewing(
        existing: Vec<ExistingAccount>,
        results: Vec<(Chain, ScanResult)>,
    ) -> SafeOnboardingScreen {
        let mut s = scanning(existing);
        complete_scan(&mut s, results);
        assert_eq!(s.phase.name(), "Review");
        s
    }

    fn review(s: &SafeOnboardingScreen) -> &ReviewState {
        match &s.phase {
            Phase::Review(r) => r,
            other => panic!("expected Review, got {other:?}"),
        }
    }

    fn review_mut(s: &mut SafeOnboardingScreen) -> &mut ReviewState {
        match &mut s.phase {
            Phase::Review(r) => r,
            other => panic!("expected Review, got {other:?}"),
        }
    }

    /// Review's role summary as `(chain, signers)` per included chain.
    fn signers_by_chain(s: &SafeOnboardingScreen) -> Vec<(Chain, Vec<u32>)> {
        review(s)
            .chain_roles(&s.existing, &s.existing_safes)
            .into_iter()
            .map(|r| (r.chain, r.signers))
            .collect()
    }

    /// The wallet's entry for the test Safe on `chain_id`.
    fn saved(chain_id: u64, name: Option<&str>, links: Vec<u32>) -> ExistingSafe {
        ExistingSafe {
            key: (safe_addr().into(), chain_id),
            name: name.map(str::to_owned),
            linked_signer_indices: links,
        }
    }

    fn find(s: &SafeOnboardingScreen) -> &FindState {
        match &s.phase {
            Phase::Find(f) => f,
            other => panic!("expected Find, got {other:?}"),
        }
    }

    fn confirm(s: &mut SafeOnboardingScreen) -> (SafeDescriptor, Vec<SafeDescriptor>) {
        let (_task, outcome) = s.update(Message::Confirm);
        let Some(Outcome::Done { primary, siblings }) = outcome else {
            panic!("expected Done, got {outcome:?}");
        };
        (*primary, siblings)
    }

    /// `(chain_id, linked_signer_indices)` for every emitted descriptor,
    /// sorted by chain id.
    fn links_by_chain(
        primary: &SafeDescriptor,
        siblings: &[SafeDescriptor],
    ) -> Vec<(u64, Vec<u32>)> {
        let mut out: Vec<(u64, Vec<u32>)> = std::iter::once(primary)
            .chain(siblings.iter())
            .map(|d| (d.chain_id, d.linked_signer_indices.clone()))
            .collect();
        out.sort();
        out
    }

    fn three_chain_hits(owners: Vec<Address>) -> Vec<(Chain, ScanResult)> {
        vec![
            canonical_hit(Chain::Mainnet, owners.clone()),
            canonical_hit(Chain::Optimism, owners.clone()),
            canonical_hit(Chain::Base, owners),
        ]
    }

    // ── Find ─────────────────────────────────────────────────────────

    #[test]
    fn initial_phase_is_an_idle_find() {
        let s = screen(Vec::new());
        assert_eq!(s.phase.name(), "Find");
        let f = find(&s);
        assert!(f.input.is_empty() && f.error.is_none() && f.no_safe.is_none());
    }

    #[test]
    fn address_submit_with_invalid_input_sets_error_and_stays() {
        let mut s = screen(Vec::new());
        let _ = s.update(Message::AddressInput("not an address".into()));
        let _ = s.update(Message::AddressSubmit);
        assert!(find(&s).error.is_some());
        assert!(find(&s).scanning.is_none());
    }

    #[test]
    fn address_submit_with_empty_input_sets_error() {
        let mut s = screen(Vec::new());
        let _ = s.update(Message::AddressSubmit);
        assert!(find(&s).error.is_some());
    }

    #[test]
    fn submitting_a_hex_address_scans_in_place() {
        let s = scanning(Vec::new());
        let target = find(&s).scanning.as_ref().expect("scan in flight");
        assert_eq!(target.address, safe_addr());
        assert!(!target.from_name);
        // The typed text stays in the input while it scans.
        assert_eq!(find(&s).input, format!("{:?}", safe_addr()));
    }

    #[test]
    fn submit_while_scanning_does_not_restart_the_scan() {
        let mut s = scanning(Vec::new());
        let seq = s.input_seq;
        let (_task, outcome) = s.update(Message::AddressSubmit);
        assert!(outcome.is_none());
        assert_eq!(s.input_seq, seq);
        assert_eq!(s.phase.name(), "Scanning");
    }

    #[tokio::test]
    async fn scan_with_zero_hits_stays_on_find_with_breakdown() {
        // Mock returns empty get_code for every chain → ScanResult::NotDeployed.
        let mock = Arc::new(CallMock::new());
        let net: Arc<dyn BalanceFetcher> = mock.clone();
        let mut s = SafeOnboardingScreen::new(net, Vec::new());
        let _ = s.update(Message::AddressInput(format!("{:?}", safe_addr())));
        let _ = s.update(Message::AddressSubmit);
        let results = safe::scan_across_chains(mock.as_ref(), safe_addr()).await;
        complete_scan(&mut s, results);
        assert_eq!(s.phase.name(), "NoSafe");
        let f = find(&s);
        assert!(f.scanning.is_none());
        let ns = f.no_safe.as_ref().expect("per-chain breakdown");
        assert_eq!(ns.address, safe_addr());
        assert_eq!(ns.results.len(), Chain::ALL.len());
        assert!(
            ns.results
                .iter()
                .all(|(_, r)| scan_reason(r) == "no contract at this address")
        );
        // The input survives so the user can fix a typo and rescan.
        assert_eq!(f.input, format!("{:?}", safe_addr()));
    }

    #[test]
    fn no_hit_breakdown_names_every_reason() {
        let mut s = scanning(Vec::new());
        complete_scan(
            &mut s,
            vec![
                (Chain::Mainnet, ScanResult::NotDeployed),
                (
                    Chain::Base,
                    ScanResult::NotASafe {
                        reason: "VERSION() reverted".into(),
                    },
                ),
                (Chain::Optimism, ScanResult::NotDeployed),
            ],
        );
        let ns = find(&s).no_safe.as_ref().expect("breakdown");
        let reasons: Vec<(Chain, String)> = ns
            .results
            .iter()
            .map(|(c, r)| (*c, scan_reason(r)))
            .collect();
        assert_eq!(
            reasons,
            vec![
                (Chain::Mainnet, "no contract at this address".to_string()),
                (Chain::Base, "not a Safe: VERSION() reverted".to_string()),
                (Chain::Optimism, "no contract at this address".to_string()),
            ]
        );
    }

    #[test]
    fn editing_the_input_clears_the_breakdown_and_cancels_a_scan() {
        let mut s = scanning(Vec::new());
        complete_scan(&mut s, vec![(Chain::Mainnet, ScanResult::NotDeployed)]);
        assert!(find(&s).no_safe.is_some());
        let _ = s.update(Message::AddressInput("0x12".into()));
        assert!(find(&s).no_safe.is_none());

        // Edit mid-scan: the scan is abandoned and its result dropped.
        let mut s = scanning(Vec::new());
        let stale_seq = s.input_seq;
        let _ = s.update(Message::AddressInput("0x1".into()));
        assert_eq!(s.phase.name(), "Find");
        let _ = s.update(Message::ScanCompleted {
            seq: stale_seq,
            address: safe_addr(),
            results: three_chain_hits(vec![owner_a()]),
        });
        assert_eq!(s.phase.name(), "Find");
    }

    #[test]
    fn stale_scan_completion_is_dropped() {
        let mut s = scanning(Vec::new());
        let stale_seq = s.input_seq.wrapping_sub(1);
        let _ = s.update(Message::ScanCompleted {
            seq: stale_seq,
            address: safe_addr(),
            results: three_chain_hits(vec![owner_a()]),
        });
        // Still scanning because the seq was stale.
        assert_eq!(s.phase.name(), "Scanning");
        // Right seq, wrong address: also dropped.
        let _ = s.update(Message::ScanCompleted {
            seq: s.input_seq,
            address: owner_a(),
            results: three_chain_hits(vec![owner_a()]),
        });
        assert_eq!(s.phase.name(), "Scanning");
    }

    #[test]
    fn back_while_scanning_cancels_in_place() {
        let mut s = scanning(Vec::new());
        let seq_at_spawn = s.input_seq;
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(
            outcome.is_none(),
            "cancelling a scan must not leave the screen"
        );
        assert_eq!(s.phase.name(), "Find");
        assert_eq!(find(&s).input, format!("{:?}", safe_addr()));
        // The in-flight result lands later and is dropped.
        let _ = s.update(Message::ScanCompleted {
            seq: seq_at_spawn,
            address: safe_addr(),
            results: three_chain_hits(vec![owner_a()]),
        });
        assert_eq!(s.phase.name(), "Find");
    }

    #[test]
    fn back_from_find_propagates_outcome_back() {
        let mut s = screen(Vec::new());
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(matches!(outcome, Some(Outcome::Back)));
    }

    #[test]
    fn stale_ens_result_is_dropped() {
        let mut s = screen(Vec::new());
        let _ = s.update(Message::AddressInput("treasury.eth".into()));
        let _ = s.update(Message::AddressSubmit);
        assert_eq!(s.phase.name(), "ResolvingName");
        let seq = s.input_seq;
        // User keeps typing — the lookup in flight is abandoned.
        let _ = s.update(Message::AddressInput("treasury2.eth".into()));
        let _ = s.update(Message::EnsResolved {
            seq,
            name: "treasury.eth".into(),
            result: Ok(Some(safe_addr())),
        });
        assert_eq!(s.phase.name(), "Find");
    }

    // ── Scan → Review ────────────────────────────────────────────────

    #[test]
    fn single_chain_hit_goes_straight_to_review() {
        let s = reviewing(
            Vec::new(),
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                (Chain::Optimism, ScanResult::NotDeployed),
                (Chain::Base, ScanResult::NotASafe { reason: "x".into() }),
            ],
        );
        let r = review(&s);
        assert_eq!(r.focused, Chain::Mainnet);
        let included: Vec<Chain> = r.included().map(|(c, _, _)| c).collect();
        assert_eq!(included, vec![Chain::Mainnet]);
        // Misses stay for the strip, normalized to `Chain::ALL` order.
        let order: Vec<Chain> = r.results.iter().map(|(c, _)| *c).collect();
        assert_eq!(order, Chain::ALL.to_vec());
    }

    #[test]
    fn multi_chain_hit_includes_every_chain_by_default() {
        let s = reviewing(Vec::new(), three_chain_hits(vec![owner_a()]));
        let r = review(&s);
        let included: Vec<Chain> = r.included().map(|(c, _, _)| c).collect();
        assert_eq!(included, Chain::ALL.to_vec());
        // First hit in `Chain::ALL` order is focused.
        assert_eq!(r.focused, Chain::Mainnet);
    }

    #[test]
    fn chain_focused_switches_the_security_column() {
        let mut s = reviewing(
            Vec::new(),
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                canonical_hit(Chain::Base, vec![owner_a()]),
                (Chain::Optimism, ScanResult::NotDeployed),
            ],
        );
        let _ = s.update(Message::ChainFocused(Chain::Base));
        assert_eq!(review(&s).focused, Chain::Base);
        // A miss can't be focused — there's nothing to review.
        let _ = s.update(Message::ChainFocused(Chain::Optimism));
        assert_eq!(review(&s).focused, Chain::Base);
    }

    #[test]
    fn review_default_checks_only_owner_accounts() {
        let stranger = address!("0x000000000000000000000000000000000000c0de");
        let s = reviewing(
            vec![acct(0, owner_a()), acct(1, stranger)],
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        // Only account 0 (owner_a) is a real owner; account 1 isn't, so
        // it's neither listed nor checked.
        assert_eq!(review(&s).selected, BTreeSet::from([0u32]));
        assert!(review(&s).owned_chains(stranger).is_empty());
    }

    #[test]
    fn ens_name_prefills_the_label() {
        let mut s = screen(Vec::new());
        let _ = s.update(Message::AddressInput("treasury.eth".into()));
        let _ = s.update(Message::AddressSubmit);
        assert_eq!(s.phase.name(), "ResolvingName");
        let _ = s.update(Message::EnsResolved {
            seq: s.input_seq,
            name: "treasury.eth".into(),
            result: Ok(Some(safe_addr())),
        });
        let target = find(&s).scanning.as_ref().expect("scan in flight");
        assert!(target.from_name);
        complete_scan(&mut s, vec![canonical_hit(Chain::Mainnet, vec![owner_a()])]);
        let r = review(&s);
        assert_eq!(r.name, "treasury.eth");
        assert_eq!(r.typed_name.as_deref(), Some("treasury.eth"));
    }

    #[test]
    fn hex_address_leaves_the_label_blank() {
        let s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        assert!(review(&s).name.is_empty());
        assert!(review(&s).typed_name.is_none());
    }

    #[test]
    fn back_from_review_returns_to_find_keeping_the_input() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(outcome.is_none(), "in-flow back must not propagate");
        let f = find(&s);
        assert_eq!(f.input, format!("{:?}", safe_addr()));
        assert!(f.error.is_none() && f.scanning.is_none() && f.no_safe.is_none());
        // Enter rescans the same address.
        let _ = s.update(Message::AddressSubmit);
        assert_eq!(s.phase.name(), "Scanning");
    }

    #[test]
    fn existing_safes_are_flagged_per_chain() {
        let s = screen(Vec::new()).with_existing_safes(vec![saved(8453, None, vec![])]);
        let is_saved = |address, chain| saved_entry(&s.existing_safes, address, chain).is_some();
        assert!(is_saved(safe_addr(), Chain::Base));
        assert!(!is_saved(safe_addr(), Chain::Mainnet));
        assert!(!is_saved(owner_a(), Chain::Base));
    }

    // ── A Safe that's already saved ──────────────────────────────────

    #[test]
    fn hex_address_of_a_saved_safe_prefills_its_saved_name() {
        // Base saved unnamed (frozen-default shapes aside), Mainnet named:
        // the first named entry wins, as `upsert_safe` picks for a new
        // chain.
        let mut s = scanning(Vec::new()).with_existing_safes(vec![
            saved(8453, None, vec![]),
            saved(1, Some("Treasury"), vec![]),
        ]);
        complete_scan(&mut s, three_chain_hits(vec![owner_a()]));
        assert_eq!(review(&s).name, "Treasury");
        assert!(review(&s).typed_name.is_none());

        // Saved but unnamed everywhere: nothing to prefill.
        let mut s = scanning(Vec::new()).with_existing_safes(vec![saved(1, None, vec![])]);
        complete_scan(&mut s, three_chain_hits(vec![owner_a()]));
        assert!(review(&s).name.is_empty());

        // Another Safe's name never leaks in.
        let other = ExistingSafe {
            key: (owner_c().into(), 1),
            ..saved(1, Some("Grants"), vec![])
        };
        let mut s = scanning(Vec::new()).with_existing_safes(vec![other]);
        complete_scan(&mut s, three_chain_hits(vec![owner_a()]));
        assert!(review(&s).name.is_empty());
    }

    #[test]
    fn the_saved_name_wins_over_a_name_typed_into_the_finder() {
        // Finding a saved Safe by ENS is a lookup, not a rename: the field
        // keeps the saved name, so confirming untouched renames nothing.
        let mut s =
            screen(Vec::new()).with_existing_safes(vec![saved(1, Some("Treasury"), vec![])]);
        let _ = s.update(Message::AddressInput("dao.eth".into()));
        let _ = s.update(Message::AddressSubmit);
        let _ = s.update(Message::EnsResolved {
            seq: s.input_seq,
            name: "dao.eth".into(),
            result: Ok(Some(safe_addr())),
        });
        complete_scan(&mut s, vec![canonical_hit(Chain::Mainnet, vec![owner_a()])]);
        assert_eq!(review(&s).name, "Treasury");
        // The typed name is still remembered (shown as "resolved from").
        assert_eq!(review(&s).typed_name.as_deref(), Some("dao.eth"));
        let (_, renames) =
            name_hint(&s.existing_safes, safe_addr(), &review(&s).name).expect("saved");
        assert!(!renames);
        let (primary, _) = confirm(&mut s);
        assert_eq!(primary.name.as_deref(), Some("Treasury"));
    }

    #[test]
    fn untouched_prefill_confirms_the_saved_name() {
        // The emitted name equals every saved entry's, so the App's
        // `upsert_safes` renames nothing.
        let mut s = scanning(vec![acct(0, owner_a())]).with_existing_safes(vec![saved(
            1,
            Some("Treasury"),
            vec![0],
        )]);
        complete_scan(&mut s, three_chain_hits(vec![owner_a()]));
        let (primary, siblings) = confirm(&mut s);
        assert!(
            std::iter::once(&primary)
                .chain(&siblings)
                .all(|d| d.name.as_deref() == Some("Treasury"))
        );
    }

    #[test]
    fn name_hint_says_what_confirming_does_to_the_saved_name() {
        let safes = vec![
            saved(1, Some("Treasury"), vec![]),
            saved(8453, None, vec![]),
        ];
        // Not saved anywhere: no hint.
        assert_eq!(name_hint(&safes, owner_a(), "Vault"), None);
        // Blank renames nothing; new chains take the saved name.
        assert_eq!(
            name_hint(&safes, safe_addr(), "  "),
            Some((
                "Left blank, it keeps its saved name “Treasury”".to_string(),
                false
            ))
        );
        // A different name renames every chain.
        assert_eq!(
            name_hint(&safes, safe_addr(), "Vault"),
            Some(("Renames this Safe on every chain".to_string(), true))
        );
        // The saved name still renames the unnamed Base entry (the
        // App heals a split name) — so it says so.
        assert_eq!(
            name_hint(&safes, safe_addr(), " Treasury "),
            Some(("Renames this Safe on every chain".to_string(), true))
        );
        // One name everywhere and the field matches: nothing changes.
        let one_name = vec![
            saved(1, Some("Treasury"), vec![]),
            saved(8453, Some("Treasury"), vec![]),
        ];
        assert_eq!(
            name_hint(&one_name, safe_addr(), "Treasury"),
            Some((
                "Already saved under this name — it applies on every chain".to_string(),
                false
            ))
        );
        // Saved unnamed, field blank.
        assert_eq!(
            name_hint(&[saved(1, None, vec![])], safe_addr(), ""),
            Some(("Applies to this Safe on every chain".to_string(), false))
        );
    }

    #[test]
    fn a_saved_chain_keeps_its_links_in_the_role_summary() {
        // Mainnet is saved linking account 0. Unticking 0 doesn't unlink
        // it there (a merge never unlinks), so Mainnet still reads
        // signer; Base, new, goes watch-only.
        let mut s = scanning(vec![acct(0, owner_a())]).with_existing_safes(vec![saved(
            1,
            Some("Treasury"),
            vec![0],
        )]);
        complete_scan(
            &mut s,
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                canonical_hit(Chain::Base, vec![owner_a()]),
            ],
        );
        let _ = s.update(Message::SignerToggled(0));
        let roles = review(&s).chain_roles(&s.existing, &s.existing_safes);
        assert_eq!(
            roles,
            vec![
                ChainRole {
                    chain: Chain::Mainnet,
                    saved: true,
                    signers: vec![0],
                    kept: 1,
                },
                ChainRole {
                    chain: Chain::Base,
                    saved: false,
                    signers: vec![],
                    kept: 0,
                },
            ]
        );
        assert_eq!(
            roles[0].line(false),
            "Mainnet — already in your wallet · signer · 1 key (1 already linked — kept)"
        );
        assert_eq!(
            roles[1].line(false),
            "Base — watch-only (none of your selected keys own it here)"
        );
        assert_eq!(
            confirm_label(&roles),
            "Add to wallet →",
            "Mainnet still signs"
        );

        // Ticked again: the saved link is just a tick, nothing "kept".
        let _ = s.update(Message::SignerToggled(0));
        let roles = review(&s).chain_roles(&s.existing, &s.existing_safes);
        assert_eq!(
            roles[0].line(true),
            "Mainnet — already in your wallet · signer · 1 key · owner Safe linked"
        );
    }

    #[test]
    fn saved_links_that_cannot_sign_are_not_counted() {
        // Mainnet's saved links: a dangling index (9), a view-only
        // account (1) and an account the fresh scan no longer lists as
        // an owner (2). None can sign, so the chain is watch-only and —
        // with nothing ticked — so is the whole add.
        let mut s = scanning(vec![
            acct(0, owner_a()),
            watched(1, owner_b()),
            acct(2, owner_c()),
        ])
        .with_existing_safes(vec![saved(1, None, vec![9, 1, 2])]);
        complete_scan(
            &mut s,
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::SignerToggled(0));
        let roles = review(&s).chain_roles(&s.existing, &s.existing_safes);
        assert_eq!(roles.len(), 1);
        assert!(roles[0].saved);
        assert!(roles[0].signers.is_empty());
        assert_eq!(
            roles[0].line(false),
            "Mainnet — already in your wallet · watch-only (none of your selected keys own it here)"
        );
        assert_eq!(confirm_label(&roles), "Add as watch-only →");
    }

    // ── Parked under a nested sub-flow ───────────────────────────────

    #[test]
    fn note_account_lists_and_ticks_an_owner_without_resuming() {
        let mut s = reviewing(
            vec![acct(0, owner_a())],
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()]),
                canonical_hit(Chain::Base, vec![owner_b()]),
            ],
        );
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::SignerMethodPicked(SignerMethod::NestedSafe));
        assert_eq!(s.phase.name(), "AwaitingSigner");
        s.note_account(acct(5, owner_b()));
        // Still parked: this screen didn't ask for the account.
        assert_eq!(s.phase.name(), "AwaitingSigner");
        assert!(review(&s).add_signer_open);
        assert!(review(&s).selected.contains(&5));
        assert!(review(&s).unclaimed_owners(&s.existing).is_empty());
        assert_eq!(
            signers_by_chain(&s),
            vec![(Chain::Mainnet, vec![0, 5]), (Chain::Base, vec![5])]
        );

        // A non-owner joins the snapshot unticked; a known index (the
        // user's tick or untick) is left alone; view-only is never ticked.
        s.note_account(acct(6, owner_d()));
        assert!(s.existing.iter().any(|e| e.account_idx == 6));
        assert!(!review(&s).selected.contains(&6));
        let _ = s.update(Message::SignerToggled(5));
        s.note_account(acct(5, owner_b()));
        assert!(!review(&s).selected.contains(&5));
        s.note_account(watched(7, owner_b()));
        assert!(!review(&s).selected.contains(&7));
    }

    #[test]
    fn owners_differ_considers_only_included_chains() {
        let mut s = reviewing(
            Vec::new(),
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                canonical_hit(Chain::Base, vec![owner_b()]),
            ],
        );
        assert!(review(&s).owners_differ());
        let _ = s.update(Message::ChainIncludeToggled(Chain::Base));
        assert!(!review(&s).owners_differ());
        // Same owners in another order, different threshold also counts.
        let s = reviewing(
            Vec::new(),
            vec![
                hit_with(Chain::Mainnet, vec![owner_a(), owner_b()], 1),
                hit_with(Chain::Base, vec![owner_b(), owner_a()], 2),
            ],
        );
        assert!(review(&s).owners_differ());
        let s = reviewing(
            Vec::new(),
            vec![
                hit_with(Chain::Mainnet, vec![owner_a(), owner_b()], 2),
                hit_with(Chain::Base, vec![owner_b(), owner_a()], 2),
            ],
        );
        assert!(!review(&s).owners_differ());
    }

    #[test]
    fn danger_surfaces_differ_flags_a_chain_not_on_screen() {
        let mut s = reviewing(
            Vec::new(),
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                (
                    Chain::Base,
                    ScanResult::Canonical(SafeMetadata {
                        chain_id: 8453,
                        modules: vec![owner_d()],
                        ..fake_metadata_with_owners(vec![owner_a()], 1)
                    }),
                ),
            ],
        );
        assert!(review(&s).danger_surfaces_differ());
        assert!(!review(&s).owners_differ());
        // Focused-but-excluded Mainnet is still what's on screen, and
        // Base (which will be added) has a module it doesn't.
        let _ = s.update(Message::ChainIncludeToggled(Chain::Mainnet));
        assert!(review(&s).danger_surfaces_differ());
        // Looking at Base itself: nothing hidden any more.
        let _ = s.update(Message::ChainFocused(Chain::Base));
        assert!(!review(&s).danger_surfaces_differ());
    }

    #[test]
    fn a_differing_module_guard_counts_as_a_differing_danger_surface() {
        // Same owners, same modules — only the 1.5.0 module guard differs. It
        // can veto every module transaction, so it is reviewed per chain too.
        let s = reviewing(
            Vec::new(),
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                (
                    Chain::Base,
                    ScanResult::Canonical(SafeMetadata {
                        chain_id: 8453,
                        version: "1.5.0".into(),
                        module_guard: Some(owner_d()),
                        ..fake_metadata_with_owners(vec![owner_a()], 1)
                    }),
                ),
            ],
        );
        assert!(review(&s).danger_surfaces_differ());
        assert!(!review(&s).owners_differ());
    }

    // ── Chain inclusion ──────────────────────────────────────────────

    #[test]
    fn last_included_chain_cannot_be_excluded() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        let _ = s.update(Message::ChainIncludeToggled(Chain::Mainnet));
        assert!(review(&s).is_included(Chain::Mainnet));

        let mut s = reviewing(Vec::new(), three_chain_hits(vec![owner_a()]));
        let _ = s.update(Message::ChainIncludeToggled(Chain::Mainnet));
        let _ = s.update(Message::ChainIncludeToggled(Chain::Base));
        let _ = s.update(Message::ChainIncludeToggled(Chain::Optimism));
        let included: Vec<Chain> = review(&s).included().map(|(c, _, _)| c).collect();
        assert_eq!(included, vec![Chain::Optimism]);
        // Re-including works.
        let _ = s.update(Message::ChainIncludeToggled(Chain::Base));
        assert!(review(&s).is_included(Chain::Base));
    }

    #[test]
    fn excluded_chain_is_not_emitted() {
        let mut s = reviewing(Vec::new(), three_chain_hits(vec![owner_a()]));
        let _ = s.update(Message::ChainIncludeToggled(Chain::Base));
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(primary.chain_id, 1);
        assert_eq!(primary.sibling_chains, vec![10]);
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0].chain_id, 10);
        assert_eq!(siblings[0].sibling_chains, vec![1]);
    }

    #[test]
    fn primary_is_the_focused_chain() {
        let mut s = reviewing(Vec::new(), three_chain_hits(vec![owner_a()]));
        let _ = s.update(Message::ChainFocused(Chain::Base));
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(primary.chain_id, 8453);
        // Remaining chosen chains in `Chain::ALL` order.
        assert_eq!(primary.sibling_chains, vec![1, 10]);
        let sib_ids: Vec<u64> = siblings.iter().map(|d| d.chain_id).collect();
        assert_eq!(sib_ids, vec![1, 10]);

        // A focused-but-excluded chain falls back to the first included.
        let mut s = reviewing(Vec::new(), three_chain_hits(vec![owner_a()]));
        let _ = s.update(Message::ChainFocused(Chain::Mainnet));
        let _ = s.update(Message::ChainIncludeToggled(Chain::Mainnet));
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(primary.chain_id, 8453);
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0].chain_id, 10);
    }

    // ── Confirm ──────────────────────────────────────────────────────

    #[test]
    fn confirm_emits_done_with_descriptor() {
        let mut s = reviewing(
            vec![acct(0, owner_a())],
            vec![hit_with(Chain::Mainnet, vec![owner_a(), owner_b()], 2)],
        );
        let _ = s.update(Message::NameInput("  Treasury  ".into()));
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(primary.name.as_deref(), Some("Treasury"));
        assert_eq!(primary.chain_id, 1);
        assert_eq!(primary.address, <[u8; 20]>::from(safe_addr()));
        assert_eq!(primary.threshold, 2);
        assert_eq!(primary.linked_signer_indices, vec![0]);
        assert_eq!(primary.trust, SafeTrust::Canonical);
        // No Advanced input → public service (stored as None).
        assert!(primary.tx_service_url.is_none());
        assert!(primary.sibling_chains.is_empty());
        assert!(siblings.is_empty());
    }

    #[test]
    fn unrecognized_impl_keeps_its_trust() {
        let mut s = reviewing(
            Vec::new(),
            vec![(
                Chain::Mainnet,
                ScanResult::UnrecognizedImpl(fake_metadata_with_owners(vec![owner_a()], 1)),
            )],
        );
        let (primary, _) = confirm(&mut s);
        assert_eq!(primary.trust, SafeTrust::UnrecognizedImpl);
    }

    #[test]
    fn blank_name_is_stored_as_none() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        let _ = s.update(Message::NameInput("   ".into()));
        let (primary, _) = confirm(&mut s);
        assert!(primary.name.is_none());
    }

    #[test]
    fn sibling_chains_become_separate_descriptors_with_cross_links() {
        let mut s = reviewing(Vec::new(), three_chain_hits(vec![owner_a()]));
        let _ = s.update(Message::NameInput("Treasury".into()));
        let _ = s.update(Message::AdvancedToggled);
        let _ = s.update(Message::ServiceUrlInput(
            "https://txs.example-dao.org/".into(),
        ));
        let (primary, siblings) = confirm(&mut s);
        // Primary lists OP + Base as siblings (chain IDs 10 + 8453).
        let mut primary_siblings = primary.sibling_chains.clone();
        primary_siblings.sort();
        assert_eq!(primary_siblings, vec![10, 8453]);
        assert_eq!(siblings.len(), 2);
        for sib in &siblings {
            // No wallet accounts at all → nothing to link anywhere.
            assert!(sib.linked_signer_indices.is_empty());
            // Each sibling lists the OTHER two chains as siblings.
            assert_eq!(sib.sibling_chains.len(), 2);
            assert!(!sib.sibling_chains.contains(&sib.chain_id));
            assert_eq!(sib.name.as_deref(), Some("Treasury"));
            // The custom mirror serves the multi-chain layout, so
            // siblings inherit it (normalized: trailing slash gone).
            assert_eq!(
                sib.tx_service_url.as_deref(),
                Some("https://txs.example-dao.org"),
            );
        }
        assert_eq!(
            primary.tx_service_url.as_deref(),
            Some("https://txs.example-dao.org"),
        );
    }

    #[test]
    fn bad_service_url_blocks_confirm_and_opens_advanced() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        // Typed, then collapsed on purpose: the error must force it back open.
        let _ = s.update(Message::AdvancedToggled);
        // Non-loopback http.
        let _ = s.update(Message::ServiceUrlInput(
            "http://txs.example-dao.org".into(),
        ));
        let _ = s.update(Message::AdvancedToggled);
        assert!(!review(&s).advanced);
        let (_task, outcome) = s.update(Message::Confirm);
        assert!(outcome.is_none(), "must not emit Done with a bad URL");
        let r = review(&s);
        assert!(r.advanced, "section reopens to show the error");
        assert!(r.service_url_error.is_some());
        // Editing the URL clears the error.
        let _ = s.update(Message::ServiceUrlInput(String::new()));
        assert!(review(&s).service_url_error.is_none());
    }

    #[test]
    fn multichain_flow_links_signer_on_every_owned_chain() {
        // The reported bug: a Safe on several chains was saved watch-only
        // on every chain but the one picked first. Account 0 owns the
        // Safe on Mainnet and Base; Optimism's owner is someone else.
        let mut s = scanning(vec![acct(0, owner_a())]);
        complete_scan(
            &mut s,
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                canonical_hit(Chain::Base, vec![owner_a()]),
                canonical_hit(Chain::Optimism, vec![owner_b()]),
            ],
        );
        // The role summary shows it before confirming.
        assert_eq!(
            signers_by_chain(&s),
            vec![
                (Chain::Mainnet, vec![0]),
                (Chain::Base, vec![0]),
                (Chain::Optimism, vec![]),
            ]
        );
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(primary.chain_id, 1);
        assert_eq!(
            links_by_chain(&primary, &siblings),
            vec![(1, vec![0]), (10, vec![]), (8453, vec![0])]
        );
    }

    #[test]
    fn signer_that_owns_only_a_sibling_chain_is_linked_there() {
        let mut s = reviewing(
            vec![acct(0, owner_a()), acct(2, owner_c())],
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                canonical_hit(Chain::Base, vec![owner_a(), owner_c()]),
            ],
        );
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(
            links_by_chain(&primary, &siblings),
            vec![(1, vec![0]), (8453, vec![0, 2])]
        );
    }

    #[test]
    fn unchecking_a_signer_unlinks_it_on_every_chain() {
        let mut s = reviewing(
            vec![acct(0, owner_a()), acct(1, owner_b())],
            three_chain_hits(vec![owner_a(), owner_b()]),
        );
        let _ = s.update(Message::SignerToggled(0));
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(
            links_by_chain(&primary, &siblings),
            vec![(1, vec![1]), (10, vec![1]), (8453, vec![1])]
        );
    }

    #[test]
    fn unchecking_every_signer_saves_watch_only() {
        let mut s = reviewing(vec![acct(0, owner_a())], three_chain_hits(vec![owner_a()]));
        assert!(
            signers_by_chain(&s)
                .iter()
                .all(|(_, links)| !links.is_empty())
        );
        let _ = s.update(Message::SignerToggled(0));
        assert!(
            signers_by_chain(&s)
                .iter()
                .all(|(_, links)| links.is_empty()),
            "every chain reads watch-only"
        );
        let r = review(&s);
        assert_eq!(
            confirm_label(&r.chain_roles(&s.existing, &s.existing_safes)),
            "Add as watch-only →"
        );
        let (primary, siblings) = confirm(&mut s);
        assert!(primary.linked_signer_indices.is_empty());
        assert!(siblings.iter().all(|d| d.linked_signer_indices.is_empty()));
    }

    #[test]
    fn view_only_account_is_never_linked() {
        let mut s = reviewing(
            vec![watched(0, owner_a()), acct(1, owner_b())],
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        // Listed (it owns the Safe) but not pre-checked, and its toggle
        // is refused.
        assert_eq!(review(&s).owned_chains(owner_a()), vec![Chain::Mainnet]);
        assert_eq!(review(&s).selected, BTreeSet::from([1u32]));
        let _ = s.update(Message::SignerToggled(0));
        assert!(!review(&s).selected.contains(&0));
        // Even a selection that sneaks in is filtered on confirm.
        review_mut(&mut s).selected.insert(0);
        let (primary, _) = confirm(&mut s);
        assert_eq!(primary.linked_signer_indices, vec![1]);
    }

    // ── Add-signer sub-flow ──────────────────────────────────────────

    #[test]
    fn add_signer_section_lists_unclaimed_owners() {
        let mut s = reviewing(
            vec![acct(0, owner_a())],
            vec![canonical_hit(
                Chain::Mainnet,
                vec![owner_a(), owner_b(), owner_c()],
            )],
        );
        let (_task, outcome) = s.update(Message::AddSignerToggled);
        assert!(outcome.is_none());
        let r = review(&s);
        assert!(r.add_signer_open);
        // owner_a is already in the wallet, so only b and c are unclaimed.
        assert_eq!(r.unclaimed_owners(&s.existing), vec![owner_b(), owner_c()]);
    }

    #[test]
    fn allowed_owners_is_union_over_included_chains_minus_existing() {
        let mut s = reviewing(
            vec![acct(0, owner_a())],
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()]),
                canonical_hit(Chain::Base, vec![owner_b(), owner_c()]),
                canonical_hit(Chain::Optimism, vec![owner_d()]),
            ],
        );
        let _ = s.update(Message::ChainIncludeToggled(Chain::Optimism));
        let _ = s.update(Message::AddSignerToggled);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::Hardware));
        let Some(Outcome::RequestAddSigner {
            method,
            allowed_owners,
        }) = outcome
        else {
            panic!("expected RequestAddSigner, got {outcome:?}");
        };
        assert_eq!(method, SignerMethod::Hardware);
        assert_eq!(allowed_owners, vec![owner_b(), owner_c()]);
    }

    #[test]
    fn view_only_owner_is_not_offered_for_import() {
        // Its address is already in the wallet, so the parent would
        // refuse the import as a duplicate anyway.
        let s = reviewing(
            vec![watched(0, owner_a())],
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        assert_eq!(review(&s).unclaimed_owners(&s.existing), vec![owner_b()]);
    }

    #[test]
    fn picking_method_emits_request_add_signer_with_allowed_owners() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(
                Chain::Mainnet,
                vec![owner_a(), owner_b(), owner_c()],
            )],
        );
        let _ = s.update(Message::AddSignerToggled);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::PrivateKey));
        let Some(Outcome::RequestAddSigner {
            method,
            allowed_owners,
        }) = outcome
        else {
            panic!("expected RequestAddSigner, got {outcome:?}");
        };
        assert_eq!(method, SignerMethod::PrivateKey);
        let mut got = allowed_owners.clone();
        got.sort();
        let mut want = vec![owner_a(), owner_b(), owner_c()];
        want.sort();
        assert_eq!(got, want);
        // Parked in Review, waiting for the parent's callback.
        assert_eq!(s.phase.name(), "AwaitingSigner");
        assert!(review(&s).add_signer_open);
    }

    #[test]
    fn picking_method_with_no_unclaimed_owners_sets_error() {
        let mut s = reviewing(
            vec![acct(0, owner_a())],
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::SeedPhrase));
        assert!(outcome.is_none());
        assert_eq!(s.phase.name(), "Review");
        assert!(review(&s).signer_error.is_some());
        // Toggling a signer clears it.
        let _ = s.update(Message::SignerToggled(0));
        assert!(review(&s).signer_error.is_none());
    }

    #[test]
    fn back_collapses_add_signer_section_before_leaving_review() {
        let mut s = reviewing(
            vec![acct(0, owner_a())],
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(outcome.is_none());
        let r = review(&s);
        assert!(!r.add_signer_open);
        assert!(r.selected.contains(&0), "selection preserved");
        // Second Back leaves Review.
        let _ = s.update(Message::BackPressed);
        assert_eq!(s.phase.name(), "Find");
    }

    #[test]
    fn restoring_the_stash_without_a_callback_resumes_review() {
        // Back out of the import sub-screen: the parent restores the
        // parked screen as-is. The next message clears the parked marker.
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::SignerMethodPicked(SignerMethod::PrivateKey));
        assert_eq!(s.phase.name(), "AwaitingSigner");
        let _ = s.update(Message::NameInput("Vault".into()));
        assert_eq!(s.phase.name(), "Review");
        assert_eq!(review(&s).name, "Vault");
    }

    #[test]
    fn apply_added_signer_links_new_account_checked() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::SignerMethodPicked(SignerMethod::PrivateKey));
        review_mut(&mut s).signer_error = Some("stale".into());
        s.apply_added_signer(acct(7, owner_b()));
        assert_eq!(s.phase.name(), "Review");
        let r = review(&s);
        assert!(r.selected.contains(&7));
        assert!(r.signer_error.is_none());
        assert!(!r.add_signer_open, "section folds away after a success");
        assert_eq!(r.owned_chains(owner_b()), vec![Chain::Mainnet]);
        // Snapshot is also updated so the next allow-list sees the new
        // account as already claimed.
        assert!(s.existing.iter().any(|e| e.account_idx == 7));
        assert_eq!(r.unclaimed_owners(&s.existing), vec![owner_a()]);
    }

    #[test]
    fn signer_added_mid_flow_is_linked_on_every_chain_it_owns() {
        let mut s = reviewing(
            Vec::new(),
            vec![
                canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()]),
                canonical_hit(Chain::Base, vec![owner_b()]),
                canonical_hit(Chain::Optimism, vec![owner_a()]),
            ],
        );
        let _ = s.update(Message::AddSignerToggled);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::PrivateKey));
        assert!(matches!(outcome, Some(Outcome::RequestAddSigner { .. })));
        s.apply_added_signer(acct(7, owner_b()));
        let (primary, siblings) = confirm(&mut s);
        assert_eq!(
            links_by_chain(&primary, &siblings),
            vec![(1, vec![7]), (10, vec![]), (8453, vec![7])]
        );
    }

    #[test]
    fn nested_safe_method_emits_request_with_allowed_owners() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::NestedSafe));
        let Some(Outcome::RequestAddSigner {
            method,
            allowed_owners,
        }) = outcome
        else {
            panic!("expected RequestAddSigner");
        };
        assert_eq!(method, SignerMethod::NestedSafe);
        assert_eq!(allowed_owners, vec![owner_a(), owner_b()]);
    }

    #[test]
    fn apply_added_nested_safe_records_owner() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::SignerMethodPicked(SignerMethod::NestedSafe));
        s.apply_added_nested_safe(owner_b());
        assert_eq!(s.phase.name(), "Review");
        let r = review(&s);
        assert_eq!(r.linked_nested_safes, vec![owner_b()]);
        assert!(r.signer_error.is_none());
        assert!(!r.add_signer_open);
    }

    #[test]
    fn nested_safes_persist_across_add_signer_roundtrip() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::SignerMethodPicked(SignerMethod::NestedSafe));
        s.apply_added_nested_safe(owner_b());
        // Re-open the section and back out of it again; the already
        // linked nested Safe survives.
        let _ = s.update(Message::AddSignerToggled);
        assert!(review(&s).add_signer_open);
        let _ = s.update(Message::BackPressed);
        assert!(!review(&s).add_signer_open);
        assert_eq!(review(&s).linked_nested_safes, vec![owner_b()]);
    }

    #[test]
    fn apply_added_nested_safe_is_idempotent() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        s.apply_added_nested_safe(owner_b());
        // Second call with the same address must not duplicate.
        let _ = s.update(Message::AddSignerToggled);
        s.apply_added_nested_safe(owner_b());
        assert_eq!(review(&s).linked_nested_safes, vec![owner_b()]);
    }

    #[test]
    fn apply_signer_import_error_sets_error_and_stays_in_review() {
        let mut s = reviewing(
            Vec::new(),
            vec![canonical_hit(Chain::Mainnet, vec![owner_a(), owner_b()])],
        );
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::SignerMethodPicked(SignerMethod::PrivateKey));
        s.apply_signer_import_error("Imported address is not an owner.".to_string());
        assert_eq!(s.phase.name(), "Review");
        let r = review(&s);
        assert_eq!(
            r.signer_error.as_deref(),
            Some("Imported address is not an owner.")
        );
        // Section stays open so the user can retry.
        assert!(r.add_signer_open);
    }

    // ── Views ────────────────────────────────────────────────────────

    #[test]
    fn view_builds_in_every_phase() {
        let t = KaoTheme::for_kind(settings::theme());
        let mut s = screen(vec![acct(0, owner_a()), watched(1, owner_b())]);
        let _ = s.view();
        let _ = s.update(Message::AddressInput(format!("{:?}", safe_addr())));
        let _ = s.update(Message::AddressSubmit);
        let _ = s.view();
        complete_scan(&mut s, vec![(Chain::Mainnet, ScanResult::NotDeployed)]);
        let _ = s.view();

        let mut s = reviewing(
            vec![acct(0, owner_a()), watched(1, owner_b())],
            vec![
                hit_with(Chain::Mainnet, vec![owner_a(), owner_b()], 1),
                (
                    Chain::Base,
                    ScanResult::UnrecognizedImpl(SafeMetadata {
                        modules: vec![owner_d()],
                        guard: Some(owner_c()),
                        fallback_handler: Some(owner_c()),
                        ..fake_metadata_with_owners(vec![owner_c()], 1)
                    }),
                ),
                (Chain::Optimism, ScanResult::NotASafe { reason: "x".into() }),
            ],
        )
        .with_existing_safes(vec![saved(1, Some("Treasury"), vec![0, 9])]);
        let _ = s.update(Message::ChainFocused(Chain::Base));
        let _ = s.update(Message::AddSignerToggled);
        let _ = s.update(Message::AdvancedToggled);
        s.apply_added_nested_safe(owner_c());
        review_mut(&mut s).signer_error = Some("x".into());
        review_mut(&mut s).service_url_error = Some("x".into());
        let _ = s.view();
        // The layout pass picks the column mode; build both directly.
        let r = review(&s);
        let _ = view_review(t, r, &s.existing, &s.existing_safes, true);
        let _ = view_review(t, r, &s.existing, &s.existing_safes, false);
    }
}
