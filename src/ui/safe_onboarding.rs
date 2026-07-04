//! Multi-step onboarding flow for adding a Safe to the wallet.
//!
//! The flow is six sub-steps held in a single `Step` enum so each step
//! carries exactly the data it needs (invalid states are
//! unrepresentable):
//!
//! 1. `AddressInput` — paste a hex address or ENS name. ENS resolves
//!    on mainnet via the same helper `ImportAddressScreen` uses.
//! 2. `Scanning` — spawn `safe::scan_across_chains` and wait.
//! 3. `ChainChooser` — skipped if exactly one chain hit; otherwise the
//!    user picks among Canonical / UnrecognizedImpl results.
//! 4. `Inspect` — show owners, threshold, modules, guard, fallback
//!    handler (each with classification labels via `safe::classify_module`).
//! 5. `RoleSelection` — intersect on-chain owners with the user's
//!    existing accounts; offer to link any matches, proceed as
//!    watch-only, OR enter the add-signer sub-flow to import a new
//!    account that owns this Safe.
//! 6. `PickSignerMethod` — only reachable from RoleSelection via "Add
//!    a new signer". Offer seed phrase, private key, or hardware
//!    wallet as the import method. Picking one emits
//!    `Outcome::RequestAddSigner` so the parent app can run the import
//!    flow with the allowed-owner constraint, then call back into the
//!    screen via `apply_added_signer` / `apply_signer_import_error`.
//! 7. `Label` — name the Safe, optionally add sibling chains where the
//!    same address is also a Safe, confirm.
//!
//! On `Label` confirm the screen emits `Outcome::Done { descriptor,
//! siblings }` so the parent can append to the wallet and persist.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use iced::keyboard;
use iced::widget::{Space, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};

use crate::chain::Chain;
use crate::names;
use crate::net::BalanceFetcher;
use crate::safe::{self, SafeMetadata, ScanResult};
use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, colored_address, error_text, ghost_button, hint_pill, kao_checkbox,
    kao_hero, link_button, method_card, mono, mono_bold, primary_button, screen_subtitle,
    screen_title, text_input_style, vspace,
};
use crate::wallet::{SafeDescriptor, SafeTrust};

pub const ADDRESS_INPUT_ID: &str = "safe_onboarding_address";
pub const NAME_INPUT_ID: &str = "safe_onboarding_name";

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Message {
    // AddressInput
    AddressInput(String),
    AddressSubmit,
    EnsResolved {
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    },

    // Scanning
    ScanCompleted {
        seq: u64,
        address: Address,
        results: Vec<(Chain, ScanResult)>,
    },

    // ChainChooser
    ChainPicked(Chain),

    // Inspect
    InspectContinue,

    // RoleSelection
    SignerToggled(u32),
    /// User chose to proceed as a non-signing observer. Implicitly
    /// clears any signer checkboxes and advances to Label.
    WatchOnlySelected,
    /// User confirmed the signer selection from the matched-existing
    /// list. Advances to Label with the currently-selected signers.
    RoleConfirm,
    /// User wants to import a new account that owns this Safe. Moves
    /// to `PickSignerMethod`.
    AddSignerPressed,

    // PickSignerMethod
    SignerMethodPicked(SignerMethod),

    // Label
    NameInput(String),
    SiblingToggled(Chain),
    /// Expand/collapse the Advanced section (custom transaction
    /// service).
    AdvancedToggled,
    /// Custom Safe Transaction Service base URL input.
    ServiceUrlInput(String),
    LabelConfirm,

    // Cross-step
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
    /// at `PickSignerMethod` and must be kept alive (stashed).
    RequestAddSigner {
        method: SignerMethod,
        /// Owners of the Safe whose key isn't already represented by
        /// an account in the wallet. The parent enforces this set on
        /// the imported address — anything outside is rejected.
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

/// A matched existing account — pre-computed by `new()` so we don't
/// have to repeat the keccak-derived address calculation on every
/// view. `account_idx` indexes into the wallet's `accounts` Vec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAccount {
    pub account_idx: u32,
    pub address: Address,
    /// Display name as the dashboard would render it — passed in so we
    /// don't re-derive `display_name(idx)` here.
    pub label: String,
}

#[derive(Debug)]
enum Step {
    AddressInput {
        input: String,
        error: Option<String>,
        /// `Some(seq)` while an ENS lookup is in flight.
        ens_resolving: Option<u64>,
    },
    Scanning {
        address: Address,
        /// Display string for the address/ENS the user submitted.
        /// Shown on the spinner so the user can confirm the right
        /// target is being scanned.
        what: String,
    },
    /// At least one chain returned `Canonical` or `UnrecognizedImpl`,
    /// and the user has not yet picked one. Skipped automatically when
    /// `safe_count == 1`.
    ChainChooser {
        address: Address,
        results: Vec<(Chain, ScanResult)>,
    },
    /// Zero chains returned a Safe — terminal error screen with a
    /// per-chain breakdown of *why*.
    NoChain {
        address: Address,
        results: Vec<(Chain, ScanResult)>,
    },
    Inspect {
        chain: Chain,
        metadata: SafeMetadata,
        trust: SafeTrust,
        /// Carried forward so step 9 can offer sibling chains.
        all_results: Vec<(Chain, ScanResult)>,
    },
    RoleSelection {
        chain: Chain,
        metadata: SafeMetadata,
        trust: SafeTrust,
        all_results: Vec<(Chain, ScanResult)>,
        /// Existing accounts that intersect this Safe's owner set.
        matched: Vec<ExistingAccount>,
        /// Subset of `matched` (by `account_idx`) the user has
        /// checked. Empty = will be a watch-only Safe.
        selected: BTreeSet<u32>,
        /// Owners that are themselves Safes the user has onboarded
        /// during this session via the nested-Safe sub-flow.
        /// Informational — the parent→child link is derived from the
        /// owner-set intersection at signing time, not persisted on
        /// `SafeDescriptor`.
        linked_nested_safes: Vec<Address>,
        /// Optional error from a previous add-signer attempt — shown
        /// once when we return to this step. Cleared on any toggle.
        signer_error: Option<String>,
    },
    /// Sub-step of RoleSelection: user has pressed "Add a new signer"
    /// and is picking an import method. Carries forward the
    /// RoleSelection state verbatim so backing out is a clean rewind.
    PickSignerMethod {
        chain: Chain,
        metadata: SafeMetadata,
        trust: SafeTrust,
        all_results: Vec<(Chain, ScanResult)>,
        matched: Vec<ExistingAccount>,
        selected: BTreeSet<u32>,
        linked_nested_safes: Vec<Address>,
        /// Owners not yet represented by an existing wallet account.
        /// Surfaced on the picker so the user knows which addresses
        /// the import must derive to, and used by the parent as the
        /// allowed-list when validating the imported signer.
        unclaimed_owners: Vec<Address>,
    },
    Label {
        chain: Chain,
        metadata: SafeMetadata,
        trust: SafeTrust,
        linked: Vec<u32>,
        name: String,
        /// Other chains where this address is also a Safe. The bool
        /// is "user wants to add this sibling too". Defaults to true.
        siblings: Vec<(Chain, SafeMetadata, SafeTrust, bool)>,
        /// Advanced section expanded. Collapsed by default — almost
        /// everyone wants the public service.
        advanced: bool,
        /// Custom Transaction Service base URL, raw as typed.
        /// Validated through `service::normalize_service_base` on
        /// confirm; blank means the public default.
        service_url: String,
        /// Validation error from the last confirm attempt.
        service_url_error: Option<String>,
    },
}

impl Step {
    fn name(&self) -> &'static str {
        match self {
            Step::AddressInput { .. } => "AddressInput",
            Step::Scanning { .. } => "Scanning",
            Step::ChainChooser { .. } => "ChainChooser",
            Step::NoChain { .. } => "NoChain",
            Step::Inspect { .. } => "Inspect",
            Step::RoleSelection { .. } => "RoleSelection",
            Step::PickSignerMethod { .. } => "PickSignerMethod",
            Step::Label { .. } => "Label",
        }
    }
}

pub struct SafeOnboardingScreen {
    network: Arc<dyn BalanceFetcher>,
    /// Snapshot of every account in the wallet right before the screen
    /// opened — used in `RoleSelection` to intersect with the Safe's
    /// owner set. Cheap pre-computation keeps the view function tight.
    existing: Vec<ExistingAccount>,
    step: Step,
    /// Monotonic counter bumped on every address input change; ENS and
    /// scan tasks stamp results with the value they were spawned at and
    /// the screen drops stale results. Without this, a user who typed
    /// fast could race a stale scan into the wrong step.
    input_seq: u64,
}

impl std::fmt::Debug for SafeOnboardingScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeOnboardingScreen")
            .field("existing_count", &self.existing.len())
            .field("step", &self.step)
            .field("input_seq", &self.input_seq)
            .finish()
    }
}

impl SafeOnboardingScreen {
    pub fn new(network: Arc<dyn BalanceFetcher>, existing: Vec<ExistingAccount>) -> Self {
        Self {
            network,
            existing,
            step: Step::AddressInput {
                input: String::new(),
                error: None,
                ens_resolving: None,
            },
            input_seq: 0,
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("safe_onboarding", &message);
        let step_before = self.step.name();
        let (task, outcome) = self.update_inner(message);
        let step_after = self.step.name();
        if step_before != step_after {
            crate::trace::state("safe_onboarding", "step", step_before, step_after);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("safe_onboarding", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
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
            Message::ChainPicked(chain) => self.handle_chain_picked(chain),
            Message::InspectContinue => self.handle_inspect_continue(),
            Message::SignerToggled(idx) => self.handle_signer_toggled(idx),
            Message::WatchOnlySelected => self.handle_watch_only(),
            Message::RoleConfirm => self.handle_role_confirm(),
            Message::AddSignerPressed => self.handle_add_signer_pressed(),
            Message::SignerMethodPicked(method) => self.handle_signer_method_picked(method),
            Message::NameInput(s) => self.handle_name_input(s),
            Message::SiblingToggled(chain) => self.handle_sibling_toggled(chain),
            Message::AdvancedToggled => self.handle_advanced_toggled(),
            Message::ServiceUrlInput(s) => self.handle_service_url_input(s),
            Message::LabelConfirm => self.handle_label_confirm(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());
        let card_body = match &self.step {
            Step::AddressInput {
                input,
                error,
                ens_resolving,
            } => view_address_input(t, input, error.as_deref(), ens_resolving.is_some()),
            Step::Scanning { what, .. } => view_scanning(t, what),
            Step::ChainChooser { address, results } => view_chain_chooser(t, *address, results),
            Step::NoChain { address, results } => view_no_chain(t, *address, results),
            Step::Inspect {
                chain,
                metadata,
                trust,
                ..
            } => view_inspect(t, *chain, metadata, trust),
            Step::RoleSelection {
                chain,
                metadata,
                matched,
                selected,
                linked_nested_safes,
                signer_error,
                ..
            } => view_role_selection(
                t,
                *chain,
                metadata,
                matched,
                selected,
                linked_nested_safes,
                signer_error.as_deref(),
            ),
            Step::PickSignerMethod {
                chain,
                metadata,
                unclaimed_owners,
                ..
            } => view_pick_signer_method(t, *chain, metadata, unclaimed_owners),
            Step::Label {
                chain,
                metadata,
                trust,
                linked,
                name,
                siblings,
                advanced,
                service_url,
                service_url_error,
            } => view_label(
                t,
                *chain,
                metadata,
                trust,
                linked,
                name,
                siblings,
                *advanced,
                service_url,
                service_url_error.as_deref(),
            ),
        };
        let card = auth_card(t, 560.0, card_body);
        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);
        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);
        auth_background(t, layout.into())
    }

    // ── Step handlers ────────────────────────────────────────────────

    fn handle_back(&mut self) -> (Task<Message>, Option<Outcome>) {
        // Within-screen back: rewind one step. Only AddressInput's
        // back propagates Outcome::Back to the parent.
        match &self.step {
            Step::AddressInput { .. } => (Task::none(), Some(Outcome::Back)),
            Step::PickSignerMethod { .. } => {
                self.rewind_picker_to_role(None, |_, _, _| {});
                (Task::none(), None)
            }
            _ => {
                self.step = Step::AddressInput {
                    input: String::new(),
                    error: None,
                    ens_resolving: None,
                };
                (Task::none(), None)
            }
        }
    }

    fn handle_address_input(&mut self, s: String) -> (Task<Message>, Option<Outcome>) {
        let Step::AddressInput {
            input,
            error,
            ens_resolving,
        } = &mut self.step
        else {
            return (Task::none(), None);
        };
        *input = s;
        *error = None;
        *ens_resolving = None;
        self.input_seq = self.input_seq.wrapping_add(1);
        (Task::none(), None)
    }

    fn handle_address_submit(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Step::AddressInput { input, .. } = &self.step else {
            return (Task::none(), None);
        };
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            self.set_address_error("Please enter an Ethereum address or name.");
            return (Task::none(), None);
        }
        // Try hex address first; cheaper than spawning a name-resolution task.
        if let Ok(address) = trimmed.parse::<Address>() {
            return self.kick_off_scan(address, trimmed);
        }
        if names::looks_like_name(&trimmed) {
            return self.kick_off_ens(trimmed);
        }
        self.set_address_error(
            "Not a valid Ethereum address or name. Expected `0x…` (40 hex chars) or a `.eth` / `.gwei` / `.wei` name.",
        );
        (Task::none(), None)
    }

    fn kick_off_ens(&mut self, name: String) -> (Task<Message>, Option<Outcome>) {
        let seq = self.input_seq;
        if let Step::AddressInput { ens_resolving, .. } = &mut self.step {
            *ens_resolving = Some(seq);
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
        let Step::AddressInput { ens_resolving, .. } = &self.step else {
            return (Task::none(), None);
        };
        if *ens_resolving != Some(seq) {
            return (Task::none(), None);
        }
        match result {
            Ok(Some(address)) => self.kick_off_scan(address, name),
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
    ) -> (Task<Message>, Option<Outcome>) {
        let seq = self.input_seq;
        self.step = Step::Scanning {
            address,
            what: what.clone(),
        };
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
        results: Vec<(Chain, ScanResult)>,
    ) -> (Task<Message>, Option<Outcome>) {
        if seq != self.input_seq {
            // User backed out and started over; drop stale scan.
            return (Task::none(), None);
        }
        let Step::Scanning {
            address: scan_addr, ..
        } = &self.step
        else {
            return (Task::none(), None);
        };
        if *scan_addr != address {
            return (Task::none(), None);
        }
        let hits: Vec<(Chain, &ScanResult)> = results
            .iter()
            .filter(|(_, r)| {
                matches!(
                    r,
                    ScanResult::Canonical(_) | ScanResult::UnrecognizedImpl(_)
                )
            })
            .map(|(c, r)| (*c, r))
            .collect();
        match hits.len() {
            0 => {
                self.step = Step::NoChain { address, results };
            }
            1 => {
                let chain = hits[0].0;
                self.enter_inspect_from_results(chain, results);
            }
            _ => {
                self.step = Step::ChainChooser { address, results };
            }
        }
        (Task::none(), None)
    }

    fn enter_inspect_from_results(&mut self, chain: Chain, results: Vec<(Chain, ScanResult)>) {
        let found = results
            .iter()
            .find(|(c, _)| *c == chain)
            .and_then(|(_, r)| match r {
                ScanResult::Canonical(md) => Some((md.clone(), SafeTrust::Canonical)),
                ScanResult::UnrecognizedImpl(md) => Some((md.clone(), SafeTrust::UnrecognizedImpl)),
                _ => None,
            });
        // Callers pre-filter so `chain` always has a Canonical/UnrecognizedImpl
        // result, but don't panic the whole GUI if that ever stops holding —
        // just decline the transition into Inspect.
        let Some((metadata, trust)) = found else {
            return;
        };
        self.step = Step::Inspect {
            chain,
            metadata,
            trust,
            all_results: results,
        };
    }

    fn handle_chain_picked(&mut self, chain: Chain) -> (Task<Message>, Option<Outcome>) {
        let Step::ChainChooser { results, .. } = &self.step else {
            return (Task::none(), None);
        };
        let results = results.clone();
        self.enter_inspect_from_results(chain, results);
        (Task::none(), None)
    }

    fn handle_inspect_continue(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Step::Inspect {
            chain,
            metadata,
            trust,
            all_results,
        } = &self.step
        else {
            return (Task::none(), None);
        };
        let owners: BTreeSet<Address> = metadata.owners.iter().copied().collect();
        let matched: Vec<ExistingAccount> = self
            .existing
            .iter()
            .filter(|acc| owners.contains(&acc.address))
            .cloned()
            .collect();
        // Default-check every match — the design says "show as a match
        // with a default-checked checkbox", letting the user opt out
        // rather than opt in. They still have to confirm the screen.
        let selected: BTreeSet<u32> = matched.iter().map(|m| m.account_idx).collect();
        self.step = Step::RoleSelection {
            chain: *chain,
            metadata: metadata.clone(),
            trust: trust.clone(),
            all_results: all_results.clone(),
            matched,
            selected,
            linked_nested_safes: Vec::new(),
            signer_error: None,
        };
        (Task::none(), None)
    }

    fn handle_signer_toggled(&mut self, idx: u32) -> (Task<Message>, Option<Outcome>) {
        if let Step::RoleSelection {
            selected,
            signer_error,
            ..
        } = &mut self.step
        {
            if !selected.remove(&idx) {
                selected.insert(idx);
            }
            *signer_error = None;
        }
        (Task::none(), None)
    }

    fn handle_add_signer_pressed(&mut self) -> (Task<Message>, Option<Outcome>) {
        if !matches!(self.step, Step::RoleSelection { .. }) {
            return (Task::none(), None);
        }
        let existing_addrs: BTreeSet<Address> = self.existing.iter().map(|e| e.address).collect();
        let placeholder = Step::AddressInput {
            input: String::new(),
            error: None,
            ens_resolving: None,
        };
        let Step::RoleSelection {
            chain,
            metadata,
            trust,
            all_results,
            matched,
            selected,
            linked_nested_safes,
            ..
        } = std::mem::replace(&mut self.step, placeholder)
        else {
            unreachable!("guarded above")
        };
        let unclaimed_owners: Vec<Address> = metadata
            .owners
            .iter()
            .copied()
            .filter(|a| !existing_addrs.contains(a))
            .collect();
        self.step = Step::PickSignerMethod {
            chain,
            metadata,
            trust,
            all_results,
            matched,
            selected,
            linked_nested_safes,
            unclaimed_owners,
        };
        (Task::none(), None)
    }

    fn handle_signer_method_picked(
        &mut self,
        method: SignerMethod,
    ) -> (Task<Message>, Option<Outcome>) {
        let Step::PickSignerMethod {
            unclaimed_owners, ..
        } = &self.step
        else {
            return (Task::none(), None);
        };
        if unclaimed_owners.is_empty() {
            self.rewind_picker_to_role(
                Some("Every owner of this Safe is already in your wallet.".to_string()),
                |_, _, _| {},
            );
            return (Task::none(), None);
        }
        let allowed_owners = unclaimed_owners.clone();
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
    /// snapshot (so subsequent picker entries treat it as already
    /// claimed) and the RoleSelection's matched/selected lists.
    pub fn apply_added_signer(&mut self, new_account: ExistingAccount) {
        let step_before = self.step.name();
        if !self
            .existing
            .iter()
            .any(|e| e.account_idx == new_account.account_idx)
        {
            self.existing.push(new_account.clone());
        }
        self.rewind_picker_to_role(None, |matched, selected, _| {
            if !matched
                .iter()
                .any(|m| m.account_idx == new_account.account_idx)
            {
                matched.push(new_account.clone());
            }
            selected.insert(new_account.account_idx);
        });
        if step_before != self.step.name() {
            crate::trace::state("safe_onboarding", "step", step_before, self.step.name());
        }
    }

    /// Called by the parent after a nested-Safe sub-flow finished and
    /// the inner Safe was saved to the wallet. Records the nested
    /// Safe's address as a linked owner so the RoleSelection view can
    /// surface it as a sign-capable owner.
    pub fn apply_added_nested_safe(&mut self, address: Address) {
        let step_before = self.step.name();
        self.rewind_picker_to_role(None, |_, _, linked| {
            if !linked.contains(&address) {
                linked.push(address);
            }
        });
        if step_before != self.step.name() {
            crate::trace::state("safe_onboarding", "step", step_before, self.step.name());
        }
    }

    /// Called by the parent when an import attempt failed validation
    /// (e.g., the derived address wasn't an owner of this Safe). Bounce
    /// the user back to RoleSelection with the error displayed.
    pub fn apply_signer_import_error(&mut self, message: String) {
        let step_before = self.step.name();
        self.rewind_picker_to_role(Some(message), |_, _, _| {});
        if step_before != self.step.name() {
            crate::trace::state("safe_onboarding", "step", step_before, self.step.name());
        }
    }

    /// Common rewind from `PickSignerMethod` to `RoleSelection`. Moves
    /// the carried-forward state by value (no metadata/all_results
    /// clone) and runs `mutate` on the matched/selected/nested-safe
    /// lists before rebuilding the step. No-op if the current step
    /// isn't the picker.
    fn rewind_picker_to_role(
        &mut self,
        signer_error: Option<String>,
        mutate: impl FnOnce(&mut Vec<ExistingAccount>, &mut BTreeSet<u32>, &mut Vec<Address>),
    ) {
        if !matches!(self.step, Step::PickSignerMethod { .. }) {
            return;
        }
        let placeholder = Step::AddressInput {
            input: String::new(),
            error: None,
            ens_resolving: None,
        };
        let Step::PickSignerMethod {
            chain,
            metadata,
            trust,
            all_results,
            mut matched,
            mut selected,
            mut linked_nested_safes,
            ..
        } = std::mem::replace(&mut self.step, placeholder)
        else {
            unreachable!("guarded above")
        };
        mutate(&mut matched, &mut selected, &mut linked_nested_safes);
        self.step = Step::RoleSelection {
            chain,
            metadata,
            trust,
            all_results,
            matched,
            selected,
            linked_nested_safes,
            signer_error,
        };
    }

    fn handle_watch_only(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Step::RoleSelection {
            chain,
            metadata,
            trust,
            all_results,
            ..
        } = &self.step
        else {
            return (Task::none(), None);
        };
        self.enter_label(
            *chain,
            metadata.clone(),
            trust.clone(),
            Vec::new(),
            all_results.clone(),
        );
        (Task::none(), None)
    }

    fn handle_role_confirm(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Step::RoleSelection {
            chain,
            metadata,
            trust,
            all_results,
            selected,
            ..
        } = &self.step
        else {
            return (Task::none(), None);
        };
        let linked: Vec<u32> = selected.iter().copied().collect();
        self.enter_label(
            *chain,
            metadata.clone(),
            trust.clone(),
            linked,
            all_results.clone(),
        );
        (Task::none(), None)
    }

    fn enter_label(
        &mut self,
        chain: Chain,
        metadata: SafeMetadata,
        trust: SafeTrust,
        linked: Vec<u32>,
        all_results: Vec<(Chain, ScanResult)>,
    ) {
        // Siblings = every chain hit OTHER than the primary, each
        // default-checked. Sourced from the same scan results so we
        // don't have to re-fetch.
        let siblings: Vec<(Chain, SafeMetadata, SafeTrust, bool)> = all_results
            .into_iter()
            .filter_map(|(c, r)| {
                if c == chain {
                    return None;
                }
                match r {
                    ScanResult::Canonical(md) => Some((c, md, SafeTrust::Canonical, true)),
                    ScanResult::UnrecognizedImpl(md) => {
                        Some((c, md, SafeTrust::UnrecognizedImpl, true))
                    }
                    _ => None,
                }
            })
            .collect();
        self.step = Step::Label {
            chain,
            metadata,
            trust,
            linked,
            name: String::new(),
            siblings,
            advanced: false,
            service_url: String::new(),
            service_url_error: None,
        };
    }

    fn handle_name_input(&mut self, s: String) -> (Task<Message>, Option<Outcome>) {
        if let Step::Label { name, .. } = &mut self.step {
            *name = s;
        }
        (Task::none(), None)
    }

    fn handle_sibling_toggled(&mut self, chain: Chain) -> (Task<Message>, Option<Outcome>) {
        if let Step::Label { siblings, .. } = &mut self.step
            && let Some(entry) = siblings.iter_mut().find(|(c, _, _, _)| *c == chain)
        {
            entry.3 = !entry.3;
        }
        (Task::none(), None)
    }

    fn handle_advanced_toggled(&mut self) -> (Task<Message>, Option<Outcome>) {
        if let Step::Label { advanced, .. } = &mut self.step {
            *advanced = !*advanced;
        }
        (Task::none(), None)
    }

    fn handle_service_url_input(&mut self, s: String) -> (Task<Message>, Option<Outcome>) {
        if let Step::Label {
            service_url,
            service_url_error,
            ..
        } = &mut self.step
        {
            *service_url = s;
            *service_url_error = None;
        }
        (Task::none(), None)
    }

    fn handle_label_confirm(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Step::Label {
            chain,
            metadata,
            trust,
            linked,
            name,
            siblings,
            service_url,
            ..
        } = &self.step
        else {
            return (Task::none(), None);
        };
        // Validate the Advanced service URL before anything is built —
        // a typo'd mirror must not get persisted and then silently
        // 404/timeout every queue fetch.
        let tx_service_url = match crate::safe::service::normalize_service_base(service_url) {
            Ok(v) => v,
            Err(e) => {
                if let Step::Label {
                    advanced,
                    service_url_error,
                    ..
                } = &mut self.step
                {
                    // Re-open the section so the error is visible even
                    // if the user collapsed it after typing.
                    *advanced = true;
                    *service_url_error = Some(e);
                }
                return (Task::none(), None);
            }
        };
        let now = unix_seconds();
        let clean_name = clean_label(name);
        let primary = descriptor_from(
            metadata,
            *chain,
            trust.clone(),
            clean_name.clone(),
            linked.clone(),
            siblings
                .iter()
                .filter(|(_, _, _, on)| *on)
                .map(|(c, _, _, _)| c.chain_id())
                .collect(),
            now,
            tx_service_url.clone(),
        );
        // Sibling descriptors: each is its own (address, chain_id)
        // record (separate owner cache; the storage layer treats
        // them as independent). All siblings of a sibling include
        // the primary plus the OTHER siblings, so each descriptor
        // self-describes its peer list — matches what the dashboard
        // needs to render "this Safe is also deployed on chain X".
        let all_chain_ids: Vec<u64> = std::iter::once(chain.chain_id())
            .chain(
                siblings
                    .iter()
                    .filter(|(_, _, _, on)| *on)
                    .map(|(c, _, _, _)| c.chain_id()),
            )
            .collect();
        let siblings_descriptors: Vec<SafeDescriptor> = siblings
            .iter()
            .filter(|(_, _, _, on)| *on)
            .map(|(c, md, sibling_trust, _)| {
                let others: Vec<u64> = all_chain_ids
                    .iter()
                    .copied()
                    .filter(|id| *id != c.chain_id())
                    .collect();
                descriptor_from(
                    md,
                    *c,
                    sibling_trust.clone(),
                    clean_name.clone(),
                    // Sibling owner sets can diverge; we don't
                    // auto-link signers on siblings. The user can
                    // re-onboard each sibling individually later
                    // to link signers there. Conservative default.
                    Vec::new(),
                    others,
                    now,
                    // A custom mirror serves the multi-chain
                    // /tx-service/{chain} layout, so siblings share it.
                    // Adjustable per Safe later in Settings → Safes.
                    tx_service_url.clone(),
                )
            })
            .collect();
        (
            Task::none(),
            Some(Outcome::Done {
                primary: Box::new(primary),
                siblings: siblings_descriptors,
            }),
        )
    }

    fn set_address_error(&mut self, msg: &str) {
        if let Step::AddressInput {
            error,
            ens_resolving,
            ..
        } = &mut self.step
        {
            *error = Some(msg.to_string());
            *ens_resolving = None;
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
        linked_signer_indices,
        sibling_chains,
        cached_at,
        tx_service_url,
    }
}

// ── Views (per step) ────────────────────────────────────────────────────────

fn view_address_input<'a>(
    t: KaoTheme,
    input: &'a str,
    error: Option<&'a str>,
    resolving: bool,
) -> Element<'a, Message> {
    let addr_input = text_input("0x… or a name (.eth / .gwei / .wei)", input)
        .id(ADDRESS_INPUT_ID)
        .on_input(Message::AddressInput)
        .on_submit(Message::AddressSubmit)
        .padding(Padding::from([12, 14]))
        .size(14)
        .font(mono())
        .style(move |_theme, status| text_input_style(t, status));

    let btn_label = if resolving {
        "Resolving name…"
    } else {
        "Scan →"
    };
    let btn = primary_button(t, btn_label, !resolving).on_press_maybe(if resolving {
        None
    } else {
        Some(Message::AddressSubmit)
    });

    let hint = container(
        row![
            hint_pill(t, "Enter"),
            Space::new().width(6),
            text("to scan · ").size(11).color(t.sub),
            hint_pill(t, "Esc"),
            Space::new().width(6),
            text("to go back").size(11).color(t.sub),
        ]
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .center_x(Length::Fill);

    let mut content = column![
        kao_hero(t, "(˶>⩊<˶)", 56.0),
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

    if let Some(e) = error {
        content = content.push(vspace(10)).push(error_text(t, e));
    }
    content.into()
}

fn view_scanning<'a>(t: KaoTheme, what: &'a str) -> Element<'a, Message> {
    column![
        kao_hero(t, "ദ്ദി◝ ⩊ ◜.ᐟ", 56.0),
        vspace(10),
        screen_title(t, "Scanning…"),
        vspace(6),
        screen_subtitle(t, "Checking Mainnet, Optimism, and Base in parallel."),
        vspace(22),
        text(what).size(13).color(t.sub).font(mono()),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center)
    .into()
}

fn view_chain_chooser<'a>(
    t: KaoTheme,
    address: Address,
    results: &'a [(Chain, ScanResult)],
) -> Element<'a, Message> {
    let mut col = column![
        kao_hero(t, "(๑ᵔ⤙ᵔ๑)", 56.0),
        vspace(10),
        screen_title(t, "Pick a chain"),
        vspace(6),
        screen_subtitle(
            t,
            "This address is a Safe on more than one chain. Pick the one to add now — siblings can be added at the next step."
        ),
        vspace(14),
        container(colored_address(t, address)).center_x(Length::Fill),
        vspace(18),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    for (chain, result) in results {
        if let ScanResult::Canonical(md) | ScanResult::UnrecognizedImpl(md) = result {
            let trust_label = match result {
                ScanResult::Canonical(_) => "Canonical",
                _ => "Unrecognized impl",
            };
            let inner: Element<'_, Message> = column![
                row![
                    text(chain.display_name())
                        .size(14)
                        .color(t.text)
                        .font(mono_bold()),
                    Space::new().width(8),
                    text(trust_label).size(11).color(t.sub).font(mono()),
                ]
                .align_y(Alignment::Center),
                vspace(4),
                row![
                    text(format!("threshold {}", md.threshold))
                        .size(12)
                        .color(t.sub)
                        .font(mono()),
                    Space::new().width(12),
                    text(format!(
                        "{} owner{}",
                        md.owners.len(),
                        if md.owners.len() == 1 { "" } else { "s" }
                    ))
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
                    Space::new().width(12),
                    text(format!("v{}", md.version))
                        .size(12)
                        .color(t.sub)
                        .font(mono()),
                ]
                .align_y(Alignment::Center),
            ]
            .spacing(0)
            .into();
            let btn = ghost_button(t, inner)
                .padding(Padding::from([10, 12]))
                .width(Length::Fill)
                .on_press(Message::ChainPicked(*chain));
            col = col.push(btn).push(vspace(8));
        }
    }
    col.into()
}

fn view_no_chain<'a>(
    t: KaoTheme,
    address: Address,
    results: &'a [(Chain, ScanResult)],
) -> Element<'a, Message> {
    let mut col = column![
        kao_hero(t, "(*ᴗ͈ˬᴗ͈)ꕤ*.ﾟ", 56.0),
        vspace(10),
        screen_title(t, "No Safe found"),
        vspace(6),
        screen_subtitle(
            t,
            "Couldn't find a Safe at this address on Mainnet, Optimism, or Base."
        ),
        vspace(14),
        container(colored_address(t, address)).center_x(Length::Fill),
        vspace(18),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    for (chain, result) in results {
        let reason = match result {
            ScanResult::NotDeployed => "no contract at this address".to_string(),
            ScanResult::NotASafe { reason } => format!("not a Safe: {reason}"),
            _ => unreachable!("filtered to non-Safe variants"),
        };
        let line = row![
            text(chain.label()).size(12).color(t.text).font(mono_bold()),
            Space::new().width(10),
            text(reason).size(11).color(t.sub).font(mono()),
        ]
        .align_y(Alignment::Center);
        col = col.push(line).push(vspace(4));
    }
    col.into()
}

fn view_inspect<'a>(
    t: KaoTheme,
    chain: Chain,
    md: &'a SafeMetadata,
    trust: &SafeTrust,
) -> Element<'a, Message> {
    let trust_badge = match trust {
        SafeTrust::Canonical => text("✓ Canonical").size(11).color(t.a1).font(mono_bold()),
        SafeTrust::UnrecognizedImpl => text("⚠ Unrecognized impl")
            .size(11)
            .color(t.a2)
            .font(mono_bold()),
    };

    let header = column![
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
            trust_badge,
        ]
        .align_y(Alignment::Center),
        vspace(8),
        colored_address(t, md.address),
    ];

    let threshold_line = text(format!(
        "threshold {} of {} owner{}",
        md.threshold,
        md.owners.len(),
        if md.owners.len() == 1 { "" } else { "s" }
    ))
    .size(12)
    .color(t.sub)
    .font(mono());

    let mut owners_col = column![text("Owners").size(12).color(t.text).font(mono_bold())];
    for owner in &md.owners {
        owners_col = owners_col.push(vspace(4)).push(colored_address(t, *owner));
    }

    let modules_col = danger_block(t, "Modules", &md.modules, "no modules enabled");
    let guard_col = danger_block(t, "Guard", md.guard.as_slice(), "no guard set");
    let fallback_col = danger_block(
        t,
        "Fallback handler",
        md.fallback_handler.as_slice(),
        "no fallback handler set",
    );

    let mut body = column![
        kao_hero(t, "⸜(｡˃ ᵕ ˂ )⸝♡", 48.0),
        vspace(8),
        screen_title(t, "Safe found"),
        vspace(12),
        header,
        vspace(14),
        threshold_line,
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    if md.threshold == 1 {
        body = body.push(vspace(6)).push(
            text("⚠ Threshold = 1 — any owner can act alone")
                .size(11)
                .color(t.a2)
                .font(mono_bold()),
        );
    }

    body = body
        .push(vspace(14))
        .push(owners_col)
        .push(vspace(14))
        .push(modules_col)
        .push(vspace(10))
        .push(guard_col)
        .push(vspace(10))
        .push(fallback_col)
        .push(vspace(18))
        .push(primary_button(t, "Continue →", true).on_press(Message::InspectContinue));

    scrollable(body).height(Length::Shrink).into()
}

/// Render one of the "danger surfaces" — modules / guard / fallback —
/// with classification labels next to each address. Unknown addresses
/// get a warning-styled label since they're a standing security
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
    ];
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

fn view_role_selection<'a>(
    t: KaoTheme,
    chain: Chain,
    md: &'a SafeMetadata,
    matched: &'a [ExistingAccount],
    selected: &BTreeSet<u32>,
    linked_nested_safes: &'a [Address],
    signer_error: Option<&'a str>,
) -> Element<'a, Message> {
    let header = column![
        screen_title(t, "Your role"),
        vspace(6),
        screen_subtitle(
            t,
            "Link the wallet accounts that own this Safe — or continue as a watch-only observer."
        ),
        vspace(8),
        text(format!("Safe on {} — {}", chain.display_name(), md.address))
            .size(11)
            .color(t.sub)
            .font(mono()),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    let mut body = column![header, vspace(18)]
        .width(Length::Fill)
        .align_x(Alignment::Center);

    if matched.is_empty() {
        body = body.push(
            text("No accounts in this wallet are owners of this Safe.")
                .size(12)
                .color(t.sub)
                .font(mono()),
        );
    } else {
        body = body.push(
            text("Matched owners")
                .size(12)
                .color(t.text)
                .font(mono_bold()),
        );
        for m in matched {
            let is_selected = selected.contains(&m.account_idx);
            let idx = m.account_idx;
            let cb = kao_checkbox(t, is_selected)
                .label(format!("{} · {}", m.label, m.address))
                .on_toggle(move |_| Message::SignerToggled(idx))
                .size(16)
                .spacing(10)
                .text_size(13)
                .text_line_height(1.4)
                .font(mono());
            body = body.push(vspace(6)).push(cb);
        }
    }

    if !linked_nested_safes.is_empty() {
        body = body.push(vspace(14)).push(
            text("Linked owner Safes")
                .size(12)
                .color(t.text)
                .font(mono_bold()),
        );
        for a in linked_nested_safes {
            body = body.push(vspace(6)).push(colored_address(t, *a));
        }
    }

    let confirm_label = match (selected.is_empty(), linked_nested_safes.is_empty()) {
        (true, true) => "Continue as watch-only →",
        (true, false) => "Continue →",
        (false, _) => "Link signers →",
    };
    body = body
        .push(vspace(20))
        .push(
            primary_button(t, confirm_label, true).on_press(if selected.is_empty() {
                Message::WatchOnlySelected
            } else {
                Message::RoleConfirm
            }),
        )
        .push(vspace(10))
        .push({
            let label: Element<'_, Message> =
                text("Add a new signer →").size(12).color(t.text).into();
            ghost_button(t, label)
                .padding(Padding::from([10, 14]))
                .on_press(Message::AddSignerPressed)
        });
    if let Some(err) = signer_error {
        body = body.push(vspace(10)).push(error_text(t, err));
    }
    body.into()
}

/// Pick the import method for a new signer. Surfaces the list of
/// owners the user still needs to "claim" (i.e., own a key for) so
/// they can verify the upcoming import is targeting the right one.
fn view_pick_signer_method<'a>(
    t: KaoTheme,
    chain: Chain,
    md: &'a SafeMetadata,
    unclaimed_owners: &'a [Address],
) -> Element<'a, Message> {
    let header = column![
        kao_hero(t, "(っ◔◡◔)っ", 48.0),
        vspace(8),
        screen_title(t, "Add a new signer"),
        vspace(6),
        screen_subtitle(
            t,
            "Pick an import method. The address it derives must be one of this Safe's owners.",
        ),
        vspace(8),
        text(format!("Safe on {} — {}", chain.display_name(), md.address))
            .size(11)
            .color(t.sub)
            .font(mono()),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    let mut owners_col = column![
        text("Unclaimed owners")
            .size(12)
            .color(t.text)
            .font(mono_bold())
    ];
    if unclaimed_owners.is_empty() {
        owners_col = owners_col.push(vspace(4)).push(
            text("Every owner is already in your wallet — nothing to import.")
                .size(11)
                .color(t.sub)
                .font(mono()),
        );
    } else {
        for a in unclaimed_owners {
            owners_col = owners_col.push(vspace(4)).push(colored_address(t, *a));
        }
    }

    let mut body = column![header, vspace(16), owners_col]
        .width(Length::Fill)
        .align_x(Alignment::Center);

    if !unclaimed_owners.is_empty() {
        body = body
            .push(vspace(18))
            .push(method_card(
                t,
                t.ab1,
                t.a1,
                "1",
                "Seed phrase",
                "Restore an account from a 12 or 24-word phrase, then pick the matching HD index.",
                Message::SignerMethodPicked(SignerMethod::SeedPhrase),
            ))
            .push(vspace(10))
            .push(method_card(
                t,
                t.ab2,
                t.a2,
                "2",
                "Private key",
                "Paste a raw 32-byte hex key. Rejected if it doesn't derive to an owner.",
                Message::SignerMethodPicked(SignerMethod::PrivateKey),
            ))
            .push(vspace(10))
            .push(method_card(
                t,
                t.ab3,
                t.a3,
                "3",
                "Hardware wallet",
                "Connect a Ledger or Trezor and pick the matching account.",
                Message::SignerMethodPicked(SignerMethod::Hardware),
            ))
            .push(vspace(10))
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
    scrollable(body).height(Length::Shrink).into()
}

#[allow(clippy::too_many_arguments)]
fn view_label<'a>(
    t: KaoTheme,
    chain: Chain,
    md: &'a SafeMetadata,
    trust: &SafeTrust,
    linked: &[u32],
    name: &str,
    siblings: &'a [(Chain, SafeMetadata, SafeTrust, bool)],
    advanced: bool,
    service_url: &str,
    service_url_error: Option<&'a str>,
) -> Element<'a, Message> {
    let trust_badge = match trust {
        SafeTrust::Canonical => text("Canonical").size(11).color(t.a1).font(mono()),
        SafeTrust::UnrecognizedImpl => text("Unrecognized impl").size(11).color(t.a2).font(mono()),
    };
    let role_label = if linked.is_empty() {
        format!("Watch-only Safe on {}", chain.display_name())
    } else {
        format!(
            "Signer Safe on {} ({} linked key{})",
            chain.display_name(),
            linked.len(),
            if linked.len() == 1 { "" } else { "s" }
        )
    };

    let name_input = text_input("Treasury · Council · Personal hot…", name)
        .id(NAME_INPUT_ID)
        .on_input(Message::NameInput)
        .on_submit(Message::LabelConfirm)
        .padding(Padding::from([12, 14]))
        .size(14)
        .font(mono())
        .style(move |_theme, status| text_input_style(t, status));

    let mut siblings_col = column![];
    if !siblings.is_empty() {
        siblings_col = siblings_col
            .push(
                text("Also detected on")
                    .size(12)
                    .color(t.text)
                    .font(mono_bold()),
            )
            .push(vspace(6));
        for (sib_chain, _md, _trust, on) in siblings {
            let chain_label = sib_chain.display_name().to_string();
            let captured_chain = *sib_chain;
            let cb = kao_checkbox(t, *on)
                .label(format!("Add as separate entry · {chain_label}"))
                .on_toggle(move |_| Message::SiblingToggled(captured_chain))
                .size(16)
                .spacing(10)
                .text_size(13)
                .font(mono());
            siblings_col = siblings_col.push(cb).push(vspace(4));
        }
    }

    // Advanced section — collapsed by default; holds the custom
    // Transaction Service mirror. Per-Safe, validated on confirm.
    let advanced_header = link_button(
        t,
        if advanced {
            "Advanced ▾"
        } else {
            "Advanced ▸"
        },
    )
    .on_press(Message::AdvancedToggled);
    let mut advanced_col = column![advanced_header].width(Length::Fill);
    if advanced {
        let service_input = text_input(crate::safe::service::DEFAULT_TX_SERVICE_BASE, service_url)
            .on_input(Message::ServiceUrlInput)
            .on_submit(Message::LabelConfirm)
            .padding(Padding::from([10, 12]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));
        advanced_col = advanced_col
            .push(vspace(8))
            .push(
                text("Transaction service")
                    .size(12)
                    .color(t.text)
                    .font(mono_bold()),
            )
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
        if let Some(err) = service_url_error {
            advanced_col = advanced_col.push(vspace(6)).push(error_text(t, err));
        }
    }

    let body = column![
        screen_title(t, "Label this Safe"),
        vspace(8),
        row![
            text(format!("v{}", md.version))
                .size(11)
                .color(t.sub)
                .font(mono()),
            Space::new().width(10),
            trust_badge,
        ]
        .align_y(Alignment::Center),
        vspace(4),
        text(role_label).size(11).color(t.sub).font(mono()),
        vspace(18),
        name_input,
        vspace(16),
        siblings_col,
        vspace(12),
        advanced_col,
        vspace(20),
        primary_button(t, "Add to wallet →", true).on_press(Message::LabelConfirm),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    body.into()
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

    /// Canned `SafeMetadata` for tests that need to inject Inspect or
    /// Label state directly. Versioned 1.4.1 with the canonical L1
    /// singleton so it would classify as `Canonical` if it went
    /// through the registry; we set the trust explicitly in callers.
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
            nonce: U256::ZERO,
        }
    }

    fn canonical_hit(chain: Chain, owners: Vec<Address>) -> (Chain, ScanResult) {
        (
            chain,
            ScanResult::Canonical(SafeMetadata {
                chain_id: chain.chain_id(),
                ..fake_metadata_with_owners(owners, 1)
            }),
        )
    }

    fn screen(
        mock: Arc<dyn BalanceFetcher>,
        existing: Vec<ExistingAccount>,
    ) -> SafeOnboardingScreen {
        SafeOnboardingScreen::new(mock, existing)
    }

    #[test]
    fn initial_step_is_address_input() {
        let mock = Arc::new(CallMock::new()) as Arc<dyn BalanceFetcher>;
        let s = screen(mock, Vec::new());
        assert!(matches!(s.step, Step::AddressInput { .. }));
    }

    #[test]
    fn address_submit_with_invalid_input_sets_error_and_stays() {
        let mock = Arc::new(CallMock::new()) as Arc<dyn BalanceFetcher>;
        let mut s = screen(mock, Vec::new());
        let _ = s.update(Message::AddressInput("not an address".into()));
        let _ = s.update(Message::AddressSubmit);
        match &s.step {
            Step::AddressInput { error, .. } => assert!(error.is_some()),
            other => panic!("expected AddressInput, got {other:?}"),
        }
    }

    #[test]
    fn address_submit_with_empty_input_sets_error() {
        let mock = Arc::new(CallMock::new()) as Arc<dyn BalanceFetcher>;
        let mut s = screen(mock, Vec::new());
        let _ = s.update(Message::AddressSubmit);
        match &s.step {
            Step::AddressInput { error, .. } => assert!(error.is_some()),
            _ => panic!("expected AddressInput"),
        }
    }

    #[tokio::test]
    async fn scan_with_zero_hits_transitions_to_no_chain() {
        // Mock returns empty get_code for every chain → ScanResult::NotDeployed.
        let mock = Arc::new(CallMock::new());
        let net: Arc<dyn BalanceFetcher> = mock.clone();
        let mut s = screen(net, Vec::new());
        let _ = s.update(Message::AddressInput(format!("{:?}", safe_addr())));
        let _ = s.update(Message::AddressSubmit);
        // Scanning is in flight — simulate the completion message.
        let results = safe::scan_across_chains(mock.as_ref(), safe_addr()).await;
        let _ = s.update(Message::ScanCompleted {
            seq: s.input_seq,
            address: safe_addr(),
            results,
        });
        assert!(matches!(s.step, Step::NoChain { .. }));
    }

    #[tokio::test]
    async fn single_chain_hit_skips_chooser_and_goes_straight_to_inspect() {
        let mock = Arc::new(CallMock::new());
        // We deliberately only plant on the network — CallMock ignores
        // chain, so every chain "hits". Plant once, then the post-scan
        // logic should see 3 hits and go to the chooser. To test the
        // single-hit branch we need a different setup: skip planting
        // and use the per-chain inspect path indirectly. The simplest
        // path is to skip the scan and inject results directly via
        // ScanCompleted.
        let net: Arc<dyn BalanceFetcher> = mock.clone();
        let mut s = screen(net, Vec::new());
        // Move the screen into Scanning manually so the precondition
        // is satisfied; ScanCompleted ignores the message if step != Scanning.
        s.step = Step::Scanning {
            address: safe_addr(),
            what: format!("{:?}", safe_addr()),
        };
        let single_hit_results = vec![
            (
                Chain::Mainnet,
                ScanResult::Canonical(SafeMetadata {
                    chain_id: 1,
                    address: safe_addr(),
                    implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
                    version: "1.4.1".into(),
                    threshold: 1,
                    owners: vec![owner_a()],
                    modules: vec![],
                    guard: None,
                    fallback_handler: None,
                    nonce: U256::ZERO,
                }),
            ),
            (Chain::Optimism, ScanResult::NotDeployed),
            (Chain::Base, ScanResult::NotASafe { reason: "x".into() }),
        ];
        let _ = s.update(Message::ScanCompleted {
            seq: s.input_seq,
            address: safe_addr(),
            results: single_hit_results,
        });
        match &s.step {
            Step::Inspect { chain, .. } => assert_eq!(*chain, Chain::Mainnet),
            other => panic!("expected Inspect on Mainnet, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multi_chain_hit_transitions_to_chain_chooser() {
        // Inject the scan-complete message directly. The integration
        // with `safe::scan_across_chains` is covered by that module's
        // own tests — here we're testing the state-machine branching
        // on `hits.len() > 1`.
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::Scanning {
            address: safe_addr(),
            what: format!("{:?}", safe_addr()),
        };
        let results = vec![
            canonical_hit(Chain::Mainnet, vec![owner_a()]),
            canonical_hit(Chain::Optimism, vec![owner_a()]),
            canonical_hit(Chain::Base, vec![owner_a()]),
        ];
        let _ = s.update(Message::ScanCompleted {
            seq: s.input_seq,
            address: safe_addr(),
            results,
        });
        match &s.step {
            Step::ChainChooser { results, .. } => assert_eq!(results.len(), 3),
            other => panic!("expected ChainChooser, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn chain_picked_transitions_chooser_to_inspect() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::ChainChooser {
            address: safe_addr(),
            results: vec![
                canonical_hit(Chain::Mainnet, vec![owner_a()]),
                canonical_hit(Chain::Base, vec![owner_a()]),
            ],
        };
        let _ = s.update(Message::ChainPicked(Chain::Base));
        match &s.step {
            Step::Inspect { chain, .. } => assert_eq!(*chain, Chain::Base),
            other => panic!("expected Inspect on Base, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inspect_continue_intersects_existing_accounts_and_default_checks_them() {
        let mock = Arc::new(CallMock::new());
        let net: Arc<dyn BalanceFetcher> = mock.clone();
        let existing = vec![
            ExistingAccount {
                account_idx: 0,
                address: owner_a(),
                label: "Account 1".into(),
            },
            ExistingAccount {
                account_idx: 1,
                address: address!("0x000000000000000000000000000000000000c0de"),
                label: "Account 2".into(),
            },
        ];
        let mut s = screen(net, existing);
        s.step = Step::Inspect {
            chain: Chain::Mainnet,
            metadata: SafeMetadata {
                chain_id: 1,
                address: safe_addr(),
                implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
                version: "1.4.1".into(),
                threshold: 1,
                owners: vec![owner_a(), owner_b()],
                modules: vec![],
                guard: None,
                fallback_handler: None,
                nonce: U256::ZERO,
            },
            trust: SafeTrust::Canonical,
            all_results: vec![],
        };
        let _ = s.update(Message::InspectContinue);
        match &s.step {
            Step::RoleSelection {
                matched, selected, ..
            } => {
                // Only account 0 (owner_a) is a real owner; account 1
                // isn't in the owner set, so it's not in `matched`.
                assert_eq!(matched.len(), 1);
                assert_eq!(matched[0].account_idx, 0);
                // Default-checked.
                assert!(selected.contains(&0));
            }
            other => panic!("expected RoleSelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watch_only_exit_advances_to_label_with_no_linked_signers() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::RoleSelection {
            chain: Chain::Mainnet,
            metadata: SafeMetadata {
                chain_id: 1,
                address: safe_addr(),
                implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
                version: "1.4.1".into(),
                threshold: 1,
                owners: vec![owner_a()],
                modules: vec![],
                guard: None,
                fallback_handler: None,
                nonce: U256::ZERO,
            },
            trust: SafeTrust::Canonical,
            all_results: vec![],
            matched: vec![],
            selected: BTreeSet::new(),
            linked_nested_safes: Vec::new(),
            signer_error: None,
        };
        let _ = s.update(Message::WatchOnlySelected);
        match &s.step {
            Step::Label { linked, .. } => assert!(linked.is_empty()),
            other => panic!("expected Label, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn label_confirm_emits_done_with_descriptor() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::Label {
            chain: Chain::Mainnet,
            metadata: SafeMetadata {
                chain_id: 1,
                address: safe_addr(),
                implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
                version: "1.4.1".into(),
                threshold: 2,
                owners: vec![owner_a(), owner_b()],
                modules: vec![],
                guard: None,
                fallback_handler: None,
                nonce: U256::ZERO,
            },
            trust: SafeTrust::Canonical,
            linked: vec![0],
            name: "  Treasury  ".into(),
            siblings: vec![],
            advanced: false,
            service_url: String::new(),
            service_url_error: None,
        };
        let (_task, outcome) = s.update(Message::LabelConfirm);
        let Some(Outcome::Done { primary, siblings }) = outcome else {
            panic!("expected Done, got {outcome:?}");
        };
        let primary = *primary;
        assert_eq!(primary.name.as_deref(), Some("Treasury"));
        assert_eq!(primary.chain_id, 1);
        assert_eq!(primary.threshold, 2);
        assert_eq!(primary.linked_signer_indices, vec![0]);
        assert_eq!(primary.trust, SafeTrust::Canonical);
        // No Advanced input → public service (stored as None).
        assert!(primary.tx_service_url.is_none());
        assert!(siblings.is_empty());
    }

    #[tokio::test]
    async fn sibling_chains_become_separate_descriptors_with_cross_links() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        let md = SafeMetadata {
            chain_id: 1,
            address: safe_addr(),
            implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
            version: "1.4.1".into(),
            threshold: 1,
            owners: vec![owner_a()],
            modules: vec![],
            guard: None,
            fallback_handler: None,
            nonce: U256::ZERO,
        };
        s.step = Step::Label {
            chain: Chain::Mainnet,
            metadata: md.clone(),
            trust: SafeTrust::Canonical,
            linked: vec![],
            name: "Treasury".into(),
            siblings: vec![
                (Chain::Optimism, md.clone(), SafeTrust::Canonical, true),
                (Chain::Base, md.clone(), SafeTrust::Canonical, true),
            ],
            advanced: true,
            service_url: "https://txs.example-dao.org/".into(),
            service_url_error: None,
        };
        let (_task, outcome) = s.update(Message::LabelConfirm);
        let Some(Outcome::Done { primary, siblings }) = outcome else {
            panic!("expected Done");
        };
        let primary = *primary;
        // Primary lists OP + Base as siblings (chain IDs 10 + 8453).
        let mut primary_siblings = primary.sibling_chains.clone();
        primary_siblings.sort();
        assert_eq!(primary_siblings, vec![10, 8453]);
        // Two sibling descriptors, neither linking any signers
        // (sibling owner sets can diverge; user must re-onboard each
        // explicitly to link).
        assert_eq!(siblings.len(), 2);
        for sib in &siblings {
            assert!(sib.linked_signer_indices.is_empty());
            // Each sibling lists the OTHER two chains as siblings.
            assert_eq!(sib.sibling_chains.len(), 2);
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

    #[tokio::test]
    async fn label_confirm_rejects_bad_service_url_and_stays() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::Label {
            chain: Chain::Mainnet,
            metadata: fake_metadata_with_owners(vec![owner_a()], 1),
            trust: SafeTrust::Canonical,
            linked: vec![],
            name: "Treasury".into(),
            siblings: vec![],
            // Collapsed on purpose: the error must force it back open.
            advanced: false,
            service_url: "http://txs.example-dao.org".into(), // non-loopback http
            service_url_error: None,
        };
        let (_task, outcome) = s.update(Message::LabelConfirm);
        assert!(outcome.is_none(), "must not emit Done with a bad URL");
        match &s.step {
            Step::Label {
                advanced,
                service_url_error,
                ..
            } => {
                assert!(*advanced, "section reopens to show the error");
                assert!(service_url_error.is_some());
            }
            other => panic!("expected to stay on Label, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn back_from_address_input_propagates_outcome_back() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(matches!(outcome, Some(Outcome::Back)));
    }

    #[tokio::test]
    async fn back_from_later_step_rewinds_to_address_input_without_outcome() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::Inspect {
            chain: Chain::Mainnet,
            metadata: SafeMetadata {
                chain_id: 1,
                address: safe_addr(),
                implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
                version: "1.4.1".into(),
                threshold: 1,
                owners: vec![owner_a()],
                modules: vec![],
                guard: None,
                fallback_handler: None,
                nonce: U256::ZERO,
            },
            trust: SafeTrust::Canonical,
            all_results: vec![],
        };
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(outcome.is_none(), "in-flow back must not propagate");
        assert!(matches!(s.step, Step::AddressInput { .. }));
    }

    /// Build a RoleSelection step with the given owner set, matched
    /// accounts, and selection. The screen's `existing` snapshot is
    /// derived from `matched` so the picker's "unclaimed owners"
    /// computation has a real intersection to work against.
    fn role_selection_with(
        owners: Vec<Address>,
        matched: Vec<ExistingAccount>,
        selected: BTreeSet<u32>,
    ) -> SafeOnboardingScreen {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = SafeOnboardingScreen::new(net, matched.clone());
        s.step = Step::RoleSelection {
            chain: Chain::Mainnet,
            metadata: fake_metadata_with_owners(owners, 1),
            trust: SafeTrust::Canonical,
            all_results: vec![],
            matched,
            selected,
            linked_nested_safes: Vec::new(),
            signer_error: None,
        };
        s
    }

    #[tokio::test]
    async fn add_signer_pressed_transitions_to_picker_with_unclaimed_owners() {
        let owner_c = address!("0x0000000000000000000000000000000000000c0c");
        let matched = vec![ExistingAccount {
            account_idx: 0,
            address: owner_a(),
            label: "Account 1".into(),
        }];
        let mut s = role_selection_with(
            vec![owner_a(), owner_b(), owner_c],
            matched,
            BTreeSet::from([0u32]),
        );
        let (_task, outcome) = s.update(Message::AddSignerPressed);
        assert!(outcome.is_none());
        match &s.step {
            Step::PickSignerMethod {
                unclaimed_owners, ..
            } => {
                // owner_a is already in the wallet (via existing), so
                // only owner_b and owner_c are unclaimed.
                let mut unclaimed = unclaimed_owners.clone();
                unclaimed.sort();
                let mut expected = vec![owner_b(), owner_c];
                expected.sort();
                assert_eq!(unclaimed, expected);
            }
            other => panic!("expected PickSignerMethod, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn picking_method_emits_request_add_signer_with_allowed_owners() {
        let owner_c = address!("0x0000000000000000000000000000000000000c0c");
        let mut s =
            role_selection_with(vec![owner_a(), owner_b(), owner_c], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
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
        let mut want = vec![owner_a(), owner_b(), owner_c];
        want.sort();
        assert_eq!(got, want);
        // Screen stays at PickSignerMethod waiting for the parent's
        // callback (apply_added_signer or apply_signer_import_error).
        assert!(matches!(s.step, Step::PickSignerMethod { .. }));
    }

    #[tokio::test]
    async fn picking_method_with_no_unclaimed_owners_returns_role_with_error() {
        let matched = vec![ExistingAccount {
            account_idx: 0,
            address: owner_a(),
            label: "Account 1".into(),
        }];
        let mut s = role_selection_with(vec![owner_a()], matched, BTreeSet::from([0u32]));
        let _ = s.update(Message::AddSignerPressed);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::SeedPhrase));
        assert!(outcome.is_none());
        match &s.step {
            Step::RoleSelection { signer_error, .. } => assert!(signer_error.is_some()),
            other => panic!("expected RoleSelection with error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn back_from_picker_returns_to_role_selection() {
        let mut s = role_selection_with(
            vec![owner_a(), owner_b()],
            vec![ExistingAccount {
                account_idx: 0,
                address: owner_a(),
                label: "Account 1".into(),
            }],
            BTreeSet::from([0u32]),
        );
        let _ = s.update(Message::AddSignerPressed);
        let (_task, outcome) = s.update(Message::BackPressed);
        assert!(outcome.is_none());
        match &s.step {
            Step::RoleSelection { selected, .. } => assert!(selected.contains(&0)),
            other => panic!("expected RoleSelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_added_signer_returns_to_role_selection_with_new_match_checked() {
        let mut s = role_selection_with(vec![owner_a(), owner_b()], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
        s.apply_added_signer(ExistingAccount {
            account_idx: 7,
            address: owner_b(),
            label: "Account 8".into(),
        });
        match &s.step {
            Step::RoleSelection {
                matched,
                selected,
                signer_error,
                ..
            } => {
                assert_eq!(matched.len(), 1);
                assert_eq!(matched[0].account_idx, 7);
                assert_eq!(matched[0].address, owner_b());
                assert!(selected.contains(&7));
                assert!(signer_error.is_none());
            }
            other => panic!("expected RoleSelection, got {other:?}"),
        }
        // Snapshot is also updated so future picker entries see the new
        // account as already-claimed.
        assert!(s.existing.iter().any(|e| e.account_idx == 7));
    }

    #[tokio::test]
    async fn nested_safe_method_emits_request_with_allowed_owners() {
        let mut s = role_selection_with(vec![owner_a(), owner_b()], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
        let (_task, outcome) = s.update(Message::SignerMethodPicked(SignerMethod::NestedSafe));
        let Some(Outcome::RequestAddSigner { method, .. }) = outcome else {
            panic!("expected RequestAddSigner");
        };
        assert_eq!(method, SignerMethod::NestedSafe);
    }

    #[tokio::test]
    async fn apply_added_nested_safe_records_owner_and_returns_to_role() {
        let mut s = role_selection_with(vec![owner_a(), owner_b()], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
        s.apply_added_nested_safe(owner_b());
        match &s.step {
            Step::RoleSelection {
                linked_nested_safes,
                signer_error,
                ..
            } => {
                assert_eq!(linked_nested_safes, &vec![owner_b()]);
                assert!(signer_error.is_none());
            }
            other => panic!("expected RoleSelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nested_safes_persist_across_picker_roundtrip() {
        let mut s = role_selection_with(vec![owner_a(), owner_b()], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
        s.apply_added_nested_safe(owner_b());
        // Re-enter the picker; the already-linked nested Safe should
        // survive the round-trip.
        let _ = s.update(Message::AddSignerPressed);
        match &s.step {
            Step::PickSignerMethod {
                linked_nested_safes,
                ..
            } => assert_eq!(linked_nested_safes, &vec![owner_b()]),
            other => panic!("expected PickSignerMethod, got {other:?}"),
        }
        let _ = s.update(Message::BackPressed);
        match &s.step {
            Step::RoleSelection {
                linked_nested_safes,
                ..
            } => assert_eq!(linked_nested_safes, &vec![owner_b()]),
            other => panic!("expected RoleSelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_added_nested_safe_is_idempotent() {
        let mut s = role_selection_with(vec![owner_a(), owner_b()], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
        s.apply_added_nested_safe(owner_b());
        // Second call with the same address must not duplicate.
        let _ = s.update(Message::AddSignerPressed);
        s.apply_added_nested_safe(owner_b());
        match &s.step {
            Step::RoleSelection {
                linked_nested_safes,
                ..
            } => assert_eq!(linked_nested_safes, &vec![owner_b()]),
            other => panic!("expected RoleSelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_signer_import_error_returns_to_role_selection_with_error() {
        let mut s = role_selection_with(vec![owner_a(), owner_b()], vec![], BTreeSet::new());
        let _ = s.update(Message::AddSignerPressed);
        s.apply_signer_import_error("Imported address is not an owner.".to_string());
        match &s.step {
            Step::RoleSelection { signer_error, .. } => {
                assert_eq!(
                    signer_error.as_deref(),
                    Some("Imported address is not an owner.")
                );
            }
            other => panic!("expected RoleSelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stale_scan_completion_is_dropped() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut s = screen(net, Vec::new());
        s.step = Step::Scanning {
            address: safe_addr(),
            what: "x".into(),
        };
        let stale_seq = s.input_seq.wrapping_sub(1);
        let _ = s.update(Message::ScanCompleted {
            seq: stale_seq,
            address: safe_addr(),
            results: vec![],
        });
        // Still in Scanning because the seq was stale.
        assert!(matches!(s.step, Step::Scanning { .. }));
    }
}
