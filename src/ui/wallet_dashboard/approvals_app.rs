//! Approvals app — list the allowances the active identity has left standing
//! and hand the ones the user picks to the Transaction Builder as a revoke
//! batch.
//!
//! The scan runs as a chain of requests rather than one long task, so it can
//! show progress and be stopped: read the head, walk the log windows to the
//! lookback floor one at a time, then read every candidate back through
//! Helios. Each step is an [`Outcome`] the coordinator services and answers
//! through an `on_*` callback, which returns the next step. `seq` retires a
//! step the moment the chain, lookback or identity moves underneath it.
//!
//! What a scan learns is cached per `(account, chain)` in a [`ChainScan`]:
//! the contiguous block range searched, every candidate found in it, and the
//! last verified rows. Switching tabs shows the cache; a longer lookback reads
//! only the older blocks it's missing, and a rescan only the ones since.
//!
//! Revoking never happens here. The picked rows become `QueuedCall`s, and the
//! Builder — which already knows how to simulate, batch through a Safe or
//! EIP-7702, and walk the user through sign-review — takes it from there.

use std::collections::{BTreeSet, HashMap, HashSet};

use alloy::primitives::Address;
use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use crate::approvals::{self, Approval, Candidate, Kind, Lookback, Verified};
use crate::chain::Chain;
use crate::txbuilder::QueuedCall;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    avatar, bold, ghost_button, kao_checkbox, mono, mono_bold, primary_button, progress_bar,
    screen_subtitle, screen_title, small_secondary_button,
};
use crate::wallet::short_address;

pub const KAO_MASCOT: &str = "(¬‿¬)";
const KAO_SCANNING: &str = "(◐_◐)";
const KAO_CLEAN: &str = "(ﾉ◕ヮ◕)ﾉ";

#[derive(Debug, Clone)]
pub enum Message {
    Back,
    SelectChain(Chain),
    SelectLookback(Lookback),
    Scan,
    /// Stop walking the logs and check what has been found so far.
    Stop,
    Toggle(Candidate),
    SelectAll,
    SelectNone,
    Revoke,
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// Step back to the Apps launcher.
    Close,
    /// Read the chain head. Answered via [`ApprovalsApp::on_head`].
    Head { seq: u64, chain: Chain },
    /// Scan one `[from, to]` window of `owner`'s approval logs. Answered via
    /// [`ApprovalsApp::on_logs`].
    Logs {
        seq: u64,
        chain: Chain,
        owner: Address,
        from: u64,
        to: u64,
    },
    /// Read `candidates` back through Helios. The coordinator adds the
    /// held-token seeds, which this pane can't see. Answered via
    /// [`ApprovalsApp::on_verified`].
    Verify {
        seq: u64,
        chain: Chain,
        owner: Address,
        candidates: Vec<Candidate>,
    },
    /// Queue these revokes in the Transaction Builder, on `chain`.
    Revoke {
        chain: Chain,
        calls: Vec<QueuedCall>,
    },
}

impl Outcome {
    pub fn name(&self) -> &'static str {
        match self {
            Outcome::Close => "Close",
            Outcome::Head { .. } => "Head",
            Outcome::Logs { .. } => "Logs",
            Outcome::Verify { .. } => "Verify",
            Outcome::Revoke { .. } => "Revoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing is cached for this account and chain, and nothing is running.
    Idle,
    Head,
    /// Reading windows until the cached coverage reaches `floor`.
    Logs {
        floor: u64,
    },
    Verifying,
    Done,
}

/// Everything learned about one account's approvals on one chain.
#[derive(Debug, Clone, Default)]
struct ChainScan {
    /// The newest head read; lookback floors are measured from it. `None`
    /// when the read failed and nothing has been searched.
    head: Option<u64>,
    /// The contiguous `[low, high]` range whose logs are folded into `found`.
    covered: Option<(u64, u64)>,
    /// Every candidate the logs have named, across scans.
    found: BTreeSet<Candidate>,
    /// Whether `rows` predate something `found` or the head now says.
    stale: bool,
    /// The last verification's answer; `None` until one has finished.
    rows: Option<Vec<Approval>>,
    checked: usize,
    selected: HashSet<Candidate>,
    /// Something the user should know about how complete the scan was.
    notice: Option<String>,
}

impl ChainScan {
    fn covers(&self, floor: u64) -> bool {
        matches!((self.covered, self.head), (Some((low, high)), Some(head)) if low <= floor && high >= head)
    }

    /// The next `[from, to]` window on the way to `floor`: blocks newer than
    /// the coverage first, walking up so the range stays contiguous, then
    /// older ones below it, walking down.
    fn next_window(&self, floor: u64) -> Option<(u64, u64)> {
        let head = self.head?;
        match self.covered {
            None => Some(approvals::window(head, floor)),
            Some((_, high)) if high < head => Some(approvals::window_up(high + 1, head)),
            Some((low, _)) if low > floor => Some(approvals::window(low - 1, floor)),
            Some(_) => None,
        }
    }

    /// Fold a finished window in. [`Self::next_window`] only ever asks for
    /// one adjacent to the coverage, so the union stays one range.
    fn extend(&mut self, from: u64, to: u64) {
        self.covered = Some(match self.covered {
            None => (from, to),
            Some((low, high)) => (low.min(from), high.max(to)),
        });
    }

    /// Share of `[floor, head]` already searched, for the progress bar.
    fn progress(&self, floor: u64) -> f32 {
        let (Some(head), Some((low, high))) = (self.head, self.covered) else {
            return 0.0;
        };
        let (low, high) = (low.max(floor), high.min(head));
        if high < low {
            return 0.0;
        }
        (high - low + 1) as f32 / (head - floor + 1) as f32
    }
}

#[derive(Debug)]
pub struct ApprovalsApp {
    owner: Address,
    /// The chain a Safe identity lives on. `None` for an EOA, which can pick.
    pinned: Option<Chain>,
    chain: Chain,
    lookback: Lookback,
    /// Tag every step's reply must echo. Drawn from
    /// [`super::next_task_seq`], never counted locally: a scan the previous
    /// dashboard started still answers here after an account switch.
    seq: u64,
    /// The step running for the current `(owner, chain)`, if any.
    phase: Phase,
    scans: HashMap<(Address, Chain), ChainScan>,
    error: Option<String>,
}

impl ApprovalsApp {
    pub fn new(owner: Address) -> Self {
        Self {
            owner,
            pinned: None,
            chain: Chain::Mainnet,
            lookback: Lookback::default(),
            seq: 0,
            phase: Phase::Idle,
            scans: HashMap::new(),
            error: None,
        }
    }

    /// The identity the app reads for. A change retires any step in flight
    /// and shows what's cached for the new identity, if anything — never the
    /// old one's rows, which it couldn't revoke.
    pub fn set_identity(&mut self, owner: Address, pinned: Option<Chain>) {
        if owner == self.owner && pinned == self.pinned {
            return;
        }
        self.owner = owner;
        self.pinned = pinned;
        if let Some(c) = pinned {
            self.chain = c;
        }
        self.seq = super::next_task_seq();
        self.error = None;
        self.phase = match self.scan() {
            Some(s) if s.rows.is_some() => Phase::Done,
            _ => Phase::Idle,
        };
    }

    /// Opening the app resumes (or starts) the scan for what's on screen.
    pub fn on_open(&mut self) -> Option<Outcome> {
        match self.phase {
            Phase::Idle | Phase::Done => self.resume(),
            _ => None,
        }
    }

    pub fn set_error(&mut self, e: String) {
        self.error = Some(e);
    }

    fn key(&self) -> (Address, Chain) {
        (self.owner, self.chain)
    }

    fn scan(&self) -> Option<&ChainScan> {
        self.scans.get(&self.key())
    }

    fn scan_mut(&mut self) -> &mut ChainScan {
        let key = self.key();
        self.scans.entry(key).or_default()
    }

    fn floor(&self) -> u64 {
        let head = self.scan().and_then(|s| s.head).unwrap_or(0);
        self.lookback.floor(self.chain, head)
    }

    fn busy(&self) -> bool {
        !matches!(self.phase, Phase::Idle | Phase::Done)
    }

    /// Pick up wherever the cache for the current tab leaves off: nothing to
    /// do when it already covers the lookback and its rows are current, a
    /// fresh read when rows are stale, the missing windows otherwise.
    fn resume(&mut self) -> Option<Outcome> {
        self.seq = super::next_task_seq();
        self.error = None;
        let floor = self.floor();
        match self.scan() {
            None | Some(ChainScan { head: None, .. }) => Some(self.read_head()),
            Some(s) if s.covers(floor) && !s.stale && s.rows.is_some() => {
                self.phase = Phase::Done;
                None
            }
            Some(_) => {
                self.scan_mut().notice = None;
                Some(self.advance(floor))
            }
        }
    }

    fn read_head(&mut self) -> Outcome {
        self.phase = Phase::Head;
        Outcome::Head {
            seq: self.seq,
            chain: self.chain,
        }
    }

    pub fn update(&mut self, msg: Message) -> Option<Outcome> {
        match msg {
            Message::Back => Some(Outcome::Close),
            Message::SelectChain(c) => {
                if self.pinned.is_none() && c != self.chain {
                    self.chain = c;
                    return self.resume();
                }
                None
            }
            Message::SelectLookback(l) => {
                if l != self.lookback {
                    self.lookback = l;
                    return self.resume();
                }
                None
            }
            // A rescan keeps what's cached and reads only what's new since —
            // but always re-reads the allowances, which can change without
            // an `Approval` log (most tokens spend one down silently).
            Message::Scan => {
                self.seq = super::next_task_seq();
                self.error = None;
                let s = self.scan_mut();
                s.notice = None;
                s.stale = true;
                Some(self.read_head())
            }
            Message::Stop => match self.phase {
                Phase::Logs { .. } => {
                    let s = self.scan_mut();
                    s.notice = Some(match s.covered {
                        Some((low, _)) => format!(
                            "Stopped at block {low} — approvals granted before it weren't \
                             searched. Tokens you hold were still checked against well-known \
                             spenders."
                        ),
                        None => "Stopped before any blocks were searched. Tokens you hold were \
                                 still checked against well-known spenders."
                            .into(),
                    });
                    Some(self.verify())
                }
                _ => None,
            },
            Message::Toggle(key) => {
                let s = self.scan_mut();
                if !s.selected.remove(&key) {
                    s.selected.insert(key);
                }
                None
            }
            Message::SelectAll => {
                let s = self.scan_mut();
                s.selected = s.rows.iter().flatten().map(Approval::key).collect();
                None
            }
            Message::SelectNone => {
                self.scan_mut().selected.clear();
                None
            }
            Message::Revoke => {
                let s = self.scan()?;
                let picked: Vec<&Approval> = s
                    .rows
                    .iter()
                    .flatten()
                    .filter(|r| s.selected.contains(&r.key()))
                    .collect();
                if picked.is_empty() {
                    return None;
                }
                let calls = approvals::revoke_calls(&picked);
                self.error = None;
                Some(Outcome::Revoke {
                    chain: self.chain,
                    calls,
                })
            }
        }
    }

    fn verify(&mut self) -> Outcome {
        self.phase = Phase::Verifying;
        let candidates = self.scan_mut().found.iter().copied().collect();
        Outcome::Verify {
            seq: self.seq,
            chain: self.chain,
            owner: self.owner,
            candidates,
        }
    }

    /// The next window towards `floor`, or the verify step once the cache
    /// covers it.
    fn advance(&mut self, floor: u64) -> Outcome {
        match self.scan_mut().next_window(floor) {
            Some((from, to)) => {
                self.phase = Phase::Logs { floor };
                Outcome::Logs {
                    seq: self.seq,
                    chain: self.chain,
                    owner: self.owner,
                    from,
                    to,
                }
            }
            None => self.verify(),
        }
    }

    pub fn on_head(&mut self, seq: u64, result: Result<u64, String>) -> Option<Outcome> {
        if seq != self.seq || self.phase != Phase::Head {
            return None;
        }
        match result {
            Ok(head) => {
                let s = self.scan_mut();
                // A lagging RPC can answer below a head already searched;
                // the cache stays anchored to the newer one.
                s.head = Some(s.head.map_or(head, |h| h.max(head)));
                let floor = self.floor();
                Some(self.advance(floor))
            }
            Err(e) => {
                self.scan_mut().notice = Some(format!(
                    "No new logs were searched ({e}). Tokens you hold were still checked against \
                     well-known spenders."
                ));
                Some(self.verify())
            }
        }
    }

    pub fn on_logs(
        &mut self,
        seq: u64,
        from: u64,
        to: u64,
        result: Result<Vec<Candidate>, String>,
    ) -> Option<Outcome> {
        let Phase::Logs { floor } = self.phase else {
            return None;
        };
        if seq != self.seq {
            return None;
        }
        match result {
            Ok(found) => {
                let s = self.scan_mut();
                let before = s.found.len();
                s.found.extend(found);
                s.stale |= s.found.len() != before;
                s.extend(from, to);
                Some(self.advance(floor))
            }
            Err(e) => {
                self.scan_mut().notice = Some(format!(
                    "The log search stopped at blocks {from}–{to}: {e}. Tokens you hold were \
                     still checked against well-known spenders; Rescan picks up where it left off."
                ));
                Some(self.verify())
            }
        }
    }

    pub fn on_verified(&mut self, seq: u64, result: Result<Verified, String>) {
        if seq != self.seq || self.phase != Phase::Verifying {
            return;
        }
        self.phase = Phase::Done;
        match result {
            Ok(v) => {
                let s = self.scan_mut();
                if v.skipped > 0 {
                    let extra = format!(
                        "{} more candidate pairs were past the {} this wallet reads in one pass \
                         and weren't checked.",
                        v.skipped,
                        approvals::MAX_CANDIDATES
                    );
                    s.notice = Some(match s.notice.take() {
                        Some(n) => format!("{n} {extra}"),
                        None => extra,
                    });
                }
                let live: HashSet<Candidate> = v.approvals.iter().map(Approval::key).collect();
                s.selected.retain(|k| live.contains(k));
                s.rows = Some(v.approvals);
                s.checked = v.checked;
                s.stale = false;
            }
            Err(e) => self.error = Some(format!("Couldn't check the approvals: {e}")),
        }
    }

    // ── view ────────────────────────────────────────────────────────────

    pub fn view(&self, t: KaoTheme) -> Element<'_, Message> {
        let mut content = column![
            ghost_button(t, text("← Apps").size(13).color(t.sub).font(bold()))
                .on_press(Message::Back),
            Space::new().height(10),
            row![
                avatar(t, KAO_MASCOT, 40.0, t.ab3),
                Space::new().width(12),
                column![
                    screen_title(t, "Approvals"),
                    screen_subtitle(
                        t,
                        "Allowances this account has granted — pick the ones to revoke"
                    ),
                ]
                .spacing(4),
            ]
            .align_y(Alignment::Center),
            Space::new().height(18),
            self.controls(t),
            Space::new().height(16),
        ]
        .width(Length::Fill)
        .max_width(560);

        content = content.push(self.status(t));

        if let Some(e) = &self.error {
            content = content.push(Space::new().height(10));
            content = content.push(text(e.clone()).size(12).color(t.down));
        }
        if let Some(n) = self.scan().and_then(|s| s.notice.as_ref()) {
            content = content.push(Space::new().height(10));
            content = content.push(text(n.clone()).size(12).color(t.sub));
        }

        content = content.push(Space::new().height(18));
        content = content.push(
            text(
                "Found through your RPC's event logs plus the tokens you hold, then every \
                 allowance is re-read through the Helios light client. An RPC can leave an \
                 approval out of its logs, but it can't make one up or change an amount.",
            )
            .size(11)
            .color(t.sub),
        );
        content.into()
    }

    fn controls<'a>(&self, t: KaoTheme) -> Element<'a, Message> {
        let chains: Element<'a, Message> = match self.pinned {
            Some(c) => text(format!("This Safe is on {}", c.display_name()))
                .size(12)
                .color(t.sub)
                .into(),
            None => {
                let mut r = row![].spacing(8);
                for c in Chain::ALL {
                    r = r.push(tab(t, c.label(), c == self.chain, Message::SelectChain(c)));
                }
                r.into()
            }
        };
        let mut lookbacks = row![text("Look back").size(12).color(t.sub)]
            .spacing(8)
            .align_y(Alignment::Center);
        for l in Lookback::ALL {
            lookbacks = lookbacks.push(tab(
                t,
                l.label(),
                l == self.lookback,
                Message::SelectLookback(l),
            ));
        }
        let rescan = small_secondary_button(t, "↻ Rescan");
        let rescan = if self.busy() {
            rescan
        } else {
            rescan.on_press(Message::Scan)
        };
        column![
            chains,
            Space::new().height(10),
            row![lookbacks, Space::new().width(Length::Fill), rescan].align_y(Alignment::Center),
        ]
        .into()
    }

    fn status<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let scan = self.scan();
        match (self.phase, scan) {
            (Phase::Head, _) => card(
                t,
                row![
                    avatar(t, KAO_SCANNING, 36.0, t.card_alt),
                    Space::new().width(12),
                    text(format!("Reading the {} head…", self.chain.display_name()))
                        .size(13)
                        .color(t.text),
                ]
                .align_y(Alignment::Center)
                .into(),
            ),
            (Phase::Logs { floor }, Some(s)) => {
                let head = s.head.unwrap_or(floor);
                let searched = match s.covered {
                    Some((low, high)) => format!("Searched {low}–{high}"),
                    None => "Starting".to_string(),
                };
                card(
                    t,
                    column![
                        row![
                            avatar(t, KAO_SCANNING, 36.0, t.card_alt),
                            Space::new().width(12),
                            column![
                                text("Searching for approval events…")
                                    .size(13)
                                    .color(t.text)
                                    .font(bold()),
                                text(format!(
                                    "{searched} of {floor}–{head} · {} found so far",
                                    s.found.len()
                                ))
                                .size(11)
                                .color(t.sub)
                                .font(mono()),
                            ]
                            .spacing(2)
                            .width(Length::Fill),
                            small_secondary_button(t, "Stop").on_press(Message::Stop),
                        ]
                        .align_y(Alignment::Center),
                        Space::new().height(10),
                        progress_bar(t, s.progress(floor), t.a1),
                    ]
                    .into(),
                )
            }
            (Phase::Verifying, _) => card(
                t,
                row![
                    avatar(t, KAO_SCANNING, 36.0, t.card_alt),
                    Space::new().width(12),
                    text("Checking what's still live through Helios…")
                        .size(13)
                        .color(t.text),
                ]
                .align_y(Alignment::Center)
                .into(),
            ),
            (
                Phase::Done,
                Some(
                    s @ ChainScan {
                        rows: Some(rows), ..
                    },
                ),
            ) => self.results(t, s, rows),
            _ => card(
                t,
                column![
                    text(format!(
                        "Search {} for the approvals this account has granted.",
                        self.chain.display_name()
                    ))
                    .size(13)
                    .color(t.text),
                    Space::new().height(12),
                    primary_button(t, "Scan", true).on_press(Message::Scan),
                ]
                .into(),
            ),
        }
    }

    fn results<'a>(
        &'a self,
        t: KaoTheme,
        s: &'a ChainScan,
        rows: &'a [Approval],
    ) -> Element<'a, Message> {
        let pairs = format!(
            "checked {} pair{}",
            s.checked,
            if s.checked == 1 { "" } else { "s" }
        );
        let coverage = match s.covered {
            Some((low, high)) => format!("Searched blocks {low}–{high} · {pairs}"),
            None => format!("No blocks searched · {pairs}"),
        };

        if rows.is_empty() {
            let inner = column![
                avatar(t, KAO_CLEAN, 56.0, t.card_alt),
                Space::new().height(10),
                text("No live approvals found")
                    .size(14)
                    .color(t.text)
                    .font(bold()),
                text(coverage).size(11).color(t.sub).font(mono()),
            ]
            .align_x(Alignment::Center)
            .width(Length::Fill);
            return card(t, inner.into());
        }

        let all_selected = s.selected.len() == rows.len();
        let header = row![
            text(format!("{} LIVE", rows.len()))
                .size(11)
                .color(t.sub)
                .font(mono_bold()),
            Space::new().width(Length::Fill),
            if all_selected {
                small_secondary_button(t, "Clear").on_press(Message::SelectNone)
            } else {
                small_secondary_button(t, "Select all").on_press(Message::SelectAll)
            },
        ]
        .align_y(Alignment::Center);

        let now = now_unix();
        let mut list = column![].spacing(8).width(Length::Fill);
        for r in rows {
            list = list.push(approval_row(t, r, s.selected.contains(&r.key()), now));
        }

        let n = s.selected.len();
        let label = match n {
            0 => "Pick approvals to revoke".to_string(),
            1 => "Revoke 1 approval →".to_string(),
            n => format!("Revoke {n} approvals →"),
        };
        let revoke = primary_button(t, label, n > 0);
        let revoke = if n > 0 {
            revoke.on_press(Message::Revoke)
        } else {
            revoke
        };

        column![
            header,
            Space::new().height(8),
            list,
            Space::new().height(14),
            revoke,
            Space::new().height(6),
            text("Opens in the Transaction Builder, where you can simulate the batch and sign it.")
                .size(11)
                .color(t.sub),
            Space::new().height(4),
            text(coverage).size(11).color(t.sub).font(mono()),
        ]
        .width(Length::Fill)
        .into()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn approval_row<'a>(
    t: KaoTheme,
    a: &'a Approval,
    selected: bool,
    now: u64,
) -> Element<'a, Message> {
    let key = a.key();
    let spender: Element<'a, Message> = match a.spender_label {
        Some(label) => row![
            text(label).size(12).color(t.text).font(bold()),
            Space::new().width(6),
            text(short_address(a.spender))
                .size(11)
                .color(t.sub)
                .font(mono()),
        ]
        .align_y(Alignment::Center)
        .into(),
        None => text(a.spender.to_checksum(None))
            .size(11)
            .color(t.text)
            .font(mono())
            .into(),
    };

    let mut badges = row![].spacing(6);
    for r in a.risks() {
        let color = if r.is_serious() { t.down } else { t.sub };
        badges = badges.push(pill(r.label().to_string(), color));
    }
    if let Some(exp) = a.expires {
        badges = badges.push(pill(expiry_label(exp, now), t.sub));
    }

    let info = column![
        row![
            text(a.amount_label()).size(14).color(t.text).font(bold()),
            Space::new().width(Length::Fill),
            pill(a.kind.label().to_string(), t.a3),
        ]
        .align_y(Alignment::Center),
        Space::new().height(3),
        row![
            text(match a.kind {
                Kind::Operator => "operator ",
                _ => "spender ",
            })
            .size(11)
            .color(t.sub),
            spender
        ]
        .align_y(Alignment::Center),
        Space::new().height(6),
        badges,
    ]
    .width(Length::Fill);

    let body = row![
        kao_checkbox(t, selected).on_toggle(move |_| Message::Toggle(key)),
        Space::new().width(12),
        info,
    ]
    .align_y(Alignment::Center);

    button(body)
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .on_press(Message::Toggle(key))
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match (selected, status) {
                (true, _) => with_alpha(t.a1, 0.08),
                (false, button::Status::Hovered | button::Status::Pressed) => {
                    with_alpha(t.a3, 0.06)
                }
                _ => t.card_alt,
            })),
            text_color: t.text,
            border: Border {
                color: if selected {
                    with_alpha(t.a1, 0.5)
                } else {
                    t.border
                },
                width: 1.0,
                radius: Radius::from(12),
            },
            ..button::Style::default()
        })
        .into()
}

fn expiry_label(expires: u64, now: u64) -> String {
    let days = expires.saturating_sub(now) / 86_400;
    match days {
        0 => "Expires today".into(),
        1 => "Expires tomorrow".into(),
        d if d > 365 * 5 => "Never expires".into(),
        d => format!("Expires in {d} days"),
    }
}

fn pill<'a>(label: String, fg: Color) -> Element<'a, Message> {
    container(text(label).size(10).color(fg).font(mono_bold()))
        .padding(Padding::from([3, 8]))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(fg, 0.10))),
            border: Border {
                color: with_alpha(fg, 0.25),
                width: 1.0,
                radius: Radius::from(8),
            },
            text_color: Some(fg),
            ..container::Style::default()
        })
        .into()
}

fn tab<'a>(t: KaoTheme, label: &'static str, active: bool, msg: Message) -> Element<'a, Message> {
    button(
        text(label)
            .size(12)
            .font(bold())
            .color(if active { t.text } else { t.sub }),
    )
    .padding(Padding::from([5, 12]))
    .on_press(msg)
    .style(move |_, _| button::Style {
        background: Some(Background::Color(if active {
            with_alpha(t.a3, 0.14)
        } else {
            t.card
        })),
        text_color: t.text,
        border: Border {
            color: if active { t.a3 } else { t.border },
            width: 1.0,
            radius: 10.0.into(),
        },
        ..Default::default()
    })
    .into()
}

fn card<'a>(t: KaoTheme, body: Element<'a, Message>) -> Element<'a, Message> {
    container(body)
        .padding(Padding::from([16, 18]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(16),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address};

    const OWNER: Address = address!("0x1111111111111111111111111111111111111111");
    const OTHER: Address = address!("0x2222222222222222222222222222222222222222");
    const TOKEN: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const FOUND: Candidate = Candidate::Erc20 {
        token: TOKEN,
        spender: OTHER,
    };

    fn app() -> ApprovalsApp {
        let mut a = ApprovalsApp::new(Address::ZERO);
        a.set_identity(OWNER, None);
        a
    }

    fn row(spender: Address) -> Approval {
        Approval {
            kind: Kind::Erc20,
            asset: TOKEN,
            symbol: "USDC".into(),
            known_asset: true,
            decimals: Some(6),
            spender,
            spender_label: None,
            amount: Some(U256::MAX),
            expires: None,
            spender_has_code: Some(true),
            verified: true,
        }
    }

    fn verified(rows: Vec<Approval>) -> Result<Verified, String> {
        Ok(Verified {
            checked: rows.len(),
            approvals: rows,
            skipped: 0,
        })
    }

    /// Drive a scan to completion from `next`, answering every head read with
    /// `head` and every window with `FOUND`. Returns the windows it read.
    fn run(a: &mut ApprovalsApp, mut next: Option<Outcome>, head: u64) -> Vec<(u64, u64)> {
        let mut windows = Vec::new();
        loop {
            match next {
                Some(Outcome::Head { seq, .. }) => next = a.on_head(seq, Ok(head)),
                Some(Outcome::Logs { seq, from, to, .. }) => {
                    windows.push((from, to));
                    next = a.on_logs(seq, from, to, Ok(vec![FOUND]));
                }
                Some(Outcome::Verify {
                    seq, candidates, ..
                }) => {
                    assert_eq!(candidates, vec![FOUND], "deduped across windows");
                    a.on_verified(seq, verified(vec![row(OTHER)]));
                    return windows;
                }
                None => return windows,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// The whole happy path: head, every window down to the floor, verify.
    #[test]
    fn a_scan_walks_every_window_then_verifies() {
        let mut a = app();
        let next = a.on_open();
        let windows = run(&mut a, next, 300_000);
        assert_eq!(windows.len(), 5, "216k blocks in 50k windows");
        assert_eq!(a.phase, Phase::Done);
        let s = a.scan().unwrap();
        assert_eq!(s.covered, Some((84_000, 300_000)));
        assert_eq!(s.rows.as_ref().unwrap().len(), 1);
        assert!(a.on_open().is_none(), "reopening shows the cache");
    }

    /// The point of the cache: leaving a chain and coming back shows what was
    /// found, with no request at all.
    #[test]
    fn switching_tabs_back_reuses_the_cache() {
        let mut a = app();
        let next = a.on_open();
        run(&mut a, next, 300_000);
        let base = a.update(Message::SelectChain(Chain::Base));
        assert!(matches!(base, Some(Outcome::Head { .. })), "Base is new");
        assert!(a.update(Message::SelectChain(Chain::Mainnet)).is_none());
        assert_eq!(a.phase, Phase::Done);
        assert_eq!(a.scan().unwrap().rows.as_ref().unwrap().len(), 1);
    }

    /// A longer lookback reads only the older blocks; a shorter one is
    /// already covered.
    #[test]
    fn a_longer_lookback_extends_downward_only() {
        let mut a = app();
        let next = a.on_open();
        run(&mut a, next, 300_000);
        let next = a.update(Message::SelectLookback(Lookback::AllTime));
        let windows = run(&mut a, next, 300_000);
        assert_eq!(windows.first(), Some(&(34_000, 83_999)));
        assert_eq!(windows.last().map(|w| w.0), Some(0));
        assert!(
            windows.iter().all(|(_, to)| *to < 84_000),
            "nothing already searched is read again: {windows:?}"
        );
        assert_eq!(a.scan().unwrap().covered, Some((0, 300_000)));
        assert!(a.update(Message::SelectLookback(Lookback::Month)).is_none());
    }

    /// A rescan reads just the blocks since the cached head — upward, so the
    /// coverage stays one range — then re-checks every allowance.
    #[test]
    fn a_rescan_reads_only_new_blocks() {
        let mut a = app();
        let next = a.on_open();
        run(&mut a, next, 300_000);
        let next = a.update(Message::Scan);
        let windows = run(&mut a, next, 310_000);
        assert_eq!(windows, vec![(300_001, 310_000)]);
        assert_eq!(a.scan().unwrap().covered, Some((84_000, 310_000)));
        assert!(!a.scan().unwrap().stale);

        // Nothing new at all still re-verifies: allowances move without logs.
        let next = a.update(Message::Scan);
        let Some(Outcome::Head { seq, .. }) = next else {
            panic!()
        };
        assert!(matches!(
            a.on_head(seq, Ok(310_000)),
            Some(Outcome::Verify { .. })
        ));
    }

    /// Leaving mid-scan keeps the windows already read, and coming back
    /// continues below them.
    #[test]
    fn an_interrupted_scan_resumes_where_it_stopped() {
        let mut a = app();
        let Some(Outcome::Head { seq, .. }) = a.on_open() else {
            panic!()
        };
        let Some(Outcome::Logs { from, to, .. }) = a.on_head(seq, Ok(300_000)) else {
            panic!()
        };
        a.on_logs(seq, from, to, Ok(vec![FOUND]));
        a.update(Message::SelectChain(Chain::Base));
        match a.update(Message::SelectChain(Chain::Mainnet)) {
            Some(Outcome::Logs { to, .. }) => assert_eq!(to, from - 1),
            other => panic!("{other:?}"),
        }
    }

    /// The pane is rebuilt with the dashboard on an account switch, and the
    /// old pane's scan steps still answer the new one. Counted per pane, both
    /// scans carried the same seq, so the old account's windows were merged
    /// into the new account's scan and recorded as searched for it.
    #[test]
    fn a_rebuilt_pane_ignores_the_old_panes_scan() {
        let mut old = app();
        let Some(Outcome::Head { seq: stale, .. }) = old.on_open() else {
            panic!()
        };

        let mut new = ApprovalsApp::new(Address::ZERO);
        new.set_identity(OTHER, None);
        let Some(Outcome::Head { seq, .. }) = new.on_open() else {
            panic!()
        };
        assert!(new.on_head(stale, Ok(300_000)).is_none(), "old head taken");
        let Some(Outcome::Logs { from, to, .. }) = new.on_head(seq, Ok(300_000)) else {
            panic!()
        };
        assert!(
            new.on_logs(stale, from, to, Ok(vec![FOUND])).is_none(),
            "old window taken",
        );
        let s = new.scan().unwrap();
        assert!(s.found.is_empty() && s.covered.is_none());
    }

    /// A window that fails doesn't sink the scan: what was found is still
    /// checked, and the user is told how far the search got.
    #[test]
    fn a_failed_window_still_verifies_what_was_found() {
        let mut a = app();
        let Some(Outcome::Head { seq, .. }) = a.on_open() else {
            panic!()
        };
        let Some(Outcome::Logs { from, to, .. }) = a.on_head(seq, Ok(1_000_000)) else {
            panic!()
        };
        let next = a.on_logs(seq, from, to, Err("rate limited".into()));
        assert!(matches!(next, Some(Outcome::Verify { .. })));
        let notice = a.scan().unwrap().notice.clone().unwrap();
        assert!(notice.contains("rate limited"), "{notice}");
        assert_eq!(
            a.scan().unwrap().covered,
            None,
            "the failed window isn't claimed"
        );
    }

    #[test]
    fn stop_jumps_to_verify() {
        let mut a = app();
        let Some(Outcome::Head { seq, .. }) = a.on_open() else {
            panic!()
        };
        a.on_head(seq, Ok(1_000_000));
        assert!(matches!(
            a.update(Message::Stop),
            Some(Outcome::Verify { .. })
        ));
        assert!(a.scan().unwrap().notice.is_some());
    }

    /// A step answered after the tab moved lands on nothing.
    #[test]
    fn a_superseded_step_is_ignored() {
        let mut a = app();
        let Some(Outcome::Head { seq: old, .. }) = a.on_open() else {
            panic!()
        };
        let new = a.update(Message::SelectChain(Chain::Base)).unwrap();
        assert!(matches!(new, Outcome::Head { seq, .. } if seq != old));
        assert!(a.on_head(old, Ok(10)).is_none());
        assert_eq!(a.phase, Phase::Head);
        assert!(
            !a.scans.contains_key(&(OWNER, Chain::Mainnet)),
            "the stale head wasn't recorded"
        );
    }

    /// Rows describe one account, and another can't revoke them. An identity
    /// change shows that identity's own cache, or nothing.
    #[test]
    fn identities_keep_separate_caches() {
        let mut a = app();
        let next = a.on_open();
        run(&mut a, next, 300_000);
        a.update(Message::SelectAll);
        a.set_identity(OTHER, Some(Chain::Optimism));
        assert!(a.scan().is_none());
        assert_eq!(a.phase, Phase::Idle);
        assert_eq!(a.chain, Chain::Optimism, "a Safe pins the chain");
        assert!(
            a.update(Message::SelectChain(Chain::Base)).is_none(),
            "and the picker can't move it"
        );
        a.set_identity(OWNER, None);
        a.chain = Chain::Mainnet;
        assert_eq!(a.scan().unwrap().selected.len(), 1, "selection kept too");
    }

    #[test]
    fn revoke_hands_over_only_the_selection() {
        let mut a = app();
        let s = a.scan_mut();
        s.rows = Some(vec![row(OTHER), row(OWNER)]);
        a.phase = Phase::Done;
        assert!(a.update(Message::Revoke).is_none(), "nothing picked");
        a.update(Message::Toggle(row(OWNER).key()));
        match a.update(Message::Revoke) {
            Some(Outcome::Revoke { chain, calls }) => {
                assert_eq!(chain, Chain::Mainnet);
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].to, TOKEN);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn progress_counts_the_searched_share() {
        let s = ChainScan {
            head: Some(199),
            covered: Some((150, 199)),
            ..ChainScan::default()
        };
        assert!((s.progress(100) - 0.5).abs() < 1e-6);
        assert_eq!(ChainScan::default().progress(0), 0.0);
    }

    #[test]
    fn expiry_labels() {
        assert_eq!(expiry_label(100, 200), "Expires today");
        assert_eq!(expiry_label(86_400 * 3, 0), "Expires in 3 days");
        assert_eq!(expiry_label(u64::from(u32::MAX) * 100, 0), "Never expires");
    }
}
