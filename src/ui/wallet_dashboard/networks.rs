//! Networks settings sub-screen — per-chain execution RPC, per-chain
//! consensus RPC, and the checkpoint override. Owned by the dashboard's
//! Settings nav slot, not the modal stack.
//!
//! Save invalidates the shared `BalanceFetcher` so the next balance/portfolio
//! fetch rebuilds Helios against the new endpoints.
//!
//! Mainnet is the only chain whose RPCs are persisted today: settings +
//! `net.rs` are still mainnet-only. The form deliberately renders only the
//! Mainnet pair so the user doesn't believe an L2 edit will save — L2
//! rows return once per-chain plumbing lands. The `Draft` still carries
//! a `PerChain<String>` so reintroducing those rows is a render-only
//! change.

use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::B256;
use iced::widget::{Space, column, container, mouse_area, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};

use crate::net::BalanceFetcher;
use crate::settings;
use crate::chain::{Chain, PerChain};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    black, bold, kao_scrollable_style, primary_button, section, text_input_style,
};

#[derive(Debug, Clone)]
pub enum Message {
    Back,
    ExecChanged(Chain, String),
    ConsensusChanged(Chain, String),
    CheckpointChanged(String),
    Save,
    Saved,
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// User backed out (or save completed) — coordinator should return to the
    /// settings root pane.
    Closed,
}

#[derive(Debug, Clone, Default)]
struct Draft {
    exec: PerChain<String>,
    consensus: PerChain<String>,
    /// Hex of the user's pasted checkpoint override, blank to use auto.
    checkpoint_override: String,
}

#[derive(Debug)]
pub struct NetworksPane {
    draft: Draft,
    network: Arc<dyn BalanceFetcher>,
    saving: bool,
}

impl NetworksPane {
    pub fn new(network: Arc<dyn BalanceFetcher>) -> Self {
        // Settings is mainnet-only today, so seed Mainnet's slots from the
        // persisted values (falling back to chain defaults if blank) and
        // pre-fill the L2 slots with their public defaults so the form
        // looks complete the moment the pane opens.
        let saved_exec = settings::rpcs(Chain::Mainnet)
            .into_iter()
            .next()
            .unwrap_or_default();
        let saved_consensus = settings::consensus_rpcs(Chain::Mainnet)
            .into_iter()
            .next()
            .unwrap_or_default();
        let mut exec = PerChain::<String>::default();
        let mut consensus = PerChain::<String>::default();
        for chain in Chain::ALL {
            let exec_seed = match chain {
                Chain::Mainnet if !saved_exec.is_empty() => saved_exec.clone(),
                _ => chain.default_exec_url().to_string(),
            };
            let consensus_seed = match chain {
                Chain::Mainnet if !saved_consensus.is_empty() => saved_consensus.clone(),
                _ => chain.default_consensus_url().to_string(),
            };
            exec.set(chain, exec_seed);
            consensus.set(chain, consensus_seed);
        }
        let draft = Draft {
            exec,
            consensus,
            checkpoint_override: settings::checkpoint_override()
                .map(|b| format!("0x{}", alloy::hex::encode(b.as_slice())))
                .unwrap_or_default(),
        };
        Self {
            draft,
            network,
            saving: false,
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Back => (Task::none(), Some(Outcome::Closed)),
            Message::ExecChanged(chain, s) => {
                self.draft.exec.set(chain, s);
                (Task::none(), None)
            }
            Message::ConsensusChanged(chain, s) => {
                self.draft.consensus.set(chain, s);
                (Task::none(), None)
            }
            Message::CheckpointChanged(s) => {
                self.draft.checkpoint_override = s;
                (Task::none(), None)
            }
            Message::Save => {
                let exec = self.draft.exec.get(Chain::Mainnet).trim().to_string();
                let consensus = self.draft.consensus.get(Chain::Mainnet).trim().to_string();
                let checkpoint_override = parse_checkpoint(self.draft.checkpoint_override.trim());
                settings::set_rpcs(Chain::Mainnet, vec![exec]);
                settings::set_consensus_rpcs(Chain::Mainnet, vec![consensus]);
                settings::set_checkpoint_override(checkpoint_override);
                self.saving = true;
                let network = self.network.clone();
                let task = Task::perform(
                    async move {
                        network.invalidate().await;
                    },
                    |_| Message::Saved,
                );
                (task, None)
            }
            Message::Saved => {
                self.saving = false;
                (Task::none(), Some(Outcome::Closed))
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::none()
    }

    pub fn view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let header = row![
            mouse_area(
                container(text("← Back").size(12).color(t.sub).font(bold()))
                    .padding(Padding::from([4, 0])),
            )
            .on_press(Message::Back),
            Space::new().width(Length::Fill),
            text("Networks").size(14).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            // Symmetry placeholder so the title centers visually.
            text("    ").size(12),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        // Mainnet is the only chain we persist today. Render exactly one
        // row per section so the form can't promise an L2 edit will save.
        let exec_input = text_input("https://…", self.draft.exec.get(Chain::Mainnet))
            .on_input(|s| Message::ExecChanged(Chain::Mainnet, s))
            .padding(Padding::from([6, 10]))
            .style(move |_theme, status| text_input_style(t, status));
        let exec_rows = column![labeled_row(t, Chain::Mainnet.label(), exec_input.into())]
            .spacing(6)
            .width(Length::Fill);
        let exec_section = section(
            t,
            "Execution RPC",
            "(◕‿◕✿)",
            "Helios verifies every response against the consensus layer. Per-chain endpoints land once L2 support ships.",
            exec_rows.into(),
        );

        let consensus_input = text_input("https://…", self.draft.consensus.get(Chain::Mainnet))
            .on_input(|s| Message::ConsensusChanged(Chain::Mainnet, s))
            .padding(Padding::from([6, 10]))
            .style(move |_theme, status| text_input_style(t, status));
        let consensus_rows = column![labeled_row(
            t,
            Chain::Mainnet.label(),
            consensus_input.into(),
        )]
        .spacing(6)
        .width(Length::Fill);
        let consensus_section = section(
            t,
            "Consensus RPC",
            "( ´ ▽ ` )ﾉ",
            "Beacon-chain LC API endpoint Helios bootstraps from.",
            consensus_rows.into(),
        );

        let placeholder = format!(
            "auto: 0x{}",
            alloy::hex::encode(settings::auto_checkpoint().as_slice())
        );
        let checkpoint_input = text_input(&placeholder, &self.draft.checkpoint_override)
            .on_input(Message::CheckpointChanged)
            .padding(Padding::from([6, 10]))
            .style(move |_theme, status| text_input_style(t, status));
        let checkpoint_section = section(
            t,
            "Checkpoint",
            "(⌐■_■)",
            "Leave blank to use the bundled checkpoint (or a freshly fetched one if it's stale). Paste a 32-byte hex hash to override.",
            checkpoint_input.into(),
        );

        let valid = draft_valid(&self.draft) && !self.saving;
        let save_btn = primary_button(t, "Save", valid);
        let save_btn = if valid {
            save_btn.on_press(Message::Save)
        } else {
            save_btn
        };
        let save_row = container(save_btn).padding(Padding::from([4, 0]));

        let body = column![
            header,
            Space::new().height(16),
            exec_section,
            Space::new().height(14),
            consensus_section,
            Space::new().height(14),
            checkpoint_section,
            Space::new().height(20),
            save_row,
        ]
        .spacing(0)
        .width(Length::Fill);

        iced::widget::scrollable(
            container(body)
                .padding(Padding::from([22, 24]))
                .width(Length::Fill),
        )
        .height(Length::Fill)
        .width(Length::Fill)
        .style(move |_, s| kao_scrollable_style(t, s))
        .into()
    }
}

fn parse_checkpoint(s: &str) -> Option<B256> {
    if s.is_empty() {
        return None;
    }
    B256::from_str(s).ok()
}

/// Fixed-width chain label (e.g. "Mainnet") next to a URL input. Used to
/// stack the per-chain rows so the inputs line up under one another.
fn labeled_row<'a>(
    t: KaoTheme,
    label: &'a str,
    input: Element<'a, Message>,
) -> Element<'a, Message> {
    let label_box = container(text(label).size(12).color(t.text).font(bold()))
        .width(Length::Fixed(80.0));
    row![label_box, input]
        .spacing(8)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
}

fn draft_valid(draft: &Draft) -> bool {
    // Mainnet is the only chain whose values get persisted today, so it's
    // the only one Save needs to enforce. L2 fields are session-only and
    // we don't block save on them — empty is fine, garbled is fine.
    if !is_https_url(draft.exec.get(Chain::Mainnet)) {
        return false;
    }
    if !is_https_url(draft.consensus.get(Chain::Mainnet)) {
        return false;
    }
    let cp = draft.checkpoint_override.trim();
    if !cp.is_empty() && B256::from_str(cp).is_err() {
        return false;
    }
    true
}

/// True iff `s` parses as an HTTPS URL.
///
/// HTTPS is required: a plain-HTTP consensus endpoint lets a network
/// attacker tamper with the light-client bootstrap before any consensus
/// signatures get verified, and a plain-HTTP exec endpoint exposes
/// `eth_getProof` responses to the same MITM.
fn is_https_url(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    matches!(url::Url::parse(s), Ok(url) if url.scheme() == "https")
}
