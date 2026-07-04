//! Networks settings sub-screen — per-chain execution RPC, per-chain
//! consensus RPC, and the checkpoint override. Retained for potential future
//! "advanced overrides" access; the primary network config is now handled by
//! `network_setup::NetworkSetupScreen`.
//!
#![allow(dead_code)]
//! Owned by the dashboard's Settings nav slot, not the modal stack.
//!
//! Save invalidates the shared `BalanceFetcher` so the next balance/portfolio
//! fetch rebuilds Helios against the new endpoints.
//!
//! Every chain gets an editable exec + consensus row. Mainnet is
//! mandatory; an L2 row left blank clears that chain's explicit
//! override, returning it to the settings-layer fallback (an exec URL
//! synthesized from the user's dRPC/Alchemy key, or the chain's default
//! consensus endpoint). Each row seeds from `settings::rpcs` /
//! `settings::consensus_rpcs`, so the form shows the URL the chain is
//! *actually* using — including a synthesized one — not just what was
//! explicitly saved.

use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::B256;
use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};

use crate::chain::{Chain, PerChain};
use crate::net::BalanceFetcher;
use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    black, bold, ghost_button, kao_scrollable_style, primary_button, section, text_input_style,
};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Message {
    Back,
    // RPC URLs are credential-bearing (a dRPC/Alchemy key rides inside the
    // key-synthesized endpoints this form seeds from), so the input is
    // redacted at the type level. Mirrors `network_setup`'s treatment.
    ExecChanged(Chain, crate::trace::SecretInput),
    ConsensusChanged(Chain, crate::trace::SecretInput),
    CheckpointChanged(String),
    Save,
    Saved,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Outcome {
    /// User backed out (or save completed) — coordinator should return to the
    /// settings root pane.
    Closed,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Draft {
    exec: PerChain<String>,
    consensus: PerChain<String>,
    /// Hex of the user's pasted checkpoint override, blank to use auto.
    checkpoint_override: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct NetworksPane {
    draft: Draft,
    network: Arc<dyn BalanceFetcher>,
    saving: bool,
}

impl NetworksPane {
    pub fn new(network: Arc<dyn BalanceFetcher>) -> Self {
        // Seed every chain from the resolved settings — `settings::rpcs`
        // already folds in the key-synthesized fallback, so the form
        // shows what each chain actually queries, not just the explicit
        // override. Chains with nothing resolvable fall back to their
        // public defaults so the row is still editable.
        let mut exec = PerChain::<String>::default();
        let mut consensus = PerChain::<String>::default();
        for chain in Chain::ALL {
            let exec_seed = settings::rpcs(chain)
                .into_iter()
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| chain.default_exec_url().to_string());
            let consensus_seed = settings::consensus_rpcs(chain)
                .into_iter()
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| chain.default_consensus_url().to_string());
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
        crate::trace_msg!("networks", &msg);
        let saving_before = self.saving;
        let (task, outcome) = self.update_inner(msg);
        if saving_before != self.saving {
            crate::trace::state("networks", "saving", saving_before, self.saving);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("networks", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Back => (Task::none(), Some(Outcome::Closed)),
            Message::ExecChanged(chain, s) => {
                // URL-tier credential: persists plaintext in settings.toml,
                // so a plain-String copy into the draft is acceptable.
                self.draft.exec.set(chain, s.expose().to_string());
                (Task::none(), None)
            }
            Message::ConsensusChanged(chain, s) => {
                self.draft.consensus.set(chain, s.expose().to_string());
                (Task::none(), None)
            }
            Message::CheckpointChanged(s) => {
                self.draft.checkpoint_override = s;
                (Task::none(), None)
            }
            Message::Save => {
                let checkpoint_override = parse_checkpoint(self.draft.checkpoint_override.trim());
                // A blank row clears the chain's explicit override so the
                // settings-layer fallback (key-synthesized exec URL /
                // default consensus endpoint) takes over again. Mainnet
                // can't be blank — `draft_valid` gates Save on it.
                for chain in Chain::ALL {
                    let exec = self.draft.exec.get(chain).trim().to_string();
                    settings::set_rpcs(chain, if exec.is_empty() { vec![] } else { vec![exec] });
                    let consensus = self.draft.consensus.get(chain).trim().to_string();
                    settings::set_consensus_rpcs(
                        chain,
                        if consensus.is_empty() {
                            vec![]
                        } else {
                            vec![consensus]
                        },
                    );
                }
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
            ghost_button(t, text("← Back").size(12).color(t.sub).font(bold()))
                .padding(Padding::from([4, 8]))
                .on_press(Message::Back),
            Space::new().width(Length::Fill),
            text("Networks").size(14).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            // Symmetry placeholder so the title centers visually.
            text("    ").size(12),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut exec_rows = column![].spacing(6).width(Length::Fill);
        for chain in Chain::ALL {
            let input = text_input("https://…", self.draft.exec.get(chain))
                .on_input(move |s| Message::ExecChanged(chain, s.into()))
                .padding(Padding::from([6, 10]))
                .style(move |_theme, status| text_input_style(t, status));
            exec_rows = exec_rows.push(labeled_row(t, chain.label(), input.into()));
        }
        let exec_section = section(
            t,
            "Execution RPC",
            "(◕‿◕✿)",
            "Helios verifies every response against the consensus layer. Leave an L2 blank to fall back to your provider key's endpoint.",
            exec_rows.into(),
        );

        let mut consensus_rows = column![].spacing(6).width(Length::Fill);
        for chain in Chain::ALL {
            let input = text_input("https://…", self.draft.consensus.get(chain))
                .on_input(move |s| Message::ConsensusChanged(chain, s.into()))
                .padding(Padding::from([6, 10]))
                .style(move |_theme, status| text_input_style(t, status));
            consensus_rows = consensus_rows.push(labeled_row(t, chain.label(), input.into()));
        }
        let consensus_section = section(
            t,
            "Consensus RPC",
            "( ´ ▽ ` )ﾉ",
            "Light-client endpoint Helios bootstraps from. Leave an L2 blank to use the chain's default.",
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
    let label_box =
        container(text(label).size(12).color(t.text).font(bold())).width(Length::Fixed(80.0));
    row![label_box, input]
        .spacing(8)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
}

fn draft_valid(draft: &Draft) -> bool {
    // Mainnet anchors Helios and can't be blank. L2 rows may be blank —
    // that clears the explicit override and the chain falls back to a
    // key-synthesized exec URL / default consensus endpoint — but a
    // non-blank row must be a real HTTPS URL or Save would persist junk.
    for chain in Chain::ALL {
        let exec = draft.exec.get(chain).trim();
        let consensus = draft.consensus.get(chain).trim();
        let mandatory = matches!(chain, Chain::Mainnet);
        if (mandatory || !exec.is_empty()) && !is_https_url(exec) {
            return false;
        }
        if (mandatory || !consensus.is_empty()) && !is_https_url(consensus) {
            return false;
        }
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
