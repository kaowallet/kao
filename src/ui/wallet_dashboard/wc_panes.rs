//! WalletConnect modal + Sessions pane rendering.
//!
//! No state of its own — all WC state lives in [`crate::walletconnect::state::WcState`]
//! behind an `Arc<RwLock<…>>` shared with App. These functions are pure
//! projections from that state into iced widgets.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::{Alignment, Background, Border, Element, Length, Padding};

use crate::chain::Chain;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    bold, card_style, hover_tint, kao_scrollable_style, modal_wrapper, mono, mono_bold,
    primary_button, secondary_button, small_secondary_button,
};
use crate::walletconnect::methods::{SUPPORTED_METHODS, method_label};
use crate::walletconnect::protocol::{NamespaceProposal, NamespaceSettled, PeerMetadata};
use crate::walletconnect::state::{UiProposal, UiRequest, UiSession, WcModal, WcState};

use super::Message;

/// Render whichever WC modal is currently active. Called by the dashboard's
/// view when `Modal::Wc` is selected. Renders an empty box if `wc_state`
/// has no active modal (close-animation race).
///
/// Returns an `Element<'static, _>` — every owned string is cloned out of
/// `wc` so the returned widget tree is independent of the read guard's
/// lifetime. Callers can construct the modal from a short-lived borrow
/// of `wc_state` and still place the Element in a longer-lived parent.
pub fn view(
    t: KaoTheme,
    wc: &WcState,
    progress: f32,
    proposal_details_expanded: bool,
) -> Element<'static, Message> {
    let body: Element<'static, Message> = match &wc.current_modal {
        Some(WcModal::Proposal(p)) => {
            proposal_body(t, p, wc.queue_len(), proposal_details_expanded)
        }
        Some(WcModal::Request(r)) => request_body(t, r, wc.queue_len()),
        None => empty_body(t),
    };

    // Reject buttons emit the same message even on backdrop dismiss so a
    // ghost-clicked outside area doesn't silently leave the dApp hanging
    // for a response. The current request_id is taken from the active
    // modal; if there's nothing active, the backdrop click is a no-op.
    let dismiss: Message = match &wc.current_modal {
        Some(WcModal::Proposal(p)) => Message::WcRejectProposal(p.proposal_id),
        Some(WcModal::Request(r)) => Message::WcRejectRequest(r.request_id),
        None => Message::WcDismissError, // Harmless no-op.
    };

    modal_wrapper(
        t,
        520.0,
        progress,
        dismiss,
        Message::WcDismissError, // box_click — no-op.
        body,
    )
}

fn empty_body(t: KaoTheme) -> Element<'static, Message> {
    container(text("…").size(14).color(t.sub))
        .padding(Padding::from([32, 32]))
        .into()
}

fn proposal_body(
    t: KaoTheme,
    p: &UiProposal,
    total: usize,
    details_expanded: bool,
) -> Element<'static, Message> {
    let header = modal_header(t, "Connection request", "ヽ(・∀・)ﾉ", total);

    let peer = peer_card(t, &p.peer);

    let grant = compute_grant_preview(p);
    let grant_card = grant_preview_card(t, &grant);

    // Collapsible raw-namespace block. The toggle row is always shown so
    // power users have an obvious entry point; the body only mounts when
    // `details_expanded` is true so the modal stays short in the common
    // case.
    let details_label = if details_expanded {
        "Hide details ▴"
    } else {
        "Show details ▾"
    };
    let details_toggle: Element<'static, Message> = small_secondary_button(t, details_label)
        .on_press(Message::WcToggleProposalDetails)
        .into();

    let details_block: Element<'static, Message> = if details_expanded {
        column![
            Space::new().height(8),
            section(t, "REQUIRED (raw)", namespace_list(t, &p.required)),
            Space::new().height(8),
            section(t, "OPTIONAL (raw)", namespace_list(t, &p.optional)),
        ]
        .width(Length::Fill)
        .into()
    } else {
        Space::new().width(0).height(0).into()
    };

    let proposal_id = p.proposal_id;
    let actions = row![
        secondary_button(t, "Reject")
            .on_press(Message::WcRejectProposal(proposal_id))
            .width(Length::FillPortion(1)),
        Space::new().width(12),
        primary_button(t, "Approve", true)
            .on_press(Message::WcApproveProposal(proposal_id))
            .width(Length::FillPortion(1)),
    ]
    .width(Length::Fill);

    column![
        header,
        Space::new().height(14),
        peer,
        Space::new().height(14),
        grant_card,
        Space::new().height(10),
        details_toggle,
        details_block,
        Space::new().height(18),
        actions,
    ]
    .width(Length::Fill)
    .into()
}

/// Distilled view of a `wc_sessionPropose` that mirrors what
/// `build_approved_namespaces` will actually grant. `granted_chains` and
/// `granted_methods` are the human-readable user-facing items; the `dropped_*`
/// counts feed the dim footer that tells the user *something* was filtered.
///
/// Computed against the union of required + optional namespaces under
/// `eip155` — non-eip155 keys are dropped outright (Kao only speaks EVM).
struct GrantPreview {
    granted_chains: Vec<&'static str>,
    granted_methods: Vec<&'static str>,
    dropped_chains: usize,
    dropped_methods: usize,
    /// True when the dApp's required namespaces include items we won't
    /// grant. We still let the user approve (Kao always grants the
    /// intersection); the badge just sets expectations so the user
    /// isn't surprised when the dApp later complains about a missing
    /// chain it asked for as `required`.
    required_dropped: bool,
}

fn compute_grant_preview(p: &UiProposal) -> GrantPreview {
    use std::collections::BTreeSet;

    // De-dupe across required ∪ optional. Same chain ID listed in both
    // halves shouldn't double-count toward "granted" or "dropped".
    let mut requested_chains: BTreeSet<String> = BTreeSet::new();
    let mut requested_methods: BTreeSet<String> = BTreeSet::new();
    let mut required_chains: BTreeSet<String> = BTreeSet::new();
    let mut required_methods: BTreeSet<String> = BTreeSet::new();

    for (key, ns) in &p.required {
        if key != "eip155" {
            continue;
        }
        for c in &ns.chains {
            requested_chains.insert(c.clone());
            required_chains.insert(c.clone());
        }
        for m in &ns.methods {
            requested_methods.insert(m.clone());
            required_methods.insert(m.clone());
        }
    }
    for (key, ns) in &p.optional {
        if key != "eip155" {
            continue;
        }
        for c in &ns.chains {
            requested_chains.insert(c.clone());
        }
        for m in &ns.methods {
            requested_methods.insert(m.clone());
        }
    }

    // Granted chains: requested ∩ Chain::ALL. Preserve `Chain::ALL`
    // order (Mainnet, Base, Optimism) for a stable display.
    let mut granted_chains: Vec<&'static str> = Vec::new();
    let mut granted_chain_caip: BTreeSet<String> = BTreeSet::new();
    for chain in Chain::ALL {
        let caip = format!("eip155:{}", chain.chain_id());
        if requested_chains.contains(&caip) {
            granted_chains.push(chain.label());
            granted_chain_caip.insert(caip);
        }
    }

    // Granted methods: requested ∩ SUPPORTED_METHODS. Two passes because
    // label dedup and id membership are different questions:
    //   - `granted_method_ids` records every supported id the dApp asked
    //     for. A second id mapped to an already-seen label (e.g. v4 after
    //     v1) is still granted on the wire — the user verb just doesn't
    //     repeat.
    //   - `granted_methods` is the de-duped label list shown in the card.
    let mut granted_method_ids: BTreeSet<&'static str> = BTreeSet::new();
    let mut seen_labels: BTreeSet<&'static str> = BTreeSet::new();
    let mut granted_methods: Vec<&'static str> = Vec::new();
    for m in SUPPORTED_METHODS {
        if !requested_methods.iter().any(|rm| rm == m) {
            continue;
        }
        granted_method_ids.insert(m);
        if let Some(label) = method_label(m)
            && seen_labels.insert(label)
        {
            granted_methods.push(label);
        }
    }

    let dropped_chains = requested_chains
        .iter()
        .filter(|c| !granted_chain_caip.contains(*c))
        .count();
    let dropped_methods = requested_methods
        .iter()
        .filter(|m| !granted_method_ids.iter().any(|gm| gm == m))
        .count();

    let required_dropped = required_chains
        .iter()
        .any(|c| !granted_chain_caip.contains(c))
        || required_methods
            .iter()
            .any(|m| !granted_method_ids.iter().any(|gm| gm == m));

    GrantPreview {
        granted_chains,
        granted_methods,
        dropped_chains,
        dropped_methods,
        required_dropped,
    }
}

fn grant_preview_card(t: KaoTheme, g: &GrantPreview) -> Element<'static, Message> {
    let chains_line = if g.granted_chains.is_empty() {
        "(none)".to_string()
    } else {
        g.granted_chains.join(", ")
    };
    let methods_line = if g.granted_methods.is_empty() {
        "(none)".to_string()
    } else {
        g.granted_methods.join(", ")
    };

    let chains_row = column![
        text("Networks").size(11).color(t.sub).font(bold()),
        text(chains_line).size(13).color(t.text),
    ]
    .spacing(2);
    let methods_row = column![
        text("Actions").size(11).color(t.sub).font(bold()),
        text(methods_line).size(13).color(t.text),
    ]
    .spacing(2);

    let mut body = column![chains_row, Space::new().height(10), methods_row]
        .width(Length::Fill)
        .spacing(0);

    // Footer: dim grey line summarising what gets dropped. Skip entirely
    // when nothing was dropped — keeps the modal clean for well-scoped
    // dApps.
    if g.dropped_chains > 0 || g.dropped_methods > 0 {
        let mut parts: Vec<String> = Vec::new();
        if g.dropped_chains > 0 {
            parts.push(format!(
                "{} other {}",
                g.dropped_chains,
                if g.dropped_chains == 1 {
                    "network"
                } else {
                    "networks"
                }
            ));
        }
        if g.dropped_methods > 0 {
            parts.push(format!(
                "{} other {}",
                g.dropped_methods,
                if g.dropped_methods == 1 {
                    "action"
                } else {
                    "actions"
                }
            ));
        }
        let footer = format!(
            "{} the dApp asked for won't be granted.",
            parts.join(" and ")
        );
        body = body
            .push(Space::new().height(10))
            .push(text(footer).size(11).color(t.sub));
    }

    // Required-but-dropped warning: separate banner so it's not buried
    // in the dim footer. A `required` namespace the dApp can't get back
    // means the dApp may refuse to operate post-approval; the user should
    // know that's possible before clicking Approve.
    if g.required_dropped {
        body = body.push(Space::new().height(10)).push(banner(
            t,
            "The dApp marked some networks or actions as required — those won't be granted, so the dApp may refuse to continue.",
            t.down,
        ));
    }

    container(body)
        .padding(Padding::from([13, 15]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

fn request_body(t: KaoTheme, r: &UiRequest, total: usize) -> Element<'static, Message> {
    let title: &'static str = match r.method.as_str() {
        "personal_sign" => "Sign message",
        "eth_signTypedData" | "eth_signTypedData_v4" => "Sign typed data",
        "eth_sendTransaction" => "Send transaction",
        "eth_signTransaction" => "Sign transaction",
        _ => "dApp request",
    };
    let header = modal_header(t, title, "(・∀・)", total);

    let peer = peer_card(t, &r.peer);

    let method_chip = container(
        text(format!("method · {}", r.method))
            .size(11)
            .color(t.sub)
            .font(mono()),
    )
    .padding(Padding::from([5, 9]))
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.a1, 0.12))),
        border: Border {
            color: with_alpha(t.a1, 0.25),
            width: 1.0,
            radius: Radius::from(8),
        },
        ..container::Style::default()
    });

    let chain_chip = container(
        text(format!("chain · {}", r.chain_id))
            .size(11)
            .color(t.sub)
            .font(mono()),
    )
    .padding(Padding::from([5, 9]))
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.a2, 0.12))),
        border: Border {
            color: with_alpha(t.a2, 0.25),
            width: 1.0,
            radius: Radius::from(8),
        },
        ..container::Style::default()
    });

    let meta = row![method_chip, Space::new().width(8), chain_chip].width(Length::Fill);

    let payload = section(t, "PAYLOAD", payload_body(t, &r.method, &r.params));

    // For unsupported flows the engine still emits RequestReceived (we
    // gate `eth_sendTransaction` at the dispatch site, not here). Surface
    // that prominently so the user doesn't think Approve is going to
    // produce a tx hash — it will land as a JSON-RPC error to the dApp.
    let warning: Element<'static, Message> = match r.method.as_str() {
        "eth_sendTransaction" | "eth_signTransaction" => banner(
            t,
            "Transactions can be reviewed here in a later release. Approve will reject this call back to the dApp with a not-implemented error.",
            t.down,
        ),
        _ => Space::new().width(0).height(0).into(),
    };

    let request_id = r.request_id;
    let actions = row![
        secondary_button(t, "Reject")
            .on_press(Message::WcRejectRequest(request_id))
            .width(Length::FillPortion(1)),
        Space::new().width(12),
        primary_button(t, "Approve", true)
            .on_press(Message::WcApproveRequest(request_id))
            .width(Length::FillPortion(1)),
    ]
    .width(Length::Fill);

    column![
        header,
        Space::new().height(12),
        peer,
        Space::new().height(12),
        meta,
        Space::new().height(12),
        warning,
        Space::new().height(8),
        payload,
        Space::new().height(18),
        actions,
    ]
    .width(Length::Fill)
    .into()
}

fn modal_header(
    t: KaoTheme,
    title: &'static str,
    kao: &'static str,
    total: usize,
) -> Element<'static, Message> {
    let badge = if total > 1 {
        Some(
            container(
                text(format!("1 of {total}"))
                    .size(10)
                    .color(t.sub)
                    .font(bold()),
            )
            .padding(Padding::from([3, 8]))
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.sub, 0.12))),
                border: Border {
                    color: with_alpha(t.sub, 0.3),
                    width: 1.0,
                    radius: Radius::from(10),
                },
                ..container::Style::default()
            }),
        )
    } else {
        None
    };

    let title_text = text(title).size(20).color(t.text).font(bold());
    let kao_text = text(kao).size(20).color(t.sub);

    let mut header_row = row![title_text].align_y(Alignment::Center);
    if let Some(b) = badge {
        header_row = header_row.push(Space::new().width(10)).push(b);
    }
    header_row = header_row
        .push(Space::new().width(Length::Fill))
        .push(kao_text);

    header_row.width(Length::Fill).into()
}

fn peer_card(t: KaoTheme, peer: &PeerMetadata) -> Element<'static, Message> {
    let name = if peer.name.is_empty() {
        "Unknown dApp".to_string()
    } else {
        peer.name.clone()
    };
    let url = if peer.url.is_empty() {
        "no origin".to_string()
    } else {
        peer.url.clone()
    };

    let info = column![
        text(name).size(15).color(t.text).font(bold()),
        text(url).size(11).color(t.sub).font(mono()),
    ]
    .spacing(2);

    container(info)
        .padding(Padding::from([13, 15]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

fn namespace_list(
    t: KaoTheme,
    namespaces: &BTreeMap<String, NamespaceProposal>,
) -> Element<'static, Message> {
    if namespaces.is_empty() {
        return text("(none)").size(11).color(t.sub).font(mono()).into();
    }
    let mut col = column![].spacing(6);
    for (key, ns) in namespaces {
        let chains = if ns.chains.is_empty() {
            "(no chains)".to_string()
        } else {
            ns.chains.join(", ")
        };
        let methods = if ns.methods.is_empty() {
            "(no methods)".to_string()
        } else {
            ns.methods.join(", ")
        };
        col = col.push(
            column![
                text(key.clone()).size(12).color(t.text).font(bold()),
                text(format!("chains: {chains}"))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
                text(format!("methods: {methods}"))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            ]
            .spacing(1),
        );
    }
    col.into()
}

fn settled_namespace_list(
    t: KaoTheme,
    namespaces: &BTreeMap<String, NamespaceSettled>,
) -> Element<'static, Message> {
    if namespaces.is_empty() {
        return text("(no scopes)")
            .size(11)
            .color(t.sub)
            .font(mono())
            .into();
    }
    let mut col = column![].spacing(4);
    for (key, ns) in namespaces {
        let chains = ns.chains.join(", ");
        let methods = ns.methods.join(", ");
        col = col.push(
            column![
                text(key.clone()).size(12).color(t.text).font(bold()),
                text(format!("chains: {chains}"))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
                text(format!("methods: {methods}"))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            ]
            .spacing(1),
        );
    }
    col.into()
}

fn payload_body(
    t: KaoTheme,
    method: &str,
    params: &serde_json::Value,
) -> Element<'static, Message> {
    // For `personal_sign` show the decoded UTF-8 / hex message inline so the
    // user reads the text they're signing rather than `[ "0x68656c6c6f" ]`.
    if method == "personal_sign"
        && let Some(arr) = params.as_array()
        && let Some(decoded) = decode_personal_sign(arr)
    {
        return text(decoded).size(13).color(t.text).font(mono()).into();
    }
    // Otherwise dump the JSON. Pretty-printed so deeply nested typed-data
    // is readable rather than a single line.
    let pretty = serde_json::to_string_pretty(params).unwrap_or_else(|_| params.to_string());
    scrollable(text(pretty).size(11).color(t.sub).font(mono()))
        .height(Length::Fixed(140.0))
        .width(Length::Fill)
        .style(move |_, s| kao_scrollable_style(t, s))
        .into()
}

/// Best-effort decode of personal_sign params back to a human-readable
/// string. Accepts both `[message, address]` and `[address, message]`
/// orders. Returns the decoded message on success.
fn decode_personal_sign(arr: &[serde_json::Value]) -> Option<String> {
    let first_str = arr.first()?.as_str()?;
    let second_str = arr.get(1)?.as_str()?;
    // The address element is detectable as a 42-char `0x…` hex. The other
    // is the message. Try both orderings.
    let message_raw = if is_address_str(second_str) {
        first_str
    } else if is_address_str(first_str) {
        second_str
    } else {
        first_str
    };
    if let Some(hex_str) = message_raw.strip_prefix("0x")
        && let Ok(bytes) = hex::decode(hex_str)
    {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
        return Some(format!("0x{hex_str} ({} bytes)", bytes.len()));
    }
    Some(message_raw.to_string())
}

fn is_address_str(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn section(
    t: KaoTheme,
    label: &'static str,
    content: Element<'static, Message>,
) -> Element<'static, Message> {
    column![
        text(label).size(11).color(t.sub).font(bold()),
        Space::new().height(6),
        content,
    ]
    .width(Length::Fill)
    .into()
}

fn banner(_t: KaoTheme, msg: &'static str, tint: iced::Color) -> Element<'static, Message> {
    container(text(msg).size(11).color(tint).font(bold()))
        .padding(Padding::from([9, 12]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(tint, 0.12))),
            border: Border {
                color: with_alpha(tint, 0.4),
                width: 1.0,
                radius: Radius::from(10),
            },
            ..container::Style::default()
        })
        .into()
}

// ── Sessions settings pane ───────────────────────────────────────────────

/// Read-only list of active WC sessions. Settings → Sessions enters this
/// view; rows have a per-session Disconnect button that dispatches
/// [`Message::WcDisconnectSession`] which the App routes to the engine.
pub fn sessions_view(t: KaoTheme, wc: &WcState) -> Element<'static, Message> {
    let title = text("Connected dApps").size(15).color(t.text).font(bold());
    let body: Element<'static, Message> = if wc.sessions.is_empty() {
        container(
            text("No connected dApps yet. Paste a wc: URI on the Home pane to connect.")
                .size(12)
                .color(t.sub),
        )
        .padding(Padding::from([20, 0]))
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into()
    } else {
        let mut list = column![].spacing(8);
        let now = unix_now();
        for s in &wc.sessions {
            list = list.push(session_row(t, s, now));
        }
        list.into()
    };

    let content = column![title, Space::new().height(10), body].width(Length::Fill);

    scrollable(
        container(content)
            .padding(Padding::from([22, 24]))
            .width(Length::Fill),
    )
    .height(Length::Fill)
    .width(Length::Fill)
    .style(move |_, s| kao_scrollable_style(t, s))
    .into()
}

fn session_row(t: KaoTheme, s: &UiSession, now: u64) -> Element<'static, Message> {
    let name = if s.peer.name.is_empty() {
        "Unknown dApp".to_string()
    } else {
        s.peer.name.clone()
    };
    let url = if s.peer.url.is_empty() {
        "no origin".to_string()
    } else {
        s.peer.url.clone()
    };
    let expiry = format_expiry(now, s.expiry);

    let info = column![
        text(name).size(14).color(t.text).font(bold()),
        text(url).size(11).color(t.sub).font(mono()),
        Space::new().height(2),
        settled_namespace_list(t, &s.namespaces),
        Space::new().height(2),
        text(format!("expires {expiry}"))
            .size(10)
            .color(t.sub)
            .font(mono()),
    ]
    .spacing(0)
    .width(Length::Fill);

    let topic = s.topic;
    let disconnect = button(text("Disconnect").size(11).color(t.down).font(bold()))
        .padding(Padding::from([6, 12]))
        .on_press(Message::WcDisconnectSession(topic))
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    hover_tint(with_alpha(t.down, 0.10), t.down)
                }
                _ => with_alpha(t.down, 0.10),
            })),
            text_color: t.down,
            border: Border {
                color: with_alpha(t.down, 0.4),
                width: 1.0,
                radius: Radius::from(10),
            },
            ..button::Style::default()
        });

    let inner = row![info, Space::new().width(12), disconnect]
        .align_y(Alignment::Center)
        .width(Length::Fill);

    container(inner)
        .padding(Padding::from([13, 15]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render `"in 6d 14h"` / `"in 35m"` / `"expired"` from a future Unix
/// seconds value. Resolution drops to the largest non-zero unit so the
/// label stays one line.
fn format_expiry(now: u64, expiry: u64) -> String {
    if expiry <= now {
        return "expired".to_string();
    }
    let secs = expiry - now;
    if secs >= 24 * 3600 {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        if hours == 0 {
            return format!("in {days}d");
        }
        return format!("in {days}d {hours}h");
    }
    if secs >= 3600 {
        return format!("in {}h", secs / 3600);
    }
    if secs >= 60 {
        return format!("in {}m", secs / 60);
    }
    format!("in {secs}s")
}

// ── Home-pane paste card ─────────────────────────────────────────────────

/// Inline "Connect dApp" card rendered above the balance hero on Home.
/// One-line text input + Connect button. Status text below the input
/// reflects `wc.status` and `wc.last_error` so the user has a visible
/// signal between paste and the first proposal modal landing.
pub fn paste_card<'a>(t: KaoTheme, wc: &WcState, paste_input: &'a str) -> Element<'a, Message> {
    use crate::ui::kao_widgets::text_input_style;
    use crate::walletconnect::state::WcStatus;

    let input = iced::widget::text_input("Paste wc: URI to connect a dApp", paste_input)
        .on_input(Message::WcPasteInput)
        .on_submit(Message::WcSubmitUri)
        .padding(Padding::from([10, 12]))
        .style(move |_theme, status| text_input_style(t, status))
        .width(Length::Fill);

    let connect = primary_button(t, "Connect", true).on_press(Message::WcSubmitUri);

    let row_widget = row![input, Space::new().width(10), connect].align_y(Alignment::Center);

    let (status_label, status_color) = match (&wc.status, &wc.last_error) {
        (_, Some(e)) => (format!("⚠ {e}"), t.down),
        (WcStatus::Idle, None) => ("idle".to_string(), t.sub),
        (WcStatus::Connecting, None) => ("connecting…".to_string(), t.a1),
        (WcStatus::Connected, None) => {
            let n = wc.sessions.len();
            if n == 0 {
                ("relay connected · no sessions yet".to_string(), t.sub)
            } else {
                (format!("relay connected · {n} session(s)"), t.sub)
            }
        }
        (WcStatus::Failed(e), None) => (format!("failed: {e}"), t.down),
    };

    let status_row = row![
        text(format!("WalletConnect · {status_label}"))
            .size(11)
            .color(status_color)
            .font(mono_bold()),
        Space::new().width(Length::Fill),
        dismiss_chip(t, wc.last_error.is_some()),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let body = column![row_widget, Space::new().height(6), status_row].width(Length::Fill);

    container(body)
        .padding(Padding::from([14, 16]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a2, 0.06))),
            border: Border {
                color: with_alpha(t.a2, 0.22),
                width: 1.0,
                radius: Radius::from(16),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

fn dismiss_chip(t: KaoTheme, visible: bool) -> Element<'static, Message> {
    if !visible {
        return Space::new().width(0).height(0).into();
    }
    button(text("✕").size(10).color(t.sub).font(bold()))
        .padding(Padding::from([2, 6]))
        .on_press(Message::WcDismissError)
        .style(move |_theme, _status| button::Style {
            background: Some(Background::Color(iced::Color::TRANSPARENT)),
            text_color: t.sub,
            border: Border {
                color: with_alpha(t.sub, 0.3),
                width: 1.0,
                radius: Radius::from(6),
            },
            ..button::Style::default()
        })
        .into()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_personal_sign_utf8_message_first() {
        let arr = vec![
            serde_json::Value::String("0x48656c6c6f".to_string()),
            serde_json::Value::String("0x1234567890abcdef1234567890abcdef12345678".to_string()),
        ];
        assert_eq!(decode_personal_sign(&arr).as_deref(), Some("Hello"));
    }

    #[test]
    fn decode_personal_sign_address_first_order() {
        let arr = vec![
            serde_json::Value::String("0x1234567890abcdef1234567890abcdef12345678".to_string()),
            serde_json::Value::String("0x4b616f".to_string()),
        ];
        assert_eq!(decode_personal_sign(&arr).as_deref(), Some("Kao"));
    }

    #[test]
    fn decode_personal_sign_non_utf8_hex_falls_back_to_byte_count() {
        let arr = vec![
            serde_json::Value::String("0xff00ee".to_string()),
            serde_json::Value::String("0x1234567890abcdef1234567890abcdef12345678".to_string()),
        ];
        let out = decode_personal_sign(&arr).unwrap();
        assert!(out.contains("3 bytes"), "got {out}");
    }

    #[test]
    fn format_expiry_renders_days_when_far() {
        let now = 1_700_000_000u64;
        let exp = now + 6 * 86400 + 14 * 3600;
        assert_eq!(format_expiry(now, exp), "in 6d 14h");
    }

    #[test]
    fn format_expiry_renders_minutes_when_under_an_hour() {
        let now = 1_700_000_000u64;
        let exp = now + 35 * 60;
        assert_eq!(format_expiry(now, exp), "in 35m");
    }

    #[test]
    fn format_expiry_renders_expired_when_past() {
        assert_eq!(format_expiry(100, 50), "expired");
    }

    #[test]
    fn is_address_str_accepts_full_42_char_hex() {
        assert!(is_address_str("0x1234567890abcdef1234567890abcdef12345678"));
    }

    #[test]
    fn is_address_str_rejects_short_strings() {
        assert!(!is_address_str("0x1234"));
        assert!(!is_address_str("not an address"));
    }

    // ── grant preview ──────────────────────────────────────────────────

    fn ui_proposal(
        required: &[(&str, &[&str], &[&str])],
        optional: &[(&str, &[&str], &[&str])],
    ) -> UiProposal {
        fn build(
            entries: &[(&str, &[&str], &[&str])],
        ) -> std::collections::BTreeMap<String, NamespaceProposal> {
            let mut out = std::collections::BTreeMap::new();
            for (key, chains, methods) in entries {
                out.insert(
                    (*key).to_string(),
                    NamespaceProposal {
                        chains: chains.iter().map(|s| (*s).to_string()).collect(),
                        methods: methods.iter().map(|s| (*s).to_string()).collect(),
                        events: Vec::new(),
                    },
                );
            }
            out
        }
        UiProposal {
            proposal_id: 1,
            peer: PeerMetadata {
                name: "test".into(),
                description: String::new(),
                url: String::new(),
                icons: Vec::new(),
                redirect: None,
            },
            required: build(required),
            optional: build(optional),
        }
    }

    #[test]
    fn grant_preview_drops_unsupported_chains_and_methods() {
        // Simulates the Curve.finance proposal: requested 35 chains, all
        // optional. Only Mainnet/Optimism/Base are in `Chain::ALL`; the
        // other 32 must surface as `dropped_chains`. Methods follow the
        // same intersection.
        let p = ui_proposal(
            &[],
            &[(
                "eip155",
                &[
                    "eip155:1",
                    "eip155:10",
                    "eip155:8453",
                    "eip155:137",
                    "eip155:42161",
                    "eip155:43114",
                ],
                &[
                    "personal_sign",
                    "eth_sendTransaction",
                    "eth_signTypedData_v4",
                    "wallet_addEthereumChain",
                    "wallet_scanQRCode",
                ],
            )],
        );
        let g = compute_grant_preview(&p);
        assert_eq!(g.granted_chains, vec!["Mainnet", "Base", "Optimism"]);
        // `eth_signTypedData_v4` collapses with the (absent here) v1 form
        // into one label; check the labelled set rather than the verb count
        // so the test doesn't break when method_label is extended.
        assert!(g.granted_methods.contains(&"Sign messages"));
        assert!(g.granted_methods.contains(&"Send transactions"));
        assert!(g.granted_methods.contains(&"Sign typed data"));
        assert_eq!(g.dropped_chains, 3); // 137, 42161, 43114
        assert_eq!(g.dropped_methods, 2); // wallet_addEthereumChain, wallet_scanQRCode
        assert!(!g.required_dropped); // everything was optional
    }

    #[test]
    fn grant_preview_dedupes_across_required_and_optional() {
        // Same eip155:1 appearing in both halves must count once, not twice.
        let p = ui_proposal(
            &[("eip155", &["eip155:1"], &["personal_sign"])],
            &[("eip155", &["eip155:1"], &["personal_sign"])],
        );
        let g = compute_grant_preview(&p);
        assert_eq!(g.granted_chains, vec!["Mainnet"]);
        assert_eq!(g.granted_methods, vec!["Sign messages"]);
        assert_eq!(g.dropped_chains, 0);
        assert_eq!(g.dropped_methods, 0);
    }

    #[test]
    fn grant_preview_collapses_typed_data_v4_into_one_label() {
        // The wire spec exposes two method ids (v0/v4); the user-visible
        // verb is the same so we de-dupe by label.
        let p = ui_proposal(
            &[],
            &[(
                "eip155",
                &["eip155:1"],
                &["eth_signTypedData", "eth_signTypedData_v4"],
            )],
        );
        let g = compute_grant_preview(&p);
        assert_eq!(g.granted_methods, vec!["Sign typed data"]);
        assert_eq!(g.dropped_methods, 0);
    }

    #[test]
    fn grant_preview_flags_required_dropped() {
        // dApp marked an unsupported chain as required. We still grant
        // the intersection (eip155:1) but raise the warning flag.
        let p = ui_proposal(
            &[("eip155", &["eip155:137"], &["personal_sign"])],
            &[("eip155", &["eip155:1"], &["personal_sign"])],
        );
        let g = compute_grant_preview(&p);
        assert!(g.required_dropped);
        assert_eq!(g.granted_chains, vec!["Mainnet"]);
    }

    #[test]
    fn grant_preview_ignores_non_eip155_namespaces() {
        // A dApp requesting a `solana` namespace shouldn't fatten our
        // dropped counts — Kao is EVM-only and "we don't speak Solana"
        // isn't a count-worthy fact in the eip155 preview.
        let p = ui_proposal(
            &[],
            &[
                ("eip155", &["eip155:1"], &["personal_sign"]),
                ("solana", &["solana:mainnet"], &["solana_signMessage"]),
            ],
        );
        let g = compute_grant_preview(&p);
        assert_eq!(g.granted_chains, vec!["Mainnet"]);
        assert_eq!(g.granted_methods, vec!["Sign messages"]);
        assert_eq!(g.dropped_chains, 0);
        assert_eq!(g.dropped_methods, 0);
    }
}
