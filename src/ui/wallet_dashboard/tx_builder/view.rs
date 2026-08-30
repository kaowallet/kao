//! View for the Transaction Builder app. Kept in its own module so the
//! state machine in `tx_builder.rs` stays readable. All items are private
//! to the parent module.

use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{Column, Space, button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use super::abi::AbiSource;
use super::{Message, Modal, Mode, ReadOutcome, TxBuilderApp, encode, wei_to_eth};
use crate::decode::bytecode::StateMutability;
use crate::txbuilder::abi::MethodProvenance;
use crate::txbuilder::sim::{BatchOutcome, GasFit};
use crate::txbuilder::templates::Template;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    avatar, black, bold, ghost_button, kao_checkbox, kao_scrollable_style, mono, mono_bold,
    primary_button, text_input_style,
};

pub(super) fn root(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    if app.modal != Modal::None {
        return modal_view(app, t);
    }

    let subtitle = if app.batch_layout() {
        "compose · simulate · sign — batch many calls into one atomic transaction"
    } else {
        "compose · read · send — one transaction at a time on this custom network"
    };

    let mut header = column![
        ghost_button(t, text("← Apps").size(13).color(t.sub).font(bold())).on_press(Message::Close),
        Space::new().height(10),
        row![
            container(
                row![
                    text("Transaction Builder")
                        .size(21)
                        .color(t.text)
                        .font(bold())
                        .wrapping(Wrapping::None),
                    Space::new().width(8),
                    pill(t, "beta", t.a2),
                ]
                .align_y(Alignment::Center)
            )
            .width(Length::Fill)
            .clip(true),
            Space::new().width(12),
            network_chip(app, t),
            Space::new().width(10),
            identity_chip(app, t),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    ]
    .width(Length::Fill);

    // The switcher's menu expands inline beneath the header chips (iced has no
    // floating overlay here — same pattern as the method picker).
    if app.net_menu_open {
        header = header
            .push(Space::new().height(8))
            .push(network_menu(app, t));
    }

    header = header.push(Space::new().height(4)).push(
        text(subtitle.to_string())
            .size(11)
            .color(t.sub)
            .font(mono()),
    );

    // Built-in chains / Safes get the two-pane compose+batch layout; a custom
    // network collapses to the single-transaction composer (no batching).
    let panes: Element<'_, Message> = if app.batch_layout() {
        // Two matched columns: identical width (each `Fill` → an even 50/50
        // split) and identical height (each `Fill` against the bounded pane
        // height). Each card scrolls its own overflow internally — see
        // `pane_card` — which is why the Transaction Builder opts out of the
        // shared page scroll (apps.rs); that scroll would hand the row an
        // unbounded height and collapse the equal-height fill.
        row![composer_pane(app, t), batch_pane(app, t)]
            .spacing(16)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        composer_pane(app, t)
    };

    // A standing refusal — no key for this account, or a Safe version this
    // wallet won't sign for — belongs above the composer, not in the error
    // banner at the foot of the page. Both used to be discovered on the click
    // that opens the review, with the batch already composed and simulated.
    if let Some(why) = app.no_signer_reason() {
        header = header
            .push(Space::new().height(10))
            .push(signing_block_banner(t, &why));
    }

    if app.current_delegation().is_some() {
        header = header
            .push(Space::new().height(10))
            .push(delegation_banner(app, t));
    }

    let mut col = column![header, Space::new().height(16), panes]
        .width(Length::Fill)
        .height(Length::Fill);

    if let Some(err) = &app.error {
        col = col.push(Space::new().height(12)).push(error_banner(t, err));
    }

    col.into()
}

// ============================================================================
// Header chips
// ============================================================================

/// Colour of the network dot: a warm accent for unverified custom networks,
/// the "up" green for the three Helios-verified built-ins.
fn net_dot_color(app: &TxBuilderApp, t: KaoTheme) -> Color {
    if app.net.is_custom() { t.a3 } else { t.up }
}

/// The header network chip. For a plain EOA it's a button that opens the
/// switcher; a Safe pins the network to its own chain, so it renders inert
/// (no caret, no press).
fn network_chip(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let dot_color = net_dot_color(app, t);
    let dot = container(Space::new())
        .width(8)
        .height(8)
        .style(move |_| container::Style {
            background: Some(Background::Color(dot_color)),
            border: Border {
                radius: Radius::from(4),
                ..Default::default()
            },
            ..Default::default()
        });
    let pinned = app.ctx.is_safe;
    let mut inner = row![
        dot,
        Space::new().width(8),
        text(app.net_display_name())
            .size(12)
            .color(t.text)
            .font(bold())
            .wrapping(Wrapping::None),
        Space::new().width(8),
        text(format!("chain {}", app.net.chain_id()))
            .size(11)
            .color(t.sub)
            .font(mono()),
    ]
    .align_y(Alignment::Center);
    inner = inner.push(Space::new().width(8)).push(
        text(if pinned {
            "🔒"
        } else if app.net_menu_open {
            "▲"
        } else {
            "▼"
        })
        .size(10)
        .color(t.sub),
    );

    if pinned {
        // Inert — a Safe can only transact on its own chain.
        return chip(t, inner.into(), t.card_alt, t.border);
    }

    button(inner)
        .padding(Padding::from([7, 12]))
        .on_press(Message::ToggleNetworkMenu)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered => with_alpha(t.text, 0.04),
                _ => t.card_alt,
            })),
            text_color: t.text,
            border: Border {
                color: if app.net_menu_open { t.a1 } else { t.border },
                width: 1.0,
                radius: Radius::from(11),
            },
            ..Default::default()
        })
        .into()
}

/// The inline switcher menu: the three built-ins, then any enabled custom
/// networks. Rendered beneath the header when open.
fn network_menu(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let mut menu = column![].spacing(2).width(Length::Fill);
    let options = app.network_options();
    for (net, name) in options {
        let on = net == app.net;
        let custom = net.is_custom();
        let dot_color = if custom { t.a3 } else { t.up };
        let dot = container(Space::new())
            .width(7)
            .height(7)
            .style(move |_| container::Style {
                background: Some(Background::Color(dot_color)),
                border: Border {
                    radius: Radius::from(4),
                    ..Default::default()
                },
                ..Default::default()
            });
        let mut labels = row![
            dot,
            Space::new().width(9),
            text(name)
                .size(13)
                .color(if on { t.a1 } else { t.text })
                .font(bold()),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);
        if custom {
            labels = labels
                .push(Space::new().width(7))
                .push(pill(t, "unverified", t.a3));
        }
        labels = labels.push(Space::new().width(Length::Fill)).push(
            text(format!("{}", net.chain_id()))
                .size(11)
                .color(t.sub)
                .font(mono()),
        );
        menu = menu.push(
            button(labels)
                .padding(Padding::from([9, 11]))
                .width(Length::Fill)
                .on_press(Message::SetNetwork(net))
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(if on {
                        with_alpha(t.a1, 0.12)
                    } else {
                        match status {
                            button::Status::Hovered => with_alpha(t.text, 0.04),
                            _ => Color::TRANSPARENT,
                        }
                    })),
                    text_color: t.text,
                    border: Border {
                        radius: Radius::from(9),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
        );
    }
    container(menu)
        .padding(6)
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

fn identity_chip<'a>(app: &TxBuilderApp, t: KaoTheme) -> Element<'a, Message> {
    let (label, sub) = if app.ctx.is_safe {
        ("Safe multisig", crate::wallet::short_address(app.owner))
    } else {
        ("Single account", crate::wallet::short_address(app.owner))
    };
    chip(
        t,
        column![
            text(label.to_string()).size(12).color(t.text).font(bold()),
            text(sub).size(10).color(t.sub).font(mono()),
        ]
        .spacing(1)
        .into(),
        with_alpha(t.a1, 0.12),
        with_alpha(t.a1, 0.3),
    )
}

// ============================================================================
// Composer pane (left)
// ============================================================================

fn composer_pane(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let tabs = row![
        mode_tab(
            t,
            "Write",
            app.mode == Mode::Write,
            Message::SetMode(Mode::Write)
        ),
        mode_tab(
            t,
            "Read",
            app.mode == Mode::Read,
            Message::SetMode(Mode::Read)
        ),
        mode_tab(
            t,
            "Raw hex",
            app.mode == Mode::Raw,
            Message::SetMode(Mode::Raw)
        ),
    ]
    .spacing(4);

    // Title takes the leftover width and clips (rather than wrapping and
    // overlapping the tabs) when the pane is narrow; the mode tabs keep their
    // natural width on the right.
    let head = row![
        container(
            text("New transaction")
                .size(18)
                .color(t.text)
                .font(bold())
                .wrapping(Wrapping::None)
        )
        .width(Length::Fill)
        .clip(true),
        tabs,
    ]
    .align_y(Alignment::Center)
    .spacing(10)
    .width(Length::Fill);

    let body = match app.mode {
        Mode::Write => call_composer(app, t),
        Mode::Read => read_composer(app, t),
        Mode::Raw => raw_composer(app, t),
    };

    let mut inner = column![
        head,
        Space::new().height(14),
        divider(t),
        Space::new().height(16),
        body,
    ]
    .width(Length::Fill);

    // Footer. Read mode has its own inline Query button + a "nothing queued"
    // note; Write / Raw show the add-to-batch (or single-send) CTA.
    inner = inner.push(Space::new().height(16)).push(divider(t));
    if app.mode == Mode::Read {
        inner = inner.push(Space::new().height(12)).push(
            container(
                text("read-only query · nothing is added to the batch")
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            )
            .center_x(Length::Fill),
        );
    } else {
        inner = inner
            .push(Space::new().height(14))
            .push(compose_cta(app, t));
    }

    pane_card(t, inner.into())
}

/// The composer's primary action: "Add to batch" in the two-pane layout, or
/// "Send transaction" on a custom network (single-transaction composer).
fn compose_cta(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let enabled = app.compose_valid();
    let (label, msg) = if app.is_custom() {
        ("↑ Send transaction", Message::SendSingle)
    } else {
        ("+ Add to batch", Message::AddToBatch)
    };
    primary_button(t, label, enabled)
        .width(Length::Fill)
        .on_press_maybe(enabled.then_some(msg))
        .into()
}

/// Shared composer scaffold: the address field plus the resolving / loaded-
/// banner / not-found / empty-hint status, common to the Write and Read tabs.
/// The caller appends the method-specific UI when a contract is loaded.
fn contract_head(app: &TxBuilderApp, t: KaoTheme) -> Column<'_, Message> {
    let name = name_row(app, t, super::NameSlot::Contract);
    // A name is not a malformed address. Without this the box turns red on the
    // first character of `uniswap.eth` and stays red the whole time it is
    // resolving, contradicting a lookup that is about to succeed.
    let addr_invalid = name.is_none()
        && !app.addr_input.trim().is_empty()
        && encode::parse_address(&app.addr_input).is_err();
    let placeholder = if app.is_custom() {
        "0x… or a name (paste its ABI to load)"
    } else {
        "0x… or vitalik.eth"
    };

    let addr_field = labelled(
        t,
        "Contract address",
        text_input(placeholder, &app.addr_input)
            .on_input(Message::AddrChanged)
            .padding(Padding::from([11, 13]))
            .size(13)
            .font(mono())
            .style(move |_, s| {
                let mut base = text_input_style(t, s);
                if addr_invalid {
                    base.border.color = t.down;
                }
                base
            })
            .into(),
    );

    let mut col = column![addr_field].width(Length::Fill);

    // Sits directly under the box, above the ABI ladder below: it describes
    // what is *in the field*, where the ladder describes what was found at the
    // address the field stands for.
    if let Some(n) = name {
        col = col.push(Space::new().height(6)).push(n);
    }

    if app.resolving {
        col = col.push(Space::new().height(14)).push(info_box(
            t,
            "Fetching ABI from the verified light-client…",
            t.a1,
        ));
    } else if let Some(c) = &app.loaded {
        col = col
            .push(Space::new().height(14))
            .push(contract_banner(t, c));
        // Ahead of the proxy note: "there is no contract here" outranks any
        // observation about which ABI is on screen.
        if app.nothing_deployed {
            let target = app.contract_target_label();
            col = col
                .push(Space::new().height(8))
                .push(nothing_deployed_note(app, t, &target));
        }
        if app.proxy_unverified {
            col = col
                .push(Space::new().height(8))
                .push(proxy_unverified_note(t));
        }
        col = col
            .push(Space::new().height(10))
            .push(fetch_abi_button(app, t));
    } else if let Some(e) = &app.addr_error {
        col = col.push(Space::new().height(14)).push(addr_error_box(t, e));
    } else if let Some(e) = &app.resolve_error {
        col = col
            .push(Space::new().height(14))
            .push(resolve_error_box(app, t, e));
    } else if app.not_found {
        col = col
            .push(Space::new().height(14))
            .push(not_found_box(app, t));
    } else if app.addr_input.trim().is_empty() {
        let hint = if app.is_custom() {
            "Paste a contract address, then fetch its ABI from Sourcify — Kao can't prove bytecode on a custom network."
        } else {
            "Paste a verified contract address to load its ABI."
        };
        col = col
            .push(Space::new().height(22))
            .push(container(text(hint.to_string()).size(13).color(t.sub)).center_x(Length::Fill));
    }

    col
}

fn call_composer(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let mut col = contract_head(app, t);

    if !app.resolving && app.loaded.is_some() {
        col = col
            .push(Space::new().height(16))
            .push(method_picker(app, t));

        if let Some(m) = app.selected_method() {
            if m.payable {
                col = col.push(Space::new().height(16)).push(labelled(
                    t,
                    "ETH value (wei — this method is payable)",
                    text_input("0", &app.value_input)
                        .on_input(Message::ValueChanged)
                        .padding(Padding::from([11, 13]))
                        .size(13)
                        .font(mono())
                        .style(move |_, s| text_input_style(t, s))
                        .into(),
                ));
            }
            if m.inputs.is_empty() {
                if !m.payable {
                    // "Takes no arguments" is a claim, and only a declared ABI
                    // is in a position to make it. Recovered from bytecode, an
                    // empty list is equally "evmole couldn't reach the function
                    // body" — and asserting the first reading queues a 4-byte
                    // call for a method that wanted arguments.
                    let (msg, tone) = if m.provenance.declares_argument_list() {
                        ("No parameters — this method takes no arguments.", t.sub)
                    } else {
                        (
                            "No parameters were recovered — that may mean this method takes \
                             none, or that its argument list couldn't be read out of the \
                             bytecode. Paste the contract's ABI to be sure, or use Raw hex.",
                            t.down,
                        )
                    };
                    col = col
                        .push(Space::new().height(12))
                        .push(text(msg).size(12).color(tone));
                }
            } else {
                col = col
                    .push(Space::new().height(16))
                    .push(section_label(t, "Parameters"));
                for (i, inp) in m.inputs.iter().enumerate() {
                    let val = app.args.get(i).cloned().unwrap_or_default();
                    col = col.push(Space::new().height(12)).push(param_row(
                        t,
                        i,
                        &inp.display_name(i),
                        &inp.ty_str,
                        &inp.ty,
                        &val,
                        false,
                        app.name_state(super::NameSlot::Arg(i))
                            .map(|s| (s, app.resolves_off_mainnet())),
                    ));
                }
            }
        }
    }

    col.into()
}

/// The Read tab: pick a `view`/`pure` method, fill its params, and `Query`
/// (`eth_call`). The typed return + raw hex are shown below, both copyable.
fn read_composer(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let mut col = contract_head(app, t);

    if !app.resolving
        && let Some(c) = &app.loaded
    {
        if c.read_methods.is_empty() {
            col = col.push(Space::new().height(16)).push(info_box(
                t,
                "No read methods on this ABI. Paste an ABI with view/pure functions to query.",
                t.sub,
            ));
        } else {
            col = col
                .push(Space::new().height(16))
                .push(read_method_picker(app, t));

            if let Some(m) = app.selected_read_method() {
                if !m.inputs.is_empty() {
                    col = col
                        .push(Space::new().height(16))
                        .push(section_label(t, "Parameters"));
                    for (i, inp) in m.inputs.iter().enumerate() {
                        let val = app.read_args.get(i).cloned().unwrap_or_default();
                        col = col.push(Space::new().height(12)).push(param_row(
                            t,
                            i,
                            &inp.display_name(i),
                            &inp.ty_str,
                            &inp.ty,
                            &val,
                            true,
                            app.name_state(super::NameSlot::ReadArg(i))
                                .map(|s| (s, app.resolves_off_mainnet())),
                        ));
                    }
                }

                let ready = app.read_valid() && !app.read_busy;
                let query_label = if app.read_busy {
                    "Querying…"
                } else {
                    "◈ Query"
                };
                col = col.push(Space::new().height(16)).push(query_button(
                    t,
                    query_label,
                    ready.then_some(Message::Query),
                ));

                if let Some(res) = &app.read_result {
                    col = col
                        .push(Space::new().height(16))
                        .push(read_result_panel(t, res));
                }
            }
        }
    }

    col.into()
}

fn raw_composer(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    // Every field carries its own reason. All three gate the CTA now, so a
    // refusal that used to arrive as a banner at the foot of the page lands
    // beside the box that caused it — the treatment `to` already had, and the
    // one the Write tab gives every parameter.
    // A name in this box is handled by `to_name` below, so it must not also be
    // reported here as "not a 20-byte 0x… address" — the field would go red on
    // the first character of a name that is about to resolve.
    let to_name = name_row(app, t, super::NameSlot::RawTo);
    let to_err = (to_name.is_none() && !app.raw_to.trim().is_empty())
        .then(|| encode::parse_address(&app.raw_to).err())
        .flatten();
    let value_err = encode::parse_wei(&app.raw_value).err();
    let data_err = encode::parse_data(&app.raw_data).err();
    let (to_invalid, value_invalid, data_invalid) =
        (to_err.is_some(), value_err.is_some(), data_err.is_some());

    let mut col = column![labelled(
        t,
        "To",
        text_input("0x… or a name", &app.raw_to)
            .on_input(Message::RawToChanged)
            .padding(Padding::from([11, 13]))
            .size(13)
            .font(mono())
            .style(move |_, s| {
                let mut b = text_input_style(t, s);
                if to_invalid {
                    b.border.color = t.down;
                }
                b
            })
            .into(),
    )]
    .width(Length::Fill);
    if let Some(e) = &to_err {
        col = col.push(Space::new().height(6)).push(field_error(t, e));
    }
    if let Some(n) = to_name {
        col = col.push(Space::new().height(6)).push(n);
    }
    // A well-formed address with nothing behind it. Not a field error — the
    // input is valid — but the call would succeed having done nothing, so it
    // sits with the field rather than in a banner at the bottom of the page.
    if app.raw_nothing_deployed {
        let target = app.raw_target_label();
        col = col
            .push(Space::new().height(8))
            .push(nothing_deployed_note(app, t, &target));
    }

    col = col.push(Space::new().height(14)).push(labelled(
        t,
        "ETH value (wei)",
        text_input("0", &app.raw_value)
            .on_input(Message::RawValueChanged)
            .padding(Padding::from([11, 13]))
            .size(13)
            .font(mono())
            .style(move |_, s| {
                let mut b = text_input_style(t, s);
                if value_invalid {
                    b.border.color = t.down;
                }
                b
            })
            .into(),
    ));
    if let Some(e) = &value_err {
        col = col.push(Space::new().height(6)).push(field_error(t, e));
    }

    col = col.push(Space::new().height(14)).push(labelled(
        t,
        "Data (hex calldata — leave empty for a plain transfer)",
        text_input("0x…", &app.raw_data)
            .on_input(Message::RawDataChanged)
            .padding(Padding::from([11, 13]))
            .size(12)
            .font(mono())
            .style(move |_, s| {
                let mut b = text_input_style(t, s);
                if data_invalid {
                    b.border.color = t.down;
                }
                b
            })
            .into(),
    ));
    if let Some(e) = &data_err {
        col = col.push(Space::new().height(6)).push(field_error(t, e));
    }

    col.push(Space::new().height(14))
        .push(info_box(
            t,
            "Expert mode — Kao won't decode this for you. Double-check the bytes.",
            t.sub,
        ))
        .into()
}

/// A short reason under a field, in the same register as `param_row`'s
/// `needs uint256` annotation. Full width and glyph-wrapped: some of these (the
/// EIP-55 refusal) are a sentence, and a Shrink-width label beside the section
/// header would push the row past the card.
fn field_error<'a>(t: KaoTheme, msg: &str) -> Element<'a, Message> {
    text(msg.to_string())
        .size(10)
        .color(t.down)
        .font(mono_bold())
        .wrapping(Wrapping::WordOrGlyph)
        .width(Length::Fill)
        .into()
}

/// What a name-shaped address field resolved to, as a line under that field.
///
/// One renderer for all four surfaces (contract box, raw `To`, write argument,
/// read argument), because the states are the same everywhere and a name that
/// reads one way beside the contract and another beside an argument is a name
/// the user has to interpret twice.
///
/// The resolved case always shows the **address**, never the name alone: the
/// name is a label the user typed, the address is what will be signed over, and
/// the whole point of showing this is that the two can be checked against each
/// other before anything is queued.
fn name_status<'a>(
    t: KaoTheme,
    state: &'a super::NameState,
    off_mainnet: bool,
) -> Element<'a, Message> {
    use super::NameState;
    match state {
        NameState::Resolving { name, .. } => text(format!("Resolving {name}…"))
            .size(10)
            .color(t.sub)
            .font(mono())
            .width(Length::Fill)
            .into(),
        NameState::Resolved { addr, ns, .. } => {
            let mut col = column![
                row![
                    pill(t, ns, t.up),
                    Space::new().width(6),
                    text(format!("= {}", addr.to_checksum(None)))
                        .size(10)
                        .color(t.sub)
                        .font(mono())
                        .wrapping(Wrapping::WordOrGlyph),
                ]
                .align_y(Alignment::Center)
            ]
            .width(Length::Fill);
            // Every namespace this wallet reads lives on Ethereum mainnet. When
            // the batch is bound for anywhere else, the address on screen was
            // looked up somewhere other than where it will be used — and for a
            // contract that is a different contract, or none.
            if off_mainnet {
                col = col.push(Space::new().height(3)).push(
                    text("resolved on Ethereum mainnet — check it means the same here")
                        .size(10)
                        .color(t.down)
                        .font(mono())
                        .wrapping(Wrapping::WordOrGlyph)
                        .width(Length::Fill),
                );
            }
            col.into()
        }
        NameState::NotFound { name } => field_error(t, &format!("{name} has no address record")),
        NameState::Error { name, msg } => {
            field_error(t, &format!("couldn't resolve {name} — {msg}"))
        }
    }
}

/// The name-status line for `slot`, or nothing when that field holds no name.
fn name_row<'a>(
    app: &'a TxBuilderApp,
    t: KaoTheme,
    slot: super::NameSlot,
) -> Option<Element<'a, Message>> {
    app.name_state(slot)
        .map(|s| name_status(t, s, app.resolves_off_mainnet()))
}

fn method_picker(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let Some(contract) = &app.loaded else {
        return Space::new().into();
    };
    // Split name (always visible) from the param types (clipped): a long
    // signature like `supply(address,uint256,address,uint16)` has no spaces,
    // so it can't wrap — the types go in a Fill + clip container so they
    // never spill past the card, while the method name is always readable.
    let (name, params) = app
        .selected_method()
        .map(|m| {
            let types = m
                .inputs
                .iter()
                .map(|p| p.ty_str.clone())
                .collect::<Vec<_>>()
                .join(", ");
            (m.name.clone(), format!("({types})"))
        })
        .unwrap_or_else(|| (String::new(), String::new()));

    let head = button(
        row![
            text(name).size(14).color(t.text).font(mono_bold()),
            Space::new().width(7),
            container(
                text(params)
                    .size(13)
                    .color(t.sub)
                    .font(mono())
                    .wrapping(Wrapping::None),
            )
            .width(Length::Fill)
            .clip(true),
            Space::new().width(8),
            text(if app.method_menu_open { "▲" } else { "▼" })
                .size(11)
                .color(t.sub),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .padding(Padding::from([11, 13]))
    .width(Length::Fill)
    .on_press(Message::ToggleMethodMenu)
    .style(move |_, _| field_button_style(t, app.method_menu_open));

    let mut col =
        column![section_label(t, "Method"), Space::new().height(8), head].width(Length::Fill);

    // What the name on that button is worth. The review overlay says this at
    // signing time; by then the method has been chosen, composed and simulated.
    if let Some(m) = app.selected_method()
        && let Some(caution) = m.caution()
    {
        let tone = if m.provenance.is_spoof_signal() {
            t.down
        } else {
            t.sub
        };
        col = col
            .push(Space::new().height(7))
            .push(info_box(t, &caution, tone));
    }

    if app.method_menu_open {
        let mut menu = column![].spacing(2).width(Length::Fill);
        for (i, m) in contract.methods.iter().enumerate() {
            let on = i == app.method_idx;
            let mark = match &m.provenance {
                p if p.is_spoof_signal() => Some(("⚠", t.down)),
                MethodProvenance::Ambiguous { .. } => Some(("?", t.sub)),
                // Composable, but the bytecode says it only reads. Marked
                // rather than hidden — the inference fails towards "read-only",
                // so hiding these would hide real write methods.
                _ if matches!(
                    m.inferred_mutability,
                    Some(StateMutability::View | StateMutability::Pure)
                ) =>
                {
                    Some(("view", t.sub))
                }
                _ => None,
            };
            menu = menu.push(
                button(
                    row![
                        // Spaces after commas give long signatures break points
                        // so they wrap within the menu width instead of
                        // overflowing.
                        text(m.signature.replace(',', ", "))
                            .size(13)
                            .color(if on { t.a1 } else { t.text })
                            .font(mono())
                            .width(Length::Fill),
                        // Carried per row so a contested name is visible while
                        // the menu is still open, not only once it is picked.
                        text(mark.map(|(s, _)| s).unwrap_or("").to_string())
                            .size(12)
                            .color(mark.map(|(_, c)| c).unwrap_or(t.sub)),
                    ]
                    .align_y(Alignment::Center)
                    .width(Length::Fill),
                )
                .padding(Padding::from([9, 10]))
                .width(Length::Fill)
                .on_press(Message::PickMethod(i))
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(if on {
                        with_alpha(t.a1, 0.12)
                    } else {
                        match status {
                            button::Status::Hovered => with_alpha(t.text, 0.04),
                            _ => Color::TRANSPARENT,
                        }
                    })),
                    text_color: t.text,
                    border: Border {
                        radius: Radius::from(9),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            );
        }
        col = col.push(Space::new().height(6)).push(
            container(menu)
                .padding(5)
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.card)),
                    border: Border {
                        color: t.border,
                        width: 1.0,
                        radius: Radius::from(12),
                    },
                    ..Default::default()
                }),
        );
    }

    col.into()
}

/// A labelled parameter input. `read` swaps the emitted messages so the same
/// widget drives either the Write composer args or the Read query args.
///
/// `name_state` is the resolution of a name typed into an `address` parameter,
/// when there is one. It changes three things: the ✓/needs-address annotation
/// reads the *resolved* address rather than the label, the red border is
/// withheld while a lookup is in flight, and the resolved address is printed
/// under the field — the same slot `encoded_preview` uses to say what a string
/// really encodes to, for the same reason.
#[allow(clippy::too_many_arguments)]
fn param_row<'a>(
    t: KaoTheme,
    index: usize,
    name: &str,
    ty_str: &str,
    ty: &alloy::dyn_abi::DynSolType,
    value: &str,
    read: bool,
    name_state: Option<(&'a super::NameState, bool)>,
) -> Element<'a, Message> {
    let touched = !value.trim().is_empty();
    // A name stands in for its address, so validity is a question about what it
    // resolved to. Unresolved (in flight, not found, failed) is *not* valid —
    // the CTA must not light up over a lookup that hasn't landed.
    let ok = match name_state {
        Some((s, _)) => s.address().is_some(),
        None => encode::is_valid(ty, value),
    };
    let resolving = matches!(name_state, Some((super::NameState::Resolving { .. }, _)));
    let annotation: Element<'a, Message> = if touched && !resolving {
        text(if ok {
            "✓ valid".to_string()
        } else {
            format!("needs {ty_str}")
        })
        .size(10)
        .color(if ok { t.up } else { t.down })
        .font(mono_bold())
        .into()
    } else {
        Space::new().into()
    };

    let head = row![
        text(name.to_string())
            .size(12)
            .color(t.text)
            .font(mono_bold()),
        Space::new().width(7),
        pill(t, ty_str, t.a2),
        Space::new().width(Length::Fill),
        annotation,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let bool_msg = move |b: bool| {
        if read {
            Message::ReadBoolArg(index, b)
        } else {
            Message::BoolArg(index, b)
        }
    };
    let input: Element<'a, Message> = if ty_str == "bool" {
        row![
            bool_btn(t, "true", value == "true", bool_msg(true)),
            Space::new().width(7),
            bool_btn(t, "false", value == "false", bool_msg(false)),
        ]
        .width(Length::Fill)
        .into()
    } else {
        // Withheld while a lookup is in flight: a name that is about to resolve
        // is not a wrong answer yet, and reddening the box under the user's
        // cursor as they finish typing it says otherwise.
        let invalid = touched && !ok && !resolving;
        let hint = if name_state.is_some() || matches!(ty, alloy::dyn_abi::DynSolType::Address) {
            "0x… or a name".to_string()
        } else {
            encode::type_hint(ty_str)
        };
        text_input(&hint, value)
            .on_input(move |v| {
                if read {
                    Message::ReadArgChanged(index, v)
                } else {
                    Message::ArgChanged(index, v)
                }
            })
            .padding(Padding::from([11, 13]))
            .size(13)
            .font(mono())
            .style(move |_, s| {
                let mut b = text_input_style(t, s);
                if invalid {
                    b.border.color = t.down;
                }
                b
            })
            .into()
    };

    let mut col = column![head, Space::new().height(6), input].width(Length::Fill);
    // A resolved name occupies the same slot as `encoded_preview` below and for
    // the same reason: it is what this string actually encodes to. Only one of
    // the two can apply — a name never coerces, so `encoded_preview` is `None`
    // whenever this is `Some`.
    if let Some((s, off_mainnet)) = name_state {
        col = col
            .push(Space::new().height(5))
            .push(name_status(t, s, off_mainnet));
    }
    // What this string actually encodes to, when that isn't what it says.
    // `1 ether` into a 6-decimal token's uint256 is 10¹² of it, and the field
    // annotates it ✓ valid either way — so the number being agreed to belongs
    // on screen at the keystroke, not only once the call is queued.
    if let Some(p) = encode::encoded_preview(ty, value) {
        col = col.push(Space::new().height(5)).push(
            text(format!("= {p}"))
                .size(10)
                .color(t.sub)
                .font(mono())
                .wrapping(Wrapping::WordOrGlyph)
                .width(Length::Fill),
        );
    }
    col.into()
}

// ============================================================================
// Read tab (view methods)
// ============================================================================

fn read_method_picker(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let Some(contract) = &app.loaded else {
        return Space::new().into();
    };
    let (name, params) = app
        .selected_read_method()
        .map(|m| {
            let types = m
                .inputs
                .iter()
                .map(|p| p.ty_str.clone())
                .collect::<Vec<_>>()
                .join(", ");
            (m.name.clone(), format!("({types})"))
        })
        .unwrap_or_else(|| (String::new(), String::new()));

    let head = button(
        row![
            text(name).size(14).color(t.text).font(mono_bold()),
            Space::new().width(7),
            container(
                text(params)
                    .size(13)
                    .color(t.sub)
                    .font(mono())
                    .wrapping(Wrapping::None),
            )
            .width(Length::Fill)
            .clip(true),
            Space::new().width(8),
            text(if app.read_menu_open { "▲" } else { "▼" })
                .size(11)
                .color(t.sub),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .padding(Padding::from([11, 13]))
    .width(Length::Fill)
    .on_press(Message::ToggleReadMethodMenu)
    .style(move |_, _| field_button_style(t, app.read_menu_open));

    let mut col = column![
        section_label(t, "View method (read-only · no gas)"),
        Space::new().height(8),
        head
    ]
    .width(Length::Fill);

    if app.read_menu_open {
        let mut menu = column![].spacing(2).width(Length::Fill);
        for (i, m) in contract.read_methods.iter().enumerate() {
            let on = i == app.read_idx;
            menu = menu.push(
                button(
                    text(m.signature.replace(',', ", "))
                        .size(13)
                        .color(if on { t.a1 } else { t.text })
                        .font(mono())
                        .width(Length::Fill),
                )
                .padding(Padding::from([9, 10]))
                .width(Length::Fill)
                .on_press(Message::PickReadMethod(i))
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(if on {
                        with_alpha(t.a1, 0.12)
                    } else {
                        match status {
                            button::Status::Hovered => with_alpha(t.text, 0.04),
                            _ => Color::TRANSPARENT,
                        }
                    })),
                    text_color: t.text,
                    border: Border {
                        radius: Radius::from(9),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            );
        }
        col = col.push(Space::new().height(6)).push(
            container(menu)
                .padding(5)
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.card)),
                    border: Border {
                        color: t.border,
                        width: 1.0,
                        radius: Radius::from(12),
                    },
                    ..Default::default()
                }),
        );
    }

    col.into()
}

/// The `Query` button — a full-width bordered action that fires the `eth_call`.
fn query_button<'a>(t: KaoTheme, label: &'a str, msg: Option<Message>) -> Element<'a, Message> {
    let enabled = msg.is_some();
    let mut b = button(
        container(
            text(label.to_string())
                .size(15)
                .color(if enabled { t.a1 } else { t.sub })
                .font(bold()),
        )
        .center_x(Length::Fill),
    )
    .padding(Padding::from([13, 16]))
    .width(Length::Fill)
    .style(move |_, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered if enabled => with_alpha(t.a1, 0.06),
            _ => Color::TRANSPARENT,
        })),
        text_color: if enabled { t.a1 } else { t.sub },
        border: Border {
            color: if enabled {
                with_alpha(t.a1, 0.5)
            } else {
                t.border
            },
            width: 1.5,
            radius: Radius::from(12),
        },
        ..Default::default()
    });
    if let Some(m) = msg {
        b = b.on_press(m);
    }
    b.into()
}

/// The result of the last query: a decoded-value block plus the raw return
/// data in a copyable terminal box (or the error).
fn read_result_panel<'a>(t: KaoTheme, res: &'a ReadOutcome) -> Element<'a, Message> {
    match res {
        ReadOutcome::Err(e) => info_box(t, e, t.down),
        ReadOutcome::Ok {
            rows,
            raw,
            verified,
        } => {
            let head = row![
                section_label(t, "Returned"),
                Space::new().width(9),
                pill(t, "✓ eth_call", t.up),
                Space::new().width(7),
                pill(
                    t,
                    if *verified { "verified" } else { "unverified" },
                    if *verified { t.up } else { t.a3 }
                ),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill);

            let mut col = column![head].width(Length::Fill);

            // Decoded, typed values — each copyable.
            if rows.is_empty() {
                col = col.push(Space::new().height(10)).push(
                    text("returns no decodable value — see the raw data below")
                        .size(11)
                        .color(t.sub)
                        .font(mono()),
                );
            } else {
                for (i, r) in rows.iter().enumerate() {
                    col = col
                        .push(Space::new().height(10))
                        .push(read_value_row(t, i, r));
                }
            }

            // Raw return data — a dark terminal box with a copy affordance.
            let raw_box = container(
                column![
                    row![
                        text("// raw return data")
                            .size(11)
                            .color(terminal_muted(t))
                            .font(mono()),
                        Space::new().width(Length::Fill),
                        copy_link(t, Message::CopyReadRaw),
                    ]
                    .align_y(Alignment::Center)
                    .width(Length::Fill),
                    Space::new().height(6),
                    text(raw.clone())
                        .size(11)
                        .color(terminal_fg(t))
                        .font(mono())
                        .wrapping(Wrapping::WordOrGlyph)
                        .width(Length::Fill),
                ]
                .padding(Padding::from([11, 13]))
                .width(Length::Fill),
            )
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(terminal_bg(t))),
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(10),
                },
                ..Default::default()
            });

            col.push(Space::new().height(12)).push(raw_box).into()
        }
    }
}

/// One decoded return value: `type` pill + `name ≈ value` in a soft green box,
/// with a copy button for the value.
fn read_value_row<'a>(t: KaoTheme, index: usize, r: &'a super::ReadRow) -> Element<'a, Message> {
    let body = row![
        pill(t, &r.ty, t.a2),
        Space::new().width(9),
        text(format!("{} = {}", r.name, r.value))
            .size(13)
            .color(t.text)
            .font(mono_bold())
            .wrapping(Wrapping::WordOrGlyph)
            .width(Length::Fill),
        Space::new().width(8),
        copy_link(t, Message::CopyReadValue(index)),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    container(body.padding(Padding::from([10, 13])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.up, 0.10))),
            border: Border {
                color: with_alpha(t.up, 0.3),
                width: 1.0,
                radius: Radius::from(10),
            },
            ..Default::default()
        })
        .into()
}

/// A small "copy" text button.
fn copy_link<'a>(t: KaoTheme, msg: Message) -> Element<'a, Message> {
    button(text("copy").size(10).color(t.a1).font(mono_bold()))
        .padding(Padding::from([3, 7]))
        .on_press(msg)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered => with_alpha(t.a1, 0.12),
                _ => with_alpha(t.a1, 0.06),
            })),
            text_color: t.a1,
            border: Border {
                radius: Radius::from(6),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
}

// ============================================================================
// Templates
// ============================================================================

/// The "★ Templates" toggle in the batch-pane header.
fn templates_button(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let open = app.template_menu_open;
    button(
        row![
            text("★").size(12).color(if open { t.a1 } else { t.sub }),
            Space::new().width(6),
            text("Templates")
                .size(12)
                .color(if open { t.a1 } else { t.text })
                .font(bold()),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([6, 11]))
    .on_press(Message::ToggleTemplateMenu)
    .style(move |_, status| button::Style {
        background: Some(Background::Color(if open {
            with_alpha(t.a1, 0.10)
        } else {
            match status {
                button::Status::Hovered => with_alpha(t.text, 0.04),
                _ => Color::TRANSPARENT,
            }
        })),
        text_color: t.text,
        border: Border {
            color: if open {
                with_alpha(t.a1, 0.5)
            } else {
                t.border
            },
            width: 1.0,
            radius: Radius::from(10),
        },
        ..Default::default()
    })
    .into()
}

/// The templates dropdown: the user's saved templates (load / rename / delete)
/// and a "Save current batch" action.
fn templates_menu(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let mut col = column![section_label(
        t,
        &format!("Your templates · {}", app.templates.len())
    )]
    .spacing(4)
    .width(Length::Fill);

    if app.templates.is_empty() {
        col = col.push(Space::new().height(6)).push(
            text("Save the current batch below to reuse it later.")
                .size(11)
                .color(t.sub)
                .font(mono()),
        );
    } else {
        for (i, tpl) in app.templates.iter().enumerate() {
            let renaming = (app.rename_idx == Some(i)).then_some(app.rename_buf.as_str());
            col = col
                .push(Space::new().height(2))
                .push(template_row(t, i, tpl, renaming));
        }
    }

    // Save action.
    let count = app.batch.len();
    let save_enabled = count > 0;
    let save_label = if save_enabled {
        format!("+ Save current batch · {count} calls")
    } else {
        "+ Save current batch · queue is empty".to_string()
    };
    let save_btn = button(
        container(
            text(save_label)
                .size(14)
                .color(if save_enabled { t.up } else { t.sub })
                .font(bold()),
        )
        .center_x(Length::Fill),
    )
    .padding(Padding::from([13, 14]))
    .width(Length::Fill)
    .on_press_maybe(save_enabled.then_some(Message::SaveTemplate))
    .style(move |_, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered if save_enabled => with_alpha(t.up, 0.06),
            _ => Color::TRANSPARENT,
        })),
        text_color: if save_enabled { t.up } else { t.sub },
        border: Border {
            color: if save_enabled {
                with_alpha(t.up, 0.5)
            } else {
                t.border
            },
            width: 1.5,
            radius: Radius::from(12),
        },
        ..Default::default()
    });

    col = col
        .push(Space::new().height(12))
        .push(divider(t))
        .push(Space::new().height(12))
        .push(save_btn);

    container(col.padding(Padding::from([14, 16])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(16),
            },
            ..Default::default()
        })
        .into()
}

/// One saved-template entry. Normally a clickable load row with rename (✎) and
/// delete (✕) buttons; while `renaming` is `Some(buf)` the name becomes an
/// inline text input with commit (✓) / cancel (✕) actions.
fn template_row<'a>(
    t: KaoTheme,
    index: usize,
    tpl: &Template,
    renaming: Option<&str>,
) -> Element<'a, Message> {
    // The chain is on the row because it is load-blocking: a template only
    // loads on the network it was composed for, and the user should be able to
    // see which that is before clicking rather than after the refusal. One
    // saved before the chain was recorded says exactly that — naming a chain it
    // never recorded would be the same false assertion the load path refuses.
    let subtitle = format!(
        "{} call{} · {}",
        tpl.call_count,
        if tpl.call_count == 1 { "" } else { "s" },
        tpl.chain().map_or_else(
            || "network not recorded".to_string(),
            |c| crate::chain::NetworkId::Builtin(c)
                .display_name()
                .to_string()
        ),
    );
    let kao = container(text(tpl.kaomoji.clone()).size(15).color(t.a1).font(mono()))
        .width(Length::Fixed(46.0));

    match renaming {
        Some(buf) => {
            let field = column![
                text_input("template name", buf)
                    .on_input(Message::RenameChanged)
                    .on_submit(Message::CommitRename)
                    .padding(Padding::from([6, 9]))
                    .size(13)
                    .style(move |_, s| text_input_style(t, s)),
                text(subtitle).size(11).color(t.sub).font(mono()),
            ]
            .spacing(3)
            .width(Length::Fill);
            row![
                kao,
                Space::new().width(6),
                field,
                Space::new().width(4),
                icon_btn(t, "✓", true, true, Message::CommitRename),
                icon_btn(t, "✕", true, false, Message::CancelRename),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill)
            .into()
        }
        None => {
            let load_btn = button(
                row![
                    kao,
                    Space::new().width(6),
                    column![
                        text(tpl.name.clone()).size(13).color(t.text).font(bold()),
                        text(subtitle).size(11).color(t.sub).font(mono()),
                    ]
                    .spacing(1)
                    .width(Length::Fill),
                ]
                .align_y(Alignment::Center)
                .width(Length::Fill),
            )
            .padding(Padding::from([8, 9]))
            .width(Length::Fill)
            .on_press(Message::LoadTemplate(index))
            .style(move |_, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered => with_alpha(t.text, 0.04),
                    _ => Color::TRANSPARENT,
                })),
                text_color: t.text,
                border: Border {
                    radius: Radius::from(10),
                    ..Default::default()
                },
                ..Default::default()
            });
            row![
                load_btn,
                Space::new().width(4),
                icon_btn(t, "✎", true, false, Message::StartRename(index)),
                icon_btn(t, "✕", true, false, Message::DeleteTemplate(index)),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill)
            .into()
        }
    }
}

// ============================================================================
// Batch pane (right)
// ============================================================================

fn batch_pane(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let count = app.batch.len();
    let head = row![
        text("Batch").size(18).color(t.text).font(bold()),
        Space::new().width(9),
        count_chip(t, count),
        Space::new().width(Length::Fill),
        templates_button(app, t),
        Space::new().width(8),
        ghost_button(t, text("clear").size(11).color(t.sub).font(mono()))
            .on_press_maybe((count > 0).then_some(Message::ClearBatch)),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let mut inner = column![head].width(Length::Fill);

    // What became of the last batch, above everything else. The composer used
    // to report an outcome only by emptying itself, which is what a cancel
    // looks like too.
    if let Some(settled) = app.visible_settled() {
        inner = inner
            .push(Space::new().height(12))
            .push(settled_strip(t, settled));
    }

    // The template menu expands inline beneath the header (same pattern as the
    // network switcher / method picker).
    if app.template_menu_open {
        inner = inner
            .push(Space::new().height(10))
            .push(templates_menu(app, t));
    }

    let list: Element<'_, Message> = if app.batch.is_empty() {
        empty_state(app, t)
    } else {
        let mut col = column![].spacing(8).width(Length::Fill);
        for (i, c) in app.batch.iter().enumerate() {
            col = col.push(tx_card(app, t, i, c));
        }
        col.into()
    };

    inner = inner.push(Space::new().height(14)).push(list);

    if let Some(sim) = &app.sim
        && !app.batch.is_empty()
    {
        inner = inner
            .push(Space::new().height(12))
            .push(sim_strip(app, t, sim));
    }

    // flash-approval toggle: only when the batch can batch (Safe / 7702 EOA)
    // and there's actually an allowance to revoke.
    let targets = app.revoke_targets();
    if app.can_batch() && !targets.is_empty() {
        inner = inner
            .push(Space::new().height(14))
            .push(revoke_toggle(app, t, targets.len()));
    }

    // footer
    inner = inner
        .push(Space::new().height(14))
        .push(divider(t))
        .push(Space::new().height(12));

    let sim_label = if app.sim_busy {
        "Simulating…"
    } else {
        "⟁ Simulate"
    };
    let footer_row = row![
        ghost_secondary(
            t,
            sim_label,
            (!app.batch.is_empty() && !app.sim_busy).then_some(Message::Simulate)
        ),
        Space::new().width(8),
        ghost_secondary(
            t,
            "⤓ Save",
            (!app.batch.is_empty()).then_some(Message::OpenSave)
        ),
        Space::new().width(8),
        ghost_secondary(t, "⤒ Load", Some(Message::OpenLoad)),
    ]
    .width(Length::Fill);

    let cta_enabled = !app.batch.is_empty();
    let cta_label = if !app.ctx.is_safe {
        "Review & send".to_string()
    } else if count > 0 {
        format!("Create batch · {count} → 1")
    } else {
        "Create batch".to_string()
    };
    let cta = primary_owned(
        t,
        cta_label,
        cta_enabled,
        cta_enabled.then_some(Message::Review),
    );

    inner = inner
        .push(footer_row)
        .push(Space::new().height(9))
        .push(cta);

    pane_card(t, inner.into())
}

/// Flash-approval toggle: append `approve(spender, 0)` revokes after the batch
/// so no allowance survives the transaction. `n` is the number of allowances
/// that would be reset.
/// The persistent outcome strip. Stays until dismissed: a mined batch's hash is
/// the only handle the user has on it afterwards, and a proposal's nonce is the
/// only thing that distinguishes "filed for co-signers" from "the overlay
/// closed and I don't know why".
fn settled_strip<'a>(t: KaoTheme, settled: &super::Settled) -> Element<'a, Message> {
    // Green for the two outcomes that went to plan, the warning colour for the
    // two that did not — a reverted batch rendered in the success palette is
    // the same class of lie as reporting a broadcast hash as a win.
    let good = matches!(
        settled,
        super::Settled::Executed { .. }
            | super::Settled::Proposed { .. }
            | super::Settled::Revoked { .. }
    );
    let accent = if good { t.up } else { t.down };
    let copy = || -> Option<Element<'a, Message>> {
        Some(ghost_secondary(t, "⧉ Copy hash", Some(Message::CopySettledHash)).into())
    };
    let (title, body, action): (String, String, Option<Element<'a, Message>>) = match settled {
        super::Settled::Executed { hash } => {
            ("Batch executed".to_string(), format!("{hash:#x}"), copy())
        }
        super::Settled::Revoked { hash } => (
            "Delegation removed".to_string(),
            format!("{hash:#x}\nThis account is a plain EOA again."),
            copy(),
        ),
        super::Settled::Proposed { nonce } => (
            "Batch queued for co-signers".to_string(),
            format!(
                "Filed at nonce {nonce}. It executes once enough owners confirm it — nothing                  has been sent yet."
            ),
            None,
        ),
        super::Settled::Reverted { hash } => (
            "Batch reverted".to_string(),
            format!(
                "{hash:#x}\nEvery call was rolled back and the gas was spent. The batch is still \
                 in the composer — fix it and review again."
            ),
            copy(),
        ),
        super::Settled::Unconfirmed { hash } => (
            "Broadcast — outcome unknown".to_string(),
            format!(
                "{hash:#x}\nNo receipt came back in time. This transaction may still be pending \
                 and may mine at any moment. Look the hash up before you run this batch again — \
                 rebuilding it now could execute it twice."
            ),
            copy(),
        ),
    };
    let mut col = column![
        row![
            text(title).size(12).color(accent).font(bold()),
            Space::new().width(Length::Fill),
            ghost_button(t, text("✕").size(11).color(t.sub).font(mono()))
                .on_press(Message::DismissSettled),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
        Space::new().height(3),
        text(body).size(10).color(t.sub).font(mono()),
    ]
    .width(Length::Fill);
    if let Some(a) = action {
        col = col.push(Space::new().height(8)).push(a);
    }
    container(col.padding(Padding::from([12, 14])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(accent, 0.08))),
            border: Border {
                color: with_alpha(accent, 0.4),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

fn revoke_toggle(app: &TxBuilderApp, t: KaoTheme, n: usize) -> Element<'_, Message> {
    let cb = kao_checkbox(t, app.auto_revoke)
        .label("Revoke approvals after batch")
        .on_toggle(Message::ToggleAutoRevoke)
        .size(16)
        .spacing(10)
        .text_size(13);
    let hint = if app.auto_revoke {
        // Both ends, because the wrap has two: the opening reset is what makes
        // the batch survive a zero-first token, and it is also the call the
        // user will see in the review that they did not compose.
        let opens = super::flash_approval::prepend_count(&app.batch);
        format!(
            "+{opens} reset before · +{n} revoke{} after · allowance ends at 0",
            if n == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "leaves {n} standing allowance{}",
            if n == 1 { "" } else { "s" }
        )
    };
    column![
        cb,
        row![
            Space::new().width(26),
            text(hint).size(11).color(t.sub).font(mono()),
        ]
        .align_y(Alignment::Center),
    ]
    .spacing(4)
    .width(Length::Fill)
    .into()
}

fn tx_card<'a>(
    app: &'a TxBuilderApp,
    t: KaoTheme,
    index: usize,
    c: &'a super::QueuedCall,
) -> Element<'a, Message> {
    let total = app.batch.len();
    let open = app.expanded == Some(c.id);

    let idx_chip = container(
        text((index + 1).to_string())
            .size(12)
            .color(Color::WHITE)
            .font(mono_bold()),
    )
    .width(Length::Fixed(24.0))
    .height(Length::Fixed(24.0))
    .align_x(iced::alignment::Horizontal::Center)
    .align_y(iced::alignment::Vertical::Center)
    .style(move |_| container::Style {
        background: Some(Background::Color(t.a1)),
        border: Border {
            radius: Radius::from(8),
            ..Default::default()
        },
        ..Default::default()
    });

    let info = column![
        text(c.title.clone())
            .size(13)
            .color(t.text)
            .font(mono_bold()),
        text(c.detail.clone()).size(11).color(t.sub),
    ]
    .spacing(1)
    .width(Length::Fill);

    let mut top = row![idx_chip, Space::new().width(11), info]
        .align_y(Alignment::Center)
        .width(Length::Fill);

    if c.is_raw() {
        top = top.push(Space::new().width(6)).push(pill(t, "raw", t.a2));
    }
    if !c.value.is_zero() {
        top = top.push(Space::new().width(6)).push(pill(
            t,
            &format!("{} Ξ", wei_to_eth(c.value)),
            t.a3,
        ));
    }

    top = top
        .push(Space::new().width(6))
        .push(icon_btn(t, "↑", index > 0, false, Message::MoveUp(c.id)))
        .push(icon_btn(
            t,
            "↓",
            index + 1 < total,
            false,
            Message::MoveDown(c.id),
        ))
        .push(icon_btn(t, "</>", true, open, Message::ToggleExpand(c.id)))
        .push(icon_btn(t, "✕", true, false, Message::RemoveCall(c.id)));

    let mut inner = column![top].width(Length::Fill);
    // A call addressed to the signing account gets its warning here, in the
    // queue, and not only on the review overlay. The queue is where an imported
    // bundle first becomes visible, and it is the last point at which removing
    // one call is a single click rather than a re-composition.
    let self_admin = app.self_admin_note(c);
    if let Some(note) = &self_admin {
        inner = inner.push(Space::new().height(8)).push(
            container(
                column![
                    text("⚠ Targets the signing account")
                        .size(11)
                        .color(t.down)
                        .font(mono_bold()),
                    Space::new().height(2),
                    text(note.clone()).size(10).color(t.text).font(mono()),
                ]
                .width(Length::Fill),
            )
            .padding(Padding::from([8, 10]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.down, 0.10))),
                border: Border {
                    color: t.down,
                    width: 1.0,
                    radius: Radius::from(10),
                },
                ..Default::default()
            }),
        );
    }
    if open {
        inner = inner
            .push(Space::new().height(10))
            .push(decoded_panel(t, c));
    }

    let outline = if self_admin.is_some() {
        t.down
    } else {
        t.border
    };
    container(inner.padding(Padding::from([11, 12])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: outline,
                width: 1.0,
                radius: Radius::from(14),
            },
            ..Default::default()
        })
        .into()
}

fn decoded_panel<'a>(t: KaoTheme, c: &'a super::QueuedCall) -> Element<'a, Message> {
    let mut lines = column![].spacing(2).width(Length::Fill);
    let comment = move |s: &str| {
        text(s.to_string())
            .size(11)
            .color(terminal_muted(t))
            .font(mono())
    };
    let val = move |s: String| {
        text(s)
            .size(11)
            .color(t.a1)
            .font(mono())
            .wrapping(Wrapping::WordOrGlyph)
    };

    // Every value here is a long, space-free mono string (address, hex
    // calldata, big integers). iced's default text wrapping is `Word`, which
    // only breaks on spaces — so these would overflow the card. Each value is
    // given width(Fill) plus `WordOrGlyph` wrapping so it falls back to a
    // per-glyph break and wraps within the terminal box instead of spilling
    // past the card.
    lines = lines.push(comment("// target"));
    lines = lines.push(
        text(c.to.to_string())
            .size(11)
            .color(terminal_fg(t))
            .font(mono())
            .wrapping(Wrapping::WordOrGlyph)
            .width(Length::Fill),
    );

    if let Some(sig) = &c.signature {
        if let Some(sel) = c.selector() {
            lines = lines
                .push(Space::new().height(6))
                .push(comment(&format!(
                    "// function · selector 0x{}",
                    alloy::hex::encode(sel)
                )))
                .push(
                    text(sig.clone())
                        .size(11)
                        .color(t.a2)
                        .font(mono())
                        .wrapping(Wrapping::WordOrGlyph)
                        .width(Length::Fill),
                );
        }
        if !c.decoded_args.is_empty() {
            lines = lines.push(Space::new().height(6)).push(comment("// args"));
            for a in &c.decoded_args {
                lines = lines
                    .push(
                        text(format!("{} =", a.name))
                            .size(11)
                            .color(terminal_fg(t))
                            .font(mono()),
                    )
                    .push(val(a.value.clone()).width(Length::Fill));
            }
        }
    }
    if !c.value.is_zero() {
        lines = lines
            .push(Space::new().height(6))
            .push(comment("// value"))
            .push(
                text(format!("{} wei", c.value))
                    .size(11)
                    .color(t.a3)
                    .font(mono())
                    .wrapping(Wrapping::WordOrGlyph)
                    .width(Length::Fill),
            );
    }
    lines = lines
        .push(Space::new().height(6))
        .push(comment("// calldata"))
        .push(
            text(if c.data.is_empty() {
                "0x".to_string()
            } else {
                format!("0x{}", alloy::hex::encode(&c.data))
            })
            .size(11)
            .color(t.a3)
            .font(mono())
            .wrapping(Wrapping::WordOrGlyph)
            .width(Length::Fill),
        );

    container(lines.padding(Padding::from([11, 13])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(terminal_bg(t))),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(10),
            },
            ..Default::default()
        })
        .into()
}

fn sim_strip<'a>(
    app: &TxBuilderApp,
    t: KaoTheme,
    sim: &super::BatchSimResult,
) -> Element<'a, Message> {
    let fit = sim.gas_fit();
    // A batch that cannot be mined is not a green strip, whatever the sub-calls
    // did — the sum is the part the simulator was never asked about.
    let ok = sim.is_success() && !matches!(fit, GasFit::Exceeds { .. });
    let (title, sub) = match &sim.outcome {
        BatchOutcome::Success => {
            // Approximate fee = metered gas × the block's base fee (excludes tip
            // + the execTransaction wrapper; the real quote is at execute time).
            let fee = alloy::primitives::U256::from(sim.gas_used)
                .saturating_mul(alloy::primitives::U256::from(sim.base_fee_per_gas));
            let sub = if sim.base_fee_per_gas > 0 {
                format!("≈ {} gas · {} ETH", sim.gas_used, wei_to_eth(fee))
            } else {
                format!("≈ {} gas", sim.gas_used)
            };
            let sub = match fit {
                GasFit::Exceeds {
                    block_gas_limit, ..
                } => format!(
                    "{sub} · OVER the {block_gas_limit} block gas limit — this cannot be \
                     mined; split the batch"
                ),
                GasFit::Crowded {
                    block_gas_limit, ..
                } => format!(
                    "{sub} · over half the {block_gas_limit} block gas limit, and the wrapper \
                     isn't counted here"
                ),
                GasFit::Fits | GasFit::Unknown => sub,
            };
            let title = if matches!(fit, GasFit::Exceeds { .. }) {
                "Too large to mine".to_string()
            } else {
                "Simulation passed".to_string()
            };
            (title, sub)
        }
        // The simulator indexes the *effective* calls, which with flash
        // approval on is not the numbering on the cards beside this strip —
        // `#3` over a two-card queue pointed at a call the user can't see.
        BatchOutcome::Revert { step, reason } => (
            format!("Reverts at {}", app.describe_step(*step)),
            reason.clone(),
        ),
        BatchOutcome::Halt { step, reason } => (
            format!("Halts at {}", app.describe_step(*step)),
            reason.clone(),
        ),
        // Why it couldn't run, rather than the bare shrug that used to send
        // the user back to re-run something that can't succeed.
        BatchOutcome::Error(reason) => ("Preflight couldn't run".to_string(), reason.clone()),
        BatchOutcome::Unavailable => (
            "Simulation unavailable".to_string(),
            "couldn't run preflight on this network".to_string(),
        ),
    };
    let color = if ok { t.up } else { t.down };
    // A verdict is a claim about execution, and this box was making it flat.
    // Only attached where execution actually happened: `Unavailable` and
    // `Error` ran nothing, so there is no claim to qualify.
    let ran = matches!(
        sim.outcome,
        BatchOutcome::Success | BatchOutcome::Revert { .. } | BatchOutcome::Halt { .. }
    );
    let blind_spots = if ran {
        app.sim_blind_spots()
    } else {
        Vec::new()
    };
    let body = column![
        row![
            text(title).size(12).color(color).font(bold()),
            Space::new().width(Length::Fill),
            // The height the verdict is about. Without it, a pass taken
            // twenty minutes ago is indistinguishable from one taken now.
            text(if sim.block > 0 {
                format!(
                    "{} · block {}",
                    if sim.verified {
                        "verified"
                    } else {
                        "unverified"
                    },
                    sim.block
                )
            } else {
                (if sim.verified {
                    "verified"
                } else {
                    "unverified"
                })
                .to_string()
            })
            .size(10)
            .color(t.sub)
            .font(mono()),
        ]
        .width(Length::Fill),
        text(sub).size(10).color(t.sub).font(mono()),
    ]
    .spacing(4)
    .width(Length::Fill);

    let body = if blind_spots.is_empty() {
        body
    } else {
        let mut list = column![
            Space::new().height(3),
            text("Not modelled by this preflight")
                .size(10)
                .color(t.sub)
                .font(bold()),
        ]
        .spacing(3)
        .width(Length::Fill);
        for item in blind_spots {
            list = list.push(text(format!("· {item}")).size(10).color(t.sub));
        }
        body.push(list)
    };

    container(body.padding(Padding::from([11, 13])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(color, 0.10))),
            border: Border {
                color: with_alpha(color, 0.4),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

fn empty_state(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let mut col = column![
        text("Batch is empty").size(14).color(t.text).font(bold()),
        Space::new().height(6),
        text("Compose a call on the left and hit “Add to batch” to queue it here.")
            .size(12)
            .color(t.sub),
    ]
    .align_x(Alignment::Center)
    .width(Length::Fill);
    // Sample only makes sense on Mainnet (uses Mainnet known contracts).
    if app.net.builtin() == Some(crate::chain::Chain::Mainnet) && app.ctx.is_safe {
        col = col.push(Space::new().height(14)).push(ghost_secondary(
            t,
            "Load a sample batch",
            Some(Message::LoadSample),
        ));
    }
    container(col.padding(Padding::from([40, 16])))
        .center_x(Length::Fill)
        .width(Length::Fill)
        .into()
}

// ============================================================================
// JSON modal
// ============================================================================

/// A bounded, scrolling terminal box for a JSON body.
///
/// The scrollable is given a Fill width (and the text too) so it spans the whole
/// panel — otherwise it shrinks to the widest JSON line and parks the scrollbar
/// mid-panel instead of at the right edge. `WordOrGlyph` wraps any long,
/// space-free value line (a big `data` hex) so nothing is clipped off the right.
/// Owned `String` so both callers can pass a clone rather than borrow the app
/// across the modal's lifetime.
fn json_box<'a>(t: KaoTheme, body: String, height: f32) -> Element<'a, Message> {
    container(
        scrollable(
            text(body)
                .size(11)
                .color(terminal_fg(t))
                .font(mono())
                .wrapping(Wrapping::WordOrGlyph)
                .width(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fixed(height))
        .style(move |_, s| kao_scrollable_style(t, s)),
    )
    .padding(Padding::from([12, 14]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(terminal_bg(t))),
        border: Border {
            color: t.border,
            width: 1.0,
            radius: Radius::from(12),
        },
        ..Default::default()
    })
    .into()
}

fn modal_view(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let is_save = app.modal == Modal::Save;
    let title = if is_save {
        "Export batch"
    } else {
        "Import batch"
    };
    let sub = if is_save {
        "Safe-compatible transaction bundle · JSON"
    } else {
        "Paste a bundle to reconstruct it"
    };

    let head = row![
        column![
            text(title).size(17).color(t.text).font(bold()),
            text(sub).size(11).color(t.sub).font(mono()),
        ]
        .spacing(2),
        Space::new().width(Length::Fill),
        ghost_button(t, text("✕").size(14).color(t.sub)).on_press(Message::CloseModal),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let editor: Element<'_, Message> = if is_save {
        json_box(t, app.json_text.clone(), 280.0)
    } else {
        let field = text_input("paste the batch JSON here…", &app.json_text)
            .on_input(Message::JsonChanged)
            .padding(Padding::from([12, 14]))
            .size(12)
            .font(mono())
            .style(move |_, s| {
                let mut b = text_input_style(t, s);
                if app.json_error.is_some() {
                    b.border.color = t.down;
                }
                b
            });
        // The export side has always had a bounded, scrolling box; the import
        // side showed the same JSON as one long horizontal ribbon in a
        // single-line field. Reading what you are about to load matters at
        // least as much as reading what you just wrote.
        let mut c = column![field].width(Length::Fill);
        if !app.json_text.trim().is_empty() {
            c = c
                .push(Space::new().height(10))
                .push(json_box(t, app.json_text.clone(), 200.0));
        }
        c.into()
    };

    let mut col = column![head, Space::new().height(16), editor].width(Length::Fill);

    if let Some(err) = &app.json_error {
        col = col
            .push(Space::new().height(8))
            .push(text(err.clone()).size(12).color(t.down).font(bold()));
    }

    // The ghost button's padding is bumped so it matches the taller primary CTA
    // beside it (primary: text 16 + inner pad 13 + button pad 5 ≈ 57px; ghost:
    // text 13 + button pad 20 ≈ 57px) — otherwise the two render at different
    // heights. Can't use height(Fill): the ghost is laid out before the natural
    // primary sets the row's cross size, so it would collapse to nothing.
    let ghost_pad = Padding::from([20, 12]);
    let actions: Element<'_, Message> = if is_save {
        row![
            ghost_secondary(t, "Copy JSON", Some(Message::CopyJson)).padding(ghost_pad),
            Space::new().width(9),
            primary_button(t, "Done", true)
                .width(Length::Fill)
                .on_press(Message::CloseModal),
        ]
        .width(Length::Fill)
        .into()
    } else {
        let can = !app.json_text.trim().is_empty();
        row![
            ghost_secondary(t, "Cancel", Some(Message::CloseModal)).padding(ghost_pad),
            Space::new().width(9),
            primary_button(t, "Load batch →", can)
                .width(Length::Fill)
                .on_press_maybe(can.then_some(Message::ImportJson)),
        ]
        .width(Length::Fill)
        .into()
    };

    col = col.push(Space::new().height(16)).push(actions);

    // Center the bounded card in the full pane width. `center_x` + `max_width`
    // on one container would only cap it to 620 and pin it left (centering just
    // the card *inside* that 620 box); the centering has to live on a separate
    // full-width outer container.
    let modal_card = container(card(t, col.into()))
        .width(Length::Fill)
        .max_width(620);
    container(modal_card)
        .center_x(Length::Fill)
        .padding(Padding::from([10, 0]))
        .into()
}

// ============================================================================
// Small styling helpers
// ============================================================================

/// A primary (accent-fill) button with an owned label, for dynamic text
/// the borrow-checked `primary_button(&'a str)` helper can't take.
fn primary_owned<'a>(
    t: KaoTheme,
    label: String,
    enabled: bool,
    msg: Option<Message>,
) -> Element<'a, Message> {
    let fg = if enabled { Color::WHITE } else { t.sub };
    let mut b =
        button(container(text(label).size(16).color(fg).font(black())).center_x(Length::Fill))
            .padding(Padding::from([12, 16]))
            .width(Length::Fill)
            .style(move |_, _| button::Style {
                background: Some(Background::Color(if enabled { t.a1 } else { t.border })),
                text_color: fg,
                border: Border {
                    radius: Radius::from(12),
                    ..Default::default()
                },
                ..Default::default()
            });
    if let Some(m) = msg {
        b = b.on_press(m);
    }
    b.into()
}

fn card<'a>(t: KaoTheme, body: Element<'a, Message>) -> Element<'a, Message> {
    container(body)
        .padding(Padding::from([18, 20]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(18),
            },
            text_color: Some(t.text),
            ..Default::default()
        })
        .into()
}

/// A full-height pane card (composer / batch). Unlike [`card`], it fills the
/// row height — so the two side-by-side panes are always the same height — and
/// scrolls its own overflow internally. The Transaction Builder therefore opts
/// out of the shared page scroll so these panes are handed a bounded height to
/// fill (a scrollable would give them an unbounded one, collapsing the fill).
fn pane_card<'a>(t: KaoTheme, body: Element<'a, Message>) -> Element<'a, Message> {
    let scroller = scrollable(
        container(body)
            .padding(Padding::from([18, 20]))
            .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(move |_, s| kao_scrollable_style(t, s));

    container(scroller)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(18),
            },
            text_color: Some(t.text),
            ..Default::default()
        })
        .into()
}

fn divider<'a>(t: KaoTheme) -> Element<'a, Message> {
    container(Space::new().height(1).width(Length::Fill))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.border)),
            ..Default::default()
        })
        .into()
}

fn labelled<'a>(t: KaoTheme, label: &str, field: Element<'a, Message>) -> Element<'a, Message> {
    column![section_label(t, label), Space::new().height(8), field]
        .width(Length::Fill)
        .into()
}

fn section_label<'a>(t: KaoTheme, s: &str) -> Element<'a, Message> {
    text(s.to_uppercase())
        .size(10)
        .color(t.sub)
        .font(mono_bold())
        .into()
}

fn pill<'a>(_t: KaoTheme, label: &str, color: Color) -> Element<'a, Message> {
    container(
        text(label.to_string())
            .size(10)
            .color(color)
            .font(mono_bold()),
    )
    .padding(Padding::from([2, 7]))
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(color, 0.10))),
        border: Border {
            color: with_alpha(color, 0.35),
            width: 1.0,
            radius: Radius::from(6),
        },
        ..Default::default()
    })
    .into()
}

fn chip<'a>(
    t: KaoTheme,
    body: Element<'a, Message>,
    bg: Color,
    border: Color,
) -> Element<'a, Message> {
    let _ = t;
    container(body)
        .padding(Padding::from([7, 12]))
        .style(move |_| container::Style {
            background: Some(Background::Color(bg)),
            border: Border {
                color: border,
                width: 1.0,
                radius: Radius::from(11),
            },
            ..Default::default()
        })
        .into()
}

fn count_chip<'a>(t: KaoTheme, n: usize) -> Element<'a, Message> {
    container(
        text(n.to_string())
            .size(12)
            .color(Color::WHITE)
            .font(mono_bold()),
    )
    .width(Length::Fixed(24.0))
    .height(Length::Fixed(24.0))
    .align_x(iced::alignment::Horizontal::Center)
    .align_y(iced::alignment::Vertical::Center)
    .style(move |_| container::Style {
        background: Some(Background::Color(if n > 0 { t.a1 } else { t.sub })),
        border: Border {
            radius: Radius::from(8),
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

fn mode_tab<'a>(t: KaoTheme, label: &'a str, on: bool, msg: Message) -> Element<'a, Message> {
    button(
        text(label.to_string())
            .size(12)
            .color(if on { Color::WHITE } else { t.sub })
            .font(mono_bold()),
    )
    .padding(Padding::from([6, 13]))
    .on_press(msg)
    .style(move |_, _| button::Style {
        background: Some(Background::Color(if on {
            t.a1
        } else {
            Color::TRANSPARENT
        })),
        text_color: if on { Color::WHITE } else { t.sub },
        border: Border {
            radius: Radius::from(8),
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

fn bool_btn<'a>(t: KaoTheme, label: &'a str, on: bool, msg: Message) -> Element<'a, Message> {
    button(
        text(label.to_string())
            .size(13)
            .color(if on { t.a1 } else { t.sub })
            .font(mono()),
    )
    .padding(Padding::from([9, 0]))
    .width(Length::Fill)
    .on_press(msg)
    .style(move |_, _| button::Style {
        background: Some(Background::Color(if on {
            with_alpha(t.a1, 0.12)
        } else {
            t.card_alt
        })),
        text_color: if on { t.a1 } else { t.sub },
        border: Border {
            color: if on { t.a1 } else { t.border },
            width: 1.5,
            radius: Radius::from(10),
        },
        ..Default::default()
    })
    .into()
}

fn icon_btn<'a>(
    t: KaoTheme,
    glyph: &'a str,
    enabled: bool,
    active: bool,
    msg: Message,
) -> Element<'a, Message> {
    let color = if !enabled {
        t.sub
    } else if glyph == "✕" {
        t.down
    } else if active {
        t.a1
    } else {
        t.sub
    };
    let mut b = button(
        // Center the glyph in the 24×24 box — placed raw, each glyph
        // (↑ ↓ </> ✕) sits at its own baseline and they look misaligned.
        container(
            text(glyph.to_string())
                .size(11)
                .color(color)
                .font(mono_bold()),
        )
        .center_x(Length::Fill)
        .center_y(Length::Fill),
    )
    .width(24)
    .height(24)
    .padding(0)
    .style(move |_, status| button::Style {
        background: Some(Background::Color(if active {
            with_alpha(t.a1, 0.12)
        } else {
            match status {
                button::Status::Hovered if enabled => with_alpha(t.text, 0.06),
                _ => Color::TRANSPARENT,
            }
        })),
        text_color: color,
        border: Border {
            radius: Radius::from(7),
            ..Default::default()
        },
        ..Default::default()
    });
    if enabled {
        b = b.on_press(msg);
    }
    b.into()
}

/// A ghost/secondary flat button used in the batch footer and modal.
/// Returns the `Button` (not an `Element`) so callers can chain sizing — e.g.
/// `.padding(...)` to grow it to a taller primary button's height beside it. It
/// still drops into any `row!`/`push` position via `Into<Element>`.
fn ghost_secondary<'a>(
    t: KaoTheme,
    label: &'a str,
    msg: Option<Message>,
) -> button::Button<'a, Message> {
    let enabled = msg.is_some();
    let mut b = button(
        container(
            text(label.to_string())
                .size(13)
                .color(if enabled { t.text } else { t.sub })
                .font(bold()),
        )
        .center_x(Length::Fill),
    )
    .padding(Padding::from([10, 12]))
    .width(Length::Fill)
    .style(move |_, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered if enabled => with_alpha(t.text, 0.05),
            _ => Color::TRANSPARENT,
        })),
        text_color: if enabled { t.text } else { t.sub },
        border: Border {
            color: t.border,
            width: 1.0,
            radius: Radius::from(12),
        },
        ..Default::default()
    });
    if let Some(m) = msg {
        b = b.on_press(m);
    }
    b
}

fn info_box<'a>(t: KaoTheme, msg: &str, accent: Color) -> Element<'a, Message> {
    container(text(msg.to_string()).size(12).color(t.sub).font(bold()))
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: with_alpha(accent, 0.3),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

fn contract_banner<'a>(t: KaoTheme, c: &'a super::LoadedContract) -> Element<'a, Message> {
    let badge = match c.source {
        AbiSource::Known => pill(t, "✓ verified", t.up),
        AbiSource::Sourcify => pill(t, "✓ Sourcify", t.up),
        AbiSource::Etherscan => pill(t, "✓ Etherscan", t.up),
        AbiSource::Pasted => pill(t, "pasted ABI", t.a2),
        // Guard first: a menu authored during a light-client cooldown came off
        // an untrusted endpoint, and used to be badged identically to one the
        // light client proved.
        AbiSource::Bytecode if !c.code_verified => pill(t, "⚠ unverified bytecode", t.down),
        AbiSource::Bytecode => pill(t, "from bytecode", t.a3),
    };
    let counts = format!("{} write · {} read", c.methods.len(), c.read_methods.len());
    let subtitle = if c.label.is_empty() {
        counts
    } else {
        format!("{} · {counts}", c.label)
    };
    let mut info = column![
        row![
            text(c.name.clone()).size(13).color(t.text).font(bold()),
            Space::new().width(8),
            badge,
        ]
        .align_y(Alignment::Center),
        text(subtitle).size(10).color(t.sub).font(mono()),
    ]
    .spacing(2)
    .width(Length::Fill);

    // Where the selectors came from, when that isn't the address being called.
    if let Some(impl_addr) = c.proxy_impl {
        info = info.push(
            text(format!(
                "proxy → {}",
                crate::wallet::short_address(impl_addr)
            ))
            .size(10)
            .color(t.a3)
            .font(mono()),
        );
    }

    // Brand kaomoji for a known contract, if any.
    let head: Element<'a, Message> = if let Some(kao) = c.kaomoji {
        row![
            avatar(t, kao, 34.0, with_alpha(t.a1, 0.12)),
            Space::new().width(11),
            info
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
    } else {
        info.into()
    };

    container(head)
        .padding(Padding::from([11, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a1, 0.10))),
            border: Border {
                color: with_alpha(t.a1, 0.3),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

/// The proxy walk found an implementation pointer but could only read it over
/// unverified RPC, so it wasn't followed. Says so rather than letting a
/// near-empty ABI look like the contract's real surface.
fn proxy_unverified_note(t: KaoTheme) -> Element<'static, Message> {
    info_box(
        t,
        "This address looks like a proxy, but its implementation slot could \
         only be read over unverified RPC — Kao won't follow that pointer. \
         Paste the implementation's ABI to compose against it.",
        t.down,
    )
}

/// The composer couldn't *reach* the contract's code. Deliberately not the
/// "No verified ABI" box: that one is a fact about the contract and its answer
/// is to paste an ABI by hand, which is the wrong move — and a lot of work —
/// when the real problem was a light-client hiccup on a well-known verified
/// address.
/// What is in the box can't be an address. No Retry — there is nothing to
/// retry, the text itself is the problem.
fn addr_error_box<'a>(t: KaoTheme, err: &str) -> Element<'a, Message> {
    let col = column![
        text("That isn't an address")
            .size(13)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text(capitalize_first(err)).size(12).color(t.sub),
    ]
    .width(Length::Fill);
    container(col.padding(Padding::from([13, 16])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.08))),
            border: Border {
                color: with_alpha(t.down, 0.4),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn resolve_error_box<'a>(app: &'a TxBuilderApp, t: KaoTheme, err: &'a str) -> Element<'a, Message> {
    let col = column![
        text("Couldn't read this contract")
            .size(13)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text(format!("{err}. The contract may still have a recoverable ABI — this says only that Kao couldn't fetch its code."))
            .size(12)
            .color(t.sub),
        Space::new().height(10),
        ghost_secondary(t, "↻ Retry", Some(Message::RetryResolve)),
        Space::new().height(8),
        fetch_abi_button(app, t),
        Space::new().height(8),
        abi_paste_block(app, t, "Paste ABI JSON"),
    ]
    .width(Length::Fill);
    container(col.padding(Padding::from([13, 16])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.08))),
            border: Border {
                color: with_alpha(t.down, 0.4),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

/// There is no contract at the address the user typed.
///
/// The wrong-chain paste is the most common way to lose money in a transaction
/// builder — a contract that exists on Mainnet and not on Base — and every
/// signal downstream reads as success: the ABI can be pasted by hand, the
/// preflight passes (a call to an account with no code *does* succeed, doing
/// nothing), and the receipt comes back status 1 with the ETH gone. Nothing
/// else in the flow will say this, so it is said here and kept on screen for as
/// long as it is true — a pasted ABI answers a different question and does not
/// retire it.
/// `address` is the *address* the field stands for, not the text in it. Callers
/// pass the resolved address when the box holds a name: this warning is about
/// an account having no code, so naming the label instead of the account would
/// leave the reader without the one value they can check against an explorer.
fn nothing_deployed_note<'a>(
    app: &'a TxBuilderApp,
    t: KaoTheme,
    address: &str,
) -> Element<'a, Message> {
    let col = column![
        text("⚠ Nothing is deployed at this address")
            .size(12)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text(format!(
            "{} has no contract code on {}. Calls to it will not revert — they succeed having \
             done nothing, and any ETH you attach is spent. Check the network, and check the \
             address.",
            address,
            app.net.display_name(),
        ))
        .size(11)
        .color(t.text),
    ]
    .width(Length::Fill);
    container(col.padding(Padding::from([10, 12])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.10))),
            border: Border {
                color: t.down,
                width: 1.0,
                radius: Radius::from(10),
            },
            ..Default::default()
        })
        .into()
}

/// The paste-box used to be the only way to overwrite a wrong bytecode
/// recovery. Sourcify / Etherscan is that overwrite now; the box stays as
/// the fallback when neither registry has the contract (or on a custom
/// network Sourcify doesn't know).
fn fetch_abi_button<'a>(app: &'a TxBuilderApp, t: KaoTheme) -> Element<'a, Message> {
    let label = if app.abi_fetching {
        "Fetching…"
    } else {
        "Fetch from Sourcify / Etherscan"
    };
    let ready = !app.abi_fetching && encode::parse_address(&app.addr_input).is_ok();
    ghost_secondary(t, label, ready.then_some(Message::FetchVerifiedAbi)).into()
}

/// The "Paste ABI JSON" button and, once armed, the box it opens.
///
/// One block rather than three copies, because the button used to be offered in
/// places the box was not: `resolve_error_box` rendered the button and nothing
/// listened — the paste input only existed inside `not_found_box`, so the
/// escape hatch offered on a failed fetch did visibly nothing. And a
/// successfully-loaded contract offered no way in at all, which made a wrong
/// bytecode recovery a dead end short of the Raw tab.
fn abi_paste_block<'a>(app: &'a TxBuilderApp, t: KaoTheme, label: &'a str) -> Element<'a, Message> {
    let mut col =
        column![ghost_secondary(t, label, Some(Message::ShowAbiPaste))].width(Length::Fill);
    if app.paste_open {
        col = col
            .push(Space::new().height(10))
            .push(
                text_input("[{\"type\":\"function\", …}]", &app.abi_paste)
                    .on_input(Message::AbiPasteChanged)
                    .padding(Padding::from([11, 13]))
                    .size(12)
                    .font(mono())
                    .style(move |_, s| text_input_style(t, s)),
            )
            .push(Space::new().height(8))
            .push(ghost_secondary(
                t,
                "Load ABI",
                (!app.abi_paste.trim().is_empty()).then_some(Message::LoadPastedAbi),
            ));
    }
    col.into()
}

fn not_found_box(app: &TxBuilderApp, t: KaoTheme) -> Element<'_, Message> {
    let mut col = column![
        text("No verified ABI for this address")
            .size(13)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text("Fetch a verified ABI from Sourcify or Etherscan, paste JSON, or switch to Raw hex to send custom calldata.")
            .size(12)
            .color(t.sub),
    ]
    .width(Length::Fill);

    // On a custom network this box is the whole answer — there is no registry
    // and no bytecode tier — so it is also where "there is no contract here"
    // has to be said.
    if app.nothing_deployed {
        col = col
            .push(Space::new().height(10))
            .push(nothing_deployed_note(app, t, app.addr_input.trim()));
    }

    if app.proxy_unverified {
        col = col
            .push(Space::new().height(8))
            .push(proxy_unverified_note(t));
    }

    if app.proxy_beacon {
        col = col.push(Space::new().height(8)).push(info_box(
            t,
            "This is a beacon proxy. Kao can see that it is one, but reading which \
             implementation it points at needs a call to the beacon contract, which the \
             proxy walker doesn't make yet — so paste the implementation's ABI to compose \
             against it.",
            t.a3,
        ));
    }

    col = col
        .push(Space::new().height(10))
        .push(fetch_abi_button(app, t))
        .push(Space::new().height(8))
        .push(abi_paste_block(app, t, "Paste ABI JSON"));

    container(col.padding(Padding::from([13, 16])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.08))),
            border: Border {
                color: with_alpha(t.down, 0.4),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

/// Standing notice that this EOA currently runs contract code via EIP-7702.
/// Offers a revoke when the signer can authorize one; otherwise names why not.
fn delegation_banner<'a>(app: &'a TxBuilderApp, t: KaoTheme) -> Element<'a, Message> {
    let delegate = app.current_delegation().expect("banner is gated on Some");
    let ef = crate::txbuilder::eip7702::EF_SIMPLE_7702_ACCOUNT;
    let body = if delegate == ef {
        "This account runs the batch executor (EIP-7702). Atomic batches stay available until you remove it — the delegation does not expire with the transaction that installed it.".to_string()
    } else {
        format!(
            "This account is delegated to {} — contract code another wallet installed. Kao did not set this. Removing it restores a plain EOA.",
            crate::wallet::short_address(delegate),
        )
    };
    let mut col = column![
        text("Account is delegated")
            .size(12)
            .color(t.a2)
            .font(bold()),
        Space::new().height(4),
        text(body)
            .size(11)
            .color(t.sub)
            .wrapping(Wrapping::WordOrGlyph),
    ]
    .width(Length::Fill);

    if app.can_revoke_delegation() {
        col = col.push(Space::new().height(10)).push(ghost_secondary(
            t,
            "Remove delegation",
            Some(Message::RevokeDelegation),
        ));
    } else if let Some(why) = app.revoke_block_reason() {
        col = col.push(Space::new().height(6)).push(
            text(why)
                .size(11)
                .color(t.sub)
                .wrapping(Wrapping::WordOrGlyph),
        );
    }

    container(col.padding(Padding::from([10, 14])))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a2, 0.08))),
            border: Border {
                color: with_alpha(t.a2, 0.35),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..Default::default()
        })
        .into()
}

/// A standing statement about the active identity, not a dismissible error:
/// nothing the user does in this pane clears it, so it has no ✕ and doesn't
/// share the `error` slot that a network switch or a bad argument writes to.
fn signing_block_banner<'a>(t: KaoTheme, msg: &str) -> Element<'a, Message> {
    container(
        row![
            text("Read-only here").size(12).color(t.a2).font(bold()),
            Space::new().width(10),
            text(msg.to_string()).size(11).color(t.sub),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .padding(Padding::from([10, 14]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.a2, 0.08))),
        border: Border {
            color: with_alpha(t.a2, 0.35),
            width: 1.0,
            radius: Radius::from(12),
        },
        ..Default::default()
    })
    .into()
}

fn error_banner<'a>(t: KaoTheme, msg: &str) -> Element<'a, Message> {
    button(
        row![
            text(msg.to_string()).size(12).color(t.down).font(bold()),
            Space::new().width(Length::Fill),
            text("✕").size(12).color(t.down),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .padding(Padding::from([11, 14]))
    .width(Length::Fill)
    .on_press(Message::DismissError)
    .style(move |_, _| button::Style {
        background: Some(Background::Color(with_alpha(t.down, 0.08))),
        text_color: t.down,
        border: Border {
            color: with_alpha(t.down, 0.4),
            width: 1.0,
            radius: Radius::from(12),
        },
        ..Default::default()
    })
    .into()
}

fn field_button_style(t: KaoTheme, open: bool) -> button::Style {
    button::Style {
        background: Some(Background::Color(t.card_alt)),
        text_color: t.text,
        border: Border {
            color: if open { t.a1 } else { t.border },
            width: 1.5,
            radius: Radius::from(11),
        },
        ..Default::default()
    }
}

/// Dark terminal background for decode panels — a touch darker than the
/// card in light themes; near-black in dark.
fn terminal_bg(t: KaoTheme) -> Color {
    if t.dark {
        Color::from_rgb(0.06, 0.07, 0.09)
    } else {
        Color::from_rgb(0.13, 0.15, 0.18)
    }
}

/// Foreground ink for text on `terminal_bg`. The panel is dark in *every*
/// theme, so a light theme's near-black `t.text` would be invisible on it —
/// use an explicit light ink there. Dark themes already have a light `t.text`.
fn terminal_fg(t: KaoTheme) -> Color {
    if t.dark {
        t.text
    } else {
        Color::from_rgb(0.92, 0.93, 0.96)
    }
}

/// Dimmer ink for comments / labels on `terminal_bg` (same rationale as
/// [`terminal_fg`] — a light theme's `t.sub` is too dark to read on the panel).
fn terminal_muted(t: KaoTheme) -> Color {
    if t.dark {
        t.sub
    } else {
        Color::from_rgb(0.62, 0.65, 0.72)
    }
}
