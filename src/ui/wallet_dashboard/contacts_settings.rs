//! Settings → Contacts pane. List, add, edit, delete.
//!
//! The pane never owns a separate contacts list — the canonical state
//! lives in `Arc<RwLock<ContactsBook>>` shared with the App and the rest
//! of the dashboard. Editing builds a `Draft`, and on Save we snapshot
//! the current book, apply the change (upsert at `editing_addr` or
//! append), and bubble a `SaveRequested(Vec<Contact>)` outcome up. The
//! App writes the new vec into the book and dispatches a disk save.
//!
//! Address validation accepts both 0x-hex and ENS-shaped names. ENS
//! contacts are flagged (`Contact::ens`) and re-resolved at send time
//! against their pinned address; a divergence surfaces as a banner the
//! user must explicitly accept before continuing.

use std::str::FromStr;
use std::sync::{Arc, RwLock};

use alloy::primitives::Address;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::operation::{focus as focus_widget, focus_next, focus_previous};
use iced::widget::{Space, button, column, container, mouse_area, row, scrollable, text, text_input};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription, Task};

/// Stable ID for the NAME field so we can auto-focus it when the user
/// opens Add / Edit. Tab navigation past the name then walks through
/// the rest of the form via `focus_next` / `focus_previous`, which
/// don't need explicit IDs.
const NAME_INPUT_ID: &str = "contacts:name";

use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    black, bold, card_style, colored_address, kao_scrollable_style, mono, primary_button,
    secondary_button, small_secondary_button, text_input_style,
};
use crate::wallet::{Contact, ContactEns, ContactsBook, short_address};

const DEFAULT_KAOMOJI: &str = "(◕‿◕)";

/// Cap the edit form width so inputs don't stretch edge-to-edge on wide
/// desktop windows. ~520 px sits roughly under the visual width of the
/// address chunks on the Send review screen.
const MAX_FORM_WIDTH: f32 = 520.0;

/// Cap for the list view. Wider than the edit form so the 2-column
/// card grid has room for the full colored address inside each card;
/// narrower than the full screen so contacts on a 4K monitor don't
/// fly off into the left and right margins.
const MAX_LIST_WIDTH: f32 = 920.0;

/// Fixed card height. Pinned (rather than letting iced shrink-wrap
/// content) so cards in a row stay visually equal even when one has
/// notes / an ENS pin and the other doesn't. Sized to fit avatar +
/// name/ens header + colored address + one wrapped notes line +
/// actions row, with a bit of breathing room.
const CARD_HEIGHT: f32 = 188.0;

/// Diameter of the kaomoji bubble in a card. Bumped up from the 38px
/// the avatar widget uses elsewhere because the contact card is the
/// primary visual identifier — the kaomoji *is* the contact's "face".
const CARD_AVATAR_SIZE: f32 = 56.0;

/// Pool the randomizer picks from. Curated for contact avatars: small,
/// expressive, no overly wide glyphs (the avatar circle is 38px, so
/// long horizontal arms get cropped). Rough mood mix so a re-roll feels
/// like a real shuffle rather than the same five faces.
const KAOMOJI_POOL: &[&str] = &[
    "(◕‿◕)",
    "(◕‿◕✿)",
    "(´｡• ᵕ •｡`)",
    "(˘ᵕ˘)",
    "( ´ ▽ ` )ﾉ",
    "(*´∇`*)",
    "ヽ(・∀・)ﾉ",
    "(￣ω￣)",
    "٩(◕‿◕｡)۶",
    "(¬‿¬)",
    "(✿◠‿◠)",
    "(⌐■_■)",
    "(っ◕‿◕)っ",
    "( •̀ω•́ )✧",
    "(づ｡◕‿‿◕｡)づ",
    "(*^‿^*)",
    "(^_^)v",
    "(◍•ᴗ•◍)",
    "(｡♥‿♥｡)",
    "ʕ•ᴥ•ʔ",
    "(=^･ω･^=)",
    "(￣▽￣)",
    "(ﾉ◕ヮ◕)ﾉ",
    "ᕕ( ᐛ )ᕗ",
    "(•‿•)",
    "(• ε •)",
    "(¬_¬)",
    "(´• ω •`)",
    "(✧ω✧)",
    "(o´ω`o)",
];

#[derive(Debug, Clone)]
pub enum Message {
    Back,
    OpenAdd,
    OpenEdit(usize),
    /// First click on a contact's "Delete" stages the row for deletion
    /// (the card swaps its actions to Cancel / Confirm delete). A second
    /// click on the *same* index then executes the destructive path.
    /// Clicking Delete on a different card just moves the staged index;
    /// nothing is destroyed without an explicit confirm.
    Delete(usize),
    /// User backed out of a staged deletion. Clears `pending_delete`
    /// without touching the contacts book.
    CancelDelete,
    NameChanged(String),
    /// Single-field address input: accepts `0x…` hex or an ENS-shaped
    /// name (`vitalik.eth`). Hex parses synchronously; ENS triggers a
    /// background resolution coordinated by the dashboard.
    AddressChanged(String),
    /// Result of an ENS forward-resolution dispatched by the dashboard
    /// against the current address input. `seq` is the input-generation
    /// counter that was current when the lookup was kicked off; results
    /// with a stale seq are dropped so rapid typing always wins.
    EnsResolved {
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    },
    KaomojiChanged(String),
    /// Roll a fresh random kaomoji into the draft. Pulled from
    /// `KAOMOJI_POOL`; avoids picking the current value so a click
    /// always feels like a change.
    RandomizeKaomoji,
    NotesChanged(String),
    Save,
    CancelEdit,
    /// Global keyboard event captured while the Edit form is open.
    /// Drives Tab / Shift-Tab focus navigation, Enter → Save, and
    /// Esc → reset-to-list. Routing through a single message keeps
    /// the dispatch table flat instead of scattering keypress
    /// handling across each input.
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// Back arrow / Esc — coordinator returns to the settings root.
    Closed,
    /// User clicked Save (Add or Edit) or Delete. Carries the full new
    /// contacts vec; the App swaps it into the in-memory book and writes
    /// to disk asynchronously.
    SaveRequested(Vec<Contact>),
}

#[derive(Debug, Clone, Default)]
struct Draft {
    name: String,
    /// Either a `0x…` hex address or an ENS-shaped name. Hex parses
    /// synchronously; ENS triggers a background resolution coordinated
    /// by the dashboard. The current state of that resolution lives in
    /// `ContactsPane::resolution` rather than in the draft — it's
    /// derived from this string on every change.
    address_input: String,
    kaomoji: String,
    notes: String,
}

/// Resolution state of the contacts pane's address-or-ENS input.
/// Mirrors `send::Resolution` (intentionally — same UX, same
/// semantics) but kept local so the pane doesn't depend on the Send
/// internals.
#[derive(Debug, Clone, Default)]
enum AddressResolution {
    #[default]
    Empty,
    /// User typed something that isn't hex and isn't ENS-shaped.
    Invalid,
    /// User pasted a valid hex address — no network call required.
    Hex(Address),
    /// User typed an ENS-shaped name; lookup in flight.
    Resolving { name: String },
    /// ENS lookup succeeded — the resolved address becomes the pinned
    /// `Contact.address` on save, and the typed name lives in
    /// `Contact.ens.name`.
    Resolved { name: String, addr: Address },
    /// ENS record exists but has no address mapping.
    NotFound { name: String },
    /// Lookup errored (RPC down, decoding failure, etc.).
    Error { name: String, msg: String },
}

#[derive(Debug, Clone)]
enum Mode {
    List,
    Edit {
        /// Address of the contact being edited, when editing in place.
        /// `None` means Add mode (the draft becomes a new contact).
        editing_addr: Option<Address>,
    },
}

#[derive(Debug)]
pub struct ContactsPane {
    book: Arc<RwLock<ContactsBook>>,
    mode: Mode,
    draft: Draft,
    /// Live resolution state for `draft.address_input`. Drives both
    /// the parse hint shown under the input and the address that
    /// actually gets saved.
    resolution: AddressResolution,
    /// Bumped on every address-input change. ENS lookups tag their
    /// result with the seq they were spawned at; stale results
    /// (slow resolver finishing after the user keeps typing) are
    /// dropped.
    resolution_seq: u64,
    /// Highest seq for which the dashboard has already spawned a task.
    /// Lets `take_pending_ens` return `Some` exactly once per fresh
    /// input change rather than re-firing on every redraw.
    last_dispatched_seq: Option<u64>,
    /// Last validation errors. Rendered as a small red block above the
    /// Save button. Cleared on every keystroke that could fix the input.
    validation: Vec<String>,
    /// Index of a contact the user has clicked Delete on but not yet
    /// confirmed. The card at this index renders Cancel / Confirm delete
    /// instead of Edit / Delete. Cleared on any navigation event so a
    /// stale staged index can't survive into a different list.
    pending_delete: Option<usize>,
}

impl ContactsPane {
    pub fn new(book: Arc<RwLock<ContactsBook>>) -> Self {
        Self {
            book,
            mode: Mode::List,
            draft: Draft::default(),
            resolution: AddressResolution::Empty,
            resolution_seq: 0,
            last_dispatched_seq: None,
            validation: Vec::new(),
            pending_delete: None,
        }
    }

    /// Open the pane directly in Add mode pre-filled with a recipient
    /// from the Send pane's "Save as contact" CTA. When `ens` is
    /// `Some`, the address input is pre-set to the ENS string so the
    /// resolver kicks in (giving the user a "✓ resolved → 0xabc…"
    /// confirmation); otherwise it's pre-set to the hex address.
    pub fn new_with_prefill(
        book: Arc<RwLock<ContactsBook>>,
        address: Address,
        ens: Option<String>,
    ) -> Self {
        let address_input = ens
            .clone()
            .unwrap_or_else(|| address.to_checksum(None));
        let mut pane = Self {
            book,
            mode: Mode::Edit { editing_addr: None },
            draft: Draft {
                name: String::new(),
                address_input: String::new(),
                kaomoji: DEFAULT_KAOMOJI.into(),
                notes: String::new(),
            },
            resolution: AddressResolution::Empty,
            resolution_seq: 0,
            last_dispatched_seq: None,
            validation: Vec::new(),
            pending_delete: None,
        };
        // Route the prefill through the same set_address path as a
        // normal user keystroke so the resolution state is consistent
        // (and the dashboard kicks an ENS verify when applicable).
        pane.set_address(address_input);
        pane
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Back => match self.mode {
                Mode::Edit { .. } => {
                    // From Edit mode, Back returns to the list (cancel
                    // edits without persisting). From List mode, Back
                    // bubbles up to close the pane.
                    self.reset_to_list();
                    (Task::none(), None)
                }
                Mode::List => (Task::none(), Some(Outcome::Closed)),
            },
            Message::OpenAdd => {
                self.mode = Mode::Edit { editing_addr: None };
                self.draft = Draft {
                    kaomoji: DEFAULT_KAOMOJI.into(),
                    ..Draft::default()
                };
                self.resolution = AddressResolution::Empty;
                self.resolution_seq = self.resolution_seq.wrapping_add(1);
                self.validation.clear();
                self.pending_delete = None;
                (focus_widget(NAME_INPUT_ID), None)
            }
            Message::OpenEdit(idx) => {
                let snapshot = match self.book.read() {
                    Ok(b) => b.clone(),
                    Err(_) => return (Task::none(), None),
                };
                let Some(c) = snapshot.get(idx) else {
                    return (Task::none(), None);
                };
                let addr = c.address();
                // For ENS contacts, pre-fill the input with the ENS
                // string so the resolver re-verifies it on edit
                // (catches divergence during the edit flow too).
                // Otherwise pre-fill the hex.
                let address_input = c
                    .ens
                    .as_ref()
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| addr.to_checksum(None));
                self.draft = Draft {
                    name: c.name.clone(),
                    address_input: String::new(),
                    kaomoji: if c.kaomoji.is_empty() {
                        DEFAULT_KAOMOJI.into()
                    } else {
                        c.kaomoji.clone()
                    },
                    notes: c.notes.clone(),
                };
                self.mode = Mode::Edit {
                    editing_addr: Some(addr),
                };
                self.validation.clear();
                self.pending_delete = None;
                self.set_address(address_input);
                (focus_widget(NAME_INPUT_ID), None)
            }
            Message::Delete(idx) => {
                // First click stages the row; second click on the same
                // index executes. Clicking Delete on a different card
                // moves the staged index but never destroys without an
                // explicit confirm.
                if self.pending_delete != Some(idx) {
                    self.pending_delete = Some(idx);
                    return (Task::none(), None);
                }
                self.pending_delete = None;
                let mut snapshot = match self.book.read() {
                    Ok(b) => b.clone(),
                    Err(_) => return (Task::none(), None),
                };
                snapshot.remove(idx);
                (Task::none(), Some(Outcome::SaveRequested(snapshot.into_vec())))
            }
            Message::CancelDelete => {
                self.pending_delete = None;
                (Task::none(), None)
            }
            Message::NameChanged(s) => {
                self.draft.name = s;
                self.validation.clear();
                (Task::none(), None)
            }
            Message::AddressChanged(s) => {
                self.set_address(s);
                (Task::none(), None)
            }
            Message::EnsResolved { seq, name, result } => {
                if seq != self.resolution_seq {
                    return (Task::none(), None);
                }
                let still_relevant = matches!(
                    &self.resolution,
                    AddressResolution::Resolving { name: pending } if pending == &name,
                );
                if !still_relevant {
                    return (Task::none(), None);
                }
                self.resolution = match result {
                    Ok(Some(addr)) => AddressResolution::Resolved { name, addr },
                    Ok(None) => AddressResolution::NotFound { name },
                    Err(msg) => AddressResolution::Error { name, msg },
                };
                (Task::none(), None)
            }
            Message::KaomojiChanged(s) => {
                self.draft.kaomoji = s;
                (Task::none(), None)
            }
            Message::RandomizeKaomoji => {
                self.draft.kaomoji = pick_random_kaomoji(&self.draft.kaomoji);
                (Task::none(), None)
            }
            Message::NotesChanged(s) => {
                self.draft.notes = s;
                (Task::none(), None)
            }
            Message::CancelEdit => {
                self.reset_to_list();
                (Task::none(), None)
            }
            Message::Save => self.handle_save(),
            Message::Key(event) => self.handle_key(event),
        }
    }

    fn handle_key(&mut self, event: keyboard::Event) -> (Task<Message>, Option<Outcome>) {
        // Only the Edit form claims keyboard navigation. The list view
        // is plain enough that Tab/Enter/Esc on it would just be
        // surprising no-ops.
        if !matches!(self.mode, Mode::Edit { .. }) {
            return (Task::none(), None);
        }
        let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
            return (Task::none(), None);
        };
        use keyboard::key::Named;
        match key {
            keyboard::Key::Named(Named::Tab) => {
                let task: Task<Message> = if modifiers.shift() {
                    focus_previous()
                } else {
                    focus_next()
                };
                (task, None)
            }
            keyboard::Key::Named(Named::Enter) => self.handle_save(),
            keyboard::Key::Named(Named::Escape) => {
                self.reset_to_list();
                (Task::none(), None)
            }
            _ => (Task::none(), None),
        }
    }

    /// Subscribe to global key events while the Edit form is open. The
    /// pane stays passive (no subscription) when sitting on the list
    /// view, so Tab there isn't intercepted.
    pub fn subscription(&self) -> Subscription<Message> {
        if matches!(self.mode, Mode::Edit { .. }) {
            keyboard::listen().map(Message::Key)
        } else {
            Subscription::none()
        }
    }

    /// Task that focuses the NAME input. Used by the dashboard when it
    /// opens the pane in Edit mode via the Send pane's "Save as
    /// contact" CTA — there's no `Message::OpenAdd` round-trip in that
    /// path, so the focus needs to be issued externally.
    pub fn focus_initial_task() -> Task<Message> {
        focus_widget(NAME_INPUT_ID)
    }

    /// Coordinator hook: returns `Some((seq, name))` exactly once per
    /// fresh ENS-shaped input. The dashboard spawns the actual ENS
    /// resolution task; the result lands back as
    /// `Message::EnsResolved`.
    pub fn take_pending_ens(&mut self) -> Option<(u64, String)> {
        match &self.resolution {
            AddressResolution::Resolving { name }
                if self.last_dispatched_seq != Some(self.resolution_seq) =>
            {
                let seq = self.resolution_seq;
                self.last_dispatched_seq = Some(seq);
                Some((seq, name.clone()))
            }
            _ => None,
        }
    }

    fn set_address(&mut self, raw: String) {
        self.draft.address_input = raw;
        self.resolution_seq = self.resolution_seq.wrapping_add(1);
        self.validation.clear();
        let trimmed = self.draft.address_input.trim();
        self.resolution = if trimmed.is_empty() {
            AddressResolution::Empty
        } else if let Ok(addr) = Address::from_str(trimmed) {
            AddressResolution::Hex(addr)
        } else if looks_like_dot_eth(trimmed) {
            AddressResolution::Resolving {
                name: trimmed.to_string(),
            }
        } else {
            AddressResolution::Invalid
        };
    }

    fn reset_to_list(&mut self) {
        self.mode = Mode::List;
        self.draft = Draft::default();
        self.resolution = AddressResolution::Empty;
        self.resolution_seq = self.resolution_seq.wrapping_add(1);
        self.validation.clear();
        self.pending_delete = None;
    }

    fn handle_save(&mut self) -> (Task<Message>, Option<Outcome>) {
        let editing_addr = match self.mode {
            Mode::Edit { editing_addr } => editing_addr,
            Mode::List => return (Task::none(), None),
        };

        let mut errs = Vec::new();
        let name = self.draft.name.trim().to_string();
        if name.is_empty() {
            errs.push("Name is required".into());
        }

        // Derive the address (and optional ENS pin) from the
        // resolution state. The user types one thing; we figure out
        // whether it was hex or ENS.
        let (addr, ens_for_save) = match &self.resolution {
            AddressResolution::Hex(a) => (Some(*a), None),
            AddressResolution::Resolved { name, addr } => (
                Some(*addr),
                Some(ContactEns {
                    name: name.clone(),
                    last_resolved_addr: addr.into_array(),
                }),
            ),
            AddressResolution::Empty => {
                errs.push("Address or ENS name required".into());
                (None, None)
            }
            AddressResolution::Invalid => {
                errs.push("Not a valid 0x… address or ENS name".into());
                (None, None)
            }
            AddressResolution::Resolving { .. } => {
                errs.push("Resolving ENS name… try again in a sec".into());
                (None, None)
            }
            AddressResolution::NotFound { name } => {
                errs.push(format!("ENS name “{name}” has no address record"));
                (None, None)
            }
            AddressResolution::Error { name, msg } => {
                errs.push(format!("ENS lookup for “{name}” failed: {msg}"));
                (None, None)
            }
        };

        // Block address collisions when in Add mode (different address
        // than what's being edited). Edit-in-place reuses the same slot.
        if let Some(addr) = addr
            && editing_addr.is_none_or(|e| e != addr)
            && let Ok(book) = self.book.read()
            && book.get_by_addr(addr).is_some()
        {
            errs.push("A contact with that address already exists".into());
        }

        if !errs.is_empty() {
            self.validation = errs;
            return (Task::none(), None);
        }

        let addr = addr.expect("validated above");
        let kaomoji = if self.draft.kaomoji.trim().is_empty() {
            String::new()
        } else {
            self.draft.kaomoji.clone()
        };
        let new_contact = Contact {
            name,
            address: addr.into_array(),
            kaomoji,
            notes: self.draft.notes.clone(),
            ens: ens_for_save,
        };

        let mut snapshot = match self.book.read() {
            Ok(b) => b.clone(),
            Err(_) => return (Task::none(), None),
        };
        // If editing in place AND the address changed (the user typed
        // a different ENS / pasted a new hex), drop the old entry first
        // so the upsert lands as a new row. When the address is
        // unchanged, upsert overwrites in place.
        if let Some(prev) = editing_addr
            && prev != addr
        {
            let pos = snapshot.iter().position(|c| c.address() == prev);
            if let Some(p) = pos {
                snapshot.remove(p);
            }
        }
        snapshot.upsert(new_contact);

        // Reset the pane back to the list so the next render shows the
        // updated entry.
        self.reset_to_list();

        (Task::none(), Some(Outcome::SaveRequested(snapshot.into_vec())))
    }

    pub fn view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        // Header is full-width so Back can sit at the far-left corner
        // and the right-side action (+ Add or just a spacer) sits at
        // the far-right corner. The body sits beneath at a capped
        // width so forms / card grids don't sprawl on wide screens.
        let (header, body, max_width) = match &self.mode {
            Mode::List => (
                self.list_header(t),
                self.view_list(t),
                MAX_LIST_WIDTH,
            ),
            Mode::Edit { editing_addr } => (
                self.edit_header(t, editing_addr.is_some()),
                self.view_edit(t),
                MAX_FORM_WIDTH,
            ),
        };

        let body_centered = container(
            container(body)
                .width(Length::Fixed(max_width))
                .max_width(max_width),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let content = column![
            header,
            Space::new().height(16),
            body_centered,
        ]
        .width(Length::Fill);

        scrollable(
            container(content)
                .padding(Padding::from([22, 24]))
                .width(Length::Fill),
        )
        .height(Length::Fill)
        .width(Length::Fill)
        .style(move |_, status| kao_scrollable_style(t, status))
        .into()
    }

    fn list_header<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        // Full-width header: Back hugs the far-left corner of the
        // pane, title centres in the visual middle of the body, and
        // the +Add button hugs the far-right corner. The button is
        // capped at a fixed width so it doesn't stretch across the
        // remaining whitespace on wide desktop windows (`primary_button`
        // is `Length::Fill` internally).
        row![
            mouse_area(text("← Back").size(13).color(t.a1).font(bold()))
                .on_press(Message::Back)
                .interaction(iced::mouse::Interaction::Pointer),
            Space::new().width(Length::Fill),
            text("Contacts").size(22).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            container(primary_button(t, "+ Add", true).on_press(Message::OpenAdd))
                .width(Length::Fixed(120.0)),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
    }

    fn edit_header<'a>(&'a self, t: KaoTheme, editing: bool) -> Element<'a, Message> {
        let title = if editing { "Edit contact" } else { "Add contact" };
        row![
            mouse_area(text("← Back").size(13).color(t.a1).font(bold()))
                .on_press(Message::Back)
                .interaction(iced::mouse::Interaction::Pointer),
            Space::new().width(Length::Fill),
            text(title).size(22).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            // Spacer to balance the layout — no right action in edit mode.
            text("").size(13).color(t.sub),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
    }

    fn view_list<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        // Snapshot the contacts vec out of the lock so the widget tree
        // owns its strings (the read guard would otherwise drop while
        // the returned Element still references it).
        let snapshot: Vec<Contact> = match self.book.read() {
            Ok(b) => b.iter().cloned().collect(),
            Err(_) => return text("contacts unavailable").color(t.down).into(),
        };

        if snapshot.is_empty() {
            return container(
                column![
                    text("No contacts yet (・・;)").size(13).color(t.sub),
                    Space::new().height(6),
                    text("Add one to give your recipients a name.")
                        .size(12)
                        .color(t.sub),
                ]
                .align_x(Alignment::Center),
            )
            .padding(Padding::from([22, 0]))
            .width(Length::Fill)
            .center_x(Length::Fill)
            .into();
        }

        // 2-column grid. Pair contacts up; an odd trailing entry gets
        // a same-shape empty placeholder so the last row's card keeps
        // its column width instead of stretching across both slots.
        let pending = self.pending_delete;
        let mut grid = column![].spacing(10).width(Length::Fill);
        let mut iter = snapshot.into_iter().enumerate().peekable();
        while iter.peek().is_some() {
            let (i_a, c_a) = iter.next().expect("peeked above");
            let cell_a: Element<'_, Message> =
                container(list_card(t, i_a, c_a, pending == Some(i_a)))
                    .width(Length::FillPortion(1))
                    .into();
            let cell_b: Element<'_, Message> = match iter.next() {
                Some((i_b, c_b)) => container(list_card(t, i_b, c_b, pending == Some(i_b)))
                    .width(Length::FillPortion(1))
                    .into(),
                None => Space::new().width(Length::FillPortion(1)).into(),
            };
            grid = grid.push(
                row![cell_a, Space::new().width(10), cell_b]
                    .align_y(Alignment::Start)
                    .width(Length::Fill),
            );
        }
        grid.into()
    }

    fn view_edit<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let name_field = labeled_input_with_id(
            t,
            "NAME",
            "Treasury / vitalik / friend",
            &self.draft.name,
            Message::NameChanged,
            Some(NAME_INPUT_ID),
        );
        let addr_field = labeled_input(
            t,
            "ADDRESS OR ENS NAME",
            "0x… or vitalik.eth",
            &self.draft.address_input,
            Message::AddressChanged,
        );
        let parse_hint = address_parse_hint(t, &self.resolution);
        let kao_field = labeled_input_with_action(
            t,
            "KAOMOJI",
            DEFAULT_KAOMOJI,
            &self.draft.kaomoji,
            Message::KaomojiChanged,
            "🎲 random",
            Message::RandomizeKaomoji,
        );
        let notes_field = labeled_input(
            t,
            "NOTES",
            "Anything to remember about this address",
            &self.draft.notes,
            Message::NotesChanged,
        );

        let validation: Element<'_, Message> = if self.validation.is_empty() {
            Space::new().height(0).into()
        } else {
            let mut col = column![].spacing(2);
            for e in &self.validation {
                col = col.push(text(e.clone()).size(12).color(t.down).font(bold()));
            }
            container(col).padding(Padding::from([8, 0])).into()
        };

        let actions = row![
            container(secondary_button(t, "Cancel").on_press(Message::CancelEdit))
                .width(Length::FillPortion(1)),
            Space::new().width(9),
            container(primary_button(t, "Save", true).on_press(Message::Save))
                .width(Length::FillPortion(2)),
        ]
        .width(Length::Fill);

        column![
            name_field,
            Space::new().height(12),
            addr_field,
            parse_hint,
            Space::new().height(12),
            kao_field,
            Space::new().height(12),
            notes_field,
            validation,
            Space::new().height(16),
            actions,
        ]
        .width(Length::Fill)
        .into()
    }
}

/// Inline status line shown under the ADDRESS-OR-ENS input. Mirrors
/// the parse hint on the Send recipient step so the UX is consistent
/// across the two places a user can type an ENS name.
fn address_parse_hint<'a>(t: KaoTheme, r: &AddressResolution) -> Element<'a, Message> {
    use iced::widget::container as ctr;
    let pad = Padding::from([4, 0]);
    match r {
        AddressResolution::Empty => Space::new().height(0).into(),
        AddressResolution::Hex(_) => ctr(text("✓ valid address").size(11).color(t.up).font(bold()))
            .padding(pad)
            .into(),
        AddressResolution::Resolving { name } => ctr(
            text(format!("(；・∀・) resolving {name}…"))
                .size(11)
                .color(t.sub)
                .font(bold()),
        )
        .padding(pad)
        .into(),
        AddressResolution::Resolved { name, addr } => ctr(
            row![
                text(format!("✓ {name} →  ")).size(11).color(t.up).font(bold()),
                text(short_address(*addr)).size(11).color(t.sub).font(mono()),
            ]
            .align_y(Alignment::Center),
        )
        .padding(pad)
        .into(),
        AddressResolution::NotFound { name } => ctr(
            text(format!("ENS name “{name}” has no address record"))
                .size(11)
                .color(t.down)
                .font(bold()),
        )
        .padding(pad)
        .into(),
        AddressResolution::Error { name, msg } => ctr(
            text(format!("ENS lookup for “{name}” failed: {msg}"))
                .size(11)
                .color(t.down)
                .font(bold()),
        )
        .padding(pad)
        .into(),
        AddressResolution::Invalid => ctr(
            text("Not a valid 0x… address or ENS name")
                .size(11)
                .color(t.down)
                .font(bold()),
        )
        .padding(pad)
        .into(),
    }
}

fn list_card<'a>(t: KaoTheme, idx: usize, c: Contact, pending_delete: bool) -> Element<'a, Message> {
    let kao_glyph = if c.kaomoji.is_empty() {
        DEFAULT_KAOMOJI.to_string()
    } else {
        c.kaomoji.clone()
    };
    let name = c.name.clone();
    let addr = c.address();
    // ENS line and notes line are always rendered (with `text("")`
    // placeholders when missing) so cards stay uniform-height in the
    // 2-column grid regardless of which contacts have which fields
    // populated. The earlier "render only when present" approach made
    // the row shorter when a card lacked ENS, which left the grid
    // looking ragged.
    let ens_text = c
        .ens
        .as_ref()
        .map(|e| format!("ens: {}", e.name))
        .unwrap_or_default();
    let notes_text = c.notes.clone();

    let header_row = row![
        avatar_owned(t, kao_glyph),
        Space::new().width(14),
        column![
            text(name).size(17).color(t.text).font(bold()),
            text(ens_text).size(12).color(t.sub),
        ]
        .spacing(2)
        .width(Length::Fill),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    // The full EIP-55 colored address goes on its own line under the
    // header so it has the entire card width to render its 10 chunks
    // without colliding with the avatar/name block.
    let address_block = container(colored_address(t, addr))
        .padding(Padding::from([0, 0]))
        .width(Length::Fill);

    let notes_block = text(notes_text)
        .size(11)
        .color(t.sub)
        .wrapping(text::Wrapping::WordOrGlyph);

    // When a delete is staged on this card, the actions row swaps to
    // Cancel / Confirm-delete. Confirm carries the destructive color
    // (`t.down`) so the second click reads as the dangerous one — the
    // only way to actually destroy the contact.
    let actions = if pending_delete {
        row![
            small_secondary_button(t, "Cancel").on_press(Message::CancelDelete),
            Space::new().width(8),
            small_danger_button(t, "Confirm delete").on_press(Message::Delete(idx)),
        ]
        .align_y(Alignment::Center)
    } else {
        row![
            small_secondary_button(t, "Edit").on_press(Message::OpenEdit(idx)),
            Space::new().width(8),
            small_secondary_button(t, "Delete").on_press(Message::Delete(idx)),
        ]
        .align_y(Alignment::Center)
    };

    let inner = column![
        header_row,
        Space::new().height(12),
        address_block,
        Space::new().height(10),
        notes_block,
        // Push the actions row to the bottom so cards with short notes
        // (or no notes) keep the same overall height as cards with a
        // line of notes.
        Space::new().height(Length::Fill),
        row![Space::new().width(Length::Fill), actions].width(Length::Fill),
    ]
    .spacing(0)
    .width(Length::Fill)
    .height(Length::Fill);

    container(inner)
        .padding(Padding::from([18, 20]))
        .width(Length::Fill)
        .height(Length::Fixed(CARD_HEIGHT))
        .style(move |_| card_style(t))
        .into()
}

/// Owned-string sibling of `kao_widgets::avatar`. Auto-shrinks the
/// kaomoji's font size so wide glyph clusters (lots of `( ´ ▽ ` )ﾉ`-
/// style padding) fit inside the circle instead of bleeding past the
/// edge into the contact's name and address.
fn avatar_owned<'a>(t: KaoTheme, kao: String) -> Element<'a, Message> {
    avatar_owned_sized(t, kao, CARD_AVATAR_SIZE)
}

fn avatar_owned_sized<'a>(t: KaoTheme, kao: String, size: f32) -> Element<'a, Message> {
    use crate::ui::kao_widgets::kao_fit_size;
    const INNER_PAD: f32 = 4.0;
    let budget = (size - 2.0 * INNER_PAD).max(8.0);
    let max_font = (size * 0.40).max(10.0);
    let font_size = kao_fit_size(&kao, budget, max_font);
    let glyph = text(kao).size(font_size).color(t.text);
    container(glyph)
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .center_x(Length::Fixed(size))
        .center_y(Length::Fixed(size))
        .style(move |_| iced::widget::container::Style {
            background: Some(iced::Background::Color(t.ab2)),
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: iced::border::Radius::from(size / 2.0),
            },
            text_color: Some(t.text),
            ..iced::widget::container::Style::default()
        })
        .into()
}

fn labeled_input<'a, F>(
    t: KaoTheme,
    label: &'a str,
    placeholder: &'a str,
    value: &'a str,
    on_change: F,
) -> Element<'a, Message>
where
    F: 'a + Fn(String) -> Message,
{
    labeled_input_with_id(t, label, placeholder, value, on_change, None)
}

fn labeled_input_with_id<'a, F>(
    t: KaoTheme,
    label: &'a str,
    placeholder: &'a str,
    value: &'a str,
    on_change: F,
    id: Option<&'static str>,
) -> Element<'a, Message>
where
    F: 'a + Fn(String) -> Message,
{
    let label = text(label).size(11).color(t.sub).font(bold());
    let mut input = text_input(placeholder, value)
        .on_input(on_change)
        .padding(Padding::from([12, 14]))
        .size(14)
        .style(move |_theme, status| text_input_style(t, status));
    if let Some(id) = id {
        input = input.id(id);
    }
    column![label, Space::new().height(6), input]
        .width(Length::Fill)
        .into()
}

/// Variant of `labeled_input` with a trailing action button (e.g. the
/// kaomoji randomizer). Layout: label on top, input + button on a
/// single row beneath, button shrunk to its content width.
fn labeled_input_with_action<'a, F>(
    t: KaoTheme,
    label: &'a str,
    placeholder: &'a str,
    value: &'a str,
    on_change: F,
    action_label: &'a str,
    on_action: Message,
) -> Element<'a, Message>
where
    F: 'a + Fn(String) -> Message,
{
    let label = text(label).size(11).color(t.sub).font(bold());
    let input = text_input(placeholder, value)
        .on_input(on_change)
        .padding(Padding::from([12, 14]))
        .size(14)
        .style(move |_theme, status| text_input_style(t, status));
    let action = secondary_button(t, action_label).on_press(on_action);
    let row = row![
        container(input).width(Length::Fill),
        Space::new().width(8),
        container(action).width(Length::Shrink),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);
    column![label, Space::new().height(6), row]
        .width(Length::Fill)
        .into()
}

/// Compact destructive-action button used for the "Confirm delete" step.
/// Mirrors `small_secondary_button`'s shape but renders the label and
/// border in the theme's `down` color so the user reads it as the
/// dangerous half of the Cancel / Confirm pair. Local to this file —
/// the contacts pane is the only place a destructive action surfaces
/// today, and giving the helper a wider home would be designing for a
/// hypothetical future caller.
fn small_danger_button<'a>(t: KaoTheme, label: &'a str) -> button::Button<'a, Message> {
    button(text(label.to_string()).size(11).color(t.down).font(bold()))
        .padding(Padding::from([4, 10]))
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    crate::ui::kao_theme::with_alpha(t.down, 0.14)
                }
                _ => t.card_alt,
            })),
            text_color: t.down,
            border: Border {
                color: t.down,
                width: 1.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        })
}

/// Strict `.eth`-suffix check used by the contacts add/edit form.
/// Looser `crate::ens::looks_like_ens` accepts any dotted string that
/// isn't hex — fine for the Send recipient input where the user has
/// committed to typing an ENS name, but too eager here, where a stray
/// `chrome.com` paste shouldn't fire an on-chain lookup. We only
/// treat the input as ENS-shaped when it ends in `.eth` and has a
/// non-empty label before the suffix (so `.eth` and `foo..eth` are
/// rejected).
fn looks_like_dot_eth(input: &str) -> bool {
    let lc = input.to_ascii_lowercase();
    let Some(stem) = lc.strip_suffix(".eth") else {
        return false;
    };
    !stem.is_empty() && !stem.ends_with('.')
}

/// Pick a kaomoji from the pool. Avoids returning the current value so
/// a click always changes something — if the pool only has one entry
/// (it doesn't, but be defensive) the same value is returned. Uses
/// `rand::thread_rng()` rather than a deterministic seed: this is UI
/// flair, not a security primitive.
fn pick_random_kaomoji(current: &str) -> String {
    use rand::Rng;
    if KAOMOJI_POOL.is_empty() {
        return current.to_string();
    }
    let mut rng = rand::thread_rng();
    // At most a handful of attempts to avoid the current value; bail
    // out if the pool happens to be saturated with the current pick.
    for _ in 0..6 {
        let idx = rng.gen_range(0..KAOMOJI_POOL.len());
        let candidate = KAOMOJI_POOL[idx];
        if candidate != current {
            return candidate.to_string();
        }
    }
    KAOMOJI_POOL[0].to_string()
}
