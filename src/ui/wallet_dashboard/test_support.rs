//! Test-only helpers shared by the dashboard's pane and overlay tests.
//!
//! [`texts`] lays an element out on a headless (CPU, tiny-skia) renderer and collects every text
//! it draws, in tree order — enough to assert what a panel says, and in which order, without
//! pixels. The Apps pane, the WalletConnect pane and coordinator, and the sign-review overlay
//! tests all use it. [`click_text`] clicks where a text is drawn and returns what the click
//! published — for "this looks clickable, so it must do something" (Settings rows, the network
//! wizard's review tiles).

use iced::advanced::layout::{self, Layout};
use iced::advanced::renderer::Headless;
use iced::advanced::widget::{Id, Operation, Tree};
use iced::advanced::{Shell, clipboard};
use iced::{Element, Event, Font, Pixels, Point, Rectangle, Size, mouse};

/// The headless layout bounds every helper here lays out within.
const LIMITS: Size = Size::new(560.0, 100_000.0);

struct Texts(Vec<(String, Rectangle)>);

impl Operation for Texts {
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
        operate(self)
    }

    fn text(&mut self, _id: Option<&Id>, bounds: Rectangle, text: &str) {
        self.0.push((text.to_string(), bounds));
    }
}

pub(crate) fn texts<M>(el: Element<'_, M>) -> Vec<String> {
    text_bounds(el).into_iter().map(|(s, _)| s).collect()
}

fn renderer() -> iced::Renderer {
    futures::executor::block_on(<iced::Renderer as Headless>::new(
        Font::DEFAULT,
        Pixels(16.0),
        Some("tiny-skia"),
    ))
    .expect("a headless tiny-skia renderer")
}

/// Like [`texts`], with each text's laid-out bounds: a text that wraps is taller than one line,
/// one that doesn't keeps a single line's height however far it runs past the box.
pub(crate) fn text_bounds<M>(mut el: Element<'_, M>) -> Vec<(String, Rectangle)> {
    let renderer = renderer();
    let mut tree = Tree::new(el.as_widget());
    let limits = layout::Limits::new(Size::ZERO, LIMITS);
    let node = el.as_widget_mut().layout(&mut tree, &renderer, &limits);
    let mut op = Texts(Vec::new());
    el.as_widget_mut()
        .operate(&mut tree, Layout::new(&node), &renderer, &mut op);
    op.0
}

/// Left-click (press, then release) the centre of the first text that reads exactly `needle`,
/// and return every message the click published — empty when nothing under it reacts. Panics
/// when no such text is drawn.
pub(crate) fn click_text<M>(mut el: Element<'_, M>, needle: &str) -> Vec<M> {
    let renderer = renderer();
    let mut tree = Tree::new(el.as_widget());
    let limits = layout::Limits::new(Size::ZERO, LIMITS);
    let node = el.as_widget_mut().layout(&mut tree, &renderer, &limits);
    let mut op = Texts(Vec::new());
    el.as_widget_mut()
        .operate(&mut tree, Layout::new(&node), &renderer, &mut op);
    let Some((_, bounds)) = op.0.iter().find(|(s, _)| s == needle) else {
        panic!("no text {needle:?} is drawn: {:?}", op.0);
    };
    let cursor = mouse::Cursor::Available(bounds.center());
    let viewport = Rectangle::new(Point::ORIGIN, LIMITS);
    let mut published = Vec::new();
    let mut clip = clipboard::Null;
    for event in [
        mouse::Event::CursorMoved {
            position: bounds.center(),
        },
        mouse::Event::ButtonPressed(mouse::Button::Left),
        mouse::Event::ButtonReleased(mouse::Button::Left),
    ] {
        let mut shell = Shell::new(&mut published);
        el.as_widget_mut().update(
            &mut tree,
            &Event::Mouse(event),
            Layout::new(&node),
            cursor,
            &renderer,
            &mut clip,
            &mut shell,
            &viewport,
        );
    }
    published
}
