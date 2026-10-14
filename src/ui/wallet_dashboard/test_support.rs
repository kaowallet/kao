//! Test-only helpers shared by the dashboard's pane and overlay tests.
//!
//! [`texts`] lays an element out on a headless (CPU, tiny-skia) renderer and collects every text
//! it draws, in tree order — enough to assert what a panel says, and in which order, without
//! pixels. The Apps pane, the WalletConnect pane and coordinator, and the sign-review overlay
//! tests all use it.

use iced::advanced::layout::{self, Layout};
use iced::advanced::renderer::Headless;
use iced::advanced::widget::{Id, Operation, Tree};
use iced::{Element, Font, Pixels, Rectangle, Size};

struct Texts(Vec<(String, Rectangle)>);

impl Operation for Texts {
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
        operate(self)
    }

    fn text(&mut self, _id: Option<&Id>, bounds: Rectangle, text: &str) {
        self.0.push((text.to_string(), bounds));
    }
}

pub(super) fn texts<M>(el: Element<'_, M>) -> Vec<String> {
    text_bounds(el).into_iter().map(|(s, _)| s).collect()
}

/// Like [`texts`], with each text's laid-out bounds: a text that wraps is taller than one line,
/// one that doesn't keeps a single line's height however far it runs past the box.
pub(super) fn text_bounds<M>(mut el: Element<'_, M>) -> Vec<(String, Rectangle)> {
    let renderer = futures::executor::block_on(<iced::Renderer as Headless>::new(
        Font::DEFAULT,
        Pixels(16.0),
        Some("tiny-skia"),
    ))
    .expect("a headless tiny-skia renderer");
    let mut tree = Tree::new(el.as_widget());
    let limits = layout::Limits::new(Size::ZERO, Size::new(560.0, 100_000.0));
    let node = el.as_widget_mut().layout(&mut tree, &renderer, &limits);
    let mut op = Texts(Vec::new());
    el.as_widget_mut()
        .operate(&mut tree, Layout::new(&node), &renderer, &mut op);
    op.0
}
