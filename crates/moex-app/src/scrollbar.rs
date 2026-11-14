//! A minimal overlay scrollbar for the virtualized panes.

use crate::theme::Palette;
use crate::vscroll::VScroll;
use crate::window::SCROLLBAR_W;
use gpui_kit::prelude::*;
use gpui_kit::{div, px, AnyElement, App, MouseButton, MouseDownEvent, Window};

/// Vertical scrollbar along the right edge of a `relative` container whose
/// height equals `vs.viewport`. `None` when the content fits.
pub fn vscrollbar(
    id: &'static str,
    vs: &VScroll,
    pal: &Palette,
    on_down: impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static,
) -> Option<AnyElement> {
    let (start, len) = vs.thumb(vs.viewport)?;
    Some(
        div()
            .id(id)
            .absolute()
            .top_0()
            .right_0()
            .w(px(SCROLLBAR_W))
            .h_full()
            .occlude()
            .on_mouse_down(MouseButton::Left, on_down)
            .child(
                div()
                    .absolute()
                    .top(px(start))
                    .right(px(2.))
                    .w(px(SCROLLBAR_W - 4.))
                    .h(px(len))
                    .rounded(px(4.))
                    .bg(pal.scroll_thumb),
            )
            .into_any_element(),
    )
}
