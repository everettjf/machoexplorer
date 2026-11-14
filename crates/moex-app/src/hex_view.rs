//! Hex pane: a virtualized view over the mapped file for the selected
//! node's byte range. Rows are formatted on demand for the visible range
//! only, so the size of the range does not matter.

use crate::hex::{self, ByteSelection};
use crate::theme::{self, Palette};
use crate::vscroll::{ScrollTo, VScroll};
use crate::window::{Drag, MainWindow, Pane, SCROLLBAR_W};
use gpui_kit::component::menu::ContextMenuExt;
use gpui_kit::component::ElementExt as _;
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    actions, div, px, Bounds, ClipboardItem, Context, FocusHandle, KeyDownEvent, MouseButton,
    MouseDownEvent, Pixels, Point, ScrollEvent, SharedString, Window,
};
use moex_core::{BinaryRange, Image};
use std::sync::{Arc, LazyLock};

actions!(moex_hex, [CopyHex, CopyAscii, SelectAllBytes]);

pub const HEX_ROW_H: f32 = 18.0;
pub const HEX_HEADER_H: f32 = 22.0;
pub const PAD: f32 = 8.0;
/// Width of the offset column (`0x` + 16 digits).
pub const OFFSET_W: f32 = 120.0;
pub const GAP: f32 = 10.0;
pub const HEX_CELL_W: f32 = 19.0;
pub const ASCII_CELL_W: f32 = 7.0;
pub const HEX_X: f32 = PAD + OFFSET_W + GAP;
pub const ASCII_X: f32 = HEX_X + 16.0 * HEX_CELL_W + GAP;
/// Natural width of the pane content (used for the default pane size).
pub const CONTENT_W: f32 = ASCII_X + 16.0 * ASCII_CELL_W + PAD + SCROLLBAR_W;

static HEX_STR: LazyLock<Vec<SharedString>> = LazyLock::new(|| {
    (0..=255u8)
        .map(|b| {
            let h = hex::hex_byte(b);
            SharedString::from(format!("{}{}", h[0] as char, h[1] as char))
        })
        .collect()
});

static ASCII_STR: LazyLock<Vec<SharedString>> = LazyLock::new(|| {
    (0..=255u8)
        .map(|b| SharedString::from(hex::ascii_char(b).to_string()))
        .collect()
});

/// Which column group a point is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexArea {
    Hex,
    Ascii,
}

/// Map a point relative to the row area's top-left corner to
/// `(row, column, area)`. Points left/right of the byte columns clamp to
/// the nearest column; `None` when there are no rows.
pub fn hit_test(x: f32, y: f32, scroll: &VScroll) -> Option<(u64, usize, HexArea)> {
    if scroll.total_rows == 0 {
        return None;
    }
    let row = (((scroll.top + y as f64) / scroll.row_height as f64)
        .floor()
        .max(0.0) as u64)
        .min(scroll.total_rows - 1);
    let (area, col) = if x >= ASCII_X - GAP / 2.0 {
        (HexArea::Ascii, ((x - ASCII_X) / ASCII_CELL_W).floor())
    } else {
        (HexArea::Hex, ((x - HEX_X) / HEX_CELL_W).floor())
    };
    Some((row, col.clamp(0.0, 15.0) as usize, area))
}

pub struct HexView {
    image: Option<Arc<Image>>,
    /// Displayed range, clipped to the file.
    pub range: Option<BinaryRange>,
    pub scroll: VScroll,
    pub selection: Option<ByteSelection>,
    /// First byte of a mouse selection in progress.
    anchor: Option<u64>,
    /// Copy shortcut copies ASCII when the last click was in that column.
    pub ascii_active: bool,
    pub focus: FocusHandle,
    /// Bounds of the row area.
    pub bounds: Bounds<Pixels>,
    /// Rows drawn by the last frame (for tests / diagnostics).
    pub rendered_rows: usize,
}

impl HexView {
    pub fn new(cx: &mut Context<MainWindow>) -> Self {
        HexView {
            image: None,
            range: None,
            scroll: VScroll::new(HEX_ROW_H),
            selection: None,
            anchor: None,
            ascii_active: false,
            focus: cx.focus_handle(),
            bounds: Bounds::default(),
            rendered_rows: 0,
        }
    }

    pub fn set_document(&mut self, image: Option<Arc<Image>>) {
        self.image = image;
        self.set_range(None);
    }

    pub fn set_range(&mut self, range: Option<BinaryRange>) {
        let len = self.image.as_ref().map(|i| i.len()).unwrap_or(0);
        self.range = range
            .map(|r| hex::clip_range(r, len))
            .filter(|r| r.size > 0);
        self.selection = None;
        self.anchor = None;
        self.scroll
            .set_total(self.range.as_ref().map(hex::row_count).unwrap_or(0));
        self.scroll.scroll_to_top();
    }

    fn data(&self) -> &[u8] {
        self.image.as_ref().map(|i| i.bytes()).unwrap_or(&[])
    }

    /// Highlight `sel` (clamped to the range) and scroll it into view.
    pub fn select(&mut self, sel: Option<ByteSelection>) {
        let Some(range) = self.range else {
            self.selection = None;
            return;
        };
        self.selection = sel.and_then(|s| hex::clamp_selection(&range, s));
        if let Some(s) = self.selection {
            if let (Some(first), Some(last)) = (
                hex::row_of_offset(&range, s.start),
                hex::row_of_offset(&range, s.end - 1),
            ) {
                let fully_visible = |vs: &VScroll, row: u64| {
                    let top = row as f64 * vs.row_height as f64;
                    top >= vs.top && top + vs.row_height as f64 <= vs.top + vs.viewport as f64
                };
                if !fully_visible(&self.scroll, first) || !fully_visible(&self.scroll, last) {
                    // Keep the start of the selection in view; centre it
                    // when the whole selection fits.
                    let rows = last - first + 1;
                    if rows <= self.scroll.page_rows() {
                        self.scroll
                            .ensure_visible(first + rows / 2, ScrollTo::Center);
                    } else {
                        self.scroll.ensure_visible(first, ScrollTo::Top);
                    }
                }
            }
        }
    }

    fn hit(&self, pos: Point<Pixels>) -> Option<(u64, HexArea)> {
        let range = self.range?;
        let x = f32::from(pos.x - self.bounds.origin.x);
        let y = f32::from(pos.y - self.bounds.origin.y);
        let (row, col, area) = hit_test(x, y, &self.scroll)?;
        Some((hex::offset_at(&range, row, col)?, area))
    }

    pub(crate) fn begin_select(&mut self, pos: Point<Pixels>, extend: bool) -> bool {
        let Some((offset, area)) = self.hit(pos) else {
            return false;
        };
        self.ascii_active = area == HexArea::Ascii;
        match (extend, self.anchor) {
            (true, Some(anchor)) => self.selection = Some(ByteSelection::between(anchor, offset)),
            _ => {
                self.anchor = Some(offset);
                self.selection = Some(ByteSelection::between(offset, offset));
            }
        }
        true
    }

    pub(crate) fn drag_select_to(&mut self, pos: Point<Pixels>) {
        let Some(anchor) = self.anchor else { return };
        // Auto-scroll while dragging beyond the top/bottom edge.
        let y = f32::from(pos.y - self.bounds.origin.y);
        if y < 0.0 {
            self.scroll.scroll_by(-(HEX_ROW_H as f64));
        } else if y > self.scroll.viewport {
            self.scroll.scroll_by(HEX_ROW_H as f64);
        }
        if let Some((offset, _)) = self.hit(pos) {
            self.selection = Some(ByteSelection::between(anchor, offset));
        }
    }

    pub fn select_all(&mut self) {
        if let Some(r) = self.range {
            self.selection = ByteSelection::new(r.offset, r.size);
            self.anchor = Some(r.offset);
        }
    }

    pub fn selection_text(&self, ascii: bool) -> Option<Result<String, String>> {
        let sel = self.selection?;
        Some(if ascii {
            hex::selection_as_ascii(self.data(), sel)
        } else {
            hex::selection_as_hex(self.data(), sel)
        })
    }
}

impl MainWindow {
    pub fn copy_hex_selection(&mut self, ascii: bool, window: &mut Window, cx: &mut Context<Self>) {
        match self.hex.selection_text(ascii) {
            Some(Ok(text)) => {
                cx.write_to_clipboard(ClipboardItem::new_string(text));
                let n = self.hex.selection.map(|s| s.len()).unwrap_or(0);
                self.set_status(
                    format!(
                        "Copied {n} bytes as {}",
                        if ascii { "ASCII" } else { "hex" }
                    ),
                    Some(2000),
                    cx,
                );
            }
            Some(Err(e)) => self.show_error(e, window, cx),
            None => {}
        }
    }

    fn hex_key(&mut self, ev: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let m = &ev.keystroke.modifiers;
        let page = self.hex.scroll.viewport as f64;
        match ev.keystroke.key.as_str() {
            "c" if m.secondary(cx) => {
                let ascii = self.hex.ascii_active != m.shift;
                self.copy_hex_selection(ascii, window, cx);
            }
            "a" if m.secondary(cx) => self.hex.select_all(),
            "down" => {
                self.hex.scroll.scroll_by(HEX_ROW_H as f64);
            }
            "up" => {
                self.hex.scroll.scroll_by(-(HEX_ROW_H as f64));
            }
            "pagedown" => {
                self.hex.scroll.scroll_by(page);
            }
            "pageup" => {
                self.hex.scroll.scroll_by(-page);
            }
            "home" => self.hex.scroll.scroll_to_top(),
            "end" => {
                self.hex.scroll.scroll_by(f64::MAX / 4.0);
            }
            "escape" => self.hex.selection = None,
            _ => return,
        }
        cx.stop_propagation();
        cx.notify();
    }

    pub(crate) fn render_hex_view(
        &mut self,
        pal: &Palette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let v = self.hex.scroll.visible();
        self.hex.rendered_rows = v.count;
        let focused = self.hex.focus.is_focused(window);
        // The highlight mirrors the table row, so it stays prominent even
        // when the hex pane itself is not focused.
        let _ = focused;
        let sel_bg = pal.selection_bg;
        let sel_fg = pal.selection_fg;

        let mut rows = Vec::with_capacity(v.count);
        if let Some(range) = self.hex.range {
            let data = self.hex.data();
            for i in 0..v.count {
                let row = v.first + i as u64;
                let bytes = hex::row_bytes(data, &range, row);
                let sel = hex::row_selection(&range, row, self.hex.selection);
                let is_sel = |c: usize| sel.map(|(s, e)| c >= s && c < e).unwrap_or(false);
                let label: SharedString = hex::offset_label(&range, row).into();
                rows.push(
                    div()
                        .absolute()
                        .top(px(v.y + i as f32 * HEX_ROW_H))
                        .left_0()
                        .h(px(HEX_ROW_H))
                        .flex()
                        .line_height(px(HEX_ROW_H))
                        .child(
                            div()
                                .flex_none()
                                .ml(px(PAD))
                                .w(px(OFFSET_W))
                                .text_color(pal.hex_dim)
                                .child(label),
                        )
                        .child(
                            div()
                                .flex_none()
                                .ml(px(GAP))
                                .w(px(16.0 * HEX_CELL_W))
                                .flex()
                                .children(bytes.iter().enumerate().map(|(c, b)| {
                                    div()
                                        .flex_none()
                                        .w(px(HEX_CELL_W))
                                        .h_full()
                                        .flex()
                                        .justify_center()
                                        .when(is_sel(c), |d| d.bg(sel_bg).text_color(sel_fg))
                                        .child(HEX_STR[*b as usize].clone())
                                })),
                        )
                        .child(
                            div()
                                .flex_none()
                                .ml(px(GAP))
                                .w(px(16.0 * ASCII_CELL_W))
                                .flex()
                                .children(bytes.iter().enumerate().map(|(c, b)| {
                                    div()
                                        .flex_none()
                                        .w(px(ASCII_CELL_W))
                                        .h_full()
                                        .flex()
                                        .justify_center()
                                        .when(is_sel(c), |d| d.bg(sel_bg).text_color(sel_fg))
                                        .child(ASCII_STR[*b as usize].clone())
                                })),
                        ),
                );
            }
        }

        let header = div()
            .flex_none()
            .h(px(HEX_HEADER_H))
            .w_full()
            .flex()
            .items_center()
            .bg(pal.header_bg)
            .text_color(pal.header_fg)
            .border_b_1()
            .border_color(pal.border)
            .overflow_hidden()
            .child(
                div()
                    .flex_none()
                    .ml(px(PAD))
                    .w(px(OFFSET_W))
                    .child("Offset"),
            )
            .child(
                div()
                    .flex_none()
                    .ml(px(GAP))
                    .w(px(16.0 * HEX_CELL_W))
                    .flex()
                    .children((0..16).map(|c| {
                        div()
                            .flex_none()
                            .w(px(HEX_CELL_W))
                            .flex()
                            .justify_center()
                            .child(SharedString::from(hex::hex_header_digit(c).to_string()))
                    })),
            )
            .child(
                div()
                    .flex_none()
                    .ml(px(GAP))
                    .w(px(16.0 * ASCII_CELL_W))
                    .flex()
                    .children((0..16).map(|c| {
                        div()
                            .flex_none()
                            .w(px(ASCII_CELL_W))
                            .flex()
                            .justify_center()
                            .child(SharedString::from(hex::hex_header_digit(c).to_string()))
                    })),
            );

        let vbar = crate::scrollbar::vscrollbar(
            "hex-scrollbar",
            &self.hex.scroll,
            pal,
            cx.listener(|this, ev: &MouseDownEvent, _, cx| {
                this.begin_thumb_drag(Pane::Hex, ev.position.y, cx)
            }),
        );
        let empty = self.hex.range.is_none();

        div()
            .id("hex")
            .key_context("HexView")
            .track_focus(&self.hex.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(pal.panel_bg)
            .on_key_down(cx.listener(Self::hex_key))
            .on_action(cx.listener(|this, _: &CopyHex, window, cx| {
                this.copy_hex_selection(false, window, cx)
            }))
            .on_action(cx.listener(|this, _: &CopyAscii, window, cx| {
                this.copy_hex_selection(true, window, cx)
            }))
            .on_action(cx.listener(|this, _: &SelectAllBytes, _, cx| {
                this.hex.select_all();
                cx.notify();
            }))
            .child(Self::pane_title("Hex", pal))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .flex()
                    .flex_col()
                    .font_family(theme::MONO_FONT)
                    .text_size(px(theme::MONO_SIZE))
                    .child(header)
                    .child(
                        div()
                            .id("hex-body")
                            .test_support()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .relative()
                            .overflow_hidden()
                            .cursor_text()
                            .on_scroll(cx.listener(|this, ev: &ScrollEvent, _, cx| {
                                let d = ev.delta.pixel_delta(px(HEX_ROW_H));
                                this.wheel(Pane::Hex, f32::from(d.y), cx);
                            }))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, ev: &MouseDownEvent, window, cx| {
                                    window.focus(&this.hex.focus, cx);
                                    if this.hex.begin_select(ev.position, ev.modifiers.shift) {
                                        this.drag = Some(Drag::HexSelect);
                                    }
                                    cx.notify();
                                }),
                            )
                            .on_mouse_down(
                                MouseButton::Right,
                                cx.listener(|this, _: &MouseDownEvent, window, cx| {
                                    window.focus(&this.hex.focus, cx)
                                }),
                            )
                            .on_prepaint(Self::track_bounds(Pane::Hex, cx))
                            .children(rows)
                            .when(empty, |d| {
                                d.child(
                                    div()
                                        .size_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_color(pal.muted)
                                        .child("No bytes for this node"),
                                )
                            })
                            .children(vbar)
                            .context_menu(|menu, _, _| {
                                menu.menu("Copy as Hex", Box::new(CopyHex))
                                    .menu("Copy as ASCII", Box::new(CopyAscii))
                                    .separator()
                                    .menu("Select All", Box::new(SelectAllBytes))
                            }),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_testing_maps_points_to_bytes() {
        let mut s = VScroll::new(HEX_ROW_H);
        s.set_total(1000);
        s.set_viewport(360.0);
        assert_eq!(hit_test(HEX_X + 1.0, 1.0, &s), Some((0, 0, HexArea::Hex)));
        assert_eq!(
            hit_test(HEX_X + 3.0 * HEX_CELL_W + 5.0, HEX_ROW_H * 2.0 + 3.0, &s),
            Some((2, 3, HexArea::Hex))
        );
        assert_eq!(
            hit_test(ASCII_X + 15.0 * ASCII_CELL_W + 1.0, 0.0, &s),
            Some((0, 15, HexArea::Ascii))
        );
        // Left of the bytes clamps to column 0, far right to column 15.
        assert_eq!(hit_test(0.0, 0.0, &s), Some((0, 0, HexArea::Hex)));
        assert_eq!(hit_test(5000.0, 0.0, &s), Some((0, 15, HexArea::Ascii)));
        s.scroll_by(HEX_ROW_H as f64 * 10.5);
        assert_eq!(hit_test(HEX_X, 0.0, &s).unwrap().0, 10);
        assert_eq!(hit_test(HEX_X, 1e9, &s).unwrap().0, 999);
        assert_eq!(hit_test(0.0, 0.0, &VScroll::new(HEX_ROW_H)), None);
    }

    #[test]
    fn content_width_matches_columns() {
        assert_eq!(hex::BYTES_PER_ROW, 16);
        assert!(CONTENT_W > ASCII_X + 16.0 * ASCII_CELL_W);
    }
}
