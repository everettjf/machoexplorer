//! Central table pane: virtualized rows, resizable columns, row filter,
//! selection (drives the hex pane) and copy/export.

use crate::table_model as tm;
use crate::theme::{self, Palette};
use crate::vscroll::{ScrollTo, VScroll};
use crate::window::{Drag, MainWindow, Pane, SCROLLBAR_W};
use gpui_kit::component::button::Button;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::menu::ContextMenuExt;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::ElementExt as _;
use gpui_kit::component::Sizable;
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    actions, div, px, Bounds, ClipboardItem, Context, Entity, FocusHandle, KeyDownEvent,
    MouseButton, MouseDownEvent, Pixels, ScrollEvent, SharedString, Window,
};
use moex_core::{Table, ViewNode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

actions!(moex_table, [CopyCell, CopyRow, CopyAllRows, ExportCsv]);

pub const TABLE_ROW_H: f32 = 24.0;
pub const HEADER_H: f32 = 28.0;
const CELL_PAD: f32 = 8.0;

pub struct TablePanel {
    node: Option<ViewNode>,
    /// Name of the node whose content is being built.
    pub loading: Option<SharedString>,
    pub widths: Vec<f32>,
    pub scroll: VScroll,
    pub hscroll: f32,
    /// Selected row, as an index into the visible (filtered) rows.
    pub selected: Option<usize>,
    /// Source row indices that pass the filter; `None` = no filter.
    pub filtered: Option<Arc<Vec<u32>>>,
    pub filter_input: Entity<InputState>,
    filter_seq: u64,
    filter_cancel: Arc<AtomicBool>,
    pub filter_busy: bool,
    pub focus: FocusHandle,
    /// Bounds of the row area (below the header).
    pub bounds: Bounds<Pixels>,
    /// Cell under the last right-click `(visible row, column)`.
    pub context_cell: Option<(usize, usize)>,
    /// Rows drawn by the last frame (for tests / diagnostics).
    pub rendered_rows: usize,
}

impl TablePanel {
    pub fn new(window: &mut Window, cx: &mut Context<MainWindow>) -> Self {
        let filter_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Filter rows (all columns)...")
                .clean_on_escape()
        });
        cx.subscribe_in(
            &filter_input,
            window,
            |this: &mut MainWindow, input, ev: &InputEvent, window, cx| match ev {
                InputEvent::Change => {
                    let text = input.read(cx).value().to_string();
                    this.set_table_filter(text, true, window, cx);
                }
                InputEvent::PressEnter { .. } => window.focus(&this.table.focus, cx),
                _ => {}
            },
        )
        .detach();
        TablePanel {
            node: None,
            loading: None,
            widths: Vec::new(),
            scroll: VScroll::new(TABLE_ROW_H),
            hscroll: 0.0,
            selected: None,
            filtered: None,
            filter_input,
            filter_seq: 0,
            filter_cancel: Arc::new(AtomicBool::new(false)),
            filter_busy: false,
            focus: cx.focus_handle(),
            bounds: Bounds::default(),
            context_cell: None,
            rendered_rows: 0,
        }
    }

    pub fn node_id(&self) -> Option<usize> {
        self.node.as_ref().map(|n| n.id())
    }

    /// The displayed table. Only called for nodes that were already built.
    pub fn table(&self) -> Option<&Table> {
        self.node.as_ref().and_then(|n| n.table())
    }

    pub fn total_len(&self) -> usize {
        self.table().map(|t| t.rows.len()).unwrap_or(0)
    }

    pub fn visible_len(&self) -> usize {
        match &self.filtered {
            Some(f) => f.len(),
            None => self.total_len(),
        }
    }

    /// Source row index of visible row `vis`.
    pub fn source_index(&self, vis: usize) -> Option<usize> {
        match &self.filtered {
            Some(f) => f.get(vis).map(|i| *i as usize),
            None => (vis < self.total_len()).then_some(vis),
        }
    }

    pub fn status_text(&self) -> String {
        tm::status_text(
            self.visible_len(),
            self.total_len(),
            self.filtered.is_some(),
        )
    }

    fn cancel_filter(&mut self) {
        self.filter_seq += 1;
        self.filter_cancel.store(true, Ordering::Relaxed);
        self.filter_cancel = Arc::new(AtomicBool::new(false));
        self.filter_busy = false;
    }

    pub fn set_loading(&mut self, name: String) {
        self.cancel_filter();
        self.node = None;
        self.filtered = None;
        self.selected = None;
        self.scroll.set_total(0);
        self.loading = Some(name.into());
    }

    pub fn set_node(
        &mut self,
        node: Option<ViewNode>,
        window: &mut Window,
        cx: &mut Context<MainWindow>,
    ) {
        self.cancel_filter();
        self.loading = None;
        self.node = node;
        self.filtered = None;
        self.selected = None;
        self.context_cell = None;
        self.hscroll = 0.0;
        self.widths = self.table().map(tm::initial_widths).unwrap_or_default();
        self.scroll.set_total(self.total_len() as u64);
        self.scroll.scroll_to_top();
        if !self.filter_input.read(cx).value().is_empty() {
            self.filter_input
                .update(cx, |s, cx| s.set_value("", window, cx));
        }
    }

    fn viewport_width(&self) -> f32 {
        f32::from(self.bounds.size.width)
    }

    pub fn drawn_widths(&self) -> Vec<f32> {
        tm::stretched_widths(&self.widths, self.viewport_width())
    }

    fn content_width(&self) -> f32 {
        self.drawn_widths().iter().sum()
    }

    fn max_hscroll(&self) -> f32 {
        (self.content_width() - self.viewport_width()).max(0.0)
    }

    fn clamp_hscroll(&mut self) {
        self.hscroll = self.hscroll.clamp(0.0, self.max_hscroll());
    }

    /// Horizontal thumb `(start, len)` in a track as wide as the viewport.
    fn hthumb(&self) -> Option<(f32, f32)> {
        let vw = self.viewport_width();
        let cw = self.content_width();
        if cw <= vw + 0.5 || vw <= 0.0 {
            return None;
        }
        let len = (vw / cw * vw).max(24.0);
        Some((self.hscroll / (cw - vw) * (vw - len), len))
    }

    pub(crate) fn drag_hthumb(&mut self, x: f32, grab: f32) {
        let Some((_, len)) = self.hthumb() else {
            return;
        };
        let vw = self.viewport_width();
        let start = x - f32::from(self.bounds.origin.x) - grab;
        self.hscroll = (start / (vw - len).max(1.0)).clamp(0.0, 1.0) * self.max_hscroll();
    }

    /// Column under window x-coordinate `x`.
    fn column_at(&self, x: f32) -> usize {
        let mut rel = x - f32::from(self.bounds.origin.x) + self.hscroll;
        let widths = self.drawn_widths();
        for (i, w) in widths.iter().enumerate() {
            if rel < *w {
                return i;
            }
            rel -= w;
        }
        widths.len().saturating_sub(1)
    }
}

impl MainWindow {
    /// Select visible row `vis`: highlights its bytes in the hex pane and
    /// fills the Information pane.
    pub fn select_table_row(&mut self, vis: usize, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(src) = self.table.source_index(vis) else {
            return;
        };
        self.table.selected = Some(vis);
        self.table
            .scroll
            .ensure_visible(vis as u64, ScrollTo::Nearest);
        let (range, info) = {
            let Some(table) = self.table.table() else {
                return;
            };
            let file = self.doc.as_ref().map(|d| d.image.bytes()).unwrap_or(&[]);
            (
                tm::row_byte_range(&table.rows[src]),
                tm::row_description(table, src, file),
            )
        };
        self.hex.select(range);
        self.info = info.into();
        cx.notify();
    }

    pub fn focus_table_filter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.doc.is_some() && self.modal.is_none() {
            self.table
                .filter_input
                .update(cx, |s, cx| s.focus(window, cx));
        }
    }

    pub fn clear_table_filter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.table.filter_input.read(cx).value().is_empty() {
            self.table
                .filter_input
                .update(cx, |s, cx| s.set_value("", window, cx));
        }
        self.set_table_filter(String::new(), false, window, cx);
    }

    /// Apply the row filter. With `debounce`, waits 120 ms for more typing
    /// (as Qt did); scanning runs on a background thread.
    pub fn set_table_filter(
        &mut self,
        text: String,
        debounce: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.table.cancel_filter();
        let Some(node) = self.table.node.clone() else {
            return;
        };
        let selected_src = self.table.selected.and_then(|v| self.table.source_index(v));
        if text.is_empty() {
            self.table.filtered = None;
            self.after_filter(selected_src, cx);
            return;
        }
        let seq = self.table.filter_seq;
        let cancel = self.table.filter_cancel.clone();
        self.table.filter_busy = true;
        cx.spawn_in(window, async move |this, cx| {
            if debounce {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
            }
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let rows = cx
                .background_executor()
                .spawn(async move {
                    node.table()
                        .and_then(|t| tm::filter_rows(t, &text, &cancel))
                })
                .await;
            let _ = this.update_in(cx, |this, _, cx| {
                if this.table.filter_seq != seq {
                    return;
                }
                this.table.filter_busy = false;
                if let Some(rows) = rows {
                    this.table.filtered = Some(Arc::new(rows));
                    this.after_filter(selected_src, cx);
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn after_filter(&mut self, selected_src: Option<usize>, cx: &mut Context<Self>) {
        let t = &mut self.table;
        t.scroll.set_total(t.visible_len() as u64);
        // Keep the selected row if it is still visible.
        t.selected = selected_src.and_then(|src| match &t.filtered {
            Some(f) => f.binary_search(&(src as u32)).ok(),
            None => Some(src),
        });
        match t.selected {
            Some(v) => t.scroll.ensure_visible(v as u64, ScrollTo::Center),
            None => t.scroll.scroll_to_top(),
        }
        cx.notify();
    }

    fn copy_text(&mut self, text: String, what: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.set_status(format!("Copied {what}"), Some(2000), cx);
    }

    pub fn copy_table_row(&mut self, cx: &mut Context<Self>) {
        let Some(src) = self.table.selected.and_then(|v| self.table.source_index(v)) else {
            return;
        };
        let Some(table) = self.table.table() else {
            return;
        };
        let text = tm::row_tsv(&table.rows[src], tm::column_count(table));
        self.copy_text(text, "row", cx);
    }

    pub fn copy_table_cell(&mut self, cx: &mut Context<Self>) {
        let (vis, col) = match (self.table.context_cell, self.table.selected) {
            (Some(c), _) => c,
            (None, Some(v)) => (v, 0),
            _ => return,
        };
        let Some(src) = self.table.source_index(vis) else {
            return;
        };
        let Some(table) = self.table.table() else {
            return;
        };
        let text = tm::cell(&table.rows[src], col).to_string();
        self.copy_text(text, "cell", cx);
    }

    pub fn copy_table_all(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(table) = self.table.table() else {
            return;
        };
        if tm::column_count(table) == 0 || self.table.visible_len() == 0 {
            return;
        }
        match tm::all_tsv(table, self.table.filtered.as_ref().map(|f| f.as_slice())) {
            Ok(text) => self.copy_text(text, "all visible rows", cx),
            Err(e) => self.show_error(e, window, cx),
        }
    }

    pub fn export_table_csv(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(node) = self.table.node.clone() else {
            return;
        };
        let filtered = self.table.filtered.clone();
        let dir = dirs::home_dir().unwrap_or_else(std::env::temp_dir);
        let rx = cx.prompt_for_new_path(&dir, Some("MachOExplorer-export.csv"));
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(path))) = rx.await else { return };
            let out = path.clone();
            let result = cx
                .background_executor()
                .spawn(async move {
                    let table = node
                        .table()
                        .ok_or_else(|| std::io::Error::other("no table"))?;
                    let mut file = std::io::BufWriter::new(std::fs::File::create(&out)?);
                    let n =
                        tm::write_csv(table, filtered.as_ref().map(|f| f.as_slice()), &mut file)?;
                    std::io::Write::flush(&mut file)?;
                    Ok::<_, std::io::Error>(n)
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| match result {
                Ok(n) => this.show_info(
                    format!("Exported {n} rows to {}", path.display()),
                    window,
                    cx,
                ),
                Err(_) => {
                    this.show_error(format!("Cannot write file: {}", path.display()), window, cx)
                }
            });
        })
        .detach();
    }

    /// Double click on a row of a dyld cache image list extracts that image.
    fn table_row_activated(&mut self, vis: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(path) = self.path.clone() else {
            return;
        };
        if !crate::cache_extract::is_cache_file(&path) {
            return;
        }
        let Some(src) = self.table.source_index(vis) else {
            return;
        };
        let Some(image) = self
            .table
            .table()
            .and_then(|t| tm::cache_image_path_for_row(t, src))
        else {
            return;
        };
        self.extract_cache_image(path, image, true, window, cx);
    }

    pub(crate) fn table_key(
        &mut self,
        ev: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let len = self.table.visible_len();
        let cur = self.table.selected;
        let page = self.table.scroll.page_rows() as usize;
        let m = &ev.keystroke.modifiers;
        let target = match ev.keystroke.key.as_str() {
            "c" if m.secondary(cx) && m.shift => {
                self.copy_table_all(window, cx);
                None
            }
            "c" if m.secondary(cx) => {
                self.copy_table_row(cx);
                None
            }
            "escape" => {
                self.clear_table_filter(window, cx);
                None
            }
            _ if len == 0 => return,
            "down" => Some(cur.map(|c| (c + 1).min(len - 1)).unwrap_or(0)),
            "up" => Some(cur.map(|c| c.saturating_sub(1)).unwrap_or(0)),
            "pagedown" => Some(cur.map(|c| (c + page).min(len - 1)).unwrap_or(0)),
            "pageup" => Some(cur.map(|c| c.saturating_sub(page)).unwrap_or(0)),
            "home" => Some(0),
            "end" => Some(len - 1),
            "enter" => {
                if let Some(c) = cur {
                    self.table_row_activated(c, window, cx);
                }
                None
            }
            _ => return,
        };
        if let Some(t) = target {
            if Some(t) != cur {
                self.select_table_row(t, window, cx);
            }
        }
        cx.stop_propagation();
    }

    pub(crate) fn render_table_panel(
        &mut self,
        pal: &Palette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        self.table.clamp_hscroll();
        let v = self.table.scroll.visible();
        self.table.rendered_rows = v.count;
        let focused = self.table.focus.is_focused(window);
        let widths = self.table.drawn_widths();
        let content_w: f32 = widths.iter().sum();
        let hscroll = self.table.hscroll;
        let selected = self.table.selected;
        let cols = widths.len();

        let mut rows = Vec::with_capacity(v.count);
        if let Some(table) = self.table.table() {
            for i in 0..v.count {
                let vis = v.first as usize + i;
                let Some(src) = self.table.source_index(vis) else {
                    break;
                };
                let Some(row) = table.rows.get(src) else {
                    break;
                };
                let is_selected = selected == Some(vis);
                let y = v.y + i as f32 * TABLE_ROW_H;
                let bg = if is_selected {
                    if focused {
                        pal.selection_bg
                    } else {
                        pal.selection_inactive_bg
                    }
                } else if vis % 2 == 1 {
                    pal.alt_bg
                } else {
                    pal.panel_bg
                };
                let fg = if is_selected && focused {
                    pal.selection_fg
                } else {
                    pal.text
                };
                let select =
                    cx.listener(move |this: &mut Self, ev: &MouseDownEvent, window, cx| {
                        window.focus(&this.table.focus, cx);
                        this.table.context_cell =
                            Some((vis, this.table.column_at(f32::from(ev.position.x))));
                        this.select_table_row(vis, window, cx);
                        if ev.button == MouseButton::Left && ev.click_count == 2 {
                            this.table_row_activated(vis, window, cx);
                        }
                    });
                let select_right =
                    cx.listener(move |this: &mut Self, ev: &MouseDownEvent, window, cx| {
                        window.focus(&this.table.focus, cx);
                        this.table.context_cell =
                            Some((vis, this.table.column_at(f32::from(ev.position.x))));
                        this.select_table_row(vis, window, cx);
                    });
                rows.push(
                    div()
                        .id(("table-row", vis))
                        .test_support()
                        .absolute()
                        .top(px(y))
                        .left(px(-hscroll))
                        .w(px(content_w))
                        .h(px(TABLE_ROW_H))
                        .flex()
                        .bg(bg)
                        .text_color(fg)
                        .border_b_1()
                        .border_color(pal.grid)
                        .on_mouse_down(MouseButton::Left, select)
                        .on_mouse_down(MouseButton::Right, select_right)
                        .children((0..cols).map(|c| {
                            let text: SharedString = tm::cell(row, c).to_string().into();
                            div()
                                .flex_none()
                                .w(px(widths[c]))
                                .h_full()
                                .px(px(CELL_PAD))
                                .line_height(px(TABLE_ROW_H - 1.0))
                                .border_r_1()
                                .border_color(pal.grid)
                                .truncate()
                                .child(text)
                        })),
                );
            }
        }

        let header = self.table.table().map(|table| {
            div()
                .flex_none()
                .h(px(HEADER_H))
                .w_full()
                .relative()
                .overflow_hidden()
                .bg(pal.header_bg)
                .border_b_1()
                .border_color(pal.border)
                .child(
                    div()
                        .absolute()
                        .top_0()
                        .left(px(-hscroll))
                        .w(px(content_w))
                        .h_full()
                        .flex()
                        .text_color(pal.header_fg)
                        .font_weight(gpui_kit::FontWeight::SEMIBOLD)
                        .children(table.headers.iter().enumerate().map(|(c, h)| {
                            let title: SharedString = h.clone().into();
                            div()
                                .flex_none()
                                .w(px(widths[c]))
                                .h_full()
                                .relative()
                                .px(px(CELL_PAD))
                                .line_height(px(HEADER_H - 1.0))
                                .border_r_1()
                                .border_color(pal.border)
                                .child(div().w_full().truncate().child(title))
                                .child(
                                    div()
                                        .id(("col-resize", c))
                                        .absolute()
                                        .top_0()
                                        .right(px(-3.))
                                        .w(px(7.))
                                        .h_full()
                                        .cursor_col_resize()
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(move |this, ev: &MouseDownEvent, _, cx| {
                                                let width = this
                                                    .table
                                                    .widths
                                                    .get(c)
                                                    .copied()
                                                    .unwrap_or(100.0);
                                                this.drag = Some(Drag::Column {
                                                    col: c,
                                                    start_x: f32::from(ev.position.x),
                                                    width,
                                                });
                                                cx.stop_propagation();
                                                cx.notify();
                                            }),
                                        ),
                                )
                        })),
                )
        });

        let vbar = crate::scrollbar::vscrollbar(
            "table-scrollbar",
            &self.table.scroll,
            pal,
            cx.listener(|this, ev: &MouseDownEvent, _, cx| {
                this.begin_thumb_drag(Pane::Table, ev.position.y, cx)
            }),
        );
        let hbar = self.table.hthumb().map(|(start, len)| {
            div()
                .id("table-hscrollbar")
                .absolute()
                .left_0()
                .bottom_0()
                .w_full()
                .h(px(SCROLLBAR_W))
                .occlude()
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, ev: &MouseDownEvent, _, cx| {
                        let local =
                            f32::from(ev.position.x) - f32::from(this.table.bounds.origin.x);
                        let grab = if local >= start && local <= start + len {
                            local - start
                        } else {
                            len / 2.0
                        };
                        this.table.drag_hthumb(f32::from(ev.position.x), grab);
                        this.drag = Some(Drag::TableHThumb { grab });
                        cx.stop_propagation();
                        cx.notify();
                    }),
                )
                .child(
                    div()
                        .absolute()
                        .left(px(start))
                        .bottom(px(2.))
                        .h(px(SCROLLBAR_W - 4.))
                        .w(px(len))
                        .rounded(px(4.))
                        .bg(pal.scroll_thumb),
                )
        });

        let has_table = self.table.table().is_some();
        let status: SharedString = if self.table.filter_busy {
            "Filtering…".into()
        } else {
            self.table.status_text().into()
        };
        let top_bar = div()
            .flex_none()
            .w_full()
            .p(px(4.))
            .flex()
            .items_center()
            .gap(px(6.))
            .border_b_1()
            .border_color(pal.border)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(Input::new(&self.table.filter_input).small().cleanable(true)),
            )
            .child(
                div()
                    .id("table-status")
                    .flex_none()
                    .min_w(px(120.))
                    .text_color(pal.muted)
                    .child(status),
            )
            .child(
                Button::new("table-clear-filter")
                    .small()
                    .outline()
                    .label("Clear")
                    .tooltip("Clear current filter text (same as Esc).")
                    .on_click(
                        cx.listener(|this, _, window, cx| this.clear_table_filter(window, cx)),
                    ),
            )
            .child(
                Button::new("table-export-csv")
                    .small()
                    .outline()
                    .label("Export CSV")
                    .tooltip("Export currently visible rows to CSV.")
                    .on_click(cx.listener(|this, _, window, cx| this.export_table_csv(window, cx))),
            );

        let body = div()
            .id("table-body")
            .test_support()
            .flex_1()
            .min_h_0()
            .w_full()
            .relative()
            .overflow_hidden()
            .font_family(theme::MONO_FONT)
            .text_size(px(theme::MONO_SIZE))
            .on_scroll(cx.listener(|this, ev: &ScrollEvent, _, cx| {
                let d = ev.delta.pixel_delta(px(TABLE_ROW_H));
                let (dx, dy) = (f32::from(d.x), f32::from(d.y));
                if dx.abs() > dy.abs() {
                    let before = this.table.hscroll;
                    this.table.hscroll -= dx;
                    this.table.clamp_hscroll();
                    if this.table.hscroll != before {
                        cx.notify();
                    }
                } else {
                    this.wheel(Pane::Table, dy, cx);
                }
            }))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _: &MouseDownEvent, window, cx| {
                    window.focus(&this.table.focus, cx)
                }),
            )
            .on_prepaint(Self::track_bounds(Pane::Table, cx))
            .children(rows)
            .children(vbar)
            .children(hbar)
            .context_menu(|menu, _, _| {
                menu.menu("Copy Cell", Box::new(CopyCell))
                    .menu("Copy Row", Box::new(CopyRow))
                    .menu("Copy All Visible Rows", Box::new(CopyAllRows))
                    .separator()
                    .menu("Export CSV...", Box::new(ExportCsv))
            });

        let placeholder = if let Some(name) = &self.table.loading {
            Some(
                div()
                    .id("table-loading")
                    .test_support()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap_3()
                    .child(Spinner::new().color(pal.accent))
                    .child(
                        div()
                            .text_color(pal.muted)
                            .child(format!("Loading {name}…")),
                    )
                    .into_any_element(),
            )
        } else if !has_table {
            Some(
                div()
                    .id("table-empty")
                    .flex_1()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(pal.muted)
                    .child("No table for this node")
                    .into_any_element(),
            )
        } else {
            None
        };

        div()
            .id("table")
            .key_context("NodeTable")
            .track_focus(&self.table.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(pal.panel_bg)
            .on_key_down(cx.listener(Self::table_key))
            .on_action(cx.listener(|this, _: &CopyCell, _, cx| this.copy_table_cell(cx)))
            .on_action(cx.listener(|this, _: &CopyRow, _, cx| this.copy_table_row(cx)))
            .on_action(
                cx.listener(|this, _: &CopyAllRows, window, cx| this.copy_table_all(window, cx)),
            )
            .on_action(
                cx.listener(|this, _: &ExportCsv, window, cx| this.export_table_csv(window, cx)),
            )
            .child(top_bar)
            .map(|d| match placeholder {
                Some(p) => d.child(p),
                None => d.children(header).child(body),
            })
    }
}
