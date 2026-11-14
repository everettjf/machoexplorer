//! The main window: one document per window. Owns the pane states and wires
//! tree selection -> table -> hex. Rendering of each pane lives in its own
//! module (`tree_panel`, `table_panel`, `hex_view`, `log_panel`, ...).

use crate::app::{AppState, APP_NAME};
use crate::hex_view::HexView;
use crate::log_panel::LogPanel;
use crate::modal::Modal;
use crate::settings::PaneSettings;
use crate::start_screen::StartScreen;
use crate::table_panel::TablePanel;
use crate::theme::{self, Palette};
use crate::tree_model::{self, LoadBudget};
use crate::tree_panel::TreePanel;
use crate::vscroll::VScroll;
use gpui_kit::component::menu::AppMenuBar;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::ElementExt as _;
use gpui_kit::component::TitleBar;
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    div, px, App, Bounds, Context, Entity, ExternalPaths, FocusHandle, KeyDownEvent, MouseButton,
    MouseMoveEvent, MouseUpEvent, PathPromptOptions, Pixels, SharedString, Window,
};
use moex_core::{Document, ViewNode};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

pub const TITLE_H: f32 = 26.0;
pub const STATUS_H: f32 = 24.0;
pub const SPLIT: f32 = 5.0;
pub const SCROLLBAR_W: f32 = 12.0;

/// Scrollable regions (each has a [`VScroll`] and recorded bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Tree,
    Table,
    Hex,
    Log,
    Images,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Split {
    Layout,
    Hex,
    Bottom,
    LogInfo,
}

/// An in-progress mouse drag, tracked at window level so it keeps working
/// when the pointer leaves the element it started on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Drag {
    Split {
        which: Split,
        start: f32,
        value: f32,
    },
    Column {
        col: usize,
        start_x: f32,
        width: f32,
    },
    Thumb {
        pane: Pane,
        grab: f32,
    },
    TableHThumb {
        grab: f32,
    },
    HexSelect,
}

pub struct MainWindow {
    pub focus: FocusHandle,
    pub doc: Option<Document>,
    pub path: Option<String>,
    /// Path being parsed (loading indicator).
    pub opening: Option<String>,
    /// Bumped whenever the document changes; stale async results are dropped.
    pub doc_seq: u64,
    pub tree: TreePanel,
    pub table: TablePanel,
    pub hex: HexView,
    pub log: LogPanel,
    pub info: SharedString,
    pub status: SharedString,
    status_seq: u64,
    pub modal: Option<Modal>,
    pub drag: Option<Drag>,
    pub start: StartScreen,
    pub body_bounds: Bounds<Pixels>,
    pub bottom_bounds: Bounds<Pixels>,
    pub menu_bar: Option<Entity<AppMenuBar>>,
    pub extract_cancel: Option<std::sync::Arc<AtomicBool>>,
}

pub const INFO_DEFAULT: &str = "# Hi, have a nice day !";

impl MainWindow {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        // macOS uses the native menu bar; elsewhere the menus are drawn in
        // the window's title bar. (Debug builds can force the in-window bar
        // with MOEX_DEBUG_MENUBAR=1 to inspect it on macOS.)
        let in_window_menus = !cfg!(target_os = "macos")
            || (cfg!(debug_assertions) && std::env::var_os("MOEX_DEBUG_MENUBAR").is_some());
        let menu_bar = in_window_menus.then(|| AppMenuBar::new(cx));
        let mut this = MainWindow {
            focus: cx.focus_handle(),
            doc: None,
            path: None,
            opening: None,
            doc_seq: 0,
            tree: TreePanel::new(window, cx),
            table: TablePanel::new(window, cx),
            hex: HexView::new(cx),
            log: LogPanel::new(),
            info: INFO_DEFAULT.into(),
            status: "Welcome".into(),
            status_seq: 0,
            modal: None,
            drag: None,
            start: StartScreen::new(window, cx),
            body_bounds: Bounds::default(),
            bottom_bounds: Bounds::default(),
            menu_bar,
            extract_cancel: None,
        };
        this.refresh_recent_files(cx);
        cx.observe_window_appearance(window, |_, window, cx| {
            if AppState::get(cx).settings.theme_mode == crate::settings::ThemeMode::System {
                theme::apply(crate::settings::ThemeMode::System, Some(window), cx);
            }
        })
        .detach();
        cx.observe_window_bounds(window, |_, window, cx| {
            let size = window.viewport_size();
            let (w, h) = (f32::from(size.width), f32::from(size.height));
            if w >= 600.0 && h >= 400.0 && !window.is_fullscreen() && !window.is_maximized() {
                // Kept in memory; written with the next settings save.
                AppState::update(cx, |s| {
                    s.settings.window.width = w;
                    s.settings.window.height = h;
                });
            }
        })
        .detach();
        cx.on_release(|_, cx| AppState::update_settings(cx, |_| {}))
            .detach();
        this
    }

    pub(crate) fn reload_menu_bar(&mut self, cx: &mut Context<Self>) {
        if let Some(bar) = &self.menu_bar {
            bar.update(cx, |bar, cx| bar.reload(cx));
        }
    }

    pub(crate) fn panes(&self, cx: &App) -> PaneSettings {
        AppState::get(cx).settings.panes.clone()
    }

    pub fn focus_default(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.doc.is_some() {
            window.focus(&self.tree.focus, cx);
        } else {
            window.focus(&self.focus, cx);
        }
    }

    // ---- status / log -------------------------------------------------

    /// Show a status bar message, optionally cleared after `timeout_ms`.
    pub fn set_status(
        &mut self,
        text: impl Into<SharedString>,
        timeout_ms: Option<u64>,
        cx: &mut Context<Self>,
    ) {
        self.status = text.into();
        self.status_seq += 1;
        let seq = self.status_seq;
        if let Some(ms) = timeout_ms {
            cx.spawn(async move |this, cx| {
                cx.background_executor()
                    .timer(Duration::from_millis(ms))
                    .await;
                let _ = this.update(cx, |this, cx| {
                    if this.status_seq == seq {
                        this.status = SharedString::default();
                        cx.notify();
                    }
                });
            })
            .detach();
        }
        cx.notify();
    }

    pub fn add_log(&mut self, line: impl Into<String>, cx: &mut Context<Self>) {
        self.log.add(line.into());
        cx.notify();
    }

    // ---- opening files -------------------------------------------------

    pub fn prompt_open_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Open File".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = rx.await {
                if let Some(path) = paths.into_iter().next() {
                    let _ = this.update_in(cx, |this, window, cx| {
                        this.open_path(path.to_string_lossy().into_owned(), window, cx)
                    });
                }
            }
        })
        .detach();
    }

    /// Parse `path` on a background thread and show it in this window.
    pub fn open_path(&mut self, path: String, window: &mut Window, cx: &mut Context<Self>) {
        let path = path.trim().to_string();
        if path.is_empty() {
            self.add_log("[workspace] openFile ignored: empty path", cx);
            return;
        }
        if self.opening.is_some() {
            self.add_log("Still parsing the previous file; please wait...", cx);
            return;
        }
        self.opening = Some(path.clone());
        self.add_log(format!("Start parsing {path}"), cx);
        let parse_path = path.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let doc = Document::open(&parse_path)?;
                    // Build the top of the tree here too, so the first frame
                    // after parsing already shows File -> Mach Header -> ...
                    let cancel = AtomicBool::new(false);
                    let budget = LoadBudget {
                        max_nodes: 4096,
                        deadline: tree_model::deadline_in(1500),
                        cancel: &cancel,
                    };
                    let mut loaded = tree_model::load_subtree(&doc.root, 2, &budget);
                    let depth = tree_model::default_expand_depth(&doc.root, true);
                    if depth > 1 {
                        loaded.extend(tree_model::load_subtree(&doc.root, depth + 1, &budget));
                    }
                    Ok::<_, moex_core::Error>((doc, loaded, depth))
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.opening = None;
                match result {
                    Ok((doc, loaded, depth)) => {
                        this.show_document(doc, path, loaded, depth, window, cx)
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        this.add_log(msg.clone(), cx);
                        this.show_error(msg, window, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// Show a parsed document. `loaded` are the ids of the nodes already
    /// built (see `tree_model::load_subtree`), `depth` the initial expansion
    /// depth. Called by `open_path`; public so tests can show synthetic
    /// documents.
    pub fn show_document(
        &mut self,
        doc: Document,
        path: String,
        loaded: Vec<usize>,
        depth: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.add_log("Parse succeed", cx);
        self.doc_seq += 1;
        self.tree.reset(window, cx);
        self.table.set_node(None, window, cx);
        self.hex.set_document(Some(doc.image.clone()));
        self.info = INFO_DEFAULT.into();
        self.tree.model.set_root(Some(doc.root.clone()));
        self.tree.model.mark_loaded(loaded);
        self.tree.default_depth = depth;
        self.tree.model.expand_to_depth(depth);
        self.tree.model.rebuild();
        self.tree.sync_scroll();
        let root = doc.root.clone();
        self.doc = Some(doc);
        self.path = Some(path.clone());
        window.set_window_title(&format!("{APP_NAME} — {}", crate::util::file_name(&path)));
        AppState::update_settings(cx, |s| s.push_recent(&path));
        self.refresh_recent_files(cx);
        if self.modal.is_none() {
            window.focus(&self.tree.focus, cx);
        }
        self.select_node(root, window, cx);
    }

    /// Select `node` in the tree and show its table and bytes.
    pub fn select_node(&mut self, node: ViewNode, window: &mut Window, cx: &mut Context<Self>) {
        let id = node.id();
        self.tree.selected = Some(id);
        if let Some(ix) = self.tree.model.index_of(id) {
            self.tree
                .scroll
                .ensure_visible(ix as u64, crate::vscroll::ScrollTo::Nearest);
        }
        if self.tree.model.is_loaded(id) {
            self.display_node(&node, window, cx);
        } else {
            self.table.set_loading(node.name().to_string());
            self.hex.set_range(None);
            self.load_node(node, false, window, cx);
        }
        cx.notify();
    }

    /// Build `node` (content, children, and its children's children within a
    /// small time budget so leaves lose their arrow) off the UI thread.
    pub(crate) fn load_node(
        &mut self,
        node: ViewNode,
        expand: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let id = node.id();
        if expand {
            self.tree.pending_expand.insert(id);
        }
        if !self.tree.loading.insert(id) {
            return;
        }
        let seq = self.doc_seq;
        cx.spawn_in(window, async move |this, cx| {
            let n = node.clone();
            let ids = cx
                .background_executor()
                .spawn(async move {
                    let cancel = AtomicBool::new(false);
                    let budget = LoadBudget {
                        max_nodes: 4096,
                        deadline: tree_model::deadline_in(200),
                        cancel: &cancel,
                    };
                    let mut ids = vec![tree_model::load_node(&n)];
                    ids.extend(tree_model::load_subtree(&n, 1, &budget));
                    ids
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                if this.doc_seq != seq {
                    return;
                }
                this.tree.loading.remove(&id);
                this.tree.model.mark_loaded(ids);
                if this.tree.pending_expand.remove(&id) {
                    this.tree.model.set_expanded(id, true);
                }
                this.tree.model.rebuild();
                this.tree.sync_scroll();
                if this.tree.selected == Some(id) && this.table.node_id() != Some(id) {
                    this.display_node(&node, window, cx);
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Show an already built node in the table and hex panes.
    fn display_node(&mut self, node: &ViewNode, window: &mut Window, cx: &mut Context<Self>) {
        self.table.set_node(Some(node.clone()), window, cx);
        self.hex.set_range(node.binary());
        if self.table.visible_len() > 0 {
            self.select_table_row(0, window, cx);
        } else {
            self.hex.selection = None;
            self.info = SharedString::default();
        }
    }

    // ---- drags ---------------------------------------------------------

    pub(crate) fn scroll_of(&mut self, pane: Pane) -> Option<&mut VScroll> {
        match pane {
            Pane::Tree => Some(&mut self.tree.scroll),
            Pane::Table => Some(&mut self.table.scroll),
            Pane::Hex => Some(&mut self.hex.scroll),
            Pane::Log => Some(&mut self.log.scroll),
            Pane::Images => match &mut self.modal {
                Some(Modal::ImageSelector { scroll, .. }) => Some(scroll),
                _ => None,
            },
        }
    }

    pub(crate) fn bounds_of(&self, pane: Pane) -> Bounds<Pixels> {
        match pane {
            Pane::Tree => self.tree.bounds,
            Pane::Table => self.table.bounds,
            Pane::Hex => self.hex.bounds,
            Pane::Log => self.log.bounds,
            Pane::Images => match &self.modal {
                Some(Modal::ImageSelector { bounds, .. }) => *bounds,
                _ => Bounds::default(),
            },
        }
    }

    fn set_bounds(&mut self, pane: Pane, b: Bounds<Pixels>) -> bool {
        let slot = match pane {
            Pane::Tree => &mut self.tree.bounds,
            Pane::Table => &mut self.table.bounds,
            Pane::Hex => &mut self.hex.bounds,
            Pane::Log => &mut self.log.bounds,
            Pane::Images => match &mut self.modal {
                Some(Modal::ImageSelector { bounds, .. }) => bounds,
                _ => return false,
            },
        };
        if *slot == b {
            return false;
        }
        *slot = b;
        if let Some(s) = self.scroll_of(pane) {
            s.set_viewport(f32::from(b.size.height));
        }
        if pane == Pane::Log {
            self.log.after_layout();
        }
        true
    }

    /// Prepaint callback recording the on-screen bounds of a scroll region.
    pub(crate) fn track_bounds(
        pane: Pane,
        cx: &Context<Self>,
    ) -> impl FnOnce(Bounds<Pixels>, &mut Window, &mut App) + 'static {
        let this = cx.weak_entity();
        move |b, _, cx| {
            // Entities cannot be invalidated while a frame is being drawn.
            cx.defer(move |cx| {
                let _ = this.update(cx, |this, cx| {
                    if this.set_bounds(pane, b) {
                        cx.notify();
                    }
                });
            });
        }
    }

    pub(crate) fn wheel(&mut self, pane: Pane, dy: f32, cx: &mut Context<Self>) {
        if let Some(s) = self.scroll_of(pane) {
            if s.scroll_by(-(dy as f64)) {
                if pane == Pane::Log {
                    self.log.user_scrolled();
                }
                cx.notify();
            }
        }
    }

    pub(crate) fn begin_thumb_drag(&mut self, pane: Pane, y: Pixels, cx: &mut Context<Self>) {
        let top = f32::from(self.bounds_of(pane).origin.y);
        let Some(vs) = self.scroll_of(pane) else {
            return;
        };
        let track = vs.viewport;
        let Some((start, len)) = vs.thumb(track) else {
            return;
        };
        let local = f32::from(y) - top;
        let grab = if local >= start && local <= start + len {
            local - start
        } else {
            vs.set_thumb_start(track, local - len / 2.0);
            len / 2.0
        };
        self.drag = Some(Drag::Thumb { pane, grab });
        cx.stop_propagation();
        cx.notify();
    }

    fn drag_move(&mut self, ev: &MouseMoveEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(drag) = self.drag else { return };
        if ev.pressed_button != Some(MouseButton::Left) {
            self.end_drag(cx);
            return;
        }
        let (x, y) = (f32::from(ev.position.x), f32::from(ev.position.y));
        match drag {
            Drag::Split {
                which,
                start,
                value,
            } => {
                let body_w = f32::from(self.body_bounds.size.width).max(600.0);
                let body_h = f32::from(self.body_bounds.size.height).max(300.0);
                AppState::update(cx, |s| {
                    let p = &mut s.settings.panes;
                    match which {
                        Split::Layout => {
                            p.layout_width = (value + x - start).clamp(160.0, body_w - 300.0)
                        }
                        Split::Hex => {
                            p.hex_width = (value - (x - start)).clamp(200.0, body_w - 300.0)
                        }
                        Split::Bottom => {
                            p.bottom_height = (value - (y - start)).clamp(60.0, body_h - 120.0)
                        }
                        Split::LogInfo => {
                            let w = f32::from(self.bottom_bounds.size.width).max(200.0);
                            p.log_fraction = (value + (x - start) / w).clamp(0.15, 0.85);
                        }
                    }
                });
            }
            Drag::Column {
                col,
                start_x,
                width,
            } => {
                if let Some(w) = self.table.widths.get_mut(col) {
                    *w = (width + x - start_x).max(crate::table_model::MIN_COLUMN_WIDTH);
                }
            }
            Drag::Thumb { pane, grab } => {
                let top = f32::from(self.bounds_of(pane).origin.y);
                if let Some(vs) = self.scroll_of(pane) {
                    let track = vs.viewport;
                    vs.set_thumb_start(track, y - top - grab);
                }
                if pane == Pane::Log {
                    self.log.user_scrolled();
                }
            }
            Drag::TableHThumb { grab } => self.table.drag_hthumb(x, grab),
            Drag::HexSelect => self.hex.drag_select_to(ev.position),
        }
        cx.notify();
    }

    fn end_drag(&mut self, cx: &mut Context<Self>) {
        if let Some(Drag::Split { .. }) = self.drag.take() {
            AppState::update_settings(cx, |_| {});
        }
        cx.notify();
    }

    pub(crate) fn begin_split_drag(
        &mut self,
        which: Split,
        pos: gpui_kit::Point<Pixels>,
        cx: &mut Context<Self>,
    ) {
        let p = self.panes(cx);
        let (start, value) = match which {
            Split::Layout => (f32::from(pos.x), p.layout_width),
            Split::Hex => (f32::from(pos.x), p.hex_width),
            Split::Bottom => (f32::from(pos.y), p.bottom_height),
            Split::LogInfo => (f32::from(pos.x), p.log_fraction),
        };
        self.drag = Some(Drag::Split {
            which,
            start,
            value,
        });
        cx.notify();
    }

    fn splitter(&self, which: Split, pal: &Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let vertical_bar = which != Split::Bottom;
        let active = matches!(self.drag, Some(Drag::Split { which: w, .. }) if w == which);
        div()
            .id(match which {
                Split::Layout => "split-layout",
                Split::Hex => "split-hex",
                Split::Bottom => "split-bottom",
                Split::LogInfo => "split-loginfo",
            })
            .flex_none()
            .map(|d| {
                if vertical_bar {
                    d.w(px(SPLIT)).h_full().cursor_col_resize()
                } else {
                    d.h(px(SPLIT)).w_full().cursor_row_resize()
                }
            })
            .bg(if active { pal.accent } else { pal.window_bg })
            .hover(|s| s.bg(pal.border))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, ev: &gpui_kit::MouseDownEvent, _, cx| {
                    this.begin_split_drag(which, ev.position, cx);
                    cx.stop_propagation();
                }),
            )
    }

    // ---- keys ----------------------------------------------------------

    fn root_key(&mut self, ev: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.modal.is_some() {
            match ev.keystroke.key.as_str() {
                "escape" => self.cancel_modal(window, cx),
                "enter" => self.confirm_modal(window, cx),
                _ => return,
            }
            cx.stop_propagation();
        }
    }

    // ---- rendering -----------------------------------------------------

    pub(crate) fn pane_title(text: &'static str, pal: &Palette) -> impl IntoElement {
        div()
            .flex_none()
            .h(px(TITLE_H))
            .w_full()
            .px(px(10.))
            .flex()
            .items_center()
            .bg(pal.title_bg)
            .text_color(pal.title_fg)
            .font_weight(gpui_kit::FontWeight::SEMIBOLD)
            .child(text)
    }

    fn render_body(
        &mut self,
        pal: &Palette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        if let Some(path) = &self.opening {
            return div()
                .id("loading")
                .test_support()
                .size_full()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap_3()
                .child(Spinner::new().color(pal.accent))
                .child(
                    div()
                        .text_color(pal.muted)
                        .child(format!("Parsing {}…", crate::util::file_name(path))),
                )
                .into_any_element();
        }
        if self.doc.is_none() {
            return self.render_start_screen(pal, window, cx).into_any_element();
        }

        let panes = self.panes(cx);
        let show_bottom = panes.show_log || panes.show_information;
        let top = div()
            .flex_1()
            .min_h_0()
            .w_full()
            .flex()
            .when(panes.show_layout, |d| {
                d.child(
                    div()
                        .flex_none()
                        .w(px(panes.layout_width))
                        .h_full()
                        .child(self.render_tree_panel(pal, window, cx)),
                )
                .child(self.splitter(Split::Layout, pal, cx))
            })
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(self.render_table_panel(pal, window, cx)),
            )
            .when(panes.show_hex, |d| {
                d.child(self.splitter(Split::Hex, pal, cx)).child(
                    div()
                        .flex_none()
                        .w(px(panes.hex_width))
                        .h_full()
                        .child(self.render_hex_view(pal, window, cx)),
                )
            });

        let mut body = div().size_full().flex().flex_col().child(top);
        if show_bottom {
            let both = panes.show_log && panes.show_information;
            let this = cx.weak_entity();
            let mut strip = div()
                .flex_none()
                .h(px(panes.bottom_height))
                .w_full()
                .flex()
                .on_prepaint(move |b, _, cx| {
                    cx.defer(move |cx| {
                        let _ = this.update(cx, |this, _| this.bottom_bounds = b);
                    });
                });
            if panes.show_log {
                let log = self.render_log_panel(pal, window, cx);
                strip = strip.child(if both {
                    div()
                        .flex_none()
                        .w(gpui_kit::relative(panes.log_fraction))
                        .h_full()
                        .child(log)
                } else {
                    div().flex_1().min_w_0().h_full().child(log)
                });
            }
            if both {
                strip = strip.child(self.splitter(Split::LogInfo, pal, cx));
            }
            if panes.show_information {
                strip = strip.child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .child(self.render_info_panel(pal, cx)),
                );
            }
            body = body
                .child(self.splitter(Split::Bottom, pal, cx))
                .child(strip);
        }
        body.into_any_element()
    }

    fn render_status(&self, pal: &Palette) -> impl IntoElement {
        div()
            .id("status-bar")
            .flex_none()
            .h(px(STATUS_H))
            .w_full()
            .px(px(10.))
            .flex()
            .items_center()
            .justify_between()
            .gap_4()
            .bg(pal.status_bg)
            .text_color(pal.status_fg)
            .border_t_1()
            .border_color(pal.border)
            .text_size(px(12.))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .child(self.status.clone()),
            )
            .when_some(self.path.clone(), |d, p| {
                d.child(
                    div()
                        .flex_none()
                        .max_w(gpui_kit::relative(0.6))
                        .truncate()
                        .text_color(pal.muted)
                        .child(p),
                )
            })
    }
}

impl Render for MainWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let pal = Palette::of(cx);
        let this = cx.weak_entity();
        let body = self.render_body(&pal, window, cx);
        let dragging = self.drag.is_some();
        div()
            .id("main-window")
            .key_context("MainWindow")
            .track_focus(&self.focus)
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .bg(pal.window_bg)
            .text_color(pal.text)
            .text_size(px(theme::UI_SIZE))
            .on_key_down(cx.listener(Self::root_key))
            .on_mouse_move(cx.listener(Self::drag_move))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _: &MouseUpEvent, _, cx| this.end_drag(cx)),
            )
            .on_drop(cx.listener(|this, paths: &ExternalPaths, window, cx| {
                if let Some(path) = paths.paths().first() {
                    this.open_path(path.to_string_lossy().into_owned(), window, cx);
                }
            }))
            .when(dragging, |d| match self.drag {
                Some(Drag::Split {
                    which: Split::Bottom,
                    ..
                }) => d.cursor_row_resize(),
                Some(Drag::Split { .. }) | Some(Drag::Column { .. }) => d.cursor_col_resize(),
                _ => d,
            })
            .when_some(self.menu_bar.clone(), |d, bar| {
                d.child(TitleBar::new().child(bar))
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .relative()
                    .child(body)
                    .on_prepaint(move |b, _, cx| {
                        cx.defer(move |cx| {
                            let _ = this.update(cx, |this, _| this.body_bounds = b);
                        });
                    }),
            )
            .child(self.render_status(&pal))
            .when(self.modal.is_some(), |d| {
                d.child(self.render_modal(&pal, window, cx))
            })
    }
}
