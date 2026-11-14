//! Layout pane: filter box, go-to-offset box and the virtualized node tree.

use crate::theme::Palette;
use crate::tree_model::{self, Expandable, LoadBudget, TreeModel};
use crate::vscroll::{ScrollTo, VScroll};
use crate::window::{MainWindow, Pane};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::ElementExt as _;
use gpui_kit::component::{Icon, IconName, Sizable};
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    div, px, Bounds, Context, Entity, FocusHandle, KeyDownEvent, MouseButton, MouseDownEvent,
    Pixels, ScrollEvent, SharedString, Window,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const TREE_ROW_H: f32 = 24.0;
const INDENT: f32 = 16.0;

pub struct TreePanel {
    pub model: TreeModel,
    pub scroll: VScroll,
    /// Id of the selected node.
    pub selected: Option<usize>,
    pub focus: FocusHandle,
    pub filter_input: Entity<InputState>,
    pub goto_input: Entity<InputState>,
    pub bounds: Bounds<Pixels>,
    pub loading: HashSet<usize>,
    pub pending_expand: HashSet<usize>,
    pub default_depth: usize,
    filter_cancel: Arc<AtomicBool>,
    /// Rows drawn by the last frame (for tests / diagnostics).
    pub rendered_rows: usize,
}

impl TreePanel {
    pub fn new(window: &mut Window, cx: &mut Context<MainWindow>) -> Self {
        let filter_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Search layout and opened tables...")
        });
        let goto_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Go to file offset (e.g. 0x4000)"));
        cx.subscribe_in(
            &filter_input,
            window,
            |this: &mut MainWindow, input, ev: &InputEvent, window, cx| match ev {
                InputEvent::Change => {
                    let text = input.read(cx).value().to_string();
                    this.set_tree_filter(&text, window, cx);
                }
                InputEvent::PressEnter { .. } => this.tree_next_match(window, cx),
                _ => {}
            },
        )
        .detach();
        cx.subscribe_in(
            &goto_input,
            window,
            |this: &mut MainWindow, input, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    let text = input.read(cx).value().to_string();
                    this.goto_offset(&text, window, cx);
                }
            },
        )
        .detach();
        TreePanel {
            model: TreeModel::new(),
            scroll: VScroll::new(TREE_ROW_H),
            selected: None,
            focus: cx.focus_handle(),
            filter_input,
            goto_input,
            bounds: Bounds::default(),
            loading: HashSet::new(),
            pending_expand: HashSet::new(),
            default_depth: 1,
            filter_cancel: Arc::new(AtomicBool::new(false)),
            rendered_rows: 0,
        }
    }

    /// Forget everything about the previous document.
    pub fn reset(&mut self, window: &mut Window, cx: &mut Context<MainWindow>) {
        self.filter_cancel.store(true, Ordering::Relaxed);
        self.filter_cancel = Arc::new(AtomicBool::new(false));
        self.model.set_root(None);
        self.selected = None;
        self.loading.clear();
        self.pending_expand.clear();
        self.scroll.set_total(0);
        self.scroll.scroll_to_top();
        self.filter_input
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.goto_input
            .update(cx, |s, cx| s.set_value("", window, cx));
    }

    pub fn sync_scroll(&mut self) {
        self.scroll.set_total(self.model.rows().len() as u64);
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.selected.and_then(|id| self.model.index_of(id))
    }

    /// Names of the visible rows, indented two spaces per level (tests).
    pub fn visible_names(&self) -> Vec<String> {
        self.model
            .rows()
            .iter()
            .map(|r| format!("{}{}", "  ".repeat(r.depth), r.node.name()))
            .collect()
    }
}

impl MainWindow {
    pub fn select_tree_row(&mut self, ix: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(row) = self.tree.model.rows().get(ix) else {
            return;
        };
        let node = row.node.clone();
        self.select_node(node, window, cx);
    }

    /// Expand or collapse the row; unknown nodes are built first.
    pub fn toggle_tree_row(&mut self, ix: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(row) = self.tree.model.rows().get(ix).cloned() else {
            return;
        };
        if self.tree.model.has_filter() {
            return;
        }
        let id = row.node.id();
        match row.expandable {
            Expandable::No => {}
            Expandable::Unknown => self.load_node(row.node, true, window, cx),
            Expandable::Yes => {
                self.tree.model.set_expanded(id, !row.expanded);
                self.tree.model.rebuild();
                self.tree.sync_scroll();
                if !row.expanded {
                    self.prefetch_children(&row.node, window, cx);
                }
            }
        }
        cx.notify();
    }

    /// After expanding, find out which children are leaves (bounded work).
    fn prefetch_children(
        &mut self,
        node: &moex_core::ViewNode,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let unknown = node
            .children()
            .iter()
            .any(|c| !self.tree.model.is_loaded(c.id()));
        if unknown {
            self.tree.loading.remove(&node.id());
            self.load_node(node.clone(), false, window, cx);
        }
    }

    pub fn set_tree_filter(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.tree.filter_cancel.store(true, Ordering::Relaxed);
        self.tree.filter_cancel = Arc::new(AtomicBool::new(false));
        self.tree.model.set_filter(text);
        if text.is_empty() {
            // As Qt: collapse everything, then expand to the default depth.
            let depth = self.tree.default_depth;
            self.tree.model.expand_to_depth(depth);
            if let Some(id) = self.tree.selected {
                self.tree.model.reveal(id);
            }
        }
        self.tree.model.rebuild();
        self.tree.sync_scroll();
        if let Some(ix) = self.tree.selected_index() {
            self.tree
                .scroll
                .ensure_visible(ix as u64, ScrollTo::Nearest);
        }
        if !text.is_empty() {
            self.load_whole_tree(window, cx);
        }
        cx.notify();
    }

    /// Filtering and go-to-offset look at every node, so build the rest of
    /// the tree in the background (bounded, cancellable) and refresh.
    fn load_whole_tree(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(root) = self.tree.model.root().cloned() else {
            return;
        };
        let cancel = self.tree.filter_cancel.clone();
        let seq = self.doc_seq;
        cx.spawn_in(window, async move |this, cx| {
            let c = cancel.clone();
            let ids = cx
                .background_executor()
                .spawn(async move {
                    let budget = LoadBudget {
                        max_nodes: 200_000,
                        deadline: tree_model::deadline_in(8000),
                        cancel: &c,
                    };
                    tree_model::load_subtree(&root, 255, &budget)
                })
                .await;
            let _ = this.update_in(cx, |this, _, cx| {
                if this.doc_seq != seq {
                    return;
                }
                this.tree.model.mark_loaded(ids);
                this.tree.model.rebuild();
                this.tree.sync_scroll();
                if let Some(ix) = this.tree.selected_index() {
                    this.tree
                        .scroll
                        .ensure_visible(ix as u64, ScrollTo::Nearest);
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Enter in the filter box: jump to the next direct match.
    pub fn tree_next_match(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(ix) = self.tree.model.next_match(self.tree.selected_index()) {
            self.select_tree_row(ix, window, cx);
            self.tree.scroll.ensure_visible(ix as u64, ScrollTo::Center);
        }
    }

    pub fn goto_offset(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(offset) = tree_model::parse_offset(text) else {
            return;
        };
        let Some(root) = self.tree.model.root().cloned() else {
            return;
        };
        let seq = self.doc_seq;
        let cancel = self.tree.filter_cancel.clone();
        // Build the tree first (as Qt's search did), then pick the smallest
        // node whose byte range contains the offset.
        cx.spawn_in(window, async move |this, cx| {
            let ids = cx
                .background_executor()
                .spawn(async move {
                    let budget = LoadBudget {
                        max_nodes: 200_000,
                        deadline: tree_model::deadline_in(8000),
                        cancel: &cancel,
                    };
                    tree_model::load_subtree(&root, 255, &budget)
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                if this.doc_seq != seq {
                    return;
                }
                this.tree.model.mark_loaded(ids);
                let Some(target) = this.tree.model.node_containing_offset(offset) else {
                    this.tree.model.rebuild();
                    this.set_status(
                        format!("No node contains offset 0x{offset:x}"),
                        Some(4000),
                        cx,
                    );
                    return;
                };
                this.tree.model.reveal(target.id());
                this.tree.model.rebuild();
                this.tree.sync_scroll();
                if let Some(ix) = this.tree.model.index_of(target.id()) {
                    this.select_tree_row(ix, window, cx);
                    this.tree.scroll.ensure_visible(ix as u64, ScrollTo::Center);
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub(crate) fn tree_key(
        &mut self,
        ev: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let rows = self.tree.model.rows().len();
        if rows == 0 {
            return;
        }
        let cur = self.tree.selected_index();
        let page = self.tree.scroll.page_rows() as usize;
        let target = match ev.keystroke.key.as_str() {
            "down" => Some(cur.map(|c| (c + 1).min(rows - 1)).unwrap_or(0)),
            "up" => Some(cur.map(|c| c.saturating_sub(1)).unwrap_or(0)),
            "pagedown" => Some(cur.map(|c| (c + page).min(rows - 1)).unwrap_or(0)),
            "pageup" => Some(cur.map(|c| c.saturating_sub(page)).unwrap_or(0)),
            "home" => Some(0),
            "end" => Some(rows - 1),
            "right" => {
                let Some(c) = cur else { return };
                let row = &self.tree.model.rows()[c];
                if row.expanded {
                    Some((c + 1).min(rows - 1))
                } else {
                    self.toggle_tree_row(c, window, cx);
                    None
                }
            }
            "left" => {
                let Some(c) = cur else { return };
                if self.tree.model.rows()[c].expanded && !self.tree.model.has_filter() {
                    self.toggle_tree_row(c, window, cx);
                    None
                } else {
                    self.tree.model.parent_index(c)
                }
            }
            "enter" | "space" => {
                if let Some(c) = cur {
                    self.toggle_tree_row(c, window, cx);
                }
                None
            }
            _ => return,
        };
        if let Some(t) = target {
            if Some(t) != cur {
                self.select_tree_row(t, window, cx);
            }
        }
        cx.stop_propagation();
    }

    pub(crate) fn render_tree_panel(
        &mut self,
        pal: &Palette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let v = self.tree.scroll.visible();
        self.tree.rendered_rows = v.count;
        let focused = self.tree.focus.is_focused(window);
        let selected = self.tree.selected;
        let filtering = self.tree.model.has_filter();
        let rows: Vec<_> = (0..v.count)
            .filter_map(|i| {
                let ix = v.first as usize + i;
                let row = self.tree.model.rows().get(ix)?;
                let is_selected = selected == Some(row.node.id());
                let y = v.y + i as f32 * TREE_ROW_H;
                let arrow = match row.expandable {
                    Expandable::No => None,
                    _ if row.expanded => Some(IconName::ChevronDown),
                    _ => Some(IconName::ChevronRight),
                };
                let busy = self.tree.loading.contains(&row.node.id());
                let name: SharedString = row.node.name().to_string().into();
                let fg = if is_selected && focused {
                    pal.selection_fg
                } else if filtering && row.matched {
                    pal.match_fg
                } else if filtering {
                    pal.muted
                } else {
                    pal.text
                };
                Some(
                    div()
                        .id(("tree-row", ix))
                        .test_support()
                        .absolute()
                        .top(px(y))
                        .left_0()
                        .w_full()
                        .h(px(TREE_ROW_H))
                        .pl(px(4.0 + row.depth as f32 * INDENT))
                        .pr(px(crate::window::SCROLLBAR_W))
                        .flex()
                        .items_center()
                        .text_color(fg)
                        .map(|d| {
                            if is_selected {
                                d.bg(if focused {
                                    pal.selection_bg
                                } else {
                                    pal.selection_inactive_bg
                                })
                            } else {
                                d.hover(|s| s.bg(pal.hover_bg))
                            }
                        })
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, ev: &MouseDownEvent, window, cx| {
                                window.focus(&this.tree.focus, cx);
                                this.select_tree_row(ix, window, cx);
                                if ev.click_count == 2 {
                                    this.toggle_tree_row(ix, window, cx);
                                }
                            }),
                        )
                        .child(
                            div()
                                .id(("tree-arrow", ix))
                                .test_support()
                                .flex_none()
                                .size(px(18.))
                                .flex()
                                .items_center()
                                .justify_center()
                                .when_some(arrow, |d, icon| {
                                    d.child(Icon::new(icon).xsmall().text_color(if busy {
                                        pal.accent
                                    } else {
                                        fg
                                    }))
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(move |this, _: &MouseDownEvent, window, cx| {
                                            window.focus(&this.tree.focus, cx);
                                            this.toggle_tree_row(ix, window, cx);
                                            cx.stop_propagation();
                                        }),
                                    )
                                }),
                        )
                        .child(div().flex_1().min_w_0().truncate().child(name)),
                )
            })
            .collect();

        let empty_filter = filtering && self.tree.model.rows().is_empty();
        let scrollbar = crate::scrollbar::vscrollbar(
            "tree-scrollbar",
            &self.tree.scroll,
            pal,
            cx.listener(|this, ev: &MouseDownEvent, _, cx| {
                this.begin_thumb_drag(Pane::Tree, ev.position.y, cx)
            }),
        );

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(pal.panel_bg)
            .child(Self::pane_title("Layout", pal))
            .child(
                div()
                    .flex_none()
                    .p(px(4.))
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .border_b_1()
                    .border_color(pal.border)
                    .child(Input::new(&self.tree.filter_input).small().cleanable(true))
                    .child(Input::new(&self.tree.goto_input).small().cleanable(true)),
            )
            .child(
                div()
                    .id("tree")
                    .test_support()
                    .key_context("LayoutTree")
                    .track_focus(&self.tree.focus)
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .relative()
                    .overflow_hidden()
                    .on_key_down(cx.listener(Self::tree_key))
                    .on_scroll(cx.listener(|this, ev: &ScrollEvent, _, cx| {
                        let d = ev.delta.pixel_delta(px(TREE_ROW_H));
                        this.wheel(Pane::Tree, f32::from(d.y), cx);
                    }))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _: &MouseDownEvent, window, cx| {
                            window.focus(&this.tree.focus, cx)
                        }),
                    )
                    .on_prepaint(Self::track_bounds(Pane::Tree, cx))
                    .children(rows)
                    .when(empty_filter, |d| {
                        d.child(div().p_3().text_color(pal.muted).child("No matching nodes"))
                    })
                    .children(scrollbar),
            )
    }
}
