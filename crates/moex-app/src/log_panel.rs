//! Log pane (virtualized, follows the tail) and the Information pane.

use crate::theme::{self, Palette};
use crate::vscroll::VScroll;
use crate::window::{MainWindow, Pane};
use gpui_kit::component::ElementExt as _;
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    div, px, Bounds, Context, MouseDownEvent, Pixels, ScrollEvent, SharedString, Window,
};

pub const LOG_ROW_H: f32 = 18.0;
const MAX_LINES: usize = 20_000;

pub struct LogPanel {
    pub lines: Vec<SharedString>,
    pub scroll: VScroll,
    pub bounds: Bounds<Pixels>,
    /// Keep the newest line in view until the user scrolls up.
    follow: bool,
}

impl LogPanel {
    pub fn new() -> Self {
        LogPanel {
            lines: Vec::new(),
            scroll: VScroll::new(LOG_ROW_H),
            bounds: Bounds::default(),
            follow: true,
        }
    }

    /// Append an entry; Qt prefixed each with `> `.
    pub fn add(&mut self, entry: String) {
        for (i, line) in entry.lines().enumerate() {
            self.lines.push(
                if i == 0 {
                    format!("> {line}")
                } else {
                    format!("  {line}")
                }
                .into(),
            );
        }
        if self.lines.len() > MAX_LINES {
            let drop = self.lines.len() - MAX_LINES;
            self.lines.drain(..drop);
        }
        self.scroll.set_total(self.lines.len() as u64);
        self.after_layout();
    }

    pub fn after_layout(&mut self) {
        if self.follow {
            self.scroll.top = self.scroll.max_top();
        }
    }

    pub fn user_scrolled(&mut self) {
        self.follow = self.scroll.top >= self.scroll.max_top() - 1.0;
    }

    /// Whole log as text (tests).
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.as_ref())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for LogPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl MainWindow {
    pub(crate) fn render_log_panel(
        &mut self,
        pal: &Palette,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let v = self.log.scroll.visible();
        let rows: Vec<_> = (0..v.count)
            .filter_map(|i| {
                let line = self.log.lines.get(v.first as usize + i)?.clone();
                Some(
                    div()
                        .absolute()
                        .top(px(v.y + i as f32 * LOG_ROW_H))
                        .left(px(8.))
                        .h(px(LOG_ROW_H))
                        .line_height(px(LOG_ROW_H))
                        .whitespace_nowrap()
                        .child(line),
                )
            })
            .collect();
        let vbar = crate::scrollbar::vscrollbar(
            "log-scrollbar",
            &self.log.scroll,
            pal,
            cx.listener(|this, ev: &MouseDownEvent, _, cx| {
                this.begin_thumb_drag(Pane::Log, ev.position.y, cx)
            }),
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(pal.panel_bg)
            .child(Self::pane_title("Log", pal))
            .child(
                div()
                    .id("log")
                    .test_support()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .relative()
                    .overflow_hidden()
                    .font_family(theme::MONO_FONT)
                    .text_size(px(theme::MONO_SIZE))
                    .on_scroll(cx.listener(|this, ev: &ScrollEvent, _, cx| {
                        let d = ev.delta.pixel_delta(px(LOG_ROW_H));
                        this.wheel(Pane::Log, f32::from(d.y), cx);
                    }))
                    .on_prepaint(Self::track_bounds(Pane::Log, cx))
                    .children(rows)
                    .children(vbar),
            )
    }

    pub(crate) fn render_info_panel(
        &mut self,
        pal: &Palette,
        _cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let lines: Vec<SharedString> = self
            .info
            .lines()
            .map(|l| SharedString::from(l.to_string()))
            .collect();
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(pal.panel_bg)
            .child(Self::pane_title("Information", pal))
            .child(
                div()
                    .id("information")
                    .test_support()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .overflow_y_scroll()
                    .px(px(8.))
                    .py(px(4.))
                    .font_family(theme::MONO_FONT)
                    .text_size(px(theme::MONO_SIZE))
                    .children(
                        lines
                            .into_iter()
                            .map(|l| div().w_full().line_height(px(LOG_ROW_H)).child(l)),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_prefixes_and_follows_tail() {
        let mut log = LogPanel::new();
        log.scroll.set_viewport(LOG_ROW_H * 3.0);
        log.add("Start parsing /bin/ls".into());
        log.add("two\nlines".into());
        assert_eq!(log.text(), "> Start parsing /bin/ls\n> two\n  lines");
        for i in 0..10 {
            log.add(format!("line {i}"));
        }
        assert_eq!(log.scroll.top, log.scroll.max_top());
        log.scroll.scroll_by(-100.0);
        log.user_scrolled();
        let top = log.scroll.top;
        log.add("more".into());
        assert_eq!(log.scroll.top, top);
        log.scroll.scroll_by(1e9);
        log.user_scrolled();
        log.add("again".into());
        assert_eq!(log.scroll.top, log.scroll.max_top());
    }
}
