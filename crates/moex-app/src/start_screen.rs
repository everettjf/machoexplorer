//! Start screen shown while no document is open (the Qt "Open File"
//! dialog): path box, file picker, recent files, drag & drop target.

use crate::app::{AppState, APP_NAME, APP_VERSION};
use crate::settings::{self, format_bytecount};
use crate::theme::{self, Palette};
use crate::window::MainWindow;
use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::Sizable;
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    div, img, px, Context, Entity, Image, ImageFormat, MouseButton, MouseDownEvent,
    PathPromptOptions, SharedString, Window,
};
use std::sync::{Arc, LazyLock};

pub static LOGO: LazyLock<Arc<Image>> = LazyLock::new(|| {
    Arc::new(Image::from_bytes(
        ImageFormat::Png,
        include_bytes!("../assets/machoexplorer.png").to_vec(),
    ))
});

#[derive(Debug, Clone, PartialEq)]
pub struct RecentEntry {
    pub path: String,
    pub size: u64,
}

pub struct StartScreen {
    pub path_input: Entity<InputState>,
    pub recent: Vec<RecentEntry>,
}

impl StartScreen {
    pub fn new(window: &mut Window, cx: &mut Context<MainWindow>) -> Self {
        let path_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Path of a Mach-O file, archive or dyld shared cache")
        });
        cx.subscribe_in(
            &path_input,
            window,
            |this: &mut MainWindow, input, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    let path = input.read(cx).value().to_string();
                    this.open_path(path, window, cx);
                }
            },
        )
        .detach();
        StartScreen {
            path_input,
            recent: Vec::new(),
        }
    }
}

/// Badge text: first two characters of the file name, upper-cased.
pub fn badge_text(path: &str) -> String {
    crate::util::file_name(path)
        .chars()
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

impl MainWindow {
    /// Re-read the recent list; entries whose file no longer exists are
    /// dropped from the settings (checked off the UI thread).
    pub fn refresh_recent_files(&mut self, cx: &mut Context<Self>) {
        let list = AppState::get(cx).settings.recent_files.clone();
        cx.spawn(async move |this, cx| {
            let entries = cx
                .background_executor()
                .spawn(async move {
                    list.into_iter()
                        .filter_map(|path| {
                            let meta = std::fs::metadata(&path).ok()?;
                            Some(RecentEntry {
                                path,
                                size: meta.len(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                let keep: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
                if AppState::get(cx).settings.recent_files != keep {
                    AppState::update_settings(cx, |s| {
                        settings::prune_recent(&mut s.recent_files, |p| keep.iter().any(|k| k == p))
                    });
                }
                this.start.recent = entries;
                cx.notify();
            });
        })
        .detach();
    }

    pub fn remove_recent(&mut self, path: &str, cx: &mut Context<Self>) {
        AppState::update_settings(cx, |s| settings::remove_recent(&mut s.recent_files, path));
        self.start.recent.retain(|e| e.path != path);
        cx.notify();
    }

    pub fn clear_recent(&mut self, cx: &mut Context<Self>) {
        AppState::update_settings(cx, |s| s.recent_files.clear());
        self.start.recent.clear();
        cx.notify();
    }

    fn start_select_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select file".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = rx.await {
                if let Some(path) = paths.into_iter().next() {
                    let _ = this.update_in(cx, |this, window, cx| {
                        let text = path.to_string_lossy().into_owned();
                        this.start
                            .path_input
                            .update(cx, |s, cx| s.set_value(text, window, cx));
                    });
                }
            }
        })
        .detach();
    }

    pub(crate) fn render_start_screen(
        &mut self,
        pal: &Palette,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let recents = self.start.recent.iter().enumerate().map(|(i, entry)| {
            let path = entry.path.clone();
            let open_path = path.clone();
            let remove_path = path.clone();
            let label: SharedString = path.clone().into();
            div()
                .id(("recent", i))
                .test_support()
                .w_full()
                .px(px(10.))
                .py(px(6.))
                .flex()
                .items_center()
                .gap(px(10.))
                .rounded(px(6.))
                .hover(|s| s.bg(pal.hover_bg))
                .cursor_pointer()
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, ev: &MouseDownEvent, window, cx| {
                        if ev.click_count >= 2 {
                            this.open_path(open_path.clone(), window, cx);
                        } else {
                            let text = open_path.clone();
                            this.start
                                .path_input
                                .update(cx, |s, cx| s.set_value(text, window, cx));
                        }
                    }),
                )
                .child(
                    div()
                        .flex_none()
                        .size(px(34.))
                        .rounded_full()
                        .bg(theme::badge_color(i))
                        .text_color(gpui_kit::white())
                        .font_weight(gpui_kit::FontWeight::BOLD)
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(badge_text(&path)),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .child(div().w_full().truncate().child(label))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(pal.muted)
                                .child(format!("Size: {}", format_bytecount(entry.size))),
                        ),
                )
                .child(
                    Button::new(("recent-remove", i))
                        .xsmall()
                        .ghost()
                        .label("Remove")
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.remove_recent(&remove_path, cx);
                            cx.stop_propagation();
                        })),
                )
        });
        let has_recent = !self.start.recent.is_empty();

        div()
            .id("start-screen")
            .test_support()
            .size_full()
            .flex()
            .justify_center()
            .overflow_hidden()
            .child(
                div()
                    .w(px(680.))
                    .max_w_full()
                    .h_full()
                    .px(px(20.))
                    .py(px(28.))
                    .flex()
                    .flex_col()
                    .gap(px(14.))
                    .child(
                        div()
                            .flex_none()
                            .flex()
                            .items_center()
                            .gap(px(14.))
                            .child(img(LOGO.clone()).size(px(64.)).flex_none())
                            .child(
                                div()
                                    .child(div().text_size(px(22.)).font_weight(gpui_kit::FontWeight::SEMIBOLD).child(APP_NAME))
                                    .child(div().text_color(pal.muted).child(format!("v{APP_VERSION} — explore Mach-O files, archives and dyld shared caches"))),
                            ),
                    )
                    .child(
                        div()
                            .flex_none()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(div().flex_none().child("File Path:"))
                            .child(div().flex_1().min_w_0().child(Input::new(&self.start.path_input).cleanable(true)))
                            .child(Button::new("start-select").label("Select").on_click(
                                cx.listener(|this, _, window, cx| this.start_select_file(window, cx)),
                            ))
                            .child(Button::new("start-open").primary().label("Open").on_click(cx.listener(
                                |this, _, window, cx| {
                                    let path = this.start.path_input.read(cx).value().to_string();
                                    this.open_path(path, window, cx);
                                },
                            ))),
                    )
                    .child(
                        div()
                            .flex_none()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(div().font_weight(gpui_kit::FontWeight::SEMIBOLD).child("Recent Files:"))
                            .when(has_recent, |d| {
                                d.child(
                                    Button::new("recent-clear")
                                        .xsmall()
                                        .ghost()
                                        .label("Clear All")
                                        .on_click(cx.listener(|this, _, _, cx| this.clear_recent(cx))),
                                )
                            }),
                    )
                    .child(
                        div()
                            .id("recent-list")
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .overflow_y_scroll()
                            .rounded(px(8.))
                            .border_1()
                            .border_color(pal.border)
                            .bg(pal.panel_bg)
                            .p(px(4.))
                            .children(recents)
                            .when(!has_recent, |d| {
                                d.child(
                                    div()
                                        .size_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_color(pal.muted)
                                        .child("No recent files — open one, or drop a file anywhere in this window."),
                                )
                            }),
                    )
                    .child(
                        div()
                            .flex_none()
                            .text_color(pal.muted)
                            .text_size(px(12.))
                            .child("Tip: drag a file onto the window to open it. Double-click a recent file to reopen it."),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badges() {
        assert_eq!(badge_text("/usr/bin/ls"), "LS");
        assert_eq!(badge_text("/a/dyld_shared_cache_arm64e"), "DY");
        assert_eq!(badge_text("x"), "X");
    }
}
