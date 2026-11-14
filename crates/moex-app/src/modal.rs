//! In-window dialogs (error/info, About, PID prompt, update prompt, dyld
//! cache image selector, progress) and the flows that use them.

use crate::app::{self, AppState, APP_NAME, APP_VERSION};
use crate::attach;
use crate::cache_extract::{self as ce, ExtractOutcome};
use crate::menus;
use crate::theme::Palette;
use crate::update::{self, UpdateOutcome};
use crate::vscroll::VScroll;
use crate::window::{MainWindow, Pane};
use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::ElementExt as _;
use gpui_kit::component::Sizable;
use gpui_kit::prelude::*;
use gpui_kit::TestSupportExt as _;
use gpui_kit::{
    div, img, px, AnyElement, Bounds, Context, Entity, MouseButton, MouseDownEvent,
    PathPromptOptions, Pixels, ScrollEvent, SharedString, Subscription, Window,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const IMAGE_ROW_H: f32 = 22.0;
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(600);

pub enum Modal {
    Message {
        title: SharedString,
        text: SharedString,
        error: bool,
    },
    About,
    Pid {
        snapshot: bool,
        input: Entity<InputState>,
        error: Option<SharedString>,
        _sub: Subscription,
    },
    Update {
        current: String,
        latest: String,
        url: String,
    },
    /// `images` empty = free-text selector (the list could not be loaded).
    ImageSelector {
        cache: String,
        images: Arc<Vec<String>>,
        filtered: Vec<usize>,
        /// Index into `filtered`.
        selected: Option<usize>,
        input: Entity<InputState>,
        scroll: VScroll,
        bounds: Bounds<Pixels>,
        error: Option<SharedString>,
        _sub: Subscription,
    },
    Progress {
        text: SharedString,
        cancel: Arc<AtomicBool>,
    },
}

impl Modal {
    /// Short name of the dialog kind (tests).
    pub fn kind(&self) -> &'static str {
        match self {
            Modal::Message { error: true, .. } => "error",
            Modal::Message { .. } => "info",
            Modal::About => "about",
            Modal::Pid { .. } => "pid",
            Modal::Update { .. } => "update",
            Modal::ImageSelector { .. } => "image-selector",
            Modal::Progress { .. } => "progress",
        }
    }

    /// Main text of a message dialog (tests).
    pub fn message(&self) -> Option<&str> {
        match self {
            Modal::Message { text, .. } => Some(text),
            _ => None,
        }
    }
}

pub fn about_text() -> String {
    format!("{APP_NAME}\n\nv{APP_VERSION}\n\nApp is written by everettjf\n\nIcon is designed by wantline")
}

pub const COPYRIGHT: &str = "Copyright © 2017 AtomSprout. All rights reserved.";

impl MainWindow {
    pub fn show_error(
        &mut self,
        text: impl Into<SharedString>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_modal(
            Modal::Message {
                title: "Error".into(),
                text: text.into(),
                error: true,
            },
            window,
            cx,
        );
    }

    pub fn show_info(
        &mut self,
        text: impl Into<SharedString>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_modal(
            Modal::Message {
                title: "Info".into(),
                text: text.into(),
                error: false,
            },
            window,
            cx,
        );
    }

    pub fn show_about(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.set_modal(Modal::About, window, cx);
    }

    fn set_modal(&mut self, modal: Modal, window: &mut Window, cx: &mut Context<Self>) {
        match &modal {
            Modal::Pid { input, .. } | Modal::ImageSelector { input, .. } => {
                input.update(cx, |s, cx| s.focus(window, cx));
            }
            _ => window.focus(&self.focus, cx),
        }
        self.modal = Some(modal);
        cx.notify();
    }

    pub fn dismiss_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.modal = None;
        self.focus_default(window, cx);
        cx.notify();
    }

    /// Escape / Cancel.
    pub fn cancel_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match &self.modal {
            Some(Modal::Progress { .. }) => self.cancel_extract(cx),
            Some(_) => self.dismiss_modal(window, cx),
            None => {}
        }
    }

    /// Enter / default button.
    pub fn confirm_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match &self.modal {
            Some(Modal::Message { .. }) | Some(Modal::About) => self.dismiss_modal(window, cx),
            Some(Modal::Pid { .. }) => self.confirm_pid(window, cx),
            Some(Modal::Update { url, .. }) => {
                let url = url.clone();
                self.update_choice(Some(url), Some(0), window, cx);
            }
            Some(Modal::ImageSelector { .. }) => self.confirm_image(window, cx),
            Some(Modal::Progress { .. }) | None => {}
        }
    }

    // ---- Attach by PID -------------------------------------------------

    pub fn prompt_attach(&mut self, snapshot: bool, window: &mut Window, cx: &mut Context<Self>) {
        if snapshot && !attach::snapshot_supported() {
            self.show_error(attach::MSG_SNAPSHOT_MAC_ONLY, window, cx);
            return;
        }
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("Process ID"));
        let sub = cx.subscribe_in(
            &input,
            window,
            |this: &mut MainWindow, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.confirm_pid(window, cx);
                }
            },
        );
        self.set_modal(
            Modal::Pid {
                snapshot,
                input,
                error: None,
                _sub: sub,
            },
            window,
            cx,
        );
    }

    fn confirm_pid(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(Modal::Pid {
            snapshot,
            input,
            error,
            ..
        }) = &mut self.modal
        else {
            return;
        };
        let snapshot = *snapshot;
        let text = input.read(cx).value().to_string();
        let Some(pid) = attach::parse_pid(&text) else {
            *error = Some("Enter a process ID between 1 and 2147483647.".into());
            cx.notify();
            return;
        };
        self.dismiss_modal(window, cx);
        self.attach_pid(pid, snapshot, window, cx);
    }

    /// Resolve (or snapshot) the process off the UI thread, then open it.
    pub fn attach_pid(
        &mut self,
        pid: i32,
        snapshot: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if snapshot {
            self.set_status(format!("Reading memory of PID {pid}..."), Some(8000), cx);
        }
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    if snapshot {
                        attach::memory_snapshot(pid)
                    } else {
                        attach::executable_path(pid)
                    }
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| match result {
                Ok(path) => {
                    let path = path.to_string_lossy().into_owned();
                    this.open_path(path.clone(), window, cx);
                    if snapshot {
                        this.set_status(
                            format!("Attached by memory snapshot to PID {pid}: {path}"),
                            Some(8000),
                            cx,
                        );
                    } else {
                        this.set_status(
                            format!("Attached by path to PID {pid}: {path}"),
                            Some(6000),
                            cx,
                        );
                    }
                }
                Err(e) if snapshot => this.show_error(
                    format!("Attach snapshot failed for PID {pid}\n{e}"),
                    window,
                    cx,
                ),
                Err(e) => this.show_error(e, window, cx),
            });
        })
        .detach();
    }

    // ---- Updates -------------------------------------------------------

    pub fn show_update_outcome(
        &mut self,
        outcome: UpdateOutcome,
        interactive: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match outcome {
            UpdateOutcome::Invalid => {
                self.add_log("[update] invalid release api response", cx);
                if interactive {
                    self.show_error("Failed to parse update response.", window, cx);
                }
            }
            UpdateOutcome::DevelopmentBuild { latest, .. } => {
                self.add_log(
                    format!("[update] development build {APP_VERSION}, latest release={latest}"),
                    cx,
                );
                if interactive {
                    self.show_info(
                        "This development version cannot be compared. Open GitHub Releases for available downloads.",
                        window,
                        cx,
                    );
                }
            }
            UpdateOutcome::UpToDate { current, latest } => {
                self.add_log(
                    format!("[update] no update, current={current} latest={latest}"),
                    cx,
                );
                if interactive {
                    self.show_info(
                        format!("You're on the latest version: v{current}"),
                        window,
                        cx,
                    );
                }
            }
            UpdateOutcome::Available {
                current,
                latest,
                url,
            } => {
                self.add_log(
                    format!("[update] new version available current={current} latest={latest}"),
                    cx,
                );
                self.set_modal(
                    Modal::Update {
                        current: current.to_string(),
                        latest: latest.to_string(),
                        url,
                    },
                    window,
                    cx,
                );
            }
        }
    }

    /// Buttons of the update prompt: `open` = download page to open,
    /// `remind_days`: `Some(0)` clears the snooze, `Some(n)` snoozes n days,
    /// `None` ("Later") leaves it unchanged.
    fn update_choice(
        &mut self,
        open: Option<String>,
        remind_days: Option<i64>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(url) = open {
            cx.open_url(&url);
        }
        if let Some(days) = remind_days {
            let until = if days == 0 {
                0
            } else {
                update::now_utc() + days * update::DAY_SECONDS
            };
            AppState::update_settings(cx, |s| s.update.remind_until_utc = until);
        }
        self.dismiss_modal(window, cx);
    }

    // ---- Extract Image From Dyld Cache ---------------------------------

    pub fn start_cache_extract(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if AppState::get(cx).extracting {
            self.set_status("An extraction task is already running.", Some(4000), cx);
            return;
        }
        match self.path.clone().filter(|p| ce::is_cache_file(p)) {
            Some(cache) => self.choose_cache_image(cache, window, cx),
            None => {
                let rx = cx.prompt_for_paths(PathPromptOptions {
                    files: true,
                    directories: false,
                    multiple: false,
                    prompt: Some("Select dyld shared cache file".into()),
                });
                cx.spawn_in(window, async move |this, cx| {
                    if let Ok(Ok(Some(paths))) = rx.await {
                        if let Some(path) = paths.into_iter().next() {
                            let _ = this.update_in(cx, |this, window, cx| {
                                this.choose_cache_image(
                                    path.to_string_lossy().into_owned(),
                                    window,
                                    cx,
                                )
                            });
                        }
                    }
                })
                .detach();
            }
        }
    }

    /// List the cache's images in the background, then ask which to extract.
    pub fn choose_cache_image(
        &mut self,
        cache: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let tools = AppState::get(cx).cache_tools.clone();
        let list_path = PathBuf::from(&cache);
        self.set_status("Loading image list...", Some(4000), cx);
        cx.spawn_in(window, async move |this, cx| {
            let listed = cx
                .background_executor()
                .spawn(async move {
                    tools
                        .list(&list_path, ce::LIST_LIMIT)
                        .map(ce::prepare_image_list)
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                let images = match listed {
                    Ok(images) => images,
                    Err(e) => {
                        this.add_log(
                            format!(
                                "[cache-list] failed err={}",
                                if e.is_empty() { "(empty)" } else { &e }
                            ),
                            cx,
                        );
                        Vec::new()
                    }
                };
                this.open_image_selector(cache, images, window, cx);
            });
        })
        .detach();
    }

    pub fn open_image_selector(
        &mut self,
        cache: String,
        images: Vec<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let manual = images.is_empty();
        let input = cx.new(|cx| {
            let mut s = InputState::new(window, cx).placeholder(if manual {
                "Image path (exact or substring)"
            } else {
                "Search images..."
            });
            if manual {
                s.set_value(ce::DEFAULT_SELECTOR, window, cx);
            }
            s
        });
        let sub = cx.subscribe_in(
            &input,
            window,
            |this: &mut MainWindow, input, ev: &InputEvent, window, cx| match ev {
                InputEvent::Change => {
                    let q = input.read(cx).value().to_string();
                    if let Some(Modal::ImageSelector {
                        images,
                        filtered,
                        selected,
                        scroll,
                        error,
                        ..
                    }) = &mut this.modal
                    {
                        *filtered = ce::filter_images(images, &q);
                        *selected = None;
                        *error = None;
                        scroll.set_total(filtered.len() as u64);
                        scroll.scroll_to_top();
                        cx.notify();
                    }
                }
                InputEvent::PressEnter { .. } => this.confirm_image(window, cx),
                _ => {}
            },
        );
        let mut scroll = VScroll::new(IMAGE_ROW_H);
        scroll.set_total(images.len() as u64);
        let filtered = (0..images.len()).collect();
        self.set_modal(
            Modal::ImageSelector {
                cache,
                images: Arc::new(images),
                filtered,
                selected: None,
                input,
                scroll,
                bounds: Bounds::default(),
                error: None,
                _sub: sub,
            },
            window,
            cx,
        );
    }

    fn confirm_image(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(Modal::ImageSelector {
            cache,
            images,
            filtered,
            selected,
            input,
            error,
            ..
        }) = &mut self.modal
        else {
            return;
        };
        // A highlighted list entry wins; otherwise the typed text is the
        // selector (the Qt combo box was editable). A single remaining
        // search hit is taken as the choice.
        let chosen = match selected
            .and_then(|s| filtered.get(s))
            .and_then(|i| images.get(*i))
        {
            Some(path) => path.clone(),
            None if filtered.len() == 1 && !images.is_empty() => images[filtered[0]].clone(),
            None => input.read(cx).value().to_string(),
        };
        match ce::validate_selector(&chosen) {
            Ok(selector) => {
                let cache = cache.clone();
                self.modal = None;
                self.extract_cache_image(cache, selector, false, window, cx);
            }
            Err(e) => {
                *error = Some(e.into());
                cx.notify();
            }
        }
    }

    fn cancel_extract(&mut self, cx: &mut Context<Self>) {
        if let Some(cancel) = &self.extract_cancel {
            if !cancel.swap(true, Ordering::Relaxed) {
                self.add_log("[extract] canceled by user", cx);
                self.set_status("Extraction canceled.", Some(5000), cx);
            }
        }
    }

    /// Run the extraction in the background with a cancellable progress
    /// dialog, then open the result. `from_row`: started by double-clicking
    /// a row of the cache's image table.
    pub fn extract_cache_image(
        &mut self,
        cache: String,
        selector: String,
        from_row: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if AppState::get(cx).extracting {
            self.show_info("An extraction task is already running.", window, cx);
            return;
        }
        let tag = if from_row {
            "[extract-row]"
        } else {
            "[extract]"
        };
        let stamp = crate::util::utc_stamp_now();
        let output = if from_row {
            ce::row_output_path(&selector, &stamp)
        } else {
            ce::output_path(&cache, &stamp)
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.extract_cancel = Some(cancel.clone());
        AppState::update(cx, |s| s.extracting = true);
        app::refresh_menus(cx);
        self.add_log(
            format!(
                "{tag} start cache={cache} selector={selector} out={}",
                output.display()
            ),
            cx,
        );
        self.set_status(format!("Extracting image: {selector}"), Some(3000), cx);
        let text = if from_row {
            "Extracting selected image..."
        } else {
            "Extracting image from dyld shared cache..."
        };
        self.set_modal(
            Modal::Progress {
                text: text.into(),
                cancel: cancel.clone(),
            },
            window,
            cx,
        );

        // Give up after ten minutes, as the Qt UI did.
        let timed_out = Arc::new(AtomicBool::new(false));
        {
            let (cancel, timed_out) = (cancel.clone(), timed_out.clone());
            cx.spawn(async move |_, cx| {
                cx.background_executor().timer(EXTRACT_TIMEOUT).await;
                if !cancel.swap(true, Ordering::Relaxed) {
                    timed_out.store(true, Ordering::Relaxed);
                }
            })
            .detach();
        }

        let tools = AppState::get(cx).cache_tools.clone();
        let started = Instant::now();
        cx.spawn_in(window, async move |this, cx| {
            let lines = Arc::new(Mutex::new(Vec::<String>::new()));
            let (sink, out, c) = (lines.clone(), output.clone(), cancel.clone());
            let outcome = cx
                .background_executor()
                .spawn(async move {
                    ce::run_extract(
                        &*tools,
                        &PathBuf::from(&cache),
                        &selector,
                        &out,
                        &c,
                        &move |l| sink.lock().unwrap().push(l),
                    )
                })
                .await;
            let ms = started.elapsed().as_millis();
            // Stop the timeout task from flagging a finished job.
            let was_timeout = timed_out.load(Ordering::Relaxed);
            cancel.store(true, Ordering::Relaxed);
            let _ = this.update_in(cx, |this, window, cx| {
                AppState::update(cx, |s| s.extracting = false);
                app::refresh_menus(cx);
                this.extract_cancel = None;
                if matches!(this.modal, Some(Modal::Progress { .. })) {
                    this.dismiss_modal(window, cx);
                }
                for line in lines.lock().unwrap().drain(..) {
                    this.add_log(format!("{tag} {line}"), cx);
                }
                match outcome {
                    ExtractOutcome::Canceled => {
                        if was_timeout {
                            this.add_log(format!("{tag} canceled by timeout"), cx);
                            this.set_status(
                                "Extraction timed out and was canceled.",
                                Some(6000),
                                cx,
                            );
                        }
                        this.add_log(format!("{tag} finished with canceled state ({ms} ms)"), cx);
                    }
                    ExtractOutcome::Failed(msg) => {
                        this.add_log(
                            format!("{tag} failed details={} ({ms} ms)", msg.replace('\n', " ")),
                            cx,
                        );
                        this.show_error(msg, window, cx);
                    }
                    ExtractOutcome::Done { size } => {
                        let path = output.to_string_lossy().into_owned();
                        this.open_path(path.clone(), window, cx);
                        this.add_log(
                            format!("{tag} success out={path} size={size} ({ms} ms)"),
                            cx,
                        );
                        if from_row {
                            this.show_info(format!("Extracted and opened:\n{path}"), window, cx);
                        } else {
                            this.set_status(
                                format!("Extracted and opened: {path}"),
                                Some(8000),
                                cx,
                            );
                        }
                    }
                }
            });
        })
        .detach();
    }

    // ---- rendering -----------------------------------------------------

    fn text_block(text: &str) -> impl IntoElement {
        div()
            .w_full()
            .flex()
            .flex_col()
            .children(text.split('\n').map(|l| {
                let line: SharedString = if l.is_empty() {
                    " ".into()
                } else {
                    l.to_string().into()
                };
                div().w_full().child(line)
            }))
    }

    pub(crate) fn render_modal(
        &mut self,
        pal: &Palette,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let Some(modal) = &self.modal else {
            return div().into_any_element();
        };
        let close = |label: &'static str, primary: bool, cx: &mut Context<Self>| {
            let b = Button::new("modal-close").label(label);
            let b = if primary { b.primary() } else { b };
            b.on_click(cx.listener(|this, _, window, cx| this.dismiss_modal(window, cx)))
        };
        let mut width = 440.0;
        let title: SharedString;
        let mut content = div().w_full().flex().flex_col().gap(px(12.));
        let mut buttons = div().w_full().flex().flex_wrap().justify_end().gap(px(8.));

        match modal {
            Modal::Message {
                title: t,
                text,
                error,
            } => {
                title = t.clone();
                content = content.child(
                    div()
                        .id("modal-text")
                        .test_support()
                        .w_full()
                        .max_h(px(320.))
                        .overflow_y_scroll()
                        .when(*error, |d| d.text_color(pal.danger))
                        .child(Self::text_block(text)),
                );
                buttons = buttons.child(close("OK", true, cx));
            }
            Modal::About => {
                title = "About MachOExplorer".into();
                let link = |id: &'static str, label: &'static str, url: &'static str| {
                    Button::new(id)
                        .small()
                        .outline()
                        .label(label)
                        .on_click(move |_, _, cx| cx.open_url(url))
                };
                content = content
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .gap(px(16.))
                            .child(
                                img(crate::start_screen::LOGO.clone())
                                    .size(px(96.))
                                    .flex_none(),
                            )
                            .child(div().flex_1().child(Self::text_block(&about_text()))),
                    )
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .flex_col()
                            .gap(px(6.))
                            .child(link(
                                "about-author",
                                "Visit everettjf's GitHub",
                                menus::URL_AUTHOR,
                            ))
                            .child(link(
                                "about-project",
                                "Open Source Project on GitHub",
                                menus::URL_SOURCE,
                            ))
                            .child(link(
                                "about-designer",
                                "Visit wantline's personal page",
                                menus::URL_ICON_DESIGNER,
                            )),
                    )
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(pal.muted)
                            .child(COPYRIGHT),
                    );
                buttons = buttons
                    .child(
                        Button::new("about-discord")
                            .label("Discord")
                            .on_click(|_, _, cx| cx.open_url(menus::URL_DISCORD)),
                    )
                    .child(close("OK", true, cx));
            }
            Modal::Pid {
                snapshot,
                input,
                error,
                ..
            } => {
                title = if *snapshot {
                    "Attach Process (Memory Snapshot)".into()
                } else {
                    "Attach Process".into()
                };
                content = content
                    .child("Process ID:")
                    .child(Input::new(input))
                    .when_some(error.clone(), |d, e| {
                        d.child(div().text_color(pal.danger).child(e))
                    });
                buttons = buttons.child(close("Cancel", false, cx)).child(
                    Button::new("modal-ok")
                        .primary()
                        .label("OK")
                        .on_click(cx.listener(|this, _, window, cx| this.confirm_pid(window, cx))),
                );
            }
            Modal::Update {
                current,
                latest,
                url,
            } => {
                title = "Update Available".into();
                width = 520.0;
                content = content.child(Self::text_block(&format!(
                    "A new version is available.\nCurrent: v{current}\nLatest: v{latest}"
                )));
                let url = url.clone();
                let choice = |id: &'static str,
                              label: &'static str,
                              open: Option<String>,
                              days: Option<i64>,
                              cx: &mut Context<Self>| {
                    Button::new(id).label(label).on_click(cx.listener(
                        move |this, _, window, cx| {
                            this.update_choice(open.clone(), days, window, cx)
                        },
                    ))
                };
                buttons = buttons
                    .child(choice("update-later", "Later", None, None, cx))
                    .child(choice("update-30", "Remind in 30 days", None, Some(30), cx))
                    .child(choice("update-7", "Remind in 7 days", None, Some(7), cx))
                    .child(choice("update-download", "Download", Some(url), Some(0), cx).primary());
            }
            Modal::ImageSelector {
                images,
                filtered,
                selected,
                input,
                scroll,
                error,
                ..
            } => {
                title = "Image Selector".into();
                width = 640.0;
                let manual = images.is_empty();
                content = content
                    .child(if manual {
                        "Image path (exact or substring):"
                    } else {
                        "Choose image path (searchable, editable):"
                    })
                    .child(Input::new(input).cleanable(true));
                if !manual {
                    let v = scroll.visible();
                    let rows: Vec<_> = (0..v.count)
                        .filter_map(|i| {
                            let ix = v.first as usize + i;
                            let path: SharedString = images.get(*filtered.get(ix)?)?.clone().into();
                            let is_sel = *selected == Some(ix);
                            Some(
                                div()
                                    .id(("image-row", ix))
                                    .test_support()
                                    .absolute()
                                    .top(px(v.y + i as f32 * IMAGE_ROW_H))
                                    .left_0()
                                    .w_full()
                                    .h(px(IMAGE_ROW_H))
                                    .px(px(8.))
                                    .line_height(px(IMAGE_ROW_H))
                                    .truncate()
                                    .map(|d| {
                                        if is_sel {
                                            d.bg(pal.selection_bg).text_color(pal.selection_fg)
                                        } else {
                                            d.hover(|s| s.bg(pal.hover_bg))
                                        }
                                    })
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(
                                            move |this, ev: &MouseDownEvent, window, cx| {
                                                if let Some(Modal::ImageSelector {
                                                    selected, ..
                                                }) = &mut this.modal
                                                {
                                                    *selected = Some(ix);
                                                }
                                                if ev.click_count >= 2 {
                                                    this.confirm_image(window, cx);
                                                }
                                                cx.notify();
                                            },
                                        ),
                                    )
                                    .child(path),
                            )
                        })
                        .collect();
                    let vbar = crate::scrollbar::vscrollbar(
                        "images-scrollbar",
                        scroll,
                        pal,
                        cx.listener(|this, ev: &MouseDownEvent, _, cx| {
                            this.begin_thumb_drag(Pane::Images, ev.position.y, cx)
                        }),
                    );
                    content = content
                        .child(
                            div()
                                .id("image-list")
                                .w_full()
                                .h(px(320.))
                                .relative()
                                .overflow_hidden()
                                .rounded(px(6.))
                                .border_1()
                                .border_color(pal.border)
                                .bg(pal.panel_bg)
                                .font_family(crate::theme::MONO_FONT)
                                .on_scroll(cx.listener(|this, ev: &ScrollEvent, _, cx| {
                                    let d = ev.delta.pixel_delta(px(IMAGE_ROW_H));
                                    this.wheel(Pane::Images, f32::from(d.y), cx);
                                }))
                                .on_prepaint(Self::track_bounds(Pane::Images, cx))
                                .children(rows)
                                .children(vbar),
                        )
                        .child(
                            div()
                                .text_color(pal.muted)
                                .text_size(px(12.))
                                .child(format!("{} of {} images", filtered.len(), images.len())),
                        );
                }
                content = content.when_some(error.clone(), |d, e| {
                    d.child(div().text_color(pal.danger).child(e))
                });
                buttons = buttons.child(close("Cancel", false, cx)).child(
                    Button::new("modal-ok").primary().label("Extract").on_click(
                        cx.listener(|this, _, window, cx| this.confirm_image(window, cx)),
                    ),
                );
            }
            Modal::Progress { text, cancel } => {
                title = "Extract Image".into();
                let canceled = cancel.load(Ordering::Relaxed);
                content = content.child(
                    div()
                        .w_full()
                        .flex()
                        .items_center()
                        .gap(px(12.))
                        .child(Spinner::new().color(pal.accent))
                        .child(if canceled {
                            SharedString::from("Canceling...")
                        } else {
                            text.clone()
                        }),
                );
                buttons = buttons.child(
                    Button::new("modal-cancel")
                        .label("Cancel")
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_extract(cx))),
                );
            }
        }

        div()
            .id("modal-overlay")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .occlude()
            .bg(pal.overlay)
            .flex()
            .items_center()
            .justify_center()
            .on_scroll(|_, _, cx| cx.stop_propagation())
            .child(
                div()
                    .id("modal")
                    .test_support()
                    .w(px(width))
                    .max_w(gpui_kit::relative(0.9))
                    .p(px(18.))
                    .flex()
                    .flex_col()
                    .gap(px(14.))
                    .rounded(px(10.))
                    .border_1()
                    .border_color(pal.border)
                    .bg(pal.card_bg)
                    .shadow_lg()
                    .child(
                        div()
                            .text_size(px(15.))
                            .font_weight(gpui_kit::FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .child(content)
                    .child(buttons),
            )
            .into_any_element()
    }
}
