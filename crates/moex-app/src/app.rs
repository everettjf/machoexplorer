//! Application state and wiring: settings, window registry, global menu
//! actions, theme, update check.

use crate::cache_extract::CacheTools;
use crate::menus::{self, MenuState};
use crate::settings::{Settings, ThemeMode};
use crate::update::{self, UpdateOutcome};
use crate::window::MainWindow;
use gpui_kit::component::GlobalState;
use gpui_kit::prelude::*;
use gpui_kit::{
    point, px, size, AnyWindowHandle, App, Bounds, Context, Entity, Global, TitlebarOptions,
    WeakEntity, Window, WindowBounds, WindowOptions,
};
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const APP_NAME: &str = "MachOExplorer";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub type ReleaseFetcher = Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>;

pub struct AppState {
    pub settings: Settings,
    /// `None`: settings are kept in memory only (tests).
    pub settings_path: Option<PathBuf>,
    pub cache_tools: Arc<dyn CacheTools>,
    pub release_fetcher: ReleaseFetcher,
    pub windows: Vec<(AnyWindowHandle, WeakEntity<MainWindow>)>,
    pub update_in_progress: bool,
    pub extracting: bool,
}

impl Global for AppState {}

impl AppState {
    pub fn get(cx: &App) -> &AppState {
        cx.global::<AppState>()
    }

    pub fn update<R>(cx: &mut App, f: impl FnOnce(&mut AppState) -> R) -> R {
        f(cx.global_mut::<AppState>())
    }

    /// Change settings and write them to disk.
    pub fn update_settings(cx: &mut App, f: impl FnOnce(&mut Settings)) {
        let state = cx.global_mut::<AppState>();
        f(&mut state.settings);
        if let Some(path) = &state.settings_path {
            if let Err(e) = state.settings.save(path) {
                eprintln!("[settings] cannot save {}: {e}", path.display());
            }
        }
    }
}

/// Initialize libraries, fonts, theme, actions and menus. `settings_path`
/// of `None` keeps settings in memory.
pub fn init(cx: &mut App, settings_path: Option<PathBuf>) {
    gpui_kit::init(cx);
    let fonts: Vec<Cow<'static, [u8]>> = vec![
        Cow::Borrowed(include_bytes!("../assets/fonts/Inconsolata-Regular.ttf")),
        Cow::Borrowed(include_bytes!("../assets/fonts/Anonymous Pro.ttf")),
    ];
    if let Err(e) = cx.text_system().add_fonts(fonts) {
        eprintln!("[fonts] cannot register bundled fonts: {e}");
    }

    let settings = settings_path
        .as_deref()
        .map(Settings::load)
        .unwrap_or_default();
    let theme_mode = settings.theme_mode;
    cx.set_global(AppState {
        settings,
        settings_path,
        cache_tools: crate::cache_extract::default_tools(),
        release_fetcher: Arc::new(update::fetch_latest_release),
        windows: Vec::new(),
        update_in_progress: false,
        extracting: false,
    });
    crate::theme::apply(theme_mode, None, cx);

    menus::bind_keys(cx);
    register_actions(cx);
    refresh_menus(cx);

    cx.on_window_closed(|cx, _| {
        AppState::update(cx, |s| s.windows.retain(|(_, w)| w.upgrade().is_some()));
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();
}

fn menu_state(cx: &App) -> MenuState {
    let state = AppState::get(cx);
    let panes = &state.settings.panes;
    MenuState {
        show_layout: panes.show_layout,
        show_hex: panes.show_hex,
        show_log: panes.show_log,
        show_information: panes.show_information,
        theme: state.settings.theme_mode,
        extracting: state.extracting,
    }
}

/// Rebuild the menu bar (check marks follow the settings).
pub fn refresh_menus(cx: &mut App) {
    let menus = menus::build_menus(&menu_state(cx));
    let owned = menus::build_menus(&menu_state(cx))
        .into_iter()
        .map(|m| m.owned())
        .collect();
    cx.set_menus(menus);
    // The in-window menu bar used on Windows/Linux reads this copy.
    GlobalState::global_mut(cx).set_app_menus(owned);
    // Deferred: this may be called while a window is being updated.
    cx.defer(|cx| {
        let windows: Vec<_> = AppState::get(cx)
            .windows
            .iter()
            .filter_map(|(_, w)| w.upgrade())
            .collect();
        for w in windows {
            w.update(cx, |w, cx| w.reload_menu_bar(cx));
        }
    });
}

/// The main window that should receive a menu command.
pub fn active_main_window(cx: &App) -> Option<(AnyWindowHandle, Entity<MainWindow>)> {
    let state = AppState::get(cx);
    let active = cx.active_window();
    state
        .windows
        .iter()
        .find(|(h, _)| Some(*h) == active)
        .or_else(|| state.windows.last())
        .and_then(|(h, w)| w.upgrade().map(|w| (*h, w)))
}

fn with_active(
    cx: &mut App,
    f: impl FnOnce(&mut MainWindow, &mut Window, &mut Context<MainWindow>),
) {
    let Some((handle, view)) = active_main_window(cx) else {
        return;
    };
    let _ = handle.update(cx, |_, window, cx| {
        view.update(cx, |v, cx| f(v, window, cx))
    });
}

fn set_pane(cx: &mut App, f: impl FnOnce(&mut crate::settings::PaneSettings)) {
    AppState::update_settings(cx, |s| f(&mut s.panes));
    let windows: Vec<_> = AppState::get(cx)
        .windows
        .iter()
        .filter_map(|(_, w)| w.upgrade())
        .collect();
    for w in windows {
        w.update(cx, |_, cx| cx.notify());
    }
    refresh_menus(cx);
}

pub fn set_theme(mode: ThemeMode, cx: &mut App) {
    AppState::update_settings(cx, |s| s.theme_mode = mode);
    crate::theme::apply(mode, None, cx);
    refresh_menus(cx);
}

fn register_actions(cx: &mut App) {
    cx.on_action(|_: &menus::Quit, cx| cx.quit());
    cx.on_action(|_: &menus::NewWindow, cx| {
        let _ = open_main_window(None, cx);
    });
    cx.on_action(|_: &menus::CloseWindow, cx| {
        if let Some(handle) = cx.active_window() {
            let _ = handle.update(cx, |_, window, _| window.remove_window());
        }
    });
    cx.on_action(|_: &menus::OpenFile, cx| {
        with_active(cx, |w, window, cx| w.prompt_open_file(window, cx))
    });
    cx.on_action(|_: &menus::AttachPath, cx| {
        with_active(cx, |w, window, cx| w.prompt_attach(false, window, cx))
    });
    cx.on_action(|_: &menus::AttachSnapshot, cx| {
        with_active(cx, |w, window, cx| w.prompt_attach(true, window, cx))
    });
    cx.on_action(|_: &menus::ExtractDyldImage, cx| {
        with_active(cx, |w, window, cx| w.start_cache_extract(window, cx))
    });
    cx.on_action(|_: &menus::FindInTable, cx| {
        with_active(cx, |w, window, cx| w.focus_table_filter(window, cx))
    });
    cx.on_action(|_: &menus::About, cx| with_active(cx, |w, window, cx| w.show_about(window, cx)));
    cx.on_action(|_: &menus::CheckUpdates, cx| check_for_updates(true, cx));
    cx.on_action(|_: &menus::ViewSource, cx| cx.open_url(menus::URL_SOURCE));
    cx.on_action(|_: &menus::ReportIssue, cx| cx.open_url(menus::URL_ISSUES));
    cx.on_action(|_: &menus::ToggleLayout, cx| set_pane(cx, |p| p.show_layout = !p.show_layout));
    cx.on_action(|_: &menus::ToggleHex, cx| set_pane(cx, |p| p.show_hex = !p.show_hex));
    cx.on_action(|_: &menus::ToggleLog, cx| set_pane(cx, |p| p.show_log = !p.show_log));
    cx.on_action(|_: &menus::ToggleInformation, cx| {
        set_pane(cx, |p| p.show_information = !p.show_information)
    });
    cx.on_action(|_: &menus::ThemeSystem, cx| set_theme(ThemeMode::System, cx));
    cx.on_action(|_: &menus::ThemeLight, cx| set_theme(ThemeMode::Light, cx));
    cx.on_action(|_: &menus::ThemeDark, cx| set_theme(ThemeMode::Dark, cx));
}

fn window_options(cx: &App) -> WindowOptions {
    let ws = &AppState::get(cx).settings.window;
    let bounds = Bounds::centered(None, size(px(ws.width), px(ws.height)), cx);
    // The title bar is drawn in-window on every platform so that it follows
    // the app's theme rather than the system appearance (a native macOS bar
    // stays dark under a light theme when the system is in dark mode).
    let titlebar = TitlebarOptions {
        title: Some(APP_NAME.into()),
        appears_transparent: true,
        traffic_light_position: Some(point(px(9.), px(9.))),
    };
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        titlebar: Some(titlebar),
        window_min_size: Some(size(px(600.), px(400.))),
        app_owns_titlebar_drag: !cfg!(target_os = "macos"),
        ..Default::default()
    }
}

/// Open a main window, optionally loading `path` in it.
pub fn open_main_window(
    path: Option<PathBuf>,
    cx: &mut App,
) -> gpui_kit::Result<(AnyWindowHandle, Entity<MainWindow>)> {
    let options = window_options(cx);
    open_main_window_with(options, path, cx)
}

pub fn open_main_window_with(
    options: WindowOptions,
    path: Option<PathBuf>,
    cx: &mut App,
) -> gpui_kit::Result<(AnyWindowHandle, Entity<MainWindow>)> {
    let (handle, view) = gpui_kit::open_window(options, cx, |window, cx| {
        cx.new(|cx| MainWindow::new(window, cx))
    })?;
    AppState::update(cx, |s| s.windows.push((handle, view.downgrade())));
    handle.update(cx, |_, window, cx| {
        window.set_window_title(APP_NAME);
        view.update(cx, |v, cx| {
            v.focus_default(window, cx);
            if let Some(path) = path {
                v.open_path(path.to_string_lossy().into_owned(), window, cx);
            }
        });
    })?;
    Ok((handle, view))
}

/// Check GitHub Releases. `interactive` = started from the menu: every
/// outcome is reported; otherwise only an available update is.
pub fn check_for_updates(interactive: bool, cx: &mut App) {
    if AppState::get(cx).update_in_progress {
        if interactive {
            with_active(cx, |w, _, cx| {
                w.set_status("Update check is already in progress.", Some(3000), cx)
            });
        }
        return;
    }
    AppState::update(cx, |s| s.update_in_progress = true);
    if interactive {
        with_active(cx, |w, _, cx| {
            w.set_status("Checking for updates...", Some(3000), cx)
        });
    }

    let now = update::now_utc();
    let (cached, fetcher) = {
        let s = AppState::get(cx);
        let u = &s.settings.update;
        let fresh = update::cache_is_fresh(u.checked_at_utc, now)
            && update::ReleaseInfo::parse(u.cached_release.as_bytes()).is_some();
        (
            fresh.then(|| u.cached_release.clone().into_bytes()),
            s.release_fetcher.clone(),
        )
    };

    cx.spawn(async move |cx| {
        let (result, from_network) = match cached {
            Some(body) => (Ok(body), false),
            None => (
                cx.background_executor()
                    .spawn(async move { fetcher() })
                    .await,
                true,
            ),
        };
        let _ = cx.update(|cx| {
            AppState::update(cx, |s| s.update_in_progress = false);
            let body = match result {
                Ok(body) => body,
                Err(err) => {
                    with_active(cx, |w, window, cx| {
                        w.add_log(format!("[update] check failed: {err}"), cx);
                        if interactive {
                            w.show_error(format!("Failed to check updates:\n{err}"), window, cx);
                        }
                    });
                    return;
                }
            };
            let outcome = update::evaluate(APP_VERSION, &body);
            if from_network && outcome != UpdateOutcome::Invalid {
                AppState::update_settings(cx, |s| {
                    s.update.cached_release = String::from_utf8_lossy(&body).into_owned();
                    s.update.checked_at_utc = now;
                });
            }
            with_active(cx, |w, window, cx| {
                w.show_update_outcome(outcome, interactive, window, cx)
            });
        });
    })
    .detach();
}

/// Qt checked 1.5 s after the first window appeared unless snoozed.
pub fn schedule_startup_update_check(cx: &mut App) {
    cx.spawn(async move |cx| {
        cx.background_executor()
            .timer(Duration::from_millis(1500))
            .await;
        let _ = cx.update(|cx| {
            let remind = AppState::get(cx).settings.update.remind_until_utc;
            if update::should_check_on_startup(remind, update::now_utc()) {
                check_for_updates(false, cx);
            }
        });
    })
    .detach();
}

/// Entry point of the binary.
pub fn run() {
    let mut args = std::env::args_os().skip(1);
    let mut file: Option<PathBuf> = None;
    for arg in args.by_ref() {
        match arg.to_str() {
            Some("-h") | Some("--help") => {
                println!("MachO Explorer\n\nUsage: {APP_NAME} [filename]\n\n  filename   Filename to open.\n  -h, --help     Show this help\n  -v, --version  Show version");
                return;
            }
            Some("-v") | Some("--version") => {
                println!("{APP_NAME} {APP_VERSION}");
                return;
            }
            _ => {
                if file.is_none() {
                    file = Some(PathBuf::from(arg));
                }
            }
        }
    }

    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            init(cx, Some(crate::settings::default_settings_path()));
            cx.activate(true);
            match open_main_window(file, cx) {
                Ok((_handle, _view)) => {
                    #[cfg(debug_assertions)]
                    debug_drive(_handle, _view, cx);
                }
                Err(e) => {
                    eprintln!("failed to open window: {e}");
                    cx.quit();
                    return;
                }
            }
            if std::env::var_os("MOEX_NO_UPDATE_CHECK").is_none() {
                schedule_startup_update_check(cx);
            }
        });
}

/// Debug builds only: drive the UI from environment variables so the window
/// can be inspected without input automation.
///
/// - `MOEX_DEBUG_SELECT=Mach Header/Load Commands/LC_MAIN` selects (and
///   expands) tree nodes by name prefix, one path segment at a time.
/// - `MOEX_DEBUG_ROW=3` then selects that table row.
/// - `MOEX_DEBUG_TREE_FILTER=text` / `MOEX_DEBUG_TABLE_FILTER=text`.
/// - `MOEX_DEBUG_MODAL=about|error|update|pid|images`.
#[cfg(debug_assertions)]
fn debug_drive(handle: AnyWindowHandle, view: Entity<MainWindow>, cx: &mut App) {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let (select, row, tree_filter, table_filter, modal) = (
        var("MOEX_DEBUG_SELECT"),
        var("MOEX_DEBUG_ROW").and_then(|r| r.parse::<usize>().ok()),
        var("MOEX_DEBUG_TREE_FILTER"),
        var("MOEX_DEBUG_TABLE_FILTER"),
        var("MOEX_DEBUG_MODAL"),
    );
    if select.is_none()
        && row.is_none()
        && tree_filter.is_none()
        && table_filter.is_none()
        && modal.is_none()
    {
        return;
    }
    cx.spawn(async move |cx| {
        let pause = |ms: u64, cx: &mut gpui_kit::AsyncApp| {
            cx.background_executor().timer(Duration::from_millis(ms))
        };
        let with = |cx: &mut gpui_kit::AsyncApp,
                    f: Box<
            dyn FnOnce(&mut MainWindow, &mut Window, &mut Context<MainWindow>) -> bool,
        >| {
            handle
                .update(cx, |_, window, cx| {
                    view.update(cx, |v, cx| f(v, window, cx))
                })
                .unwrap_or(false)
        };
        for _ in 0..100 {
            if with(
                cx,
                Box::new(|v, _, _| {
                    (v.doc.is_some() && v.table.table().is_some())
                        || v.modal.is_some()
                        || v.opening.is_none()
                }),
            ) {
                break;
            }
            pause(50, cx).await;
        }
        let mut from = 0usize;
        for seg in select.iter().flat_map(|s| s.split('/')).map(str::to_string) {
            let (s, start) = (seg.clone(), from);
            let mut found = None;
            for _ in 0..40 {
                let s = s.clone();
                let hit = handle
                    .update(cx, |_, window, cx| {
                        view.update(cx, |v, cx| {
                            let ix =
                                v.tree.model.rows().iter().enumerate().position(|(i, r)| {
                                    i >= start && r.node.name().starts_with(&s)
                                })?;
                            v.select_tree_row(ix, window, cx);
                            if !v.tree.model.rows()[ix].expanded {
                                v.toggle_tree_row(ix, window, cx);
                            }
                            Some(ix)
                        })
                    })
                    .ok()
                    .flatten();
                if hit.is_some() {
                    found = hit;
                    break;
                }
                pause(50, cx).await;
            }
            let Some(ix) = found else { break };
            from = ix + 1;
            pause(400, cx).await;
        }
        if let Some(text) = tree_filter {
            with(
                cx,
                Box::new(move |v, window, cx| {
                    // Programmatic changes do not emit a change event.
                    v.tree
                        .filter_input
                        .update(cx, |s, cx| s.set_value(text.clone(), window, cx));
                    v.set_tree_filter(&text, window, cx);
                    true
                }),
            );
            pause(600, cx).await;
        }
        if let Some(text) = table_filter {
            with(
                cx,
                Box::new(move |v, window, cx| {
                    v.table
                        .filter_input
                        .update(cx, |s, cx| s.set_value(text.clone(), window, cx));
                    v.set_table_filter(text, false, window, cx);
                    true
                }),
            );
            pause(400, cx).await;
        }
        if let Some(row) = row {
            with(
                cx,
                Box::new(move |v, window, cx| {
                    window.focus(&v.table.focus, cx);
                    v.select_table_row(row, window, cx);
                    true
                }),
            );
        }
        if let Some(kind) = modal {
            with(
                cx,
                Box::new(move |v, window, cx| {
                    match kind.as_str() {
                        "about" => v.show_about(window, cx),
                        "error" => v.show_error(
                            "Can not open file\nThis is what a parse error looks like.",
                            window,
                            cx,
                        ),
                        "pid" => v.prompt_attach(false, window, cx),
                        "update" => v.show_update_outcome(
                            UpdateOutcome::Available {
                                current: update::Version(2, 0, 16),
                                latest: update::Version(2, 0, 17),
                                url: update::RELEASE_PAGE_URL.into(),
                            },
                            false,
                            window,
                            cx,
                        ),
                        "images" => v.open_image_selector(
                            "/tmp/dyld_shared_cache_arm64e".into(),
                            (0..400)
                                .map(|i| format!("/usr/lib/system/libexample_{i:03}.dylib"))
                                .collect(),
                            window,
                            cx,
                        ),
                        _ => {}
                    }
                    true
                }),
            );
        }
    })
    .detach();
}
