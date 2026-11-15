//! Colours, fonts and theme switching.

use crate::settings::ThemeMode;
use gpui_kit::component::{Theme, ThemeMode as KitThemeMode};
use gpui_kit::{rgb, App, Hsla, Window};

/// Bundled monospace font used for tables, hex and the log (the Qt look).
pub const MONO_FONT: &str = "Inconsolata";
pub const MONO_SIZE: f32 = 13.0;
pub const UI_SIZE: f32 = 13.0;

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub window_bg: Hsla,
    pub panel_bg: Hsla,
    pub alt_bg: Hsla,
    pub text: Hsla,
    pub muted: Hsla,
    pub grid: Hsla,
    pub border: Hsla,
    pub selection_bg: Hsla,
    pub selection_fg: Hsla,
    /// Selection colour of a pane that does not have keyboard focus.
    pub selection_inactive_bg: Hsla,
    pub hover_bg: Hsla,
    pub header_bg: Hsla,
    pub header_fg: Hsla,
    pub title_bg: Hsla,
    pub title_fg: Hsla,
    pub status_bg: Hsla,
    pub status_fg: Hsla,
    pub input_bg: Hsla,
    pub accent: Hsla,
    pub match_fg: Hsla,
    pub hex_dim: Hsla,
    pub scroll_thumb: Hsla,
    pub overlay: Hsla,
    pub card_bg: Hsla,
    pub danger: Hsla,
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

fn ca(hex: u32, alpha: f32) -> Hsla {
    let mut h: Hsla = rgb(hex).into();
    h.a = alpha;
    h
}

impl Palette {
    pub fn dark() -> Self {
        // Neutral graphite surfaces with one restrained steel accent; no
        // tinted backgrounds. Text contrast is at least 4.5:1 on its surface.
        Palette {
            window_bg: c(0x1b1b1c),
            panel_bg: c(0x1e1e1f),
            alt_bg: c(0x232324),
            text: c(0xd6d6d6),
            muted: c(0x8e8e90),
            grid: c(0x2c2c2e),
            border: c(0x343436),
            selection_bg: c(0x3a4656),
            selection_fg: c(0xffffff),
            selection_inactive_bg: c(0x303032),
            hover_bg: c(0x28282a),
            header_bg: c(0x252526),
            header_fg: c(0xb9b9bb),
            title_bg: c(0x232324),
            title_fg: c(0xd0d0d2),
            status_bg: c(0x1b1b1c),
            status_fg: c(0xa6a6a8),
            input_bg: c(0x262627),
            accent: c(0x7aa2c9),
            match_fg: c(0xdcb46a),
            hex_dim: c(0x6c6c6e),
            scroll_thumb: ca(0x9a9a9c, 0.38),
            overlay: ca(0x000000, 0.55),
            card_bg: c(0x252526),
            danger: c(0xd9695f),
        }
    }

    pub fn light() -> Self {
        Palette {
            window_bg: c(0xf3f3f3),
            panel_bg: c(0xffffff),
            alt_bg: c(0xfafafa),
            text: c(0x1f1f21),
            muted: c(0x6b6b6e),
            grid: c(0xe6e6e7),
            border: c(0xd8d8da),
            selection_bg: c(0x3f6a94),
            selection_fg: c(0xffffff),
            selection_inactive_bg: c(0xe0e0e2),
            hover_bg: c(0xf0f0f1),
            header_bg: c(0xf3f3f3),
            header_fg: c(0x4a4a4d),
            title_bg: c(0xe9e9ea),
            title_fg: c(0x2a2a2c),
            status_bg: c(0xf3f3f3),
            status_fg: c(0x55555a),
            input_bg: c(0xffffff),
            accent: c(0x3f6a94),
            match_fg: c(0x9a5b00),
            hex_dim: c(0xa2a2a5),
            scroll_thumb: ca(0x55555a, 0.38),
            overlay: ca(0x000000, 0.3),
            card_bg: c(0xffffff),
            danger: c(0xb93a2e),
        }
    }

    pub fn of(cx: &App) -> Self {
        if is_dark(cx) {
            Self::dark()
        } else {
            Self::light()
        }
    }
}

pub fn is_dark(cx: &App) -> bool {
    Theme::global(cx).is_dark()
}

/// Apply `mode` to the component library's theme (which refreshes windows).
pub fn apply(mode: ThemeMode, window: Option<&mut Window>, cx: &mut App) {
    match mode {
        ThemeMode::System => Theme::sync_system_appearance(window, cx),
        ThemeMode::Light => Theme::change(KitThemeMode::Light, window, cx),
        ThemeMode::Dark => Theme::change(KitThemeMode::Dark, window, cx),
    }
}

/// Colours for the round badge of recent-file entries: muted tones that
/// read on both the dark and the light card.
pub fn badge_color(index: usize) -> Hsla {
    const COLORS: [u32; 6] = [0x6f8fae, 0xa8875a, 0x8a8f98, 0xa9726b, 0x7d9a94, 0x9b8aa6];
    c(COLORS[index % COLORS.len()])
}
