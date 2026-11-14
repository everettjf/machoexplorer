//! Colours (ported from the Qt stylesheet), fonts and theme switching.

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
        Palette {
            window_bg: c(0x15171b),
            panel_bg: c(0x161a21),
            alt_bg: c(0x1b2028),
            text: c(0xe5e9f0),
            muted: c(0x9aa3b0),
            grid: c(0x333a44),
            border: c(0x353c47),
            selection_bg: c(0x3f7d6a),
            selection_fg: c(0xffffff),
            selection_inactive_bg: c(0x2f4a44),
            hover_bg: c(0x232a34),
            header_bg: c(0x262c35),
            header_fg: c(0xe8ebf0),
            title_bg: c(0x22262d),
            title_fg: c(0xe8eaee),
            status_bg: c(0x181b20),
            status_fg: c(0xcfd3da),
            input_bg: c(0x1f232a),
            accent: c(0x4f9b84),
            match_fg: c(0xf3c66b),
            hex_dim: c(0x6f7a89),
            scroll_thumb: ca(0x9aa3b0, 0.45),
            overlay: ca(0x000000, 0.5),
            card_bg: c(0x1f232a),
            danger: c(0xe5645a),
        }
    }

    pub fn light() -> Self {
        Palette {
            window_bg: c(0xf2f3f5),
            panel_bg: c(0xffffff),
            alt_bg: c(0xf7f8fa),
            text: c(0x20242b),
            muted: c(0x6a7381),
            grid: c(0xdfe3e8),
            border: c(0xd9dde3),
            selection_bg: c(0x5f8f7f),
            selection_fg: c(0xffffff),
            selection_inactive_bg: c(0xcfe0da),
            hover_bg: c(0xeef1f4),
            header_bg: c(0xe8ebef),
            header_fg: c(0x1f242c),
            title_bg: c(0x2b313a),
            title_fg: c(0xeef1f5),
            status_bg: c(0xf7f8fa),
            status_fg: c(0x2b313a),
            input_bg: c(0xffffff),
            accent: c(0x5f8f7f),
            match_fg: c(0xb26a00),
            hex_dim: c(0x9aa3b0),
            scroll_thumb: ca(0x4a5260, 0.4),
            overlay: ca(0x000000, 0.3),
            card_bg: c(0xffffff),
            danger: c(0xc0392b),
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

/// Colours for the round badge of recent-file entries (same cycle as Qt).
pub fn badge_color(index: usize) -> Hsla {
    const COLORS: [u32; 6] = [0x1dbc9c, 0x3498db, 0x9b59b6, 0x34495e, 0xe74c3c, 0xf39c11];
    c(COLORS[index % COLORS.len()])
}
