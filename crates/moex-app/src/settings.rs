//! Persistent settings (theme, recent files, window/pane sizes, update-check
//! state) stored as JSON in the platform config directory. No UI types here.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_RECENT_FILES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PaneSettings {
    pub layout_width: f32,
    pub hex_width: f32,
    pub bottom_height: f32,
    /// Fraction of the bottom strip used by the log (rest: information).
    pub log_fraction: f32,
    pub show_layout: bool,
    pub show_hex: bool,
    pub show_log: bool,
    pub show_information: bool,
}

impl Default for PaneSettings {
    fn default() -> Self {
        PaneSettings {
            layout_width: 280.0,
            hex_width: 584.0,
            bottom_height: 150.0,
            log_fraction: 0.5,
            show_layout: true,
            show_hex: true,
            show_log: true,
            show_information: true,
        }
    }
}

impl PaneSettings {
    /// Clamp persisted values to something usable (guards hand-edited files).
    pub fn sanitized(mut self) -> Self {
        let fix =
            |v: f32, lo: f32, hi: f32, def: f32| if v.is_finite() { v.clamp(lo, hi) } else { def };
        self.layout_width = fix(self.layout_width, 160.0, 1200.0, 280.0);
        self.hex_width = fix(self.hex_width, 200.0, 1600.0, 584.0);
        self.bottom_height = fix(self.bottom_height, 60.0, 1000.0, 150.0);
        self.log_fraction = fix(self.log_fraction, 0.15, 0.85, 0.5);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowSettings {
    pub width: f32,
    pub height: f32,
}

impl Default for WindowSettings {
    fn default() -> Self {
        WindowSettings {
            width: 1400.0,
            height: 860.0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateSettings {
    /// Do not show the startup "update available" prompt before this time
    /// (seconds since the Unix epoch, UTC). 0 = no snooze.
    pub remind_until_utc: i64,
    /// When the release API was last queried successfully.
    pub checked_at_utc: i64,
    /// Body of the last valid release response (reused for one hour).
    pub cached_release: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme_mode: ThemeMode,
    pub recent_files: Vec<String>,
    pub window: WindowSettings,
    pub panes: PaneSettings,
    pub update: UpdateSettings,
}

impl Settings {
    pub fn from_json(text: &str) -> Settings {
        let mut s: Settings = serde_json::from_str(text).unwrap_or_default();
        s.panes = s.panes.sanitized();
        if !(s.window.width.is_finite() && s.window.height.is_finite()) {
            s.window = WindowSettings::default();
        }
        s.window.width = s.window.width.clamp(600.0, 10000.0);
        s.window.height = s.window.height.clamp(400.0, 10000.0);
        s.recent_files.truncate(MAX_RECENT_FILES);
        s
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn load(path: &Path) -> Settings {
        match std::fs::read_to_string(path) {
            Ok(text) => Settings::from_json(&text),
            Err(_) => Settings::default(),
        }
    }

    /// Write atomically (temp file + rename) so a crash never truncates it.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, self.to_json())?;
        std::fs::rename(&tmp, path)
    }

    /// Move `path` to the front of the recent list (deduplicated, capped).
    pub fn push_recent(&mut self, path: &str) {
        push_recent(&mut self.recent_files, path);
    }
}

pub fn push_recent(list: &mut Vec<String>, path: &str) {
    if path.is_empty() {
        return;
    }
    list.retain(|p| p != path);
    list.insert(0, path.to_string());
    list.truncate(MAX_RECENT_FILES);
}

pub fn remove_recent(list: &mut Vec<String>, path: &str) {
    list.retain(|p| p != path);
}

/// Drop entries for which `exists` is false (the start screen does this, as
/// the Qt dialog did, so stale paths disappear).
pub fn prune_recent(list: &mut Vec<String>, exists: impl Fn(&str) -> bool) {
    list.retain(|p| exists(p));
}

/// `<config dir>/MachOExplorer/settings.json`; `MOEX_CONFIG_DIR` overrides
/// the directory (used by tests and scripted runs).
pub fn default_settings_path() -> PathBuf {
    let dir = match std::env::var_os("MOEX_CONFIG_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => dirs::config_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("MachOExplorer"),
    };
    dir.join("settings.json")
}

/// Same output as the Qt `util::formatBytecount`: three significant digits
/// with a decimal (1000-based) unit, e.g. `1.23 MB`, `512  B`.
pub fn format_bytecount(bytes: u64) -> String {
    if bytes == 0 {
        return "0".into();
    }
    const SUFFIX: [char; 7] = [' ', 'k', 'M', 'G', 'T', 'P', 'E'];
    let mut exp = 0usize;
    let mut scale = 1f64;
    while exp + 1 < SUFFIX.len() && bytes as f64 >= scale * 1000.0 {
        scale *= 1000.0;
        exp += 1;
    }
    let v = bytes as f64 / scale;
    let digits = if v >= 100.0 {
        0
    } else if v >= 10.0 {
        1
    } else {
        2
    };
    let mut s = format!("{v:.digits$}");
    if s.contains('.') {
        s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    }
    format!("{s} {}B", SUFFIX[exp])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip() {
        let s = Settings::default();
        assert_eq!(Settings::from_json(&s.to_json()), s);
        assert_eq!(s.theme_mode, ThemeMode::System);
        assert!(
            s.panes.show_layout && s.panes.show_hex && s.panes.show_log && s.panes.show_information
        );
    }

    #[test]
    fn theme_mode_serializes_like_qt_setting() {
        let mut s = Settings::default();
        s.theme_mode = ThemeMode::Dark;
        assert!(s.to_json().contains("\"theme_mode\": \"dark\""));
        assert_eq!(
            Settings::from_json(r#"{"theme_mode":"light"}"#).theme_mode,
            ThemeMode::Light
        );
    }

    #[test]
    fn corrupt_or_partial_files_fall_back_to_defaults() {
        assert_eq!(Settings::from_json("not json"), Settings::default());
        let s =
            Settings::from_json(r#"{"panes":{"layout_width":5,"hex_width":1e9},"future_key":1}"#);
        assert_eq!(s.panes.layout_width, 160.0);
        assert_eq!(s.panes.hex_width, 1600.0);
        assert_eq!(s.panes.bottom_height, 150.0);
    }

    #[test]
    fn recent_files_dedupe_prepend_and_cap() {
        let mut list = Vec::new();
        for i in 0..12 {
            push_recent(&mut list, &format!("/f{i}"));
        }
        assert_eq!(list.len(), MAX_RECENT_FILES);
        assert_eq!(list[0], "/f11");
        push_recent(&mut list, "/f5");
        assert_eq!(list[0], "/f5");
        assert_eq!(list.iter().filter(|p| *p == "/f5").count(), 1);
        push_recent(&mut list, "");
        assert_eq!(list[0], "/f5");
        remove_recent(&mut list, "/f5");
        assert!(!list.contains(&"/f5".to_string()));
        prune_recent(&mut list, |p| p == "/f11");
        assert_eq!(list, vec!["/f11".to_string()]);
    }

    #[test]
    fn save_and_load_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("settings.json");
        let mut s = Settings::default();
        s.push_recent("/bin/ls");
        s.update.remind_until_utc = 42;
        s.panes.show_log = false;
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        assert_eq!(
            Settings::load(&dir.path().join("missing.json")),
            Settings::default()
        );
    }

    #[test]
    fn bytecount_format() {
        assert_eq!(format_bytecount(0), "0");
        assert_eq!(format_bytecount(512), "512  B");
        assert_eq!(format_bytecount(1500), "1.5 kB");
        assert_eq!(format_bytecount(1_234_567), "1.23 MB");
        assert_eq!(format_bytecount(25_000_000_000), "25 GB");
    }
}
