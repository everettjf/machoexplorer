//! Application actions, menu structure and key bindings.

use crate::settings::ThemeMode;
use gpui_kit::{actions, App, KeyBinding, Menu, MenuItem};

actions!(
    moex,
    [
        NewWindow,
        CloseWindow,
        OpenFile,
        AttachPath,
        AttachSnapshot,
        ExtractDyldImage,
        Quit,
        ToggleLayout,
        ToggleHex,
        ToggleLog,
        ToggleInformation,
        ThemeSystem,
        ThemeLight,
        ThemeDark,
        ViewSource,
        ReportIssue,
        CheckUpdates,
        About,
        FindInTable,
    ]
);

pub const URL_SOURCE: &str = "https://github.com/everettjf/MachOExplorer";
pub const URL_ISSUES: &str = "https://github.com/everettjf/MachOExplorer/issues";
pub const URL_AUTHOR: &str = "https://github.com/everettjf";
pub const URL_ICON_DESIGNER: &str = "https://weibo.com/wantline";
pub const URL_DISCORD: &str = "https://discord.gg/eGzEaP6TzR";

/// What the menus need to know to show check marks / disabled items.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MenuState {
    pub show_layout: bool,
    pub show_hex: bool,
    pub show_log: bool,
    pub show_information: bool,
    pub theme: ThemeMode,
    pub extracting: bool,
}

/// Plain description of a menu entry (unit-testable, platform neutral).
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    Item {
        label: &'static str,
        id: Id,
        checked: bool,
        disabled: bool,
    },
    Separator,
    Submenu {
        label: &'static str,
        entries: Vec<Entry>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id {
    NewWindow,
    CloseWindow,
    OpenFile,
    AttachPath,
    AttachSnapshot,
    ExtractDyldImage,
    Quit,
    ToggleLayout,
    ToggleHex,
    ToggleLog,
    ToggleInformation,
    ThemeSystem,
    ThemeLight,
    ThemeDark,
    ViewSource,
    ReportIssue,
    CheckUpdates,
    About,
}

fn item(label: &'static str, id: Id) -> Entry {
    Entry::Item {
        label,
        id,
        checked: false,
        disabled: false,
    }
}

fn check(label: &'static str, id: Id, checked: bool) -> Entry {
    Entry::Item {
        label,
        id,
        checked,
        disabled: false,
    }
}

/// Menu bar layout. `app_menu` adds the macOS application menu (About, Check
/// for Updates, Quit live there, as Qt arranged them on macOS); elsewhere
/// they stay in File / Help exactly like the Qt menus.
pub fn menu_model(
    state: &MenuState,
    app_menu: bool,
    attach_path: bool,
) -> Vec<(&'static str, Vec<Entry>)> {
    let mut menus = Vec::new();
    if app_menu {
        menus.push((
            "MachOExplorer",
            vec![
                item("About MachOExplorer", Id::About),
                item("Check for Updates", Id::CheckUpdates),
                Entry::Separator,
                item("Quit MachOExplorer", Id::Quit),
            ],
        ));
    }

    let mut file = vec![
        item("New Window", Id::NewWindow),
        item("Close Window", Id::CloseWindow),
        item("Open File", Id::OpenFile),
    ];
    if attach_path {
        file.push(item("Attach by PID (Executable Path)", Id::AttachPath));
    }
    file.push(item("Attach by PID (Memory Snapshot)", Id::AttachSnapshot));
    file.push(Entry::Item {
        label: "Extract Image From Dyld Cache...",
        id: Id::ExtractDyldImage,
        checked: false,
        disabled: state.extracting,
    });
    if !app_menu {
        file.push(item("Quit", Id::Quit));
    }
    menus.push(("File", file));

    menus.push((
        "Window",
        vec![
            check("Layout", Id::ToggleLayout, state.show_layout),
            check("Hex", Id::ToggleHex, state.show_hex),
            check("Log", Id::ToggleLog, state.show_log),
            check("Information", Id::ToggleInformation, state.show_information),
            Entry::Submenu {
                label: "Theme",
                entries: vec![
                    check(
                        "Follow System",
                        Id::ThemeSystem,
                        state.theme == ThemeMode::System,
                    ),
                    check("Light", Id::ThemeLight, state.theme == ThemeMode::Light),
                    check("Dark", Id::ThemeDark, state.theme == ThemeMode::Dark),
                ],
            },
        ],
    ));

    let mut help = vec![
        item("View Source", Id::ViewSource),
        item("Report Issue", Id::ReportIssue),
    ];
    if !app_menu {
        help.push(item("Check for Updates", Id::CheckUpdates));
        help.push(item("About", Id::About));
    }
    menus.push(("Help", help));
    menus
}

fn to_item(entry: Entry) -> MenuItem {
    match entry {
        Entry::Separator => MenuItem::separator(),
        Entry::Submenu { label, entries } => {
            MenuItem::submenu(Menu::new(label).items(entries.into_iter().map(to_item)))
        }
        Entry::Item {
            label,
            id,
            checked,
            disabled,
        } => {
            let it = match id {
                Id::NewWindow => MenuItem::action(label, NewWindow),
                Id::CloseWindow => MenuItem::action(label, CloseWindow),
                Id::OpenFile => MenuItem::action(label, OpenFile),
                Id::AttachPath => MenuItem::action(label, AttachPath),
                Id::AttachSnapshot => MenuItem::action(label, AttachSnapshot),
                Id::ExtractDyldImage => MenuItem::action(label, ExtractDyldImage),
                Id::Quit => MenuItem::action(label, Quit),
                Id::ToggleLayout => MenuItem::action(label, ToggleLayout),
                Id::ToggleHex => MenuItem::action(label, ToggleHex),
                Id::ToggleLog => MenuItem::action(label, ToggleLog),
                Id::ToggleInformation => MenuItem::action(label, ToggleInformation),
                Id::ThemeSystem => MenuItem::action(label, ThemeSystem),
                Id::ThemeLight => MenuItem::action(label, ThemeLight),
                Id::ThemeDark => MenuItem::action(label, ThemeDark),
                Id::ViewSource => MenuItem::action(label, ViewSource),
                Id::ReportIssue => MenuItem::action(label, ReportIssue),
                Id::CheckUpdates => MenuItem::action(label, CheckUpdates),
                Id::About => MenuItem::action(label, About),
            };
            it.checked(checked).disabled(disabled)
        }
    }
}

pub fn build_menus(state: &MenuState) -> Vec<Menu> {
    menu_model(
        state,
        cfg!(target_os = "macos"),
        crate::attach::executable_path_supported(),
    )
    .into_iter()
    .map(|(name, entries)| Menu::new(name).items(entries.into_iter().map(to_item)))
    .collect()
}

pub fn bind_keys(cx: &mut App) {
    // Cmd on macOS, Ctrl elsewhere.
    let bindings = if cfg!(target_os = "macos") {
        [
            KeyBinding::new("cmd-n", NewWindow, None),
            KeyBinding::new("cmd-w", CloseWindow, None),
            KeyBinding::new("cmd-o", OpenFile, None),
            KeyBinding::new("cmd-q", Quit, None),
            KeyBinding::new("cmd-f", FindInTable, None),
        ]
    } else {
        [
            KeyBinding::new("ctrl-n", NewWindow, None),
            KeyBinding::new("ctrl-w", CloseWindow, None),
            KeyBinding::new("ctrl-o", OpenFile, None),
            KeyBinding::new("ctrl-q", Quit, None),
            KeyBinding::new("ctrl-f", FindInTable, None),
        ]
    };
    cx.bind_keys(bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> MenuState {
        MenuState {
            show_layout: true,
            show_hex: false,
            show_log: true,
            show_information: true,
            theme: ThemeMode::Dark,
            extracting: false,
        }
    }

    fn labels(entries: &[Entry]) -> Vec<&'static str> {
        entries
            .iter()
            .map(|e| match e {
                Entry::Item { label, .. } | Entry::Submenu { label, .. } => *label,
                Entry::Separator => "-",
            })
            .collect()
    }

    #[test]
    fn qt_layout_without_app_menu() {
        let m = menu_model(&state(), false, true);
        assert_eq!(
            m.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec!["File", "Window", "Help"]
        );
        assert_eq!(
            labels(&m[0].1),
            vec![
                "New Window",
                "Close Window",
                "Open File",
                "Attach by PID (Executable Path)",
                "Attach by PID (Memory Snapshot)",
                "Extract Image From Dyld Cache...",
                "Quit"
            ]
        );
        assert_eq!(
            labels(&m[1].1),
            vec!["Layout", "Hex", "Log", "Information", "Theme"]
        );
        assert_eq!(
            labels(&m[2].1),
            vec!["View Source", "Report Issue", "Check for Updates", "About"]
        );
    }

    #[test]
    fn macos_moves_about_and_quit_to_app_menu() {
        let m = menu_model(&state(), true, true);
        assert_eq!(m[0].0, "MachOExplorer");
        assert_eq!(
            labels(&m[0].1),
            vec![
                "About MachOExplorer",
                "Check for Updates",
                "-",
                "Quit MachOExplorer"
            ]
        );
        assert!(!labels(&m[1].1).contains(&"Quit"));
        assert_eq!(labels(&m[3].1), vec!["View Source", "Report Issue"]);
    }

    #[test]
    fn check_marks_and_platform_gating() {
        let m = menu_model(&state(), false, false);
        assert!(!labels(&m[0].1).contains(&"Attach by PID (Executable Path)"));
        let checked: Vec<bool> = m[1].1[..4]
            .iter()
            .map(|e| matches!(e, Entry::Item { checked: true, .. }))
            .collect();
        assert_eq!(checked, vec![true, false, true, true]);
        let Entry::Submenu { entries, .. } = &m[1].1[4] else {
            panic!()
        };
        assert_eq!(labels(entries), vec!["Follow System", "Light", "Dark"]);
        assert!(matches!(entries[2], Entry::Item { checked: true, .. }));
        assert!(matches!(entries[0], Entry::Item { checked: false, .. }));

        let mut s = state();
        s.extracting = true;
        let m = menu_model(&s, false, true);
        assert!(matches!(m[0].1[5], Entry::Item { disabled: true, .. }));
    }
}
