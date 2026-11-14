//! UI integration tests: the real main window in a headless GPUI window.

use gpui_kit::test::{TestAppContextExt, TestWindowExt};
use gpui_kit::{
    point, px, size, AnyWindowHandle, App, AppContext as _, Bounds, Context, Entity,
    TestAppContext, Window, WindowBounds, WindowOptions,
};
use moex_app::app::{self, AppState};
use moex_app::cache_extract::{CacheTools, LogSink, MSG_NOT_AVAILABLE};
use moex_app::hex::ByteSelection;
use moex_app::modal::Modal;
use moex_app::settings::ThemeMode;
use moex_app::window::MainWindow;
use moex_core::view::{Content, FnNode};
use moex_core::{BinaryRange, Document, Image, Table, ViewNode};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(20);

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

struct Ui {
    handle: AnyWindowHandle,
    view: Entity<MainWindow>,
}

fn open_window(cx: &mut TestAppContext, file: Option<PathBuf>, settings: Option<PathBuf>) -> Ui {
    cx.update(|cx| {
        app::init(cx, settings);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds {
                origin: point(px(0.), px(0.)),
                size: size(px(1400.), px(860.)),
            })),
            ..Default::default()
        };
        let (handle, view) = app::open_main_window_with(options, file, cx).expect("open window");
        Ui { handle, view }
    })
}

impl Ui {
    /// Run `f` on the main window view.
    fn update<R>(
        &self,
        cx: &mut TestAppContext,
        f: impl FnOnce(&mut MainWindow, &mut Window, &mut Context<MainWindow>) -> R,
    ) -> R {
        let view = self.view.clone();
        cx.update_window(self.handle, |_, window, cx| {
            view.update(cx, |v, cx| f(v, window, cx))
        })
        .unwrap()
    }

    /// Run `f` with the window (for clicks, key presses and element queries).
    fn window<R>(&self, cx: &mut TestAppContext, f: impl FnOnce(&mut Window, &mut App) -> R) -> R {
        cx.update_window(self.handle, |_, window, cx| {
            window.render_frame(cx);
            f(window, cx)
        })
        .unwrap()
    }

    async fn wait(&self, cx: &mut TestAppContext, what: &str, pred: impl Fn(&MainWindow) -> bool) {
        let view = self.view.clone();
        // Shown (with the captured output) only if the wait times out.
        eprintln!("waiting for: {what}");
        cx.wait_for(self.handle, WAIT, move |_, cx| pred(view.read(cx)))
            .await;
    }

    async fn wait_document(&self, cx: &mut TestAppContext) {
        self.wait(cx, "document", |w| {
            w.doc.is_some() && w.table.table().is_some()
        })
        .await;
        // Two frames: the first records pane sizes, the second draws rows.
        self.window(cx, |window, cx| window.render_frame(cx));
        cx.run_until_parked();
        self.window(cx, |_, _| {});
    }

    fn names(&self, cx: &mut TestAppContext) -> Vec<String> {
        self.update(cx, |w, _, _| w.tree.visible_names())
    }

    fn row_named(&self, cx: &mut TestAppContext, name: &str) -> usize {
        let names = self.names(cx);
        names
            .iter()
            .position(|n| n.trim_start() == name || n.trim_start().starts_with(name))
            .unwrap_or_else(|| panic!("no tree row {name:?} in {names:#?}"))
    }

    /// Expand the tree row called `name` by clicking its arrow.
    async fn expand(&self, cx: &mut TestAppContext, name: &str) {
        let ix = self.row_named(cx, name);
        let before = self.names(cx).len();
        self.window(cx, |window, cx| window.click(("tree-arrow", ix), cx));
        self.wait(cx, "expanded", move |w| w.tree.model.rows().len() > before)
            .await;
        self.window(cx, |_, _| {});
    }

    /// Select a tree row by clicking it and wait for its table.
    async fn click_node(&self, cx: &mut TestAppContext, name: &str) -> ViewNode {
        let ix = self.row_named(cx, name);
        self.window(cx, |window, cx| window.click(("tree-row", ix), cx));
        let node = self.update(cx, |w, _, _| w.tree.model.rows()[ix].node.clone());
        let id = node.id();
        self.wait(cx, "node shown", move |w| w.table.node_id() == Some(id))
            .await;
        self.window(cx, |_, _| {});
        node
    }
}

#[gpui_kit::test]
async fn open_sample_tree_table_and_hex(cx: &mut TestAppContext) {
    let ui = open_window(cx, Some(repo("sample/simple")), None);
    // A loading state is shown while parsing runs in the background.
    assert!(ui.update(cx, |w, _, _| w.opening.is_some() && w.doc.is_none()));
    ui.window(cx, |window, _| {
        assert!(window.try_find("loading").is_some())
    });
    ui.wait_document(cx).await;

    // File -> Mach Header (x86_64) -> Load Commands, expanded to depth 1.
    let names = ui.names(cx);
    assert_eq!(names[0], "File");
    assert_eq!(names[1], "  Mach Header (x86_64)");
    assert_eq!(names[2], "    Load Commands");
    assert!(names.iter().all(|n| !n.starts_with("      ")), "{names:#?}");
    ui.window(cx, |window, _| {
        assert!(window.try_find("loading").is_none());
        assert!(window.find(("tree-row", 0usize)).visible());
        assert!(
            window.find(("tree-row", 2usize)).bounds().top()
                > window.find(("tree-row", 1usize)).bounds().top()
        );
    });
    // The root is selected and shown, as in Qt.
    ui.update(cx, |w, _, _| {
        assert_eq!(w.tree.selected_index(), Some(0));
        assert!(w.table.total_len() >= 1);
        assert!(w.log.text().contains("Parse succeed"));
        assert_eq!(
            w.path.as_deref().map(|p| p.ends_with("sample/simple")),
            Some(true)
        );
    });

    // Lazy expansion by clicking the disclosure arrow.
    ui.expand(cx, "Load Commands").await;
    let names = ui.names(cx);
    let commands: Vec<&String> = names.iter().filter(|n| n.starts_with("      ")).collect();
    assert!(commands.len() >= 5, "{names:#?}");
    assert!(
        commands.iter().any(|n| n.contains("LC_SEGMENT_64")),
        "{names:#?}"
    );

    // Selecting a load command fills the table and the hex range.
    let first_command = commands[0].trim().to_string();
    let node = ui.click_node(cx, &first_command).await;
    let expected_range = node.binary().expect("load command has bytes");
    ui.update(cx, |w, _, _| {
        let table = w.table.table().expect("table");
        assert_eq!(table.headers, node.table().unwrap().headers);
        assert!(table.rows.len() >= 2);
        assert_eq!(w.table.total_len(), table.rows.len());
        assert_eq!(w.table.status_text(), format!("{} rows", table.rows.len()));
        assert_eq!(w.hex.range, Some(expected_range));
        assert_eq!(w.hex.scroll.total_rows, expected_range.size.div_ceil(16));
        // First row is selected automatically and highlighted in hex.
        assert_eq!(w.table.selected, Some(0));
        let row = &table.rows[0];
        assert_eq!(
            w.hex.selection,
            row.offset.and_then(|o| ByteSelection::new(o, row.size))
        );
        assert!(
            w.hex.rendered_rows > 0
                && w.table.rendered_rows == table.rows.len().min(w.table.rendered_rows)
        );
    });

    // Clicking another table row moves the hex selection to its bytes.
    let table = node.table().unwrap();
    let target = (1..table.rows.len())
        .find(|i| table.rows[*i].offset.is_some() && table.rows[*i].size > 0)
        .expect("a row with bytes");
    ui.window(cx, |window, cx| window.click(("table-row", target), cx));
    ui.update(cx, |w, _, _| {
        let row = &w.table.table().unwrap().rows[target];
        assert_eq!(w.table.selected, Some(target));
        assert_eq!(
            w.hex.selection,
            ByteSelection::new(row.offset.unwrap(), row.size)
        );
        let sel = w.hex.selection.unwrap();
        assert!(
            sel.start >= expected_range.offset
                && sel.end <= expected_range.offset + expected_range.size
        );
        assert!(w.info.contains(&row.cells[1]), "{}", w.info);
        assert!(w.info.contains("Length : "));
    });
}

#[gpui_kit::test]
async fn tree_keyboard_navigation(cx: &mut TestAppContext) {
    let ui = open_window(cx, Some(repo("sample/simple")), None);
    ui.wait_document(cx).await;
    ui.window(cx, |window, cx| {
        window.click(("tree-row", 0usize), cx);
        window.press("down", cx);
        window.press("down", cx);
    });
    assert_eq!(ui.update(cx, |w, _, _| w.tree.selected_index()), Some(2));
    // Right expands "Load Commands" (lazily), right again enters it.
    let before = ui.names(cx).len();
    ui.window(cx, |window, cx| window.press("right", cx));
    ui.wait(cx, "expanded", move |w| w.tree.model.rows().len() > before)
        .await;
    ui.window(cx, |window, cx| window.press("right", cx));
    assert_eq!(ui.update(cx, |w, _, _| w.tree.selected_index()), Some(3));
    // Left goes to the parent, left again collapses it.
    ui.window(cx, |window, cx| window.press("left", cx));
    assert_eq!(ui.update(cx, |w, _, _| w.tree.selected_index()), Some(2));
    ui.window(cx, |window, cx| window.press("left", cx));
    assert_eq!(ui.names(cx).len(), before);
    ui.window(cx, |window, cx| {
        window.press("end", cx);
    });
    assert_eq!(
        ui.update(cx, |w, _, _| w.tree.selected_index()),
        Some(before - 1)
    );
    ui.window(cx, |window, cx| window.press("home", cx));
    assert_eq!(ui.update(cx, |w, _, _| w.tree.selected_index()), Some(0));
}

#[gpui_kit::test]
async fn tree_filter_keeps_matches_and_ancestors(cx: &mut TestAppContext) {
    let ui = open_window(cx, Some(repo("sample/simple")), None);
    ui.wait_document(cx).await;
    let unfiltered = ui.names(cx);

    // Type into the real filter box.
    ui.update(cx, |w, window, cx| {
        w.tree.filter_input.update(cx, |s, cx| s.focus(window, cx))
    });
    ui.window(cx, |window, cx| window.input("lc_main", cx));
    // Load commands were never expanded: the filter builds the tree in the
    // background and then shows the match with its ancestors.
    ui.wait(cx, "filtered", |w| {
        w.tree.visible_names().iter().any(|n| n.contains("LC_MAIN"))
    })
    .await;
    let names = ui.names(cx);
    assert_eq!(names[0], "File");
    assert_eq!(names[1], "  Mach Header (x86_64)");
    assert_eq!(names[2], "    Load Commands");
    assert!(names[3].trim().starts_with("LC_MAIN"), "{names:#?}");
    assert_eq!(names.len(), 4, "{names:#?}");
    ui.update(cx, |w, _, _| {
        let matched: Vec<bool> = w.tree.model.rows().iter().map(|r| r.matched).collect();
        assert_eq!(matched, vec![false, false, false, true]);
    });

    // Enter jumps to the next match and shows it.
    ui.window(cx, |window, cx| window.press("enter", cx));
    ui.wait(cx, "match selected", |w| {
        w.tree.selected_index() == Some(3) && w.table.table().is_some()
    })
    .await;

    // No match at all.
    ui.window(cx, |window, cx| {
        window.press("secondary-a", cx);
        window.input("no-such-node-xyz", cx);
    });
    ui.wait(cx, "empty", |w| w.tree.model.rows().is_empty())
        .await;

    // Clearing restores the default expansion (selection stays revealed).
    ui.window(cx, |window, cx| {
        window.press("secondary-a", cx);
        window.press("backspace", cx);
    });
    ui.wait(cx, "restored", |w| {
        !w.tree.model.has_filter() && w.tree.model.rows().len() >= 3
    })
    .await;
    let names = ui.names(cx);
    assert!(names.len() >= unfiltered.len());
    assert_eq!(&names[..3], &unfiltered[..3]);
}

#[gpui_kit::test]
async fn table_filter_and_copy(cx: &mut TestAppContext) {
    let ui = open_window(cx, Some(repo("sample/simple")), None);
    ui.wait_document(cx).await;
    let node = ui.click_node(cx, "Mach Header").await;
    let table = node.table().unwrap().clone();
    assert!(table.rows.len() > 3);

    // Copy row with the keyboard shortcut (tab separated, as in Qt).
    ui.window(cx, |window, cx| {
        window.click(("table-row", 1usize), cx);
        window.press("secondary-c", cx);
    });
    let copied = cx.read_from_clipboard().and_then(|c| c.text()).unwrap();
    assert_eq!(copied, table.rows[1].cells.join("\t"));

    // Copy all visible rows includes the header line.
    ui.update(cx, |w, window, cx| w.copy_table_all(window, cx));
    let copied = cx.read_from_clipboard().and_then(|c| c.text()).unwrap();
    assert_eq!(copied.lines().count(), table.rows.len() + 1);
    assert_eq!(copied.lines().next().unwrap(), table.headers.join("\t"));

    // Filter rows through the filter box (debounced, background scan).
    let needle = table.rows[1].cells[1].to_lowercase();
    let expected: Vec<usize> = (0..table.rows.len())
        .filter(|i| {
            table.rows[*i]
                .cells
                .iter()
                .any(|c| c.to_lowercase().contains(&needle))
        })
        .collect();
    ui.update(cx, |w, window, cx| w.focus_table_filter(window, cx));
    ui.window(cx, |window, cx| window.input(&needle, cx));
    let n = expected.len();
    ui.wait(cx, "filtered", move |w| {
        w.table.filtered.is_some() && w.table.visible_len() == n
    })
    .await;
    ui.update(cx, |w, _, _| {
        assert_eq!(
            w.table.status_text(),
            format!("{}/{} filtered", n, w.table.total_len())
        );
        assert_eq!(w.table.source_index(0), Some(expected[0]));
        // The previously selected row (1) matches, so it stays selected.
        assert_eq!(
            w.table.selected.and_then(|v| w.table.source_index(v)),
            Some(1)
        );
    });

    // Escape in the filter box clears it.
    ui.window(cx, |window, cx| window.press("escape", cx));
    ui.wait(cx, "cleared", |w| w.table.filtered.is_none()).await;
    ui.update(cx, |w, _, cx| {
        assert_eq!(w.table.visible_len(), w.table.total_len());
        assert!(w.table.filter_input.read(cx).value().is_empty());
    });
}

#[gpui_kit::test]
async fn hex_mouse_selection_and_copy(cx: &mut TestAppContext) {
    use moex_app::hex_view::{ASCII_CELL_W, ASCII_X, HEX_CELL_W, HEX_ROW_H, HEX_X};
    let ui = open_window(cx, Some(repo("sample/simple")), None);
    ui.wait_document(cx).await;
    let node = ui.click_node(cx, "Mach Header").await;
    let range = node.binary().unwrap();
    let bytes = std::fs::read(repo("sample/simple")).unwrap();

    // Drag from byte 2 of row 0 to byte 5 of row 1 in the hex column.
    let origin = ui.update(cx, |w, _, _| w.hex.bounds.origin);
    let at = |col: f32, row: f32| {
        origin
            + point(
                px(HEX_X + col * HEX_CELL_W + 4.0),
                px(row * HEX_ROW_H + 4.0),
            )
    };
    ui.window(cx, |window, cx| window.drag(at(2.0, 0.0), at(5.0, 1.0), cx));
    let sel = ui.update(cx, |w, _, _| w.hex.selection).unwrap();
    assert_eq!(
        sel,
        ByteSelection {
            start: range.offset + 2,
            end: range.offset + 16 + 6
        }
    );
    assert!(ui.update(cx, |w, _, _| w.drag.is_none()));

    ui.window(cx, |window, cx| window.press("secondary-c", cx));
    let copied = cx.read_from_clipboard().and_then(|c| c.text()).unwrap();
    let expected: Vec<String> = bytes[sel.start as usize..sel.end as usize]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(copied, expected.join(" "));

    // A click in the ASCII column makes the shortcut copy ASCII.
    let ascii_at = origin + point(px(ASCII_X + 1.0 * ASCII_CELL_W + 2.0), px(4.0));
    ui.window(cx, |window, cx| {
        window.drag(
            ascii_at,
            ascii_at + point(px(3.0 * ASCII_CELL_W), px(0.)),
            cx,
        );
        window.press("secondary-c", cx);
    });
    let copied = cx.read_from_clipboard().and_then(|c| c.text()).unwrap();
    assert_eq!(copied.len(), 4);
    let sel = ui.update(cx, |w, _, _| w.hex.selection).unwrap();
    assert_eq!(
        sel,
        ByteSelection {
            start: range.offset + 1,
            end: range.offset + 5
        }
    );
}

#[gpui_kit::test]
async fn non_macho_file_shows_error_dialog(cx: &mut TestAppContext) {
    let not_macho = repo("crates/moex-app/Cargo.toml");
    let expected = Document::open(&not_macho)
        .err()
        .expect("not a Mach-O")
        .to_string();
    let ui = open_window(cx, Some(not_macho), None);
    ui.wait(cx, "error", |w| w.modal.is_some()).await;
    ui.update(cx, |w, _, _| {
        let modal = w.modal.as_ref().unwrap();
        assert_eq!(modal.kind(), "error");
        assert_eq!(modal.message(), Some(expected.as_str()));
        assert!(w.doc.is_none() && w.opening.is_none());
        assert!(w.log.text().contains(&expected));
    });
    ui.window(cx, |window, cx| {
        assert!(window.find("modal").visible());
        assert!(window.try_find("start-screen").is_some());
        // Enter dismisses the dialog.
        window.press("enter", cx);
    });
    assert!(ui.update(cx, |w, _, _| w.modal.is_none()));

    // A missing file reports the core's message too.
    ui.update(cx, |w, window, cx| {
        w.open_path("/nonexistent/moex-test-file".into(), window, cx)
    });
    ui.wait(cx, "error", |w| w.modal.is_some()).await;
    assert_eq!(
        ui.update(cx, |w, _, _| w.modal.as_ref().unwrap().kind()),
        "error"
    );
}

/// A synthetic document: 500k table rows over a sparse 1 GiB file.
fn huge_document(dir: &Path) -> (Document, PathBuf) {
    const GIB: u64 = 1 << 30;
    let path = dir.join("huge.bin");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(GIB).unwrap();
    drop(file);
    let image = Arc::new(Image::open(&path).unwrap());
    let root = ViewNode::new(FnNode {
        name: "Huge".to_string(),
        content: || {
            let mut t = Table::new();
            t.set_headers(&["Offset", "Index", "Value"]);
            t.set_widths(&[100, 120, 300]);
            for i in 0..500_000u64 {
                t.add_data(
                    i * 2048,
                    2048,
                    [
                        format!("{:08X}", i * 2048),
                        i.to_string(),
                        format!("row {i}"),
                    ],
                );
            }
            Content::table(t).with_binary_at(0, GIB, 0x1_0000_0000)
        },
        children: Vec::new,
    });
    (Document { image, root }, path)
}

#[gpui_kit::test]
async fn huge_table_and_range_render_only_visible_rows(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (doc, path) = huge_document(dir.path());
    let ui = open_window(cx, None, None);
    let loaded = vec![moex_app::tree_model::load_node(&doc.root)];
    ui.update(cx, |w, window, cx| {
        w.show_document(
            doc,
            path.to_string_lossy().into_owned(),
            loaded,
            1,
            window,
            cx,
        )
    });
    ui.wait_document(cx).await;

    let check = |ui: &Ui, cx: &mut TestAppContext, first_row: usize| {
        ui.window(cx, |_, _| {});
        ui.update(cx, |w, _, _| {
            assert_eq!(w.table.total_len(), 500_000);
            assert_eq!(w.hex.scroll.total_rows, (1u64 << 30) / 16);
            let table_max = (w.table.scroll.viewport / 24.0).ceil() as usize + 1;
            let hex_max = (w.hex.scroll.viewport / 18.0).ceil() as usize + 1;
            assert!(
                w.table.rendered_rows > 5 && w.table.rendered_rows <= table_max,
                "{} table rows drawn",
                w.table.rendered_rows
            );
            assert!(
                w.hex.rendered_rows > 5 && w.hex.rendered_rows <= hex_max,
                "{} hex rows drawn",
                w.hex.rendered_rows
            );
            assert!(w.table.rendered_rows < 60 && w.hex.rendered_rows < 80);
            assert_eq!(w.table.scroll.visible().first as usize, first_row);
        });
    };
    check(&ui, cx, 0);
    // Only on-screen rows exist as elements.
    ui.window(cx, |window, _| {
        assert!(window.try_find(("table-row", 0usize)).is_some());
        assert!(window.try_find(("table-row", 200usize)).is_none());
    });

    // Jump to the last row: still a screenful of elements, and the hex view
    // follows to the end of the 1 GiB range.
    ui.window(cx, |window, cx| {
        window.click(("table-row", 3usize), cx);
        window.press("end", cx);
    });
    ui.window(cx, |window, _| {
        assert!(window.try_find(("table-row", 499_999usize)).is_some());
        assert!(window.try_find(("table-row", 0usize)).is_none());
    });
    ui.update(cx, |w, _, _| {
        assert_eq!(w.table.selected, Some(499_999));
        let sel = w.hex.selection.unwrap();
        assert_eq!(
            sel,
            ByteSelection {
                start: 499_999 * 2048,
                end: 500_000 * 2048
            }
        );
        let v = w.hex.scroll.visible();
        let first_sel_row = sel.start / 16;
        assert!(
            v.first <= first_sel_row && first_sel_row < v.first + v.count as u64,
            "selection row {first_sel_row} not in {v:?}"
        );
        assert_eq!(
            w.hex.range,
            Some(BinaryRange {
                offset: 0,
                size: 1 << 30,
                start_value: 0x1_0000_0000
            })
        );
    });
    let first = ui.update(cx, |w, _, _| w.table.scroll.visible().first as usize);
    assert!(first > 499_900);
    check(&ui, cx, first);

    // Wheel scrolling moves by pixels and keeps the row count bounded.
    ui.window(cx, |window, cx| {
        window.scroll(
            "hex-body",
            gpui_kit::ScrollDelta::Pixels(point(px(0.), px(-18.0 * 1000.0))),
            cx,
        );
        window.scroll(
            "table-body",
            gpui_kit::ScrollDelta::Pixels(point(px(0.), px(24.0 * 100_000.0))),
            cx,
        );
    });
    let first = ui.update(cx, |w, _, _| w.table.scroll.visible().first as usize);
    assert!(first < 400_000 && first > 399_000, "{first}");
    check(&ui, cx, first);

    // Filtering 500k rows runs in the background and stays virtualized.
    ui.update(cx, |w, window, cx| {
        w.set_table_filter("row 4999".into(), false, window, cx)
    });
    ui.wait(cx, "filtered", |w| w.table.filtered.is_some())
        .await;
    ui.update(cx, |w, _, _| {
        // "row 4999", "row 49990".."row 49999", "row 499900".."row 499999"
        assert_eq!(w.table.visible_len(), 1 + 10 + 100);
        assert_eq!(w.table.status_text(), "111/500000 filtered");
    });
}

#[gpui_kit::test]
async fn pane_toggles_and_theme_from_menu_actions(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let ui = open_window(cx, Some(repo("sample/simple")), Some(settings.clone()));
    ui.wait_document(cx).await;
    ui.window(cx, |window, _| {
        assert!(window.try_find("hex-body").is_some());
        assert!(window.try_find("log").is_some());
        assert!(window.try_find("information").is_some());
        assert!(window.try_find("tree").is_some());
    });

    cx.update(|cx| {
        cx.dispatch_action(&moex_app::menus::ToggleHex);
        cx.dispatch_action(&moex_app::menus::ToggleLog);
        cx.dispatch_action(&moex_app::menus::ThemeDark);
    });
    ui.window(cx, |window, cx| {
        assert!(window.try_find("hex-body").is_none());
        assert!(window.try_find("log").is_none());
        assert!(window.try_find("information").is_some());
        assert!(moex_app::theme::is_dark(cx));
    });
    cx.update(|cx| {
        let s = &AppState::get(cx).settings;
        assert!(!s.panes.show_hex && !s.panes.show_log && s.panes.show_layout);
        assert_eq!(s.theme_mode, ThemeMode::Dark);
    });
    // Persisted, including the recent file.
    let saved = moex_app::settings::Settings::load(&settings);
    assert!(!saved.panes.show_hex);
    assert_eq!(saved.theme_mode, ThemeMode::Dark);
    assert_eq!(saved.recent_files.len(), 1);
    assert!(saved.recent_files[0].ends_with("sample/simple"));

    cx.update(|cx| {
        cx.dispatch_action(&moex_app::menus::ToggleHex);
        cx.dispatch_action(&moex_app::menus::ToggleInformation);
        cx.dispatch_action(&moex_app::menus::ToggleLayout);
        cx.dispatch_action(&moex_app::menus::ThemeLight);
    });
    ui.window(cx, |window, cx| {
        assert!(window.try_find("hex-body").is_some());
        assert!(window.try_find("information").is_none());
        assert!(window.try_find("tree").is_none());
        assert!(!moex_app::theme::is_dark(cx));
    });

    // About dialog from the menu action; Escape closes it.
    cx.update(|cx| cx.dispatch_action(&moex_app::menus::About));
    assert_eq!(
        ui.update(cx, |w, _, _| w.modal.as_ref().map(|m| m.kind())),
        Some("about")
    );
    assert!(moex_app::modal::about_text().contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
    ui.window(cx, |window, cx| window.press("escape", cx));
    assert!(ui.update(cx, |w, _, _| w.modal.is_none()));
}

#[gpui_kit::test]
async fn start_screen_recent_files_and_second_window(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let mut seed = moex_app::settings::Settings::default();
    let sample = repo("sample/simple").to_string_lossy().into_owned();
    seed.push_recent("/nonexistent/gone-file");
    seed.push_recent(&sample);
    seed.save(&settings).unwrap();

    let ui = open_window(cx, None, Some(settings.clone()));
    // Missing files are pruned from the list; existing ones are shown.
    ui.wait(cx, "recents", |w| w.start.recent.len() == 1).await;
    ui.window(cx, |window, _| {
        assert!(window.find("start-screen").visible());
        assert!(window.find(("recent", 0usize)).visible());
    });
    assert_eq!(
        moex_app::settings::Settings::load(&settings).recent_files,
        vec![sample.clone()]
    );
    assert_eq!(ui.update(cx, |w, _, _| w.status.to_string()), "Welcome");

    // Double-clicking a recent entry opens it in this window.
    ui.window(cx, |window, cx| window.double_click(("recent", 0usize), cx));
    ui.wait_document(cx).await;
    assert_eq!(ui.update(cx, |w, _, _| w.path.clone()), Some(sample));

    // New Window: an independent window with its own (empty) document.
    cx.update(|cx| cx.dispatch_action(&moex_app::menus::NewWindow));
    cx.run_until_parked();
    let windows = cx.update(|cx| AppState::get(cx).windows.len());
    assert_eq!(windows, 2);
    let second = cx.update(|cx| AppState::get(cx).windows[1].1.upgrade().unwrap());
    assert!(cx.update(|cx| second.read(cx).doc.is_none()));
    assert!(ui.update(cx, |w, _, _| w.doc.is_some()));
}

#[gpui_kit::test]
async fn update_check_flow(cx: &mut TestAppContext) {
    let ui = open_window(cx, None, None);
    let body = |tag: &str| {
        format!(
            r#"{{"tag_name":"{tag}","html_url":"https://github.com/everettjf/MachOExplorer/releases/tag/{tag}","draft":false,"prerelease":false}}"#
        )
        .into_bytes()
    };

    // The workspace version is a -dev build: cannot be compared.
    let b = body("v2.0.16");
    cx.update(|cx| {
        AppState::update(cx, |s| s.release_fetcher = Arc::new(move || Ok(b.clone())));
        app::check_for_updates(true, cx);
    });
    ui.wait(cx, "outcome", |w| w.modal.is_some()).await;
    ui.update(cx, |w, window, cx| {
        let expected_dev = moex_app::update::parse_version(app::APP_VERSION).is_none();
        if expected_dev {
            assert_eq!(w.modal.as_ref().unwrap().kind(), "info");
            assert!(w
                .modal
                .as_ref()
                .unwrap()
                .message()
                .unwrap()
                .starts_with("This development version cannot be compared."));
        }
        assert!(w.log.text().contains("[update]"));
        w.dismiss_modal(window, cx);
    });
    cx.update(|cx| assert!(!AppState::get(cx).update_in_progress));

    // A failing fetch reports the error (cache is bypassed by clearing it).
    cx.update(|cx| {
        AppState::update(cx, |s| {
            s.settings.update.checked_at_utc = 0;
            s.release_fetcher = Arc::new(|| Err("network unreachable".into()));
        });
        app::check_for_updates(true, cx);
    });
    ui.wait(cx, "error", |w| w.modal.is_some()).await;
    ui.update(cx, |w, window, cx| {
        assert_eq!(
            w.modal.as_ref().unwrap().message(),
            Some("Failed to check updates:\nnetwork unreachable")
        );
        w.dismiss_modal(window, cx);
    });

    // Update prompt and "Remind in 7 days".
    ui.update(cx, |w, window, cx| {
        let outcome = moex_app::update::evaluate("2.0.15", &body("v2.0.16"));
        w.show_update_outcome(outcome, false, window, cx);
        assert_eq!(w.modal.as_ref().unwrap().kind(), "update");
    });
    ui.window(cx, |window, cx| window.click("update-7", cx));
    assert!(ui.update(cx, |w, _, _| w.modal.is_none()));
    cx.update(|cx| {
        let until = AppState::get(cx).settings.update.remind_until_utc;
        let now = moex_app::update::now_utc();
        assert!((until - now - 7 * 86400).abs() < 60);
        assert!(!moex_app::update::should_check_on_startup(until, now));
    });

    // "Download" opens the release page and clears the snooze.
    ui.update(cx, |w, window, cx| {
        let outcome = moex_app::update::evaluate("2.0.15", &body("v2.0.16"));
        w.show_update_outcome(outcome, false, window, cx);
    });
    ui.window(cx, |window, cx| window.click("update-download", cx));
    assert_eq!(
        cx.opened_url().as_deref(),
        Some("https://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16")
    );
    cx.update(|cx| assert_eq!(AppState::get(cx).settings.update.remind_until_utc, 0));
}

struct FakeCache {
    source: PathBuf,
}

impl CacheTools for FakeCache {
    fn list(&self, _cache: &Path, _limit: usize) -> Result<Vec<String>, String> {
        Ok(vec![
            "/usr/lib/libz.dylib".into(),
            "/usr/lib/libobjc.A.dylib".into(),
            "/usr/lib/libSystem.B.dylib".into(),
        ])
    }

    fn extract(
        &self,
        _cache: &Path,
        selector: &str,
        output: &Path,
        _cancel: &AtomicBool,
        log: LogSink,
    ) -> Result<(), String> {
        log(format!("fake extracting {selector}"));
        std::fs::copy(&self.source, output)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[gpui_kit::test]
async fn dyld_cache_extract_flow(cx: &mut TestAppContext) {
    let ui = open_window(cx, None, None);

    // Listing unavailable -> free-text selector -> error.
    cx.update(|cx| {
        AppState::update(cx, |s| {
            s.cache_tools = Arc::new(moex_app::cache_extract::UnavailableCacheTools)
        })
    });
    ui.update(cx, |w, window, cx| {
        w.choose_cache_image("/tmp/dyld_shared_cache_arm64e".into(), window, cx)
    });
    ui.wait(cx, "selector", |w| w.modal.is_some()).await;
    ui.update(cx, |w, window, cx| {
        let Some(Modal::ImageSelector { images, input, .. }) = &w.modal else {
            panic!("expected selector")
        };
        assert!(images.is_empty());
        assert_eq!(input.read(cx).value().as_ref(), "libswiftCore.dylib");
        assert!(w
            .log
            .text()
            .contains(&format!("[cache-list] failed err={MSG_NOT_AVAILABLE}")));
        w.confirm_modal(window, cx);
    });
    ui.wait(
        cx,
        "failure",
        |w| matches!(&w.modal, Some(m) if m.kind() == "error"),
    )
    .await;
    ui.update(cx, |w, window, cx| {
        assert_eq!(
            w.modal.as_ref().unwrap().message(),
            Some(format!("Extraction failed:\n{MSG_NOT_AVAILABLE}").as_str())
        );
        assert!(w.log.text().contains(
            "[extract] start cache=/tmp/dyld_shared_cache_arm64e selector=libswiftCore.dylib"
        ));
        w.dismiss_modal(window, cx);
    });
    cx.update(|cx| assert!(!AppState::get(cx).extracting));

    // With a working implementation: searchable list -> extract -> open.
    cx.update(|cx| {
        AppState::update(cx, |s| {
            s.cache_tools = Arc::new(FakeCache {
                source: repo("sample/simple"),
            })
        })
    });
    ui.update(cx, |w, window, cx| {
        w.choose_cache_image("/tmp/dyld_shared_cache_arm64e".into(), window, cx)
    });
    ui.wait(
        cx,
        "list",
        |w| matches!(&w.modal, Some(Modal::ImageSelector { images, .. }) if images.len() == 3),
    )
    .await;
    ui.update(cx, |w, _, _| {
        let Some(Modal::ImageSelector { images, .. }) = &w.modal else {
            panic!()
        };
        // Sorted case-insensitively.
        assert_eq!(
            **images,
            vec![
                "/usr/lib/libobjc.A.dylib",
                "/usr/lib/libSystem.B.dylib",
                "/usr/lib/libz.dylib"
            ]
        );
    });
    ui.window(cx, |window, cx| window.input("OBJC", cx));
    ui.update(cx, |w, _, _| {
        let Some(Modal::ImageSelector { filtered, .. }) = &w.modal else {
            panic!()
        };
        assert_eq!(filtered, &vec![0]);
    });
    ui.window(cx, |window, cx| {
        assert!(window.find(("image-row", 0usize)).visible());
        window.double_click(("image-row", 0usize), cx);
    });
    ui.wait_document(cx).await;
    ui.update(cx, |w, _, _| {
        let path = w.path.clone().unwrap();
        assert!(
            crate::util_name(&path)
                .starts_with("MachOExplorer-cache-extract-dyld_shared_cache_arm64e-"),
            "{path}"
        );
        let log = w.log.text();
        assert!(
            log.contains("[extract] fake extracting /usr/lib/libobjc.A.dylib"),
            "{log}"
        );
        assert!(log.contains("[extract] success out="), "{log}");
        assert!(
            w.status.starts_with("Extracted and opened: "),
            "{}",
            w.status
        );
        assert_eq!(w.tree.visible_names()[1], "  Mach Header (x86_64)");
        let _ = std::fs::remove_file(path);
    });
    cx.update(|cx| assert!(!AppState::get(cx).extracting));
}

fn util_name(path: &str) -> &str {
    moex_app::util::file_name(path)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[gpui_kit::test]
async fn attach_by_pid_executable_path(cx: &mut TestAppContext) {
    let ui = open_window(cx, None, None);
    // Invalid input keeps the prompt open with an error.
    ui.update(cx, |w, window, cx| w.prompt_attach(false, window, cx));
    ui.window(cx, |window, cx| {
        window.input("abc", cx);
        window.press("enter", cx);
    });
    ui.update(cx, |w, _, _| {
        let Some(Modal::Pid { error, .. }) = &w.modal else {
            panic!("prompt should stay open")
        };
        assert!(error.is_some());
    });
    ui.window(cx, |window, cx| window.press("escape", cx));
    assert!(ui.update(cx, |w, _, _| w.modal.is_none()));

    // A PID that does not exist reports the Qt error text.
    ui.update(cx, |w, window, cx| {
        w.attach_pid(i32::MAX - 7, false, window, cx)
    });
    ui.wait(cx, "error", |w| w.modal.is_some()).await;
    ui.update(cx, |w, window, cx| {
        assert_eq!(
            w.modal.as_ref().unwrap().message(),
            Some(moex_app::attach::MSG_PATH_UNRESOLVED)
        );
        w.dismiss_modal(window, cx);
    });

    // Our own PID resolves to this test binary, which is then opened
    // (a Mach-O on macOS; elsewhere the core reports its parse error).
    let pid = std::process::id() as i32;
    ui.update(cx, |w, window, cx| w.prompt_attach(false, window, cx));
    ui.window(cx, |window, cx| {
        window.input(&pid.to_string(), cx);
        window.press("enter", cx);
    });
    ui.wait(cx, "attached", |w| {
        w.doc.is_some() || matches!(&w.modal, Some(m) if m.kind() == "error")
    })
    .await;
    ui.update(cx, |w, _, _| {
        assert!(
            w.status
                .starts_with(&format!("Attached by path to PID {pid}: ")),
            "{}",
            w.status
        );
        if cfg!(target_os = "macos") {
            assert!(w.doc.is_some());
        }
    });
}

#[gpui_kit::test]
async fn table_context_menu_copies_cell(cx: &mut TestAppContext) {
    use gpui_kit::test::{TestEventExt, TestQueryExt};
    use gpui_kit::MouseButton;
    let ui = open_window(cx, Some(repo("sample/simple")), None);
    ui.wait_document(cx).await;
    let node = ui.click_node(cx, "Mach Header").await;
    let table = node.table().unwrap().clone();

    // Right-click the second column of row 2, then pick "Copy Cell".
    let (origin, widths) = ui.update(cx, |w, _, _| {
        (w.table.bounds.origin, w.table.drawn_widths())
    });
    let pos = origin + point(px(widths[0] + 10.0), px(2.0 * 24.0 + 12.0));
    ui.window(cx, |window, cx| {
        window.pointer_down(pos, MouseButton::Right, cx);
        window.pointer_up(pos, MouseButton::Right, cx);
    });
    cx.run_until_parked();
    assert_eq!(
        ui.update(cx, |w, _, _| (w.table.selected, w.table.context_cell)),
        (Some(2), Some((2, 1)))
    );
    ui.window(cx, |window, cx| {
        let labels: Vec<String> = window
            .elements()
            .iter()
            .filter_map(|e| e.label().map(str::to_string))
            .collect();
        let item = window.find_all_by_label("Copy Cell");
        assert_eq!(item.len(), 1, "menu items: {labels:?}");
        let at = item[0].bounds().center();
        window.pointer_down(at, MouseButton::Left, cx);
        window.pointer_up(at, MouseButton::Left, cx);
    });
    cx.run_until_parked();
    let copied = cx.read_from_clipboard().and_then(|c| c.text()).unwrap();
    assert_eq!(copied, table.rows[2].cells[1]);
}
