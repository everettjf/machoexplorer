//! Golden comparison against the C++ implementation.
//!
//! `tests/golden/baseline/*.json.gz` holds the JSON dump produced by the
//! original C++ `moex-dump` for every corpus file. The Rust dump must match
//! node by node: same names, order, tables (every cell) and byte ranges.
//!
//! While the port is in progress, subtrees listed in `PENDING` are skipped.
//! When `PENDING` is empty the comparison is exact, including summary counts.

use moex_core::dump::{dump_tree, DumpOptions};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};

/// View nodes (by display name) not ported yet. Remove entries as they land.
const PENDING: &[&str] = &[];

/// (corpus file relative to the repo root, baseline name)
const CASES: &[(&str, &str)] = &[
    ("sample/simple", "simple"),
    ("sample/complex", "complex"),
    ("tests/corpus/bin/cat_arm64", "cat_arm64"),
    ("tests/corpus/bin/cat_arm64_32.o", "cat_arm64_32.o"),
    ("tests/corpus/bin/cat_armv7.o", "cat_armv7.o"),
    ("tests/corpus/bin/cxx_arm64", "cxx_arm64"),
    (
        "tests/corpus/bin/dyld_chained_x86_64.dylib",
        "dyld_chained_x86_64.dylib",
    ),
    (
        "tests/corpus/bin/dyld_classic_x86_64.dylib",
        "dyld_classic_x86_64.dylib",
    ),
    ("tests/corpus/bin/dyld_synth_b", "dyld_synth_b"),
    ("tests/corpus/bin/dyld_synth_c", "dyld_synth_c"),
    ("tests/corpus/bin/hello_arm64", "hello_arm64"),
    ("tests/corpus/bin/hello_arm64e", "hello_arm64e"),
    ("tests/corpus/bin/hello_fat", "hello_fat"),
    ("tests/corpus/bin/hello_signed_arm64", "hello_signed_arm64"),
    ("tests/corpus/bin/hello_x86_64", "hello_x86_64"),
    ("tests/corpus/bin/lib_arm64.o", "lib_arm64.o"),
    ("tests/corpus/bin/lib_x86_64.o", "lib_x86_64.o"),
    ("tests/corpus/bin/libmoex_arm64.a", "libmoex_arm64.a"),
    ("tests/corpus/bin/libmulti.a", "libmulti.a"),
    (
        "tests/corpus/bin/libmoex_arm64.dylib",
        "libmoex_arm64.dylib",
    ),
    (
        "tests/corpus/bin/libmoex_x86_64.dylib",
        "libmoex_x86_64.dylib",
    ),
    ("tests/corpus/bin/objc_arm64", "objc_arm64"),
    ("tests/corpus/bin/objc_x86_64", "objc_x86_64"),
    ("tests/corpus/bin/sw_arm64", "sw_arm64"),
    ("tests/corpus/bin/sw_x86_64", "sw_x86_64"),
    ("tests/corpus/bin/swift_arm64", "swift_arm64"),
];

/// `MOEX_GOLDEN_PORTED="Name A,Name B"` treats those nodes as ported, so a
/// module can be checked before its entry is removed from `PENDING`.
fn is_pending(name: &str) -> bool {
    if !PENDING.contains(&name) {
        return false;
    }
    match std::env::var("MOEX_GOLDEN_PORTED") {
        Ok(v) => !v.split(',').any(|n| n.trim() == name),
        Err(_) => true,
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn load_baseline(name: &str) -> Value {
    let path = repo_root()
        .join("tests/golden/baseline")
        .join(format!("{name}.json.gz"));
    let file =
        std::fs::File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn rust_dump(rel: &str) -> Value {
    // Baselines are generated with TZ=UTC.
    std::env::set_var("MOEX_TZ", "UTC");
    let root =
        moex_core::open(repo_root().join(rel)).unwrap_or_else(|e| panic!("parse {rel}: {e}"));
    let options = DumpOptions {
        json_output: true,
        include_empty_nodes: true,
        ..Default::default()
    };
    let mut out = Vec::new();
    dump_tree(&root, rel, &options, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

#[derive(Default)]
struct Report {
    compared: usize,
    skipped: usize,
    diffs: Vec<String>,
}

impl Report {
    fn diff(&mut self, msg: String) {
        if self.diffs.len() < 20 {
            self.diffs.push(msg);
        }
    }
}

fn count_nodes(node: &Value) -> usize {
    1 + node["children"]
        .as_array()
        .map(|c| c.iter().map(count_nodes).sum())
        .unwrap_or(0)
}

fn first_table_diff(want: &Value, got: &Value) -> String {
    for key in [
        "headers",
        "totalRows",
        "shownRows",
        "tableMode",
        "truncated",
    ] {
        if want.get(key) != got.get(key) {
            return format!(
                "table.{key}: want {:?}, got {:?}",
                want.get(key),
                got.get(key)
            );
        }
    }
    let empty = Vec::new();
    let (w, g) = (
        want["rows"].as_array().unwrap_or(&empty),
        got["rows"].as_array().unwrap_or(&empty),
    );
    for (i, (wr, gr)) in w.iter().zip(g).enumerate() {
        if wr != gr {
            return format!("row {i}:\n      want {wr}\n      got  {gr}");
        }
    }
    format!("row count: want {}, got {}", w.len(), g.len())
}

/// The C++ tool printed pointer-table values as `<process address of the
/// entry>-><value>`, which changes on every run. The port prints the entry's
/// file offset instead, so only the part after `->` is comparable.
const POINTER_TABLE_NODES: &[&str] = &[
    "Literal Pointers",
    "Module Init Func Pointers",
    "Module Term Func Pointers",
];

fn strip_pointer_prefix(table: &mut Value) {
    fn strip(v: &mut Value) {
        if let Some(text) = v.as_str() {
            if let Some((_, tail)) = text.split_once("->") {
                *v = Value::String(tail.to_string());
            }
        }
    }
    let Some(rows) = table.get_mut("rows").and_then(Value::as_array_mut) else {
        return;
    };
    for row in rows {
        if let Some(cell) = row.pointer_mut("/cells/Value") {
            strip(cell);
        }
        if let Some(cell) = row.pointer_mut("/values/2") {
            strip(cell);
        }
    }
}

fn compare_node(want: &Value, got: &Value, strict: bool, r: &mut Report) {
    let name = want["name"].as_str().unwrap_or("");
    if POINTER_TABLE_NODES.contains(&name)
        && want.get("table").is_some()
        && got.get("table").is_some()
    {
        let (mut want, mut got) = (want.clone(), got.clone());
        strip_pointer_prefix(&mut want["table"]);
        strip_pointer_prefix(&mut got["table"]);
        return compare_node_inner(&want, &got, strict, r);
    }
    compare_node_inner(want, got, strict, r)
}

fn compare_node_inner(want: &Value, got: &Value, strict: bool, r: &mut Report) {
    let path = want["path"].as_str().unwrap_or("?");
    r.compared += 1;
    let mut keys = vec!["name", "path", "depth", "kind", "binary"];
    if strict {
        keys.push("childIndex");
    }
    for key in keys {
        if want.get(key) != got.get(key) {
            r.diff(format!(
                "{path}: {key}: want {:?}, got {:?}",
                want.get(key),
                got.get(key)
            ));
        }
    }
    match (want.get("table"), got.get("table")) {
        (Some(w), Some(g)) if w != g => r.diff(format!("{path}: {}", first_table_diff(w, g))),
        (Some(_), None) => r.diff(format!("{path}: table missing")),
        (None, Some(_)) => r.diff(format!("{path}: unexpected table")),
        _ => {}
    }

    let empty = Vec::new();
    let pending = |n: &&Value| is_pending(n["name"].as_str().unwrap_or(""));
    let want_children = want["children"].as_array().unwrap_or(&empty);
    let got_children = got["children"].as_array().unwrap_or(&empty);
    r.skipped += want_children
        .iter()
        .filter(pending)
        .map(count_nodes)
        .sum::<usize>();
    let w: Vec<&Value> = want_children.iter().filter(|n| !pending(n)).collect();
    let g: Vec<&Value> = got_children.iter().filter(|n| !pending(n)).collect();
    if w.len() != g.len() {
        let names = |v: &[&Value]| {
            v.iter()
                .map(|n| n["name"].as_str().unwrap_or("?").to_string())
                .collect::<Vec<_>>()
        };
        r.diff(format!(
            "{path}: children: want {:?}, got {:?}",
            names(&w),
            names(&g)
        ));
    }
    for (wc, gc) in w.iter().zip(&g) {
        compare_node(wc, gc, strict, r);
    }
}

#[test]
fn matches_cpp_baseline() {
    let strict = PENDING.is_empty();
    let mut failures = Vec::new();
    let (mut compared, mut skipped) = (0, 0);
    for (rel, name) in CASES {
        // Demangled C++ names come from the system runtime on macOS and from
        // a pure-Rust demangler elsewhere; only the former matches the
        // baseline text exactly.
        // Swift names are demangled by `xcrun swift-demangle`, macOS only.
        let needs_macos = matches!(
            *name,
            "cxx_arm64" | "swift_arm64" | "sw_arm64" | "sw_x86_64"
        );
        if needs_macos && !cfg!(target_os = "macos") {
            continue;
        }
        let want = load_baseline(name);
        let got = rust_dump(rel);
        let mut r = Report::default();
        compare_node(&want["analysis"], &got["analysis"], strict, &mut r);
        if strict {
            for key in [
                "summary",
                "options",
                "schemaVersion",
                "generator",
                "format",
                "file",
            ] {
                if want[key] != got[key] {
                    r.diff(format!("{key}: want {}, got {}", want[key], got[key]));
                }
            }
        }
        compared += r.compared;
        skipped += r.skipped;
        if !r.diffs.is_empty() {
            failures.push(format!("{rel}:\n    {}", r.diffs.join("\n    ")));
        }
    }
    println!(
        "golden: {} files, {compared} nodes compared, {skipped} pending ({:.1}% ported)",
        CASES.len(),
        100.0 * compared as f64 / (compared + skipped).max(1) as f64
    );
    assert!(
        failures.is_empty(),
        "mismatch against C++ baseline:\n{}",
        failures.join("\n")
    );
}
