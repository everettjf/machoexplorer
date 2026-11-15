//! Snapshot test of the analysis output.
//!
//! `tests/golden/baseline/*.json.gz` holds the JSON dump of every corpus
//! file as this implementation produced it when the baseline was last
//! accepted. The dump must match exactly: same nodes, order, tables (every
//! cell) and byte ranges. A change that alters the output on purpose
//! regenerates the baselines:
//!
//! ```text
//! MOEX_UPDATE_BASELINES=1 cargo test -p moex-core --test golden
//! ```
//!
//! and the resulting diff is reviewed like any other change (see
//! `tests/golden/README.md`).

use moex_core::dump::{dump_tree, DumpOptions};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn baseline_path(name: &str) -> PathBuf {
    repo_root()
        .join("tests/golden/baseline")
        .join(format!("{name}.json.gz"))
}

fn load_baseline(name: &str) -> Value {
    let path = baseline_path(name);
    let file =
        std::fs::File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn rust_dump(rel: &str) -> Vec<u8> {
    // Timestamps are rendered in local time; pin the zone.
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
    out
}

fn write_baseline(name: &str, json: &[u8]) {
    let file = std::fs::File::create(baseline_path(name)).unwrap();
    // No timestamp in the gzip header, so equal dumps give equal files.
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    gz.write_all(json).unwrap();
    gz.finish().unwrap();
}

fn count_nodes(node: &Value) -> usize {
    1 + node["children"]
        .as_array()
        .map(|c| c.iter().map(count_nodes).sum())
        .unwrap_or(0)
}

/// Where two tables first differ.
fn first_table_diff(want: &Value, got: &Value) -> String {
    for key in ["headers", "totalRows", "shownRows", "tableMode", "truncated"] {
        if want[key] != got[key] {
            return format!("{key}: want {}, got {}", want[key], got[key]);
        }
    }
    let empty = Vec::new();
    let w = want["rows"].as_array().unwrap_or(&empty);
    let g = got["rows"].as_array().unwrap_or(&empty);
    for (i, (a, b)) in w.iter().zip(g).enumerate() {
        if a != b {
            return format!("row {i}:\n      want {a}\n      got  {b}");
        }
    }
    format!("row count: want {}, got {}", w.len(), g.len())
}

/// Differences between two nodes and their subtrees, at most `limit`.
fn compare_node(want: &Value, got: &Value, diffs: &mut Vec<String>, limit: usize) {
    if diffs.len() >= limit {
        return;
    }
    let path = want["path"].as_str().unwrap_or("?").to_string();
    for key in ["name", "path", "depth", "kind", "childIndex", "binary"] {
        if want[key] != got[key] {
            diffs.push(format!("{path}: {key}: want {}, got {}", want[key], got[key]));
        }
    }
    if want["table"] != got["table"] {
        diffs.push(format!(
            "{path}: {}",
            first_table_diff(&want["table"], &got["table"])
        ));
    }
    let empty = Vec::new();
    let w = want["children"].as_array().unwrap_or(&empty);
    let g = got["children"].as_array().unwrap_or(&empty);
    if w.len() != g.len() {
        let names = |v: &[Value]| {
            v.iter()
                .map(|c| c["name"].as_str().unwrap_or("?").to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        diffs.push(format!(
            "{path}: children: want [{}], got [{}]",
            names(w),
            names(g)
        ));
        return;
    }
    for (a, b) in w.iter().zip(g) {
        compare_node(a, b, diffs, limit);
    }
}

/// Whether the baseline of `name` can be reproduced on this platform.
fn reproducible_here(name: &str) -> bool {
    // C++ names are demangled by the platform's C++ runtime on macOS
    // (libc++abi, which wrote the baselines) and Linux (libstdc++), and by
    // the `cpp_demangle` crate on Windows; their text can differ.
    match name {
        "cxx_arm64" => cfg!(target_os = "macos"),
        "dyld_chained_x86_64.dylib" | "dyld_classic_x86_64.dylib" => !cfg!(windows),
        _ => true,
    }
}

#[test]
fn matches_baseline() {
    let update = std::env::var_os("MOEX_UPDATE_BASELINES").is_some();
    let mut failures = Vec::new();
    let (mut files, mut nodes) = (0, 0);
    for (rel, name) in CASES {
        if !reproducible_here(name) {
            continue;
        }
        let json = rust_dump(rel);
        if update {
            write_baseline(name, &json);
        }
        let got: Value = serde_json::from_slice(&json).unwrap();
        let want = load_baseline(name);
        files += 1;
        nodes += count_nodes(&got["analysis"]);
        if want == got {
            continue;
        }
        let mut diffs = Vec::new();
        compare_node(&want["analysis"], &got["analysis"], &mut diffs, 20);
        for key in ["summary", "options", "schemaVersion", "generator", "format", "file"] {
            if want[key] != got[key] {
                diffs.push(format!("{key}: want {}, got {}", want[key], got[key]));
            }
        }
        failures.push(format!("{rel}:\n    {}", diffs.join("\n    ")));
    }
    println!("golden: {files} files, {nodes} nodes compared");
    assert!(
        failures.is_empty(),
        "output differs from the baseline (MOEX_UPDATE_BASELINES=1 accepts it):\n{}",
        failures.join("\n")
    );
}
