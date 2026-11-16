//! The disassembly and cross-reference views on the checked-in binaries:
//! facts that were checked by hand against `otool -tV` / `llvm-objdump`.

use moex_core::view::{Table, ViewNode};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn open(rel: &str) -> ViewNode {
    moex_core::open(repo_root().join(rel)).unwrap_or_else(|e| panic!("parse {rel}: {e}"))
}

/// Tables of every node called `name`, in tree order, with the name of the
/// Mach-O header node above each.
fn tables(root: &ViewNode, name: &str) -> Vec<(String, Table)> {
    fn walk(node: &ViewNode, header: &str, name: &str, out: &mut Vec<(String, Table)>) {
        let header = if node.name().starts_with("Mach Header") {
            node.name()
        } else {
            header
        };
        if node.name() == name {
            if let Some(table) = node.table() {
                out.push((header.to_string(), table.clone()));
            }
        }
        for child in node.children() {
            walk(child, header, name, out);
        }
    }
    let mut out = Vec::new();
    walk(root, "", name, &mut out);
    out
}

fn disassembly(rel: &str) -> Vec<(String, Table)> {
    tables(&open(rel), "Disassembly (Capstone)")
}

/// `(target, kind, address of the referring instruction)` of every code
/// reference of an Xref Report.
fn code_refs(table: &Table) -> BTreeSet<(String, String, String)> {
    table
        .rows
        .iter()
        .filter_map(|row| {
            let referrer = row.cells.get(3)?.strip_prefix("__TEXT/__text [")?;
            let (kind, rest) = referrer.split_once(']')?;
            let (_, vm) = rest.split_once(" vm 0x")?;
            Some((row.cells[0].clone(), kind.to_string(), vm.to_string()))
        })
        .collect()
}

fn has(refs: &BTreeSet<(String, String, String)>, target: &str, kind: &str, vm: &str) -> bool {
    refs.contains(&(target.to_string(), kind.to_string(), vm.to_string()))
}

fn row<'a>(table: &'a Table, address: &str) -> &'a [String] {
    &table
        .rows
        .iter()
        .find(|r| r.cells[0] == address)
        .unwrap_or_else(|| panic!("no row at {address}"))
        .cells
}

#[test]
fn string_references_point_at_cstrings() {
    // __cstring of hello_arm64: 10000065C "%s %zu\n", 100000664 "%f %d\n".
    let arm64 = code_refs(&tables(&open("tests/corpus/bin/hello_arm64"), "Xref Report")[0].1);
    assert!(has(&arm64, "10000065C", "addr", "1000005D0"));
    assert!(has(&arm64, "100000664", "addr", "100000620"));
    // `adrp x23` + `add x23, x23, #0` is a reference to the page itself.
    assert!(has(&arm64, "100004000", "addr", "1000005C8"));
    assert!(has(&arm64, "100000650", "call", "1000005DC"));
    assert!(has(&arm64, "1000005D4", "jump", "1000005F4"));
    // The bit numbers and tested registers of branches are not targets.
    assert!(arm64.iter().all(|(target, _, _)| target.len() == 9));

    // __cstring of hello_x86_64: 1000006B8 and 1000006C0; 1000006B0 is the
    // floating-point constant both functions load.
    let x86 = code_refs(&tables(&open("tests/corpus/bin/hello_x86_64"), "Xref Report")[0].1);
    assert!(has(&x86, "1000006B8", "addr", "100000627"));
    assert!(has(&x86, "1000006C0", "addr", "100000674"));
    assert!(has(&x86, "1000006B0", "load", "100000604"));
    assert!(has(&x86, "1000006B0", "load", "10000067B"));
    assert!(has(&x86, "10000069E", "call", "100000687"));
}

#[test]
fn fat_slices_report_what_the_thin_files_do() {
    let fat = tables(&open("tests/corpus/bin/hello_fat"), "Xref Report");
    assert_eq!(fat.len(), 2);
    for (header, table) in &fat {
        let thin = if header.contains("x86_64") {
            "tests/corpus/bin/hello_x86_64"
        } else {
            "tests/corpus/bin/hello_arm64"
        };
        let thin = code_refs(&tables(&open(thin), "Xref Report")[0].1);
        assert!(!thin.is_empty());
        assert_eq!(code_refs(table), thin, "{header}");
    }
}

#[test]
fn disassembly_rows() {
    for rel in [
        "tests/corpus/bin/hello_arm64",
        "tests/corpus/bin/hello_fat",
        "tests/corpus/bin/cat_arm64_32.o",
        "tests/corpus/bin/cat_armv7.o",
        "tests/corpus/bin/lib_x86_64.o",
        "sample/complex",
    ] {
        let found = disassembly(rel);
        assert!(!found.is_empty(), "{rel}");
        // `__text` comes first; stub sections can be a few rows long.
        assert!(found[0].1.rows.len() > 10, "{rel}");
        for (_, table) in &found {
            assert!(!table.rows.is_empty(), "{rel}");
            for (i, r) in table.rows.iter().enumerate() {
                assert_eq!(r.cells.len(), table.headers.len(), "{rel} row {i}");
                // Every row is backed by its bytes, in address order.
                assert_eq!(r.cells[1].len() as u64, 2 * r.size, "{rel} row {i}");
            }
            let offsets: Vec<u64> = table.rows.iter().filter_map(|r| r.offset).collect();
            assert_eq!(offsets.len(), table.rows.len(), "{rel}");
            assert!(
                table
                    .rows
                    .windows(2)
                    .all(|w| w[0].offset.unwrap() + w[0].size == w[1].offset.unwrap()),
                "{rel}"
            );
        }
    }
}

#[test]
fn every_code_section_is_disassembled() {
    // hello_arm64 has `__text` and `__stubs`; each stub is
    // `adrp x16` / `ldr x16, [x16, ...]` / `br x16`.
    let found = disassembly("tests/corpus/bin/hello_arm64");
    assert_eq!(found.len(), 2);
    let stubs = &found[1].1;
    assert_eq!(stubs.rows.len() % 3, 0);
    for stub in stubs.rows.chunks(3) {
        assert!(
            stub[0].cells[2].starts_with("adrp x16, "),
            "{:?}",
            stub[0].cells
        );
        assert!(
            stub[1].cells[2].starts_with("ldr x16, [x16"),
            "{:?}",
            stub[1].cells
        );
        assert_eq!(stub[2].cells[2], "br x16");
    }
    // The stubs are swept for references too: each loads its GOT slot.
    let root = open("tests/corpus/bin/hello_arm64");
    let (_, xrefs) = &tables(&root, "Xref Report")[0];
    let from_stubs = xrefs
        .rows
        .iter()
        .filter(|r| r.cells[3].starts_with("__TEXT/__stubs [load]"))
        .count();
    assert_eq!(from_stubs, stubs.rows.len() / 3);
}

#[test]
fn big_endian_object_file() {
    // A PowerPC object: everything is stored big-endian. The instructions
    // were checked against `llvm-objdump -d`, the relocations against
    // `llvm-objdump -r`.
    let root = open("tests/corpus/bin/hello_ppc.o");
    assert_eq!(root.children()[0].name(), "Mach Header (ppc)");
    let (_, code) = &tables(&root, "Disassembly (Capstone)")[0];
    let text: Vec<&str> = code.rows.iter().map(|r| r.cells[2].as_str()).collect();
    assert_eq!(
        text,
        [
            "mflr r0",
            "stw r0, 8(r1)",
            "stwu r1, -0x40(r1)",
            "bl 0x24",
            "bl 0x10",
            "addi r1, r1, 0x40",
            "lwz r0, 8(r1)",
            "mtlr r0",
            "blr",
            "li r3, 0x2a",
            "blr"
        ]
    );
    assert_eq!(row(code, "00000000")[3], "_main");
    assert_eq!(row(code, "00000024")[3], "_helper");
    let cell = |name: &str, r: usize, c: usize| tables(&root, name)[0].1.rows[r].cells[c].clone();
    assert_eq!(cell("C String Literals", 1, 3), "ppc");
    assert_eq!(cell("Floating Point Literals", 0, 2), "2.5");
    // The initializer pointer holds 0; its relocation names `_helper`.
    assert_eq!(cell("Module Init Func Pointers", 0, 2), "20C->24");
    let (_, xrefs) = &tables(&root, "Xref Report")[0];
    let referrers: Vec<&str> = xrefs
        .rows
        .iter()
        .filter(|r| r.cells[0] == "00000024" && r.cells[3].contains(" @ raw "))
        .map(|r| r.cells[3].as_str())
        .collect();
    assert_eq!(
        referrers,
        [
            "__DATA/__mod_init_func [pointer] @ raw 0x20C",
            "__TEXT/__text [call] @ raw 0x1D8 vm 0xC"
        ]
    );
    // The call to the undefined `_puts` has no address to refer to.
    assert!(xrefs.rows.iter().all(|r| !r.cells[3].contains("vm 0x10")));
}

#[test]
fn object_files_name_the_first_function() {
    let (_, table) = &disassembly("tests/corpus/bin/lib_arm64.o")[0];
    assert_eq!(table.rows[0].cells[3], "_moex_add");
    // arm64_32 code is AArch64 code.
    let (_, table) = &disassembly("tests/corpus/bin/cat_arm64_32.o")[0];
    assert!(table.rows.iter().any(|r| r.cells[2] == "ret"));
}

#[test]
fn thumb_code_and_data_in_code() {
    // An object file: Thumb functions are marked in the symbol table.
    let (_, table) = &disassembly("tests/corpus/bin/cat_armv7.o")[0];
    assert_eq!(
        row(table, "00000000"),
        ["00000000", "0020", "movs r0, #0", "+[Base alloc]", ""]
    );
    assert_eq!(row(table, "00000002")[2], "bx lr");
    assert_eq!(row(table, "00000020")[1], "FFF7EEBF");

    // A stripped executable inside a fat file: Thumb comes from the
    // function starts, and the data-in-code offsets are relative to the
    // slice.
    let found = disassembly("sample/complex");
    let (header, table) = &found[0];
    assert!(header.contains("arm"), "{header}");
    assert_eq!(row(table, "00008464")[2], "push {r7, lr}");
    assert_eq!(row(table, "00008464")[4], "function_start");
    assert_eq!(row(table, "000089FA")[2], "pop {r4, r5, r6, r7, pc}");
    assert_eq!(
        row(table, "000089FC")[2..],
        [
            ".long 0x00000000",
            "__mh_execute_header+0x49FC",
            "data_in_code:DICE_KIND_DATA"
        ]
    );
    assert_eq!(row(table, "00008A00")[2], ".long 0x4092f000");
    assert_eq!(row(table, "00008A04")[2], "push {r4, r5, r7, lr}");
    assert_eq!(row(table, "00008A04")[4], "function_start");
    let data_rows = table
        .rows
        .iter()
        .filter(|r| r.cells[4].contains("data_in_code"))
        .count();
    assert_eq!(data_rows, 2);
}
