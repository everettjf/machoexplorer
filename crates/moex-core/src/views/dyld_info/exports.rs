//! "Export Info" (the `LC_DYLD_INFO` export trie) and "Exports Trie
//! (LC_DYLD_EXPORTS_TRIE)" tables. Both commands hold the same trie and are
//! shown the same way; the Offset column and row byte ranges are file
//! offsets.

use crate::hex::{as_address, as_string, utf8_safe};
use crate::macho::dyld_info::EXPORT_SYMBOL_FLAGS_KIND_MASK;
use crate::macho::dyld_info::{DyldInfo, EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE};
use crate::macho::export_trie::{
    export_kind_name, walk_exports_trie, TrieNode, TrieTerminalKind, TrieValue,
};
use crate::macho::{LinkeditData, MachHeader};
use crate::view::{Content, Table};

/// Rows of one trie node. `trie` is the file offset of the trie and `base`
/// the image's preferred load address.
fn node_rows(trie: u64, base: u64, node: &TrieNode, t: &mut Table) {
    let mut row = |rel: u64, size: u64, kind: &str, name: &str, value: String| {
        let at = trie.saturating_add(rel);
        t.add_data(
            at,
            size,
            [as_address(at), kind.to_string(), name.to_string(), value],
        );
    };
    // From the start of `first` to the end of `last`.
    let span = |first: &TrieValue, last: &TrieValue| last.at + last.size - first.at;
    let prefix = utf8_safe(&node.prefix);
    let display = if node.prefix.is_empty() {
        "<root>"
    } else {
        prefix.as_str()
    };
    row(
        node.at,
        node.terminal_size.size,
        "node",
        display,
        format!("terminal_size={}", node.terminal_size.value),
    );

    if let Some(terminal) = &node.terminal {
        let flags = terminal.flags;
        row(
            flags.at,
            flags.size,
            "terminal.flags",
            &prefix,
            format!("0x{:X} ({})", flags.value, export_kind_name(flags.value)),
        );
        match &terminal.kind {
            TrieTerminalKind::Address(value) => {
                let text = if flags.value & EXPORT_SYMBOL_FLAGS_KIND_MASK
                    == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
                {
                    format!("absolute=0x{:X}", value.value)
                } else {
                    format!(
                        "offset=0x{:X} address=0x{:X}",
                        value.value,
                        base.wrapping_add(value.value)
                    )
                };
                row(value.at, value.size, "terminal.address", &prefix, text);
            }
            TrieTerminalKind::Reexport {
                ordinal,
                name_at,
                name,
            } => {
                let (import, name_size) = match name {
                    None => ("<unterminated>".to_string(), 0),
                    Some(n) if n.is_empty() => ("<same-name>".to_string(), 1),
                    Some(n) => (utf8_safe(n), n.len() as u64 + 1),
                };
                row(
                    ordinal.at,
                    name_at - ordinal.at + name_size,
                    "terminal.reexport",
                    &prefix,
                    format!("ordinal={} import={}", ordinal.value, import),
                );
            }
            TrieTerminalKind::Resolver { stub, resolver } => row(
                stub.at,
                span(stub, resolver),
                "terminal.resolver",
                &prefix,
                format!("stub=0x{:X} resolver=0x{:X}", stub.value, resolver.value),
            ),
            TrieTerminalKind::Truncated => row(
                flags.at + flags.size,
                0,
                "error",
                &prefix,
                "terminal payload truncated".to_string(),
            ),
        }
    }

    let Some((count_at, child_count)) = node.child_count else {
        row(
            node.at + node.terminal_size.size,
            0,
            "error",
            display,
            "terminal runs past the end of the trie".to_string(),
        );
        return;
    };
    row(count_at, 1, "child_count", display, as_string(child_count));
    for edge in &node.edges {
        row(
            edge.at,
            edge.size,
            "edge",
            &utf8_safe(&edge.name),
            format!("next=0x{:X}", edge.next),
        );
    }
}

/// Table and byte range for the trie stored in `size` bytes at file offset
/// `file_offset`.
fn trie_content(mh: &MachHeader, file_offset: u64, size: u64) -> Content {
    let mut t = Table::new();
    t.set_headers(&["Offset", "Type", "Name", "Value"]);
    t.set_widths(&[120, 220, 380, 340]);
    // The trie must lie inside this Mach-O (the slice of a fat file).
    let in_slice = file_offset >= mh.offset
        && file_offset
            .checked_add(size)
            .is_some_and(|end| end <= mh.end_offset());
    let Some(trie) = mh.image.slice(file_offset, size).filter(|_| in_slice) else {
        t.add(["-", "error", "exports trie", "blob out of range"]);
        return Content::table(t);
    };
    let base = mh.base_address();
    walk_exports_trie(trie, |node| node_rows(file_offset, base, node, &mut t));
    Content::table(t).with_binary(file_offset, size)
}

pub(super) fn classic_content(mh: &MachHeader, info: &DyldInfo) -> Content {
    trie_content(
        mh,
        mh.dyld_info_file_offset(info.export_off),
        info.export_size as u64,
    )
}

pub(super) fn modern_content(mh: &MachHeader, data: &LinkeditData) -> Content {
    trie_content(mh, data.file_offset, data.datasize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO_ONLY, LC_SEGMENT_64};
    use crate::image::Image;
    use std::sync::Arc;

    /// root -> "_" -> "a" (regular, offset 0x10), "r" (re-export of `_x`
    /// from ordinal 2), "s" (stub 0x20, resolver 0x30).
    fn trie() -> Vec<u8> {
        let mut t = vec![0x00, 0x01, b'_', 0x00, 0x05];
        t.extend([0x00, 0x03, b'a', 0x00, 16, b'r', 0x00, 20, b's', 0x00, 27]);
        assert_eq!(t.len(), 16);
        t.extend([0x02, 0x00, 0x10, 0x00]); // @16
        t.extend([0x05, 0x08, 0x02, b'_', b'x', 0x00, 0x00]); // @20: size 5
        t.extend([0x03, 0x10, 0x20, 0x30, 0x00]); // @27
        t
    }

    /// A 64-bit Mach-O `at` bytes into the file: a `__TEXT` segment (vm
    /// 0x1_0000_0000 at slice offset 0) and one command pointing at the
    /// trie at slice offset 0x200. `modern` picks `LC_DYLD_EXPORTS_TRIE`
    /// over `LC_DYLD_INFO_ONLY`.
    fn macho(at: usize, modern: bool) -> Arc<MachHeader> {
        let trie = trie();
        let cmd_size: u32 = if modern { 16 } else { 48 };
        let mut f = vec![0u8; at];
        for v in [0xfeed_facfu32, 0x0100_000c, 0, 6, 2, 72 + cmd_size, 0, 0] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        for v in [LC_SEGMENT_64, 72] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        for v in [0x1_0000_0000u64, 0x400, 0, 0x400] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(&[0u8; 16]);
        if modern {
            for v in [LC_DYLD_EXPORTS_TRIE, 16, 0x200, trie.len() as u32] {
                f.extend_from_slice(&v.to_le_bytes());
            }
        } else {
            for v in [LC_DYLD_INFO_ONLY, 48, 0, 0, 0, 0, 0, 0, 0, 0] {
                f.extend_from_slice(&v.to_le_bytes());
            }
            for v in [0x200, trie.len() as u32] {
                f.extend_from_slice(&v.to_le_bytes());
            }
        }
        f.resize(at + 0x200, 0);
        f.extend_from_slice(&trie);
        f.resize(at + 0x400, 0);
        let image = Arc::new(Image::from_vec(f).unwrap());
        Arc::new(MachHeader::parse(&image, at as u64).unwrap())
    }

    fn content_of(mh: &MachHeader, modern: bool) -> Content {
        if modern {
            modern_content(mh, &mh.linkedit_data(LC_DYLD_EXPORTS_TRIE).unwrap())
        } else {
            classic_content(mh, &mh.dyld_info().unwrap())
        }
    }

    #[test]
    fn classic_and_modern_tries_decode_alike() {
        for at in [0u64, 0x1000] {
            let mut tables = Vec::new();
            for modern in [false, true] {
                let mh = macho(at as usize, modern);
                let c = content_of(&mh, modern);
                let b = c.binary.unwrap();
                assert_eq!(
                    (b.offset, b.size, b.start_value),
                    (at + 0x200, 32, at + 0x200)
                );
                tables.push(c.table.unwrap());
            }
            assert_eq!(tables[0], tables[1]);
            let rows: Vec<(String, &str, &str, &str)> = tables[0]
                .rows
                .iter()
                .map(|r| {
                    (
                        format!("{:X}", r.offset.unwrap() - at),
                        r.cells[1].as_str(),
                        r.cells[2].as_str(),
                        r.cells[3].as_str(),
                    )
                })
                .collect();
            let expect = [
                ("200", "node", "<root>", "terminal_size=0"),
                ("201", "child_count", "<root>", "1"),
                ("202", "edge", "_", "next=0x5"),
                ("205", "node", "_", "terminal_size=0"),
                ("206", "child_count", "_", "3"),
                ("207", "edge", "_a", "next=0x10"),
                ("20A", "edge", "_r", "next=0x14"),
                ("20D", "edge", "_s", "next=0x1B"),
                ("210", "node", "_a", "terminal_size=2"),
                ("211", "terminal.flags", "_a", "0x0 (regular)"),
                (
                    "212",
                    "terminal.address",
                    "_a",
                    "offset=0x10 address=0x100000010",
                ),
                ("213", "child_count", "_a", "0"),
                ("214", "node", "_r", "terminal_size=5"),
                ("215", "terminal.flags", "_r", "0x8 (reexport)"),
                ("216", "terminal.reexport", "_r", "ordinal=2 import=_x"),
                ("21A", "child_count", "_r", "0"),
                ("21B", "node", "_s", "terminal_size=3"),
                ("21C", "terminal.flags", "_s", "0x10 (stub_and_resolver)"),
                ("21D", "terminal.resolver", "_s", "stub=0x20 resolver=0x30"),
                ("21F", "child_count", "_s", "0"),
            ];
            let got: Vec<(&str, &str, &str, &str)> =
                rows.iter().map(|r| (r.0.as_str(), r.1, r.2, r.3)).collect();
            assert_eq!(got, expect);
            // The Offset column is the file offset.
            assert_eq!(tables[0].rows[0].cells[0], as_address(at + 0x200));
            // The re-export row covers the ordinal and the import name.
            assert_eq!(tables[0].rows[14].size, 4);
        }
    }

    #[test]
    fn trie_outside_the_slice_is_not_read() {
        let mh = macho(0, true);
        let mut data = mh.linkedit_data(LC_DYLD_EXPORTS_TRIE).unwrap();
        data.datasize = 0x1000;
        let t = modern_content(&mh, &data).table.unwrap();
        assert_eq!(
            t.rows[0].cells,
            ["-", "error", "exports trie", "blob out of range"]
        );
    }
}
