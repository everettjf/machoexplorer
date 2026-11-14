//! "Export Info" (classic `LC_DYLD_INFO` trie) and "Exports Trie
//! (LC_DYLD_EXPORTS_TRIE)" tables.

use crate::hex::{as_address, as_hex_data, as_short_hex_string, as_string, utf8_safe};
use crate::image::Image;
use crate::macho::dyld_info::{DyldInfo, ExportNode, Leb};
use crate::macho::export_trie::{walk_exports_trie, TrieNode, TrieTerminalTail};
use crate::macho::{LinkeditData, MachHeader};
use crate::view::{Content, Table};

fn operand_hex(image: &Image, leb: &Leb<u64>) -> String {
    as_hex_data(image.slice(leb.offset, leb.size as u64).unwrap_or(&[]))
}

pub(super) fn classic_rows(image: &Image, nodes: &[ExportNode], t: &mut Table) {
    for (index, node) in nodes.iter().enumerate() {
        if index > 0 {
            t.add(["-", "-", "-", "-"]);
        }
        t.add([
            as_address(node.terminal_size_offset),
            format!("{:02X}", node.terminal_size),
            "Terminal Size".to_string(),
            as_string(node.terminal_size),
        ]);
        if let (Some(flags), Some(symbol_offset)) = (&node.flags, &node.symbol_offset) {
            t.add([
                as_address(flags.offset),
                operand_hex(image, flags),
                "Flags".to_string(),
                String::new(),
            ]);
            for (value, name) in node.flag_names() {
                t.add(["", "", value, name]);
            }
            t.add([
                as_address(symbol_offset.offset),
                operand_hex(image, symbol_offset),
                "Symbol Offset".to_string(),
                // QUIRK(parity): the offset is cut to a signed 32-bit value.
                as_string(symbol_offset.value as i32),
            ]);
        }
        t.add([
            as_address(node.child_count_offset),
            format!("{:02X}", node.child_count),
            "Child Count".to_string(),
            as_string(node.child_count),
        ]);
        for child in &node.children {
            // At most the first 8 bytes of the label and its terminator.
            let shown = image
                .slice(child.label_offset, (child.label_size as u64).min(8))
                .unwrap_or(&[]);
            t.add([
                as_address(child.label_offset),
                as_hex_data(shown),
                "Node Label".to_string(),
                utf8_safe(&child.label),
            ]);
            t.add([
                as_address(child.skip.offset),
                operand_hex(image, &child.skip),
                "Next Node".to_string(),
                as_address(child.skip.value),
            ]);
        }
    }
}

pub(super) fn classic_content(mh: &MachHeader, info: &DyldInfo) -> Content {
    let mut t = Table::new();
    classic_rows(&mh.image, &mh.export_trie_nodes(info), &mut t);
    // The original leaves the byte range empty.
    Content::table(t)
}

/// Rows of one modern trie node. `dataoff` is the header-relative offset of
/// the trie, which is what the Offset column is based on.
fn modern_node_rows(dataoff: u32, node: &TrieNode, t: &mut Table) {
    // QUIRK(parity): offsets are relative to the Mach-O header, not the
    // file, so they are off by the slice offset inside a fat file.
    let at = |rel: u64| as_address((dataoff as u64).wrapping_add(rel));
    let prefix = utf8_safe(&node.prefix);
    let display = if node.prefix.is_empty() {
        "<root>".to_string()
    } else {
        prefix.clone()
    };
    t.add([
        at(node.at),
        "node".to_string(),
        display.clone(),
        format!("terminal_size={}", node.terminal_size),
    ]);

    if let Some(terminal) = &node.terminal {
        t.add([
            at(terminal.flags_at),
            "terminal.flags".to_string(),
            prefix.clone(),
            format!(
                "0x{} ({})",
                as_short_hex_string(terminal.flags),
                terminal.kind_name()
            ),
        ]);
        if let Some((value_at, value, tail)) = &terminal.value {
            let value_hex = as_short_hex_string(*value);
            t.add([
                at(*value_at),
                "terminal.value".to_string(),
                prefix.clone(),
                format!("0x{}", value_hex),
            ]);
            match tail {
                TrieTerminalTail::Address => t.add([
                    at(*value_at),
                    "terminal.address".to_string(),
                    prefix.clone(),
                    format!("symbol=0x{}", value_hex),
                ]),
                TrieTerminalTail::Reexport { at: name_at, name } => {
                    let import = match name {
                        None => "<none>".to_string(),
                        Some(n) if n.is_empty() => "<same-name>".to_string(),
                        Some(n) => utf8_safe(n),
                    };
                    t.add([
                        at(*name_at),
                        "terminal.reexport".to_string(),
                        prefix.clone(),
                        format!("ordinal={} import={}", value, import),
                    ]);
                }
                TrieTerminalTail::Resolver {
                    at: resolver_at,
                    resolver,
                } => t.add([
                    at(*resolver_at),
                    "terminal.resolver".to_string(),
                    prefix.clone(),
                    format!(
                        "stub=0x{} resolver=0x{}",
                        value_hex,
                        as_short_hex_string(*resolver)
                    ),
                ]),
                TrieTerminalTail::Missing => {}
            }
        }
    }

    let Some((count_at, child_count)) = node.child_count else {
        return;
    };
    t.add([
        at(count_at),
        "child_count".to_string(),
        display,
        as_string(child_count),
    ]);
    for edge in &node.edges {
        t.add([
            at(edge.at),
            "edge".to_string(),
            utf8_safe(&edge.name),
            format!("next=0x{}", as_short_hex_string(edge.next)),
        ]);
    }
}

pub(super) fn modern_content(mh: &MachHeader, data: &LinkeditData) -> Content {
    let mut t = Table::new();
    t.set_headers(&["Offset", "Type", "Name", "Value"]);
    t.set_widths(&[120, 220, 380, 340]);
    if !mh.image.in_file(data.file_offset, data.datasize as u64) {
        t.add(["-", "error", "exports trie", "blob out of range"]);
        return Content::table(t);
    }
    walk_exports_trie(mh.image.bytes(), data.file_offset, data.datasize, |node| {
        modern_node_rows(data.dataoff, node, &mut t)
    });
    // The address label is the header-relative `dataoff`.
    Content::table(t).with_binary_at(data.file_offset, data.datasize as u64, data.dataoff as u64)
}
