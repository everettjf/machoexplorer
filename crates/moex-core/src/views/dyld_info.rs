//! "Dynamic Loader Info" node: the classic `LC_DYLD_INFO` opcode streams and
//! export trie, plus the modern `LC_DYLD_EXPORTS_TRIE` and
//! `LC_DYLD_CHAINED_FIXUPS` blobs.

mod chained;
mod exports;
mod opcodes;

use crate::consts::{LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE};
use crate::hex::as_short_hex_string;
use crate::macho::dyld_info::BindKind;
use crate::macho::MachHeader;
use crate::view::{leaf, Content, FnNode, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    let for_content = mh.clone();
    Some(ViewNode::new(FnNode {
        name: "Dynamic Loader Info".to_string(),
        content: move || content(&for_content),
        children: move || children(&mh),
    }))
}

fn content(mh: &MachHeader) -> Content {
    let mut t = Table::new();
    if let Some(info) = mh.dyld_info() {
        let fields = [
            (info.rebase_off, "Rebase Info Offset"),
            (info.rebase_size, "Rebase Info Size"),
            (info.bind_off, "Binding Info Offset"),
            (info.bind_size, "Binding Info Size"),
            (info.weak_bind_off, "Weak Binding Info Offset"),
            (info.weak_bind_size, "Weak Binding Info Size"),
            (info.lazy_bind_off, "Lazy Binding Info Offset"),
            (info.lazy_bind_size, "Lazy Binding Info Size"),
            (info.export_off, "Export Info Offset"),
            (info.export_size, "Export Info Size"),
        ];
        let mut at = info.lc.offset.saturating_add(8);
        for (value, desc) in fields {
            t.field(at, 4, desc, as_short_hex_string(value as u64));
            at = at.saturating_add(4);
        }
    }
    let modern = [
        (
            LC_DYLD_EXPORTS_TRIE,
            "Exports Trie Offset (Modern)",
            "Exports Trie Size (Modern)",
        ),
        (
            LC_DYLD_CHAINED_FIXUPS,
            "Chained Fixups Offset (Modern)",
            "Chained Fixups Size (Modern)",
        ),
    ];
    for (cmd, off_desc, size_desc) in modern {
        if let Some(d) = mh.linkedit_data(cmd) {
            t.field(
                d.lc.offset.saturating_add(8),
                4,
                off_desc,
                as_short_hex_string(d.dataoff as u64),
            );
            t.field(
                d.lc.offset.saturating_add(12),
                4,
                size_desc,
                as_short_hex_string(d.datasize as u64),
            );
        }
    }
    Content::table(t)
}

fn children(mh: &Arc<MachHeader>) -> Vec<ViewNode> {
    let mut nodes = Vec::new();
    if let Some(info) = mh.dyld_info() {
        // A blob is present when it has a size (and, as offset 0 is the
        // Mach-O header, an offset).
        let present = |off: u32, size: u32| off != 0 && size != 0;
        if present(info.rebase_off, info.rebase_size) {
            let mh = mh.clone();
            nodes.push(leaf("Rebase Info", move || {
                opcodes::rebase_content(&mh, &info)
            }));
        }
        let binds = [
            ("Binding Info", BindKind::Bind),
            ("Weak Binding Info", BindKind::WeakBind),
            ("Lazy Binding Info", BindKind::LazyBind),
        ];
        for (name, kind) in binds {
            let (off, size) = info.bind_range(kind);
            if present(off, size) {
                let mh = mh.clone();
                nodes.push(leaf(name, move || opcodes::bind_content(&mh, &info, kind)));
            }
        }
        if present(info.export_off, info.export_size) {
            let mh = mh.clone();
            nodes.push(leaf("Export Info", move || {
                exports::classic_content(&mh, &info)
            }));
        }
    }
    if let Some(data) = mh
        .linkedit_data(LC_DYLD_EXPORTS_TRIE)
        .filter(|d| d.datasize > 0)
    {
        let mh = mh.clone();
        nodes.push(leaf("Exports Trie (LC_DYLD_EXPORTS_TRIE)", move || {
            exports::modern_content(&mh, &data)
        }));
    }
    if let Some(data) = mh
        .linkedit_data(LC_DYLD_CHAINED_FIXUPS)
        .filter(|d| d.datasize > 0)
    {
        let mh = mh.clone();
        nodes.push(leaf("Chained Fixups (LC_DYLD_CHAINED_FIXUPS)", move || {
            chained::content(&mh, &data)
        }));
    }
    nodes
}
