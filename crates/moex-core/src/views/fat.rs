use super::mach_header::mach_header_node;
use crate::consts::FAT_HEADER_SIZE;
use crate::hex::{as_short_hex_string, as_string};
use crate::macho::fat::SliceContent;
use crate::macho::FatHeader;
use crate::names;
use crate::view::{Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

struct FatNode(Arc<FatHeader>);

pub fn fat_node(fat: Arc<FatHeader>) -> ViewNode {
    ViewNode::new(FatNode(fat))
}

impl NodeSource for FatNode {
    fn name(&self) -> String {
        "Fat Header".into()
    }

    fn content(&self) -> Content {
        let d = &self.0;
        let mut t = Table::new();
        t.field(d.offset, 4, "Magic Number", names::magic(d.magic));
        t.field(
            d.offset + 4,
            4,
            "Number of Architecture",
            as_string(d.nfat_arch),
        );
        t.separator();
        let mut size = FAT_HEADER_SIZE;
        for a in &d.archs {
            let e = a.entry_offset;
            // (offset of field within entry, field size) for offset/size/align
            let (off, sz, align) = if a.is_fat64 {
                ((8, 8), (16, 8), 24)
            } else {
                ((8, 4), (12, 4), 16)
            };
            t.field(e, 4, "CPU Type", names::cpu_type(a.cputype));
            t.field(
                e + 4,
                4,
                "CPU SubType",
                names::cpu_subtype(a.cputype, a.cpusubtype),
            );
            t.field(e + off.0, off.1, "Offset", as_short_hex_string(a.offset));
            t.field(e + sz.0, sz.1, "Size", as_short_hex_string(a.size));
            let align_value = if a.align < 63 { 1u64 << a.align } else { 0 };
            t.field(
                e + align,
                4,
                "Align",
                if align_value == 0 {
                    as_string(a.align)
                } else {
                    as_string(align_value)
                },
            );
            t.separator();
            size += a.entry_size();
        }
        Content::table(t).with_binary(d.offset, size)
    }

    fn children(&self) -> Vec<ViewNode> {
        self.0
            .archs
            .iter()
            .map(|a| match &a.content {
                SliceContent::MachO(mh) => mach_header_node(mh.clone()),
                SliceContent::Archive(archive) => super::archive::node_named(
                    archive.clone(),
                    format!("Archive ({})", names::arch(a.cputype, a.cpusubtype)),
                ),
                SliceContent::Unknown(reason) => ViewNode::new(UnknownSlice {
                    name: format!("Slice ({})", names::arch(a.cputype, a.cpusubtype)),
                    reason: reason.clone(),
                    offset: a.offset,
                    size: a.size,
                }),
            })
            .collect()
    }
}

/// A slice that is neither a Mach-O nor an archive: its bytes and why.
struct UnknownSlice {
    name: String,
    reason: String,
    offset: u64,
    size: u64,
}

impl NodeSource for UnknownSlice {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn content(&self) -> Content {
        let mut t = Table::new();
        t.set_headers(&["Information"]);
        t.set_widths(&[300]);
        t.add([self.reason.as_str()]);
        Content::table(t).with_binary(self.offset, self.size)
    }

    fn children(&self) -> Vec<ViewNode> {
        Vec::new()
    }
}
