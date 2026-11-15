//! "Dynamic Symbol Table" node with its "Indirect Symbols" and
//! "Relocations" children.

use crate::consts::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use crate::hex::{as_address, as_hex_string, as_short_hex_string};
use crate::macho::{MachHeader, Relocation};
use crate::view::{leaf, Content, FnNode, Table, ViewNode};
use std::sync::Arc;

const R_SCATTERED: u32 = 0x8000_0000;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    let (for_content, for_children) = (mh.clone(), mh);
    Some(ViewNode::new(FnNode {
        name: "Dynamic Symbol Table".to_string(),
        content: move || content(&for_content),
        children: move || children(&for_children),
    }))
}

fn content(mh: &MachHeader) -> Content {
    match mh.dysymtab().and_then(|d| d.data_range()) {
        Some((off, size)) => Content::default().with_binary(mh.offset.saturating_add(off), size),
        None => Content::default(),
    }
}

fn children(mh: &Arc<MachHeader>) -> Vec<ViewNode> {
    let Some(dysym) = mh.dysymtab() else {
        return Vec::new();
    };
    let mut nodes = Vec::new();
    if dysym.has_indirect_symbols() {
        let mh = mh.clone();
        nodes.push(leaf("Indirect Symbols", move || indirect_symbols(&mh)));
    }
    if dysym.has_external_relocations() || dysym.has_local_relocations() {
        let mh = mh.clone();
        nodes.push(leaf("Relocations", move || relocations(&mh)));
    }
    nodes
}

fn indirect_symbols(mh: &MachHeader) -> Content {
    let Some(dysym) = mh.dysymtab().filter(|d| d.has_indirect_symbols()) else {
        return Content::default();
    };
    let mut t = Table::new();
    t.set_headers(&["Offset", "Data", "Description", "Value"]);
    t.set_widths(&[100, 100, 100, 400]);
    for s in dysym.indirect_symbols() {
        t.add_data(
            s.offset,
            4,
            [
                as_address(s.offset),
                as_hex_string(s.symbol_index as u64),
                "Indirect Index".to_string(),
                as_short_hex_string(s.symbol_index as u64),
            ],
        );
    }
    Content::table(t).with_binary(
        dysym.indirect_symbols_offset(),
        dysym.nindirectsyms as u64 * 4,
    )
}

fn reloc_type_name(cputype: u32, r_type: u32) -> String {
    const X86_64: &[&str] = &[
        "X86_64_RELOC_UNSIGNED",
        "X86_64_RELOC_SIGNED",
        "X86_64_RELOC_BRANCH",
        "X86_64_RELOC_GOT_LOAD",
        "X86_64_RELOC_GOT",
        "X86_64_RELOC_SUBTRACTOR",
        "X86_64_RELOC_SIGNED_1",
        "X86_64_RELOC_SIGNED_2",
        "X86_64_RELOC_SIGNED_4",
        "X86_64_RELOC_TLV",
    ];
    const ARM64: &[&str] = &[
        "ARM64_RELOC_UNSIGNED",
        "ARM64_RELOC_SUBTRACTOR",
        "ARM64_RELOC_BRANCH26",
        "ARM64_RELOC_PAGE21",
        "ARM64_RELOC_PAGEOFF12",
        "ARM64_RELOC_GOT_LOAD_PAGE21",
        "ARM64_RELOC_GOT_LOAD_PAGEOFF12",
        "ARM64_RELOC_POINTER_TO_GOT",
        "ARM64_RELOC_TLVP_LOAD_PAGE21",
        "ARM64_RELOC_TLVP_LOAD_PAGEOFF12",
        "ARM64_RELOC_ADDEND",
        "ARM64_RELOC_AUTHENTICATED_POINTER",
    ];
    let (names, prefix) = match cputype {
        CPU_TYPE_X86_64 => (X86_64, "X86_64_RELOC_UNKNOWN"),
        CPU_TYPE_ARM64 => (ARM64, "ARM64_RELOC_UNKNOWN"),
        _ => return format!("RELOC_TYPE({r_type})"),
    };
    match names.get(r_type as usize) {
        Some(name) => name.to_string(),
        None => format!("{prefix}({r_type})"),
    }
}

/// Cells of one relocation row. `symbol_name` resolves a symbol table index
/// and `sections` holds `segment/section` names by 1-based section ordinal.
fn relocation_cells(
    scope: &str,
    r: &Relocation,
    cputype: u32,
    symbol_name: &dyn Fn(u32) -> Option<String>,
    sections: &[String],
) -> [String; 4] {
    let (word0, word1) = (r.word0, r.word1);
    let index = format!("{scope}#{}", r.index);
    if word0 & R_SCATTERED != 0 {
        let r_address = word0 & 0x00FF_FFFF;
        let r_type = (word0 >> 24) & 0x0F;
        let r_length = (word0 >> 28) & 0x03;
        let r_pcrel = (word0 >> 30) & 0x01;
        return [
            index,
            format!("addr=0x{:X} value=0x{:X}", r_address, word1),
            reloc_type_name(cputype, r_type),
            format!("scattered pcrel={} len={}", r_pcrel, 1u32 << r_length),
        ];
    }

    let r_address = word0 as i32;
    let r_symbolnum = word1 & 0x00FF_FFFF;
    let r_pcrel = (word1 >> 24) & 0x01 != 0;
    let r_length = (word1 >> 25) & 0x03;
    let r_extern = (word1 >> 27) & 0x01 != 0;
    let r_type = (word1 >> 28) & 0x0F;

    // Unreachable in practice: bit 31 set means scattered. Kept to mirror
    // the original's formatting of a negative address.
    let addr = if r_address >= 0 {
        format!("0x{:X}", r_address as u32)
    } else {
        format!("-0x{:X}", r_address.wrapping_neg() as u32)
    };
    let target = if r_extern {
        symbol_name(r_symbolnum).unwrap_or_else(|| format!("symbol#{r_symbolnum}"))
    } else if r_symbolnum == 0 {
        "R_ABS".to_string()
    } else {
        match sections.get(r_symbolnum as usize - 1) {
            Some(name) => name.clone(),
            None => format!("section#{r_symbolnum}"),
        }
    };
    [
        index,
        format!("addr={addr} target={target}"),
        reloc_type_name(cputype, r_type),
        format!(
            "extern={} pcrel={} len={}",
            r_extern,
            r_pcrel,
            1u32 << r_length
        ),
    ]
}

fn relocations(mh: &MachHeader) -> Content {
    let Some(dysym) = mh.dysymtab() else {
        return Content::default();
    };
    let mut t = Table::new();
    t.set_headers(&["Index", "Address/Target", "Type", "Attributes"]);
    t.set_widths(&[120, 420, 280, 240]);

    let symtab = mh.symtab();
    let symbol_name = |index: u32| symtab.as_ref().and_then(|s| s.symbol_name(index));
    // Section ordinals count the sections of all 32-bit segments first,
    // then those of the 64-bit segments.
    let sections: Vec<String> = [false, true]
        .into_iter()
        .flat_map(|want64| mh.segments.iter().filter(move |s| s.is64 == want64))
        .flat_map(|seg| seg.sections.iter())
        .map(|s| format!("{}/{}", s.segname, s.sectname))
        .collect();

    let mut add = |scope: &str, r: Relocation| {
        t.add_data(
            r.offset,
            8,
            relocation_cells(scope, &r, mh.cputype, &symbol_name, &sections),
        );
    };
    for r in dysym.external_relocations() {
        add("ext", r);
    }
    for r in dysym.local_relocations() {
        add("loc", r);
    }
    if !dysym.has_external_relocations() && !dysym.has_local_relocations() {
        t.add(["-", "No relocation entries in LC_DYSYMTAB", "-", "-"]);
    }
    Content::table(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(word0: u32, word1: u32, cputype: u32) -> [String; 4] {
        let r = Relocation {
            index: 3,
            offset: 0,
            word0,
            word1,
        };
        let names = |i: u32| (i == 1).then(|| "_sym".to_string());
        relocation_cells("ext", &r, cputype, &names, &["__TEXT/__text".to_string()])
    }

    #[test]
    fn plain_relocations() {
        // symbolnum 1, pcrel, len 2, extern, type 2
        let w1 = 1 | (1 << 24) | (2 << 25) | (1 << 27) | (2 << 28);
        assert_eq!(
            cells(0x10, w1, CPU_TYPE_X86_64),
            [
                "ext#3",
                "addr=0x10 target=_sym",
                "X86_64_RELOC_BRANCH",
                "extern=true pcrel=true len=4"
            ]
        );
        // Unknown symbol / section ordinals and R_ABS.
        assert_eq!(
            cells(0, 9 | (1 << 27), CPU_TYPE_ARM64)[1],
            "addr=0x0 target=symbol#9"
        );
        assert_eq!(
            cells(0, 1, CPU_TYPE_ARM64)[1],
            "addr=0x0 target=__TEXT/__text"
        );
        assert_eq!(cells(0, 2, CPU_TYPE_ARM64)[1], "addr=0x0 target=section#2");
        assert_eq!(cells(0, 0, CPU_TYPE_ARM64)[1], "addr=0x0 target=R_ABS");
        assert_eq!(
            cells(0, 0xF << 28, CPU_TYPE_ARM64)[2],
            "ARM64_RELOC_UNKNOWN(15)"
        );
        assert_eq!(
            cells(0, 0xB << 28, CPU_TYPE_X86_64)[2],
            "X86_64_RELOC_UNKNOWN(11)"
        );
        assert_eq!(cells(0, 1 << 28, 7)[2], "RELOC_TYPE(1)");
    }

    #[test]
    fn scattered_relocations() {
        let w0 = R_SCATTERED | (1 << 30) | (3 << 28) | (1 << 24) | 0x1234;
        assert_eq!(
            cells(w0, 0xABCD, CPU_TYPE_ARM64),
            [
                "ext#3",
                "addr=0x1234 value=0xABCD",
                "ARM64_RELOC_SUBTRACTOR",
                "scattered pcrel=1 len=8"
            ]
        );
    }
}
