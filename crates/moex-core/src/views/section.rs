//! One `Section(segment,section)` node: the fields of its `section` /
//! `section_64` header, plus child nodes interpreting the section contents
//! (strings, literals, pointers, stubs, disassembly, ObjC/Swift metadata).

mod disasm;
mod literals;
mod objc;
mod pointers;
mod swift;

use crate::hex::as_short_hex_string;
use crate::macho::{MachHeader, Section};
use crate::view::{leaf, Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

/// `flags & SECTION_TYPE` selects the content type of a section.
pub const SECTION_TYPE: u32 = 0x0000_00ff;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_4BYTE_LITERALS: u32 = 0x3;
pub const S_8BYTE_LITERALS: u32 = 0x4;
pub const S_LITERAL_POINTERS: u32 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
pub const S_16BYTE_LITERALS: u32 = 0xe;
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;

struct SectionNode {
    mh: Arc<MachHeader>,
    section: Section,
}

/// Node for the `section_index`-th section of `mh.sections()` (0-based, all
/// segments in load-command order). `None` when the index is out of range.
pub fn section_node(mh: Arc<MachHeader>, section_index: usize) -> Option<ViewNode> {
    let section = mh.sections().nth(section_index)?.clone();
    Some(ViewNode::new(SectionNode { mh, section }))
}

/// Builds the table of one content view.
type TableBuilder = fn(&MachHeader, &Section) -> Table;

/// The content views a section gets, as `(node name, table builder)` in
/// display order: first the one chosen by the section type, then those
/// chosen by segment/section name.
fn content_views(section: &Section) -> Vec<(&'static str, TableBuilder)> {
    let mut views: Vec<(&'static str, TableBuilder)> = Vec::new();
    match section.flags & SECTION_TYPE {
        S_CSTRING_LITERALS => views.push(("C String Literals", literals::cstrings)),
        S_4BYTE_LITERALS => views.push(("Floating Point Literals", literals::literals4)),
        S_8BYTE_LITERALS => views.push(("Floating Point Literals", literals::literals8)),
        S_16BYTE_LITERALS => views.push(("Floating Point Literals", literals::literals16)),
        S_LITERAL_POINTERS => views.push(("Literal Pointers", pointers::pointers)),
        S_MOD_INIT_FUNC_POINTERS => views.push(("Module Init Func Pointers", pointers::pointers)),
        S_MOD_TERM_FUNC_POINTERS => views.push(("Module Term Func Pointers", pointers::pointers)),
        S_LAZY_SYMBOL_POINTERS => views.push(("Lazy Symbol Pointers", pointers::indirect_pointers)),
        S_NON_LAZY_SYMBOL_POINTERS => {
            views.push(("Non-Lazy Symbol Pointers", pointers::indirect_pointers))
        }
        S_LAZY_DYLIB_SYMBOL_POINTERS => {
            views.push(("Lazy Dylib Symbol Pointers", pointers::indirect_pointers))
        }
        S_SYMBOL_STUBS => views.push(("Symbol Stubs", pointers::symbol_stubs)),
        _ => {}
    }

    let sect = section.sectname.as_str();
    let unique = format!("{}/{}", section.segname, sect);
    let is = |a: &str, b: &str| unique == a || unique == b;
    if is("__OBJC/__image_info", "__DATA/__objc_imageinfo") {
        views.push(("ObjC2 Image Info", objc::image_info));
    }
    if sect == "__cfstring" {
        views.push(("ObjC CFStrings", objc::cfstrings));
    }
    if unique == "__TEXT/__text" {
        views.push(("Disassembly (Capstone)", disasm::disassembly));
    }
    if sect.starts_with("__swift5_") {
        views.push(("Swift Metadata", swift::metadata));
    }
    // QUIRK(parity): only sections of a segment named exactly `__DATA` (or
    // the legacy `__OBJC2`) get the ObjC views; `__DATA_CONST` and
    // `__DATA_DIRTY`, where current linkers put these sections, do not.
    if is("__OBJC2/__category_list", "__DATA/__objc_catlist") {
        views.push(("ObjC2 Category Metadata", objc::category_metadata));
    }
    if is("__OBJC2/__class_list", "__DATA/__objc_classlist") {
        views.push(("ObjC2 Class Metadata", objc::class_metadata));
    }
    if is("__OBJC2/__class_refs", "__DATA/__objc_classrefs") {
        views.push(("ObjC2 Class References", objc::pointer_refs));
    }
    if is("__OBJC2/__super_refs", "__DATA/__objc_superrefs") {
        views.push(("ObjC2 Super References", objc::pointer_refs));
    }
    if is("__OBJC2/__protocol_list", "__DATA/__objc_protolist") {
        views.push(("ObjC2 Protocol Metadata", objc::protocol_metadata));
    }
    views
}

impl NodeSource for SectionNode {
    fn name(&self) -> String {
        format!(
            "Section({},{})",
            self.section.segname, self.section.sectname
        )
    }

    fn content(&self) -> Content {
        header_content(&self.section)
    }

    fn children(&self) -> Vec<ViewNode> {
        content_views(&self.section)
            .into_iter()
            .map(|(name, build)| {
                let (mh, section) = (self.mh.clone(), self.section.clone());
                leaf(name, move || {
                    // Every content view shows the bytes of the section
                    // header, like its parent.
                    Content::table(build(&mh, &section))
                        .with_binary(section.header_offset, section.header_size())
                })
            })
            .collect()
    }
}

/// `(file offset, value)` of each whole pointer-sized entry of the section
/// contents; the pointer width is that of the section header.
fn pointer_entries<'a>(
    mh: &'a MachHeader,
    section: &'a Section,
) -> impl Iterator<Item = (u64, u64)> + 'a {
    let step: u64 = if section.is64 { 8 } else { 4 };
    let count = section.data_size as u64 / step;
    (0..count).filter_map(move |i| {
        let at = section.data_offset.checked_add(i * step)?;
        let value = if section.is64 {
            mh.image.u64(at)?
        } else {
            u64::from(mh.image.u32(at)?)
        };
        Some((at, value))
    })
}

/// `(file offset, bytes)` of each whole `unit`-byte chunk of the section
/// contents; nothing when `unit` is 0.
fn chunks<'a>(
    mh: &'a MachHeader,
    section: &Section,
    unit: u64,
) -> impl Iterator<Item = (u64, &'a [u8])> + 'a {
    let data: &'a [u8] = section.data(&mh.image);
    let base = section.data_offset;
    let unit_len = usize::try_from(unit).unwrap_or(usize::MAX);
    let pieces = if unit_len == 0 {
        [].chunks_exact(1)
    } else {
        data.chunks_exact(unit_len)
    };
    pieces
        .enumerate()
        .map(move |(i, bytes)| (base + i as u64 * unit, bytes))
}

/// Field table and byte range of the section header itself.
fn header_content(s: &Section) -> Content {
    let o = s.header_offset;
    let hex = |v: u32| as_short_hex_string(v as u64);
    let mut t = Table::new();
    // QUIRK(parity): the "Section Name" and "Segment Name" rows (16 bytes
    // each at +0 and +16) are never emitted; in the original their `AddRow`
    // call resolved to an empty template overload.
    let rest = if s.is64 {
        t.field(o + 32, 8, "Address", as_short_hex_string(s.addr));
        t.field(o + 40, 8, "Size", as_short_hex_string(s.size));
        o + 48
    } else {
        t.field(o + 32, 4, "Address", as_short_hex_string(s.addr));
        t.field(o + 36, 4, "Size", as_short_hex_string(s.size));
        o + 40
    };
    let fields = [
        ("Offset", s.offset),
        ("Alignment", s.align),
        ("Relocations Offset", s.reloff),
        ("Number of Relocations", s.nreloc),
        ("Flags", s.flags),
        ("Reserved1", s.reserved1),
        ("Reserved2", s.reserved2),
        ("Reserved3", s.reserved3),
    ];
    let count = if s.is64 { 8 } else { 7 };
    for (i, (desc, value)) in fields.into_iter().take(count).enumerate() {
        t.field(rest + 4 * i as u64, 4, desc, hex(value));
    }
    Content::table(t).with_binary(o, s.header_size())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(segname: &str, sectname: &str, flags: u32) -> Section {
        Section {
            header_offset: 0,
            is64: true,
            sectname: sectname.into(),
            segname: segname.into(),
            addr: 0,
            size: 0,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data_offset: 0,
            data_size: 0,
        }
    }

    /// 64-bit Mach-O with a single segment (vm address == file offset)
    /// holding the given `(segname, sectname, flags, reserved2, data)`
    /// sections back to back.
    fn macho(sections: &[(&str, &str, u32, u32, &[u8])]) -> Arc<MachHeader> {
        let put32 = |f: &mut Vec<u8>, v: u32| f.extend_from_slice(&v.to_le_bytes());
        let put64 = |f: &mut Vec<u8>, v: u64| f.extend_from_slice(&v.to_le_bytes());
        let name16 = |f: &mut Vec<u8>, n: &str| {
            let mut b = n.as_bytes().to_vec();
            b.resize(16, 0);
            f.extend_from_slice(&b);
        };
        let cmdsize = 72 + 80 * sections.len() as u32;
        let data_start = 32 + cmdsize as u64;
        let total = data_start + sections.iter().map(|s| s.4.len() as u64).sum::<u64>();
        let mut f = Vec::new();
        for v in [
            0xfeedfacfu32,
            0x0100_000c,
            0,
            2,
            1,
            cmdsize,
            0,
            0,
            0x19,
            cmdsize,
        ] {
            put32(&mut f, v);
        }
        name16(&mut f, "__DATA");
        for v in [0, 0x10000, 0, total] {
            put64(&mut f, v);
        }
        for v in [7, 3, sections.len() as u32, 0] {
            put32(&mut f, v);
        }
        let mut offset = data_start;
        for (seg, sect, flags, reserved2, data) in sections {
            name16(&mut f, sect);
            name16(&mut f, seg);
            put64(&mut f, offset);
            put64(&mut f, data.len() as u64);
            for v in [offset as u32, 0, 0, 0, *flags, 0, *reserved2, 0] {
                put32(&mut f, v);
            }
            offset += data.len() as u64;
        }
        for (.., data) in sections {
            f.extend_from_slice(data);
        }
        let image = Arc::new(crate::image::Image::from_vec(f).unwrap());
        Arc::new(MachHeader::parse(&image, 0).unwrap())
    }

    /// `(row size, cells)` of the only content view of section `index`.
    fn view_rows(mh: &Arc<MachHeader>, index: usize) -> Vec<(u64, Vec<String>)> {
        let node = section_node(mh.clone(), index).unwrap();
        let [child] = node.children() else {
            panic!("expected one content view")
        };
        assert_eq!(
            child.binary().map(|b| (b.offset, b.size)),
            node.binary().map(|b| (b.offset, b.size))
        );
        child
            .table()
            .unwrap()
            .rows
            .iter()
            .map(|r| (r.size, r.cells.clone()))
            .collect()
    }

    fn row(size: u64, cells: &[&str]) -> (u64, Vec<String>) {
        (size, cells.iter().map(|c| c.to_string()).collect())
    }

    #[test]
    fn literal_and_pointer_views() {
        let lit: Vec<u8> = (1..=20).collect();
        let ptrs: Vec<u8> = [0x1122u64, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .chain([9, 9, 9])
            .collect();
        let mh = macho(&[
            ("__TEXT", "__literal8", S_8BYTE_LITERALS, 0, &lit),
            ("__TEXT", "__literal16", S_16BYTE_LITERALS, 0, &lit),
            (
                "__DATA",
                "__mod_init_func",
                S_MOD_INIT_FUNC_POINTERS,
                0,
                &ptrs,
            ),
            (
                "__DATA",
                "__la_symbol_ptr",
                S_LAZY_SYMBOL_POINTERS,
                0,
                &ptrs,
            ),
            ("__TEXT", "__stubs", S_SYMBOL_STUBS, 6, &lit),
            ("__TEXT", "__nostubs", S_SYMBOL_STUBS, 0, &lit),
            (
                "__TEXT",
                "__cstring",
                S_CSTRING_LITERALS,
                0,
                b"\0ab\0\0c\0tail",
            ),
        ]);
        // Data starts after the header (32) and the segment command.
        assert_eq!(mh.sections().next().map(|s| s.data_offset), Some(664));
        assert_eq!(
            view_rows(&mh, 0),
            [
                row(
                    8,
                    &["00000298", "Floating Point Number", "0102030405060708"]
                ),
                row(
                    8,
                    &["000002A0", "Floating Point Number", "090A0B0C0D0E0F10"]
                ),
            ]
        );
        assert_eq!(
            view_rows(&mh, 1),
            [row(
                16,
                &[
                    "000002AC",
                    "Floating Point Number",
                    "0102030405060708090A0B0C0D0E0F10"
                ]
            )]
        );
        // A trailing partial pointer is ignored.
        assert_eq!(
            view_rows(&mh, 2),
            [
                row(8, &["000002C0", "Pointer", "2C0->1122"]),
                row(8, &["000002C8", "Pointer", "2C8->0"])
            ]
        );
        assert_eq!(
            view_rows(&mh, 3),
            [
                row(8, &["000002D3", "Indirect Pointer", "1122"]),
                row(8, &["000002DB", "Indirect Pointer", "0"])
            ]
        );
        let stubs = view_rows(&mh, 4);
        assert_eq!(stubs.len(), 3);
        assert_eq!(
            stubs[2],
            row(6, &["000002F2", "Indirect Stub", "0D0E0F101112"])
        );
        // A stub size of 0 yields no rows.
        assert!(view_rows(&mh, 5).is_empty());
        assert_eq!(
            view_rows(&mh, 6),
            [
                row(2, &["0", "0000030F", "2", "ab"]),
                row(1, &["1", "00000313", "1", "c"])
            ]
        );
    }

    #[test]
    fn objc_field_views() {
        let cfstrings: Vec<u8> = [0u64, 0x7c8, 0x4000, 13]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let info: Vec<u8> = [0u32, 0x45].iter().flat_map(|v| v.to_le_bytes()).collect();
        let refs: Vec<u8> = 0x5000u64.to_le_bytes().to_vec();
        let mh = macho(&[
            ("__DATA", "__cfstring", 0, 0, &cfstrings),
            ("__DATA", "__objc_imageinfo", 0, 0, &info),
            ("__DATA", "__objc_superrefs", 0, 0, &refs),
        ]);
        assert_eq!(
            view_rows(&mh, 0),
            [
                row(8, &["00000000", "CFString Ptr", "0"]),
                row(8, &["00000000", "Data", "7C8"]),
                row(8, &["00000000", "String", "4000"]),
                row(8, &["00000000", "Size", "0000000D"]),
                row(0, &["", "", "", ""]),
            ]
        );
        assert_eq!(
            view_rows(&mh, 1),
            [
                row(4, &["00000000", "Version", "0"]),
                row(4, &["00000000", "Flags", "45"]),
                row(0, &["", "0x1", "OBJC_IMAGE_IS_REPLACEMENT"]),
                row(0, &["", "0x4", "OBJC_IMAGE_GC_ONLY"]),
            ]
        );
        assert_eq!(
            view_rows(&mh, 2),
            [row(8, &["00000000", "Pointer", "5000"])]
        );
    }

    #[test]
    fn objc_protocol_cycle_is_expanded_once() {
        // Protocol at 0x110 whose protocol list (0x150) names itself twice,
        // and a method list (0x16a) claiming a huge relative entry size.
        let entries = 0x110u64.to_le_bytes().to_vec();
        let mut body: Vec<u8> = [0u64, 0x168, 0x150, 0x16a, 0, 0, 0, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        body.extend([2u64, 0x110, 0x110].iter().flat_map(|v| v.to_le_bytes()));
        body.extend_from_slice(b"P\0");
        body.extend([0x8000_000cu32, 5].iter().flat_map(|v| v.to_le_bytes()));
        let mh = macho(&[
            ("__DATA", "__objc_protolist", 0, 0, &entries),
            ("__DATA", "__objc_const", 0, 0, &body),
        ]);
        assert_eq!(
            view_rows(&mh, 0),
            [
                row(8, &["Entry", "#0", "", "00000110"]),
                row(64, &["Protocol", "  P", "", "00000110"]),
                row(
                    8,
                    &[
                        "MethodList",
                        "    instance",
                        "count=5 entsize=2147483660",
                        "0000016A"
                    ]
                ),
                row(8, &["ProtocolList", "    ", "count=2", "00000150"]),
                row(8, &["ProtocolRef", "      ", "", "00000110"]),
                row(8, &["ProtocolRef", "      ", "", "00000110"]),
            ]
        );
    }

    fn names(s: &Section) -> Vec<&'static str> {
        content_views(s).into_iter().map(|(name, _)| name).collect()
    }

    #[test]
    fn views_by_type_and_name() {
        assert_eq!(
            names(&section("__TEXT", "__text", 0x8000_0400)),
            ["Disassembly (Capstone)"]
        );
        assert_eq!(
            names(&section("__TEXT", "__cstring", S_CSTRING_LITERALS)),
            ["C String Literals"]
        );
        assert_eq!(
            names(&section("__TEXT", "__literal16", S_16BYTE_LITERALS)),
            ["Floating Point Literals"]
        );
        assert_eq!(
            names(&section(
                "__DATA",
                "__mod_term_func",
                S_MOD_TERM_FUNC_POINTERS
            )),
            ["Module Term Func Pointers"]
        );
        assert_eq!(
            names(&section("__TEXT", "__stubs", 0x8000_0408)),
            ["Symbol Stubs"]
        );
        // Type view first, then the name-based one.
        assert_eq!(
            names(&section("__DATA", "__objc_classrefs", 0x1000_0005)),
            ["Literal Pointers", "ObjC2 Class References"]
        );
        assert_eq!(
            names(&section("__DATA", "__objc_catlist", 0)),
            ["ObjC2 Category Metadata"]
        );
        assert_eq!(
            names(&section("__DATA_CONST", "__objc_classlist", 0)),
            Vec::<&str>::new()
        );
        assert_eq!(
            names(&section("__DATA_CONST", "__cfstring", 0)),
            ["ObjC CFStrings"]
        );
        assert_eq!(
            names(&section("__TEXT", "__swift5_types", 0)),
            ["Swift Metadata"]
        );
        assert_eq!(
            names(&section("__DATA", "__objc_imageinfo", 0)),
            ["ObjC2 Image Info"]
        );
        assert_eq!(
            names(&section("__OBJC", "__image_info", 0)),
            ["ObjC2 Image Info"]
        );
        assert_eq!(names(&section("__TEXT", "__const", 0)), Vec::<&str>::new());
    }
}
