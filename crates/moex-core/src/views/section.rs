//! One `Section(segment,section)` node: the fields of its `section` /
//! `section_64` header, plus child nodes interpreting the section contents
//! (strings, literals, pointers, stubs, disassembly, ObjC/Swift metadata).

mod disasm;
mod literals;
mod objc;
mod pointers;
mod swift;

use crate::hex::{as_short_hex_string, utf8_safe};
use crate::macho::ptr::{Fixups, Pointer, PointerDecoder};
use crate::macho::{MachHeader, Section};
use crate::view::{leaf, Content, NodeSource, Table, ViewNode};
use std::sync::{Arc, OnceLock};

/// `flags & SECTION_TYPE` selects the content type of a section.
pub const SECTION_TYPE: u32 = 0x0000_00ff;
pub const S_ZEROFILL: u32 = 0x1;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_4BYTE_LITERALS: u32 = 0x3;
pub const S_8BYTE_LITERALS: u32 = 0x4;
pub const S_LITERAL_POINTERS: u32 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
pub const S_GB_ZEROFILL: u32 = 0xc;
pub const S_16BYTE_LITERALS: u32 = 0xe;
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

/// What the section nodes of one Mach-O header share.
pub struct SectionContext {
    pub mh: Arc<MachHeader>,
    fixups: OnceLock<Arc<Fixups>>,
}

impl SectionContext {
    pub fn new(mh: Arc<MachHeader>) -> Arc<Self> {
        Arc::new(SectionContext {
            mh,
            fixups: OnceLock::new(),
        })
    }

    /// Decoder for the pointers stored in the image. The fixup tables
    /// behind it are read on first use and then shared by every view, so
    /// the cost does not grow with the number of sections.
    fn pointers(&self) -> PointerDecoder<'_> {
        let fixups = self.fixups.get_or_init(|| Arc::new(Fixups::read(&self.mh)));
        PointerDecoder::with_fixups(&self.mh, fixups.clone())
    }
}

struct SectionNode {
    context: Arc<SectionContext>,
    section: Section,
}

/// Node for the `section_index`-th section of the header's sections
/// (0-based, all segments in load-command order). `None` when the index is
/// out of range.
pub fn section_node(context: Arc<SectionContext>, section_index: usize) -> Option<ViewNode> {
    let section = context.mh.sections().nth(section_index)?.clone();
    Some(ViewNode::new(SectionNode { context, section }))
}

/// Builds the table of one content view.
#[derive(Clone, Copy)]
enum TableBuilder {
    /// From the bytes of the section alone.
    Plain(fn(&MachHeader, &Section) -> Table),
    /// Also following the pointers stored in the image.
    Pointers(fn(&SectionContext, &Section) -> Table),
}

impl TableBuilder {
    fn build(self, context: &SectionContext, section: &Section) -> Table {
        match self {
            TableBuilder::Plain(build) => build(&context.mh, section),
            TableBuilder::Pointers(build) => build(context, section),
        }
    }
}

/// The content views a section gets, as `(node name, table builder)` in
/// display order: first the one chosen by the section type, then those
/// chosen by segment/section name.
fn content_views(section: &Section) -> Vec<(&'static str, TableBuilder)> {
    use TableBuilder::{Plain, Pointers};
    let mut views: Vec<(&'static str, TableBuilder)> = Vec::new();
    match section.flags & SECTION_TYPE {
        S_CSTRING_LITERALS => views.push(("C String Literals", Plain(literals::cstrings))),
        S_4BYTE_LITERALS => views.push(("Floating Point Literals", Plain(literals::literals4))),
        S_8BYTE_LITERALS => views.push(("Floating Point Literals", Plain(literals::literals8))),
        S_16BYTE_LITERALS => views.push(("Floating Point Literals", Plain(literals::literals16))),
        S_LITERAL_POINTERS => views.push(("Literal Pointers", Pointers(pointers::pointers))),
        S_MOD_INIT_FUNC_POINTERS => {
            views.push(("Module Init Func Pointers", Pointers(pointers::pointers)))
        }
        S_MOD_TERM_FUNC_POINTERS => {
            views.push(("Module Term Func Pointers", Pointers(pointers::pointers)))
        }
        S_LAZY_SYMBOL_POINTERS => views.push((
            "Lazy Symbol Pointers",
            Pointers(pointers::indirect_pointers),
        )),
        S_NON_LAZY_SYMBOL_POINTERS => views.push((
            "Non-Lazy Symbol Pointers",
            Pointers(pointers::indirect_pointers),
        )),
        S_LAZY_DYLIB_SYMBOL_POINTERS => views.push((
            "Lazy Dylib Symbol Pointers",
            Pointers(pointers::indirect_pointers),
        )),
        S_SYMBOL_STUBS => views.push(("Symbol Stubs", Plain(pointers::symbol_stubs))),
        _ => {}
    }

    let sect = section.sectname.as_str();
    let seg = section.segname.as_str();
    // The ObjC sections are recognised by section name alone: linkers put
    // them in `__DATA`, `__DATA_CONST`, `__DATA_DIRTY`, `__AUTH`,
    // `__AUTH_CONST`, ... depending on platform and version. The `__OBJC2`
    // and `__OBJC` spellings are those of early ObjC 2 toolchains.
    let named = |modern: &[&str], legacy_seg: &str, legacy: &str| {
        modern.contains(&sect) || (seg == legacy_seg && sect == legacy)
    };
    if named(&["__objc_imageinfo"], "__OBJC", "__image_info") {
        views.push(("ObjC2 Image Info", Plain(objc::image_info)));
    }
    if sect == "__cfstring" {
        views.push(("ObjC CFStrings", Pointers(objc::cfstrings)));
    }
    if seg == "__TEXT" && sect == "__text" {
        views.push(("Disassembly (Capstone)", Plain(disasm::disassembly)));
    }
    if sect.starts_with("__swift5_") {
        views.push(("Swift Metadata", Plain(swift::metadata)));
    }
    if named(
        &["__objc_catlist", "__objc_nlcatlist"],
        "__OBJC2",
        "__category_list",
    ) {
        views.push(("ObjC2 Category Metadata", Pointers(objc::category_metadata)));
    }
    if named(
        &["__objc_classlist", "__objc_nlclslist"],
        "__OBJC2",
        "__class_list",
    ) {
        views.push(("ObjC2 Class Metadata", Pointers(objc::class_metadata)));
    }
    if named(&["__objc_classrefs"], "__OBJC2", "__class_refs") {
        views.push(("ObjC2 Class References", Pointers(objc::pointer_refs)));
    }
    if named(&["__objc_superrefs"], "__OBJC2", "__super_refs") {
        views.push(("ObjC2 Super References", Pointers(objc::pointer_refs)));
    }
    if named(&["__objc_protolist"], "__OBJC2", "__protocol_list") {
        views.push(("ObjC2 Protocol Metadata", Pointers(objc::protocol_metadata)));
    }
    views
}

/// Whether the section has no bytes in the file (its `offset` is unused).
fn is_zerofill(section: &Section) -> bool {
    matches!(
        section.flags & SECTION_TYPE,
        S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
    )
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
                let (context, section) = (self.context.clone(), self.section.clone());
                leaf(name, move || {
                    // A content view shows the bytes of the section
                    // contents (its parent shows the section header).
                    let content = Content::table(build.build(&context, &section));
                    if section.data_size == 0 || is_zerofill(&section) {
                        content
                    } else {
                        content.with_binary(section.data_offset, section.data_size as u64)
                    }
                })
            })
            .collect()
    }
}

/// File offset of each whole pointer-sized entry of the section contents;
/// the pointer width is that of the section header.
fn pointer_offsets(section: &Section) -> impl Iterator<Item = u64> + '_ {
    let step: u64 = if section.is64 { 8 } else { 4 };
    let count = section.data_size as u64 / step;
    (0..count).filter_map(move |i| section.data_offset.checked_add(i * step))
}

/// Display text of a decoded pointer: the address in hex, or the name of
/// the imported symbol it is bound to (with a non-zero addend appended).
fn pointer_text(pointer: Pointer<'_>) -> String {
    match pointer {
        Pointer::Address(address) => as_short_hex_string(address),
        Pointer::Import { name, addend } => {
            let mut text = if name.is_empty() {
                "<import>".to_string()
            } else {
                utf8_safe(name)
            };
            if addend != 0 {
                let sign = if addend < 0 { '-' } else { '+' };
                text.push_str(&format!(
                    "{sign}0x{}",
                    as_short_hex_string(addend.unsigned_abs())
                ));
            }
            text
        }
    }
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
    t.field(o, 16, "Section Name", s.sectname.clone());
    t.field(o + 16, 16, "Segment Name", s.segname.clone());
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
        let node = section_node(SectionContext::new(mh.clone()), index).unwrap();
        let [child] = node.children() else {
            panic!("expected one content view")
        };
        // The node shows the section header, its view the contents.
        let section = mh.sections().nth(index).unwrap();
        assert_eq!(
            node.binary().map(|b| (b.offset, b.size)),
            Some((section.header_offset, 80))
        );
        assert_eq!(
            child.binary().map(|b| (b.offset, b.size, b.start_value)),
            (section.data_size != 0).then_some((
                section.data_offset,
                section.data_size as u64,
                section.data_offset
            ))
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
    fn section_header_rows() {
        let mh = macho(&[("__TEXT", "__const", 0, 0, &[1, 2, 3])]);
        let node = section_node(SectionContext::new(mh.clone()), 0).unwrap();
        assert_eq!(node.name(), "Section(__TEXT,__const)");
        let rows: Vec<_> = node
            .table()
            .unwrap()
            .rows
            .iter()
            .map(|r| (r.offset, r.size, r.cells.clone()))
            .collect();
        let field = |offset: u64, size: u64, cells: &[&str]| {
            (
                Some(offset),
                size,
                cells.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(rows.len(), 12);
        assert_eq!(
            rows[..5],
            [
                field(0x68, 16, &["00000068", "Section Name", "__const"]),
                field(0x78, 16, &["00000078", "Segment Name", "__TEXT"]),
                field(0x88, 8, &["00000088", "Address", "B8"]),
                field(0x90, 8, &["00000090", "Size", "3"]),
                field(0x98, 4, &["00000098", "Offset", "B8"]),
            ]
        );
        // No content view for this section type and name.
        assert!(node.children().is_empty());
    }

    #[test]
    fn literal_and_pointer_views() {
        let floats: Vec<u8> = [1.5f32, -0.0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .chain([9, 9])
            .collect();
        let doubles: Vec<u8> = [1.0f64, -2.5e10]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let wide: Vec<u8> = [2.0f64.to_bits(), 0x7fff_ffff_ffff_ffff]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let lit: Vec<u8> = (1..=20).collect();
        let ptrs: Vec<u8> = [0x1122u64, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .chain([9, 9, 9])
            .collect();
        let mh = macho(&[
            ("__TEXT", "__literal4", S_4BYTE_LITERALS, 0, &floats),
            ("__TEXT", "__literal8", S_8BYTE_LITERALS, 0, &doubles),
            ("__TEXT", "__literal16", S_16BYTE_LITERALS, 0, &wide),
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
        assert_eq!(mh.sections().next().map(|s| s.data_offset), Some(0x2e8));
        // A trailing partial literal is ignored.
        assert_eq!(
            view_rows(&mh, 0),
            [
                row(4, &["000002E8", "Float", "1.5", "0000C03F"]),
                row(4, &["000002EC", "Float", "-0.0", "00000080"]),
            ]
        );
        assert_eq!(
            view_rows(&mh, 1),
            [
                row(8, &["000002F2", "Double", "1.0", "000000000000F03F"]),
                row(
                    8,
                    &["000002FA", "Double", "-25000000000.0", "000000E8764817C2"]
                ),
            ]
        );
        assert_eq!(
            view_rows(&mh, 2),
            [row(
                16,
                &[
                    "00000302",
                    "16-byte Literal",
                    "0x7FFFFFFFFFFFFFFF4000000000000000 (doubles: 2.0, NaN)",
                    "0000000000000040FFFFFFFFFFFFFF7F"
                ]
            )]
        );
        let headers = |index: usize| {
            let node = section_node(SectionContext::new(mh.clone()), index).unwrap();
            node.children()[0].table().unwrap().headers.clone()
        };
        assert_eq!(headers(0), ["Offset", "Description", "Value", "Bytes"]);
        assert_eq!(headers(3), ["Offset", "Description", "Value"]);
        // A trailing partial pointer is ignored.
        assert_eq!(
            view_rows(&mh, 3),
            [
                row(8, &["00000312", "Pointer", "312->1122"]),
                row(8, &["0000031A", "Pointer", "31A->0"])
            ]
        );
        assert_eq!(
            view_rows(&mh, 4),
            [
                row(8, &["00000325", "Indirect Pointer", "1122"]),
                row(8, &["0000032D", "Indirect Pointer", "0"])
            ]
        );
        let stubs = view_rows(&mh, 5);
        assert_eq!(stubs.len(), 3);
        assert_eq!(
            stubs[2],
            row(6, &["00000344", "Indirect Stub", "0D0E0F101112"])
        );
        // A stub size of 0 yields no rows.
        assert!(view_rows(&mh, 6).is_empty());
        assert_eq!(
            view_rows(&mh, 7),
            [
                row(2, &["0", "00000361", "2", "ab"]),
                row(1, &["1", "00000365", "1", "c"])
            ]
        );
    }

    #[test]
    fn pointer_texts() {
        assert_eq!(pointer_text(Pointer::Address(0x1f00)), "1F00");
        let import = |name: &'static [u8], addend: i64| Pointer::Import { name, addend };
        assert_eq!(pointer_text(import(b"_objc_msgSend", 0)), "_objc_msgSend");
        assert_eq!(pointer_text(import(b"_tbl", 0x10)), "_tbl+0x10");
        assert_eq!(pointer_text(import(b"_tbl", -8)), "_tbl-0x8");
        assert_eq!(pointer_text(import(b"", 0)), "<import>");
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
            ("__DATA_CONST", "__objc_imageinfo", 0, 0, &info),
            ("__AUTH_CONST", "__objc_superrefs", 0, 0, &refs),
        ]);
        // The first column is the file offset of each field.
        assert_eq!(
            view_rows(&mh, 0),
            [
                row(8, &["00000158", "CFString Ptr", "0"]),
                row(8, &["00000160", "Data", "7C8"]),
                row(8, &["00000168", "String", "4000"]),
                row(8, &["00000170", "Size", "0000000D"]),
                row(0, &["", "", "", ""]),
            ]
        );
        assert_eq!(
            view_rows(&mh, 1),
            [
                row(4, &["00000178", "Version", "0"]),
                row(4, &["0000017C", "Flags", "45"]),
                row(0, &["", "0x1", "OBJC_IMAGE_IS_REPLACEMENT"]),
                row(0, &["", "0x4", "OBJC_IMAGE_GC_ONLY"]),
                row(0, &["", "0x40", "OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES"]),
            ]
        );
        assert_eq!(
            view_rows(&mh, 2),
            [row(8, &["00000180", "Pointer", "5000"])]
        );
        // Three-cell rows under three headers.
        for index in 0..3 {
            let node = section_node(SectionContext::new(mh.clone()), index).unwrap();
            assert_eq!(
                node.children()[0].table().unwrap().headers,
                ["Offset", "Description", "Value"]
            );
        }
    }

    #[test]
    fn objc_protocol_cycle_is_expanded_once() {
        // Protocol at 0x110 whose protocol list (0x150) names itself twice,
        // and a relative method list (0x16a, selectors direct) that claims
        // five entries of which one is in the file.
        let entries = 0x110u64.to_le_bytes().to_vec();
        let mut body: Vec<u8> = [0u64, 0x168, 0x150, 0x16a, 0, 0, 0, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        body.extend([2u64, 0x110, 0x110].iter().flat_map(|v| v.to_le_bytes()));
        body.extend_from_slice(b"P\0");
        body.extend([0xc000_000cu32, 5].iter().flat_map(|v| v.to_le_bytes()));
        // name -> 0x168 ("P"), types -> 0x169 (""), no implementation.
        body.extend([-10i32, -13, 0].iter().flat_map(|v| v.to_le_bytes()));
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
                        "count=5 entsize=12 (relative)",
                        "0000016A"
                    ]
                ),
                row(12, &["Method", "      P", "imp=0x0", "00000172"]),
                row(8, &["ProtocolList", "    ", "count=2", "00000150"]),
                row(8, &["ProtocolRef", "      ", "", "00000110"]),
                row(8, &["ProtocolRef", "      ", "", "00000110"]),
            ]
        );
    }

    /// Appends pieces to a section body and tells where each one lands.
    struct Body {
        base: u64,
        bytes: Vec<u8>,
    }

    impl Body {
        fn here(&self) -> u64 {
            self.base + self.bytes.len() as u64
        }
        fn bytes(&mut self, b: &[u8]) -> u64 {
            let at = self.here();
            self.bytes.extend_from_slice(b);
            at
        }
        fn align8(&mut self) {
            while !self.here().is_multiple_of(8) {
                self.bytes.push(0);
            }
        }
        fn u32s(&mut self, v: &[u32]) -> u64 {
            let b: Vec<u8> = v.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.bytes(&b)
        }
        fn u64s(&mut self, v: &[u64]) -> u64 {
            let b: Vec<u8> = v.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.bytes(&b)
        }
    }

    #[test]
    fn objc_class_tree() {
        // Two sections: the class list (one pointer) and everything else.
        let mut b = Body {
            base: 264 + 8,
            bytes: Vec::new(),
        };
        let name = b.bytes(b"Person\0");
        let sel = b.bytes(b"greet:\0");
        let types = b.bytes(b"v24@0:8@16\0");
        let ivar_name = b.bytes(b"_age\0");
        let ivar_type = b.bytes(b"i\0");
        let prop_name = b.bytes(b"age\0");
        let prop_attrs = b.bytes(b"Ti,N\0\0\0\0");
        // The ivar offset is a 32-bit variable; what follows is not part
        // of it.
        let offset_var = b.u32s(&[8, 0xffff_ffff]);
        let selref = b.u64s(&[sel]);
        // Relative method list: the name goes through the selector
        // reference.
        let methods = b.u32s(&[0x8000_000c, 1]);
        let entry = b.here();
        let imp = 0x4000u64;
        b.u32s(&[
            selref.wrapping_sub(entry) as u32,
            types.wrapping_sub(entry + 4) as u32,
            imp.wrapping_sub(entry + 8) as u32,
            0,
        ]);
        // Pointer method list with the "uniqued" and "sorted" flag bits.
        let class_methods = b.u32s(&[24 | 3, 1]);
        b.u64s(&[sel, types, 0x4444]);
        let ivars = b.u32s(&[32, 1]);
        b.u64s(&[offset_var, ivar_name, ivar_type]);
        b.u32s(&[2, 4]);
        let props = b.u32s(&[16, 1]);
        b.u64s(&[prop_name, prop_attrs]);
        // `class_ro_t` is 8-aligned: the low bits of a pointer to it are
        // flags.
        b.align8();
        let meta_ro = b.u32s(&[1, 40, 40, 0]);
        b.u64s(&[0, name, class_methods, 0, 0, 0, 0]);
        let ro = b.u32s(&[0, 8, 12, 0]);
        b.u64s(&[0, name, methods, 0, ivars, 0, props]);
        let class = b.here() + 40;
        let meta = b.u64s(&[0, class, 0, 0, meta_ro]);
        // The low bits of `data` are flags.
        assert_eq!(b.u64s(&[meta, 0, 0, 0, ro | 1]), class);

        let mh = macho(&[
            (
                "__DATA_CONST",
                "__objc_classlist",
                0,
                0,
                &class.to_le_bytes(),
            ),
            ("__DATA", "__objc_const", 0, 0, &b.bytes),
        ]);
        let a = as_address_cell;
        assert_eq!(
            view_rows(&mh, 0),
            [
                row(8, &["Entry", "#0", "", &a(class)]),
                row(40, &["Class", "  Person", "instance", &a(class)]),
                row(
                    8,
                    &[
                        "MethodList",
                        "    base",
                        "count=1 entsize=12 (relative)",
                        &a(methods)
                    ]
                ),
                row(
                    12,
                    &["Method", "      greet:", "v24@0:8@16 imp=0x4000", &a(entry)]
                ),
                row(8, &["IvarList", "    ", "count=1 entsize=32", &a(ivars)]),
                row(
                    32,
                    &["Ivar", "      _age", "i offset=8 size=4", &a(ivars + 8)]
                ),
                row(
                    8,
                    &["PropertyList", "    ", "count=1 entsize=16", &a(props)]
                ),
                row(16, &["Property", "      age", "Ti,N", &a(props + 8)]),
                // The metaclass, with the class methods.
                row(40, &["Class", "    Person", "meta", &a(meta)]),
                row(8, &["Superclass", "      Person", "", &a(class)]),
                row(
                    8,
                    &[
                        "MethodList",
                        "      base",
                        "count=1 entsize=24",
                        &a(class_methods)
                    ]
                ),
                row(
                    24,
                    &[
                        "Method",
                        "        greet:",
                        "v24@0:8@16 imp=0x4444",
                        &a(class_methods + 8)
                    ]
                ),
            ]
        );
    }

    fn as_address_cell(v: u64) -> String {
        crate::hex::as_address(v)
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
        // ObjC sections are recognised in any segment.
        for seg in ["__DATA", "__DATA_CONST", "__DATA_DIRTY", "__AUTH_CONST"] {
            assert_eq!(
                names(&section(seg, "__objc_classlist", 0)),
                ["ObjC2 Class Metadata"]
            );
            assert_eq!(
                names(&section(seg, "__objc_protolist", 0)),
                ["ObjC2 Protocol Metadata"]
            );
            assert_eq!(
                names(&section(seg, "__objc_superrefs", 0)),
                ["ObjC2 Super References"]
            );
            assert_eq!(
                names(&section(seg, "__objc_imageinfo", 0)),
                ["ObjC2 Image Info"]
            );
        }
        assert_eq!(
            names(&section("__DATA", "__objc_nlclslist", 0)),
            ["ObjC2 Class Metadata"]
        );
        assert_eq!(
            names(&section("__DATA", "__objc_nlcatlist", 0)),
            ["ObjC2 Category Metadata"]
        );
        // The legacy spellings only count in their own segment.
        assert_eq!(
            names(&section("__OBJC2", "__class_list", 0)),
            ["ObjC2 Class Metadata"]
        );
        assert_eq!(
            names(&section("__DATA", "__class_list", 0)),
            Vec::<&str>::new()
        );
        assert_eq!(
            names(&section("__DATA", "__image_info", 0)),
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
