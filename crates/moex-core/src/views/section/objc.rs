//! ObjC views: image info, CFStrings, class/super reference lists and the
//! class / category / protocol metadata trees.

use super::{pointer_offsets, pointer_text, SectionContext};
use crate::hex::{as_address, as_hex_string, as_short_hex_string, utf8_safe};
use crate::macho::objc::{
    CfString, ObjcCategory, ObjcClass, ObjcClassRo, ObjcImageInfo, ObjcIvar, ObjcLayout,
    ObjcListHeader, ObjcMethod, ObjcProperty, ObjcProtocol, ObjcResolver, LIST_HEADER_SIZE,
};
use crate::macho::ptr::Pointer;
use crate::macho::{MachHeader, Section};
use crate::view::Table;
use std::collections::HashSet;

/// "ObjC2 Image Info": the `objc_image_info` at the start of the section.
pub(super) fn image_info(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    let o = section.data_offset;
    // The struct is read where the section says it is, whatever the section
    // size; nothing is shown when it does not fit in the file.
    let Some(info) = ObjcImageInfo::read(&mh.image, o) else {
        return t;
    };
    t.field(o, 4, "Version", as_short_hex_string(info.version as u64));
    t.field(o + 4, 4, "Flags", as_short_hex_string(info.flags as u64));
    for (bit, name) in info.flag_names() {
        t.add(["".to_string(), format!("0x{bit:x}"), name.to_string()]);
    }
    if info.swift_version() != 0 {
        t.add([
            "".to_string(),
            format!("0x{:x}", info.flags & 0xff00),
            format!("Swift ABI version {}", info.swift_version()),
        ]);
    }
    t
}

/// Resolver for the metadata `section` belongs to, sharing the fixup tables
/// of the image.
fn resolver<'a>(context: &'a SectionContext, section: &Section) -> ObjcResolver<'a> {
    ObjcResolver::with_decoder(&context.mh, section.is64, context.pointers())
}

/// "ObjC CFStrings": the four words of each constant string object.
pub(super) fn cfstrings(context: &SectionContext, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_widths(&[100, 160, 420]);
    let r = resolver(context, section);
    let (word, entry) = (r.layout.ptr_size(), r.layout.cfstring_size());
    for i in 0..section.data_size as u64 / entry {
        let o = section.data_offset + i * entry;
        let (Some(s), Some(isa)) = (CfString::read(&r, o), r.pointer_at(o)) else {
            break;
        };
        t.field(o, word, "CFString Ptr", pointer_text(isa));
        t.field(o + word, word, "Data", as_short_hex_string(s.data));
        t.field(o + 2 * word, word, "String", as_short_hex_string(s.cstr));
        t.field(o + 3 * word, word, "Size", as_hex_string(s.size));
        t.separator();
    }
    t
}

/// "ObjC2 Class References" / "ObjC2 Super References": each pointer.
pub(super) fn pointer_refs(context: &SectionContext, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_widths(&[100, 160, 420]);
    let r = resolver(context, section);
    let size = ObjcLayout { is64: section.is64 }.ptr_size();
    for offset in pointer_offsets(section) {
        let Some(pointer) = r.pointer_at(offset) else {
            break;
        };
        t.field(offset, size, "Pointer", pointer_text(pointer));
    }
    t
}

pub(super) fn class_metadata(context: &SectionContext, section: &Section) -> Table {
    metadata(context, section, Kind::Classes)
}

pub(super) fn category_metadata(context: &SectionContext, section: &Section) -> Table {
    metadata(context, section, Kind::Categories)
}

pub(super) fn protocol_metadata(context: &SectionContext, section: &Section) -> Table {
    metadata(context, section, Kind::Protocols)
}

#[derive(Clone, Copy)]
enum Kind {
    Classes,
    Categories,
    Protocols,
}

/// A list claiming more entries than this is rejected as corrupt.
const MAX_LIST_COUNT: u64 = 100_000;

/// Upper bound on the rows of one metadata table. Lists may be shared by
/// any number of classes, so a crafted file could otherwise expand to
/// billions of rows; real binaries stay far below this.
const MAX_ROWS: usize = 2_000_000;

/// Protocols nest through their protocol lists; indentation deeper than
/// this (about a hundred levels) is not followed, to bound recursion.
const MAX_DEPTH: usize = 200;

fn indent(depth: usize) -> String {
    " ".repeat(depth * 2)
}

fn safe_name(value: &[u8], fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        utf8_safe(value)
    }
}

struct Walker<'a> {
    r: ObjcResolver<'a>,
    t: Table,
    visited_classes: HashSet<u64>,
    visited_protocols: HashSet<u64>,
}

impl Walker<'_> {
    fn full(&self) -> bool {
        self.t.rows.len() >= MAX_ROWS
    }

    /// Row whose bytes are the `size` bytes at file offset `offset`.
    fn row(
        &mut self,
        offset: u64,
        size: u64,
        kind: &str,
        name: String,
        detail: String,
        vmaddr: u64,
    ) {
        self.t.add_data(
            offset,
            size,
            [kind.to_string(), name, detail, as_address(vmaddr)],
        );
    }

    /// Row for something at `vmaddr` that could not be read; it has no
    /// bytes.
    fn unreadable(&mut self, vmaddr: u64, kind: &str, name: String, detail: &str) {
        self.t.add([
            kind.to_string(),
            name,
            detail.to_string(),
            as_address(vmaddr),
        ]);
    }

    /// Reads the `{ entsize, count }` header of the list at `list_vmaddr`.
    fn list_header(&self, list_vmaddr: u64) -> Option<(u64, ObjcListHeader)> {
        let off = self.r.struct_offset(list_vmaddr, LIST_HEADER_SIZE)?;
        Some((off, ObjcListHeader::read(self.r.image(), off)?))
    }

    fn method_list(&mut self, list_vmaddr: u64, depth: usize, method_kind: &str) {
        if list_vmaddr == 0 {
            return;
        }
        let image = self.r.image();
        let title = format!("{}{}", indent(depth), method_kind);
        let Some((list_off, list)) = self.list_header(list_vmaddr) else {
            self.unreadable(list_vmaddr, "MethodList?", title, "unmapped");
            return;
        };
        let relative = list.has_relative_methods();
        let entry_size = list.method_entry_size() as u64;
        let min_size = if relative {
            self.r.layout.relative_method_size()
        } else {
            self.r.layout.method_size()
        };
        if entry_size < min_size || list.count as u64 > MAX_LIST_COUNT {
            self.row(
                list_off,
                LIST_HEADER_SIZE,
                "MethodList?",
                title,
                "invalid entsize/count".to_string(),
                list_vmaddr,
            );
            return;
        }
        let detail = format!(
            "count={} entsize={}{}",
            list.count,
            entry_size,
            if relative { " (relative)" } else { "" }
        );
        self.row(
            list_off,
            LIST_HEADER_SIZE,
            "MethodList",
            title,
            detail,
            list_vmaddr,
        );
        for i in 0..list.count as u64 {
            let delta = LIST_HEADER_SIZE + i * entry_size;
            let cur = list_off + delta;
            if self.full() || !image.in_file(cur, entry_size) {
                break;
            }
            let entry_vmaddr = list_vmaddr.wrapping_add(delta);
            let method = if relative {
                ObjcMethod::read_relative(&self.r, cur, entry_vmaddr, list.has_direct_selectors())
            } else {
                ObjcMethod::read(&self.r, cur)
            };
            let Some(m) = method else {
                break;
            };
            let name = safe_name(self.r.cstring(m.name), "<unnamed>");
            let mut detail = utf8_safe(self.r.cstring(m.types));
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&format!("imp=0x{}", as_short_hex_string(m.imp)));
            self.row(
                cur,
                entry_size,
                "Method",
                format!("{}{}", indent(depth + 1), name),
                detail,
                entry_vmaddr,
            );
        }
    }

    fn property_list(&mut self, list_vmaddr: u64, depth: usize) {
        if list_vmaddr == 0 {
            return;
        }
        let image = self.r.image();
        let Some((list_off, list)) = self.list_header(list_vmaddr) else {
            self.unreadable(list_vmaddr, "PropertyList?", indent(depth), "unmapped");
            return;
        };
        // Property lists keep no flags in `entsize`.
        let entry_size = list.entsize as u64;
        if entry_size < self.r.layout.property_size() || list.count as u64 > MAX_LIST_COUNT {
            self.row(
                list_off,
                LIST_HEADER_SIZE,
                "PropertyList?",
                indent(depth),
                "invalid entsize/count".to_string(),
                list_vmaddr,
            );
            return;
        }
        let detail = format!("count={} entsize={}", list.count, entry_size);
        self.row(
            list_off,
            LIST_HEADER_SIZE,
            "PropertyList",
            indent(depth),
            detail,
            list_vmaddr,
        );
        for i in 0..list.count as u64 {
            let delta = LIST_HEADER_SIZE + i * entry_size;
            let cur = list_off.saturating_add(delta);
            if self.full() || !image.in_file(cur, entry_size) {
                break;
            }
            let Some(p) = ObjcProperty::read(&self.r, cur) else {
                break;
            };
            let name = safe_name(self.r.cstring(p.name), "<property>");
            let attributes = utf8_safe(self.r.cstring(p.attributes));
            self.row(
                cur,
                entry_size,
                "Property",
                format!("{}{}", indent(depth + 1), name),
                attributes,
                list_vmaddr.wrapping_add(delta),
            );
        }
    }

    fn ivar_list(&mut self, list_vmaddr: u64, depth: usize) {
        if list_vmaddr == 0 {
            return;
        }
        let image = self.r.image();
        let Some((list_off, list)) = self.list_header(list_vmaddr) else {
            self.unreadable(list_vmaddr, "IvarList?", indent(depth), "unmapped");
            return;
        };
        // Ivar lists keep no flags in `entsize`.
        let entry_size = list.entsize as u64;
        if entry_size < self.r.layout.ivar_size() || list.count as u64 > MAX_LIST_COUNT {
            self.row(
                list_off,
                LIST_HEADER_SIZE,
                "IvarList?",
                indent(depth),
                "invalid entsize/count".to_string(),
                list_vmaddr,
            );
            return;
        }
        let detail = format!("count={} entsize={}", list.count, entry_size);
        self.row(
            list_off,
            LIST_HEADER_SIZE,
            "IvarList",
            indent(depth),
            detail,
            list_vmaddr,
        );
        for i in 0..list.count as u64 {
            let delta = LIST_HEADER_SIZE + i * entry_size;
            let cur = list_off.saturating_add(delta);
            if self.full() || !image.in_file(cur, entry_size) {
                break;
            }
            let Some(iv) = ObjcIvar::read(&self.r, cur) else {
                break;
            };
            let name = safe_name(self.r.cstring(iv.name), "<ivar>");
            let type_ = utf8_safe(self.r.cstring(iv.type_));
            // `offset` points at a 32-bit variable holding the offset; it is
            // null for an ivar without storage (a bit-field, an empty type).
            let ivar_offset = match self.r.u32_at(iv.offset) {
                Some(value) => value.to_string(),
                None if iv.offset == 0 => "-".to_string(),
                None => "?".to_string(),
            };
            let detail = format!("{} offset={} size={}", type_, ivar_offset, iv.size);
            self.row(
                cur,
                entry_size,
                "Ivar",
                format!("{}{}", indent(depth + 1), name),
                detail,
                list_vmaddr.wrapping_add(delta),
            );
        }
    }

    fn protocol(&mut self, protocol_vmaddr: u64, depth: usize) {
        if protocol_vmaddr == 0 || !self.visited_protocols.insert(protocol_vmaddr) {
            return;
        }
        if depth > MAX_DEPTH || self.full() {
            return;
        }
        let size = self.r.layout.protocol_size();
        let proto = self
            .r
            .struct_offset(protocol_vmaddr, size)
            .and_then(|off| Some((off, ObjcProtocol::read(&self.r, off)?)));
        let Some((off, proto)) = proto else {
            self.unreadable(protocol_vmaddr, "Protocol?", indent(depth), "unmapped");
            return;
        };
        let name = safe_name(self.r.cstring(proto.name), "<protocol>");
        self.row(
            off,
            size,
            "Protocol",
            format!("{}{}", indent(depth), name),
            String::new(),
            protocol_vmaddr,
        );
        self.method_list(proto.instance_methods, depth + 1, "instance");
        self.method_list(proto.class_methods, depth + 1, "class");
        self.method_list(
            proto.optional_instance_methods,
            depth + 1,
            "optional-instance",
        );
        self.method_list(proto.optional_class_methods, depth + 1, "optional-class");
        self.property_list(proto.instance_properties, depth + 1);
        self.protocol_list(proto.protocols, depth + 1);
    }

    fn protocol_list(&mut self, list_vmaddr: u64, depth: usize) {
        if list_vmaddr == 0 {
            return;
        }
        let word = self.r.layout.ptr_size();
        let header_size = self.r.layout.protocol_list_header_size();
        let Some(list_off) = self.r.struct_offset(list_vmaddr, header_size) else {
            self.unreadable(list_vmaddr, "ProtocolList?", indent(depth), "unmapped");
            return;
        };
        // The count is a plain pointer-sized integer.
        let Some(count) = self.r.address_at(list_off) else {
            return;
        };
        if count > MAX_LIST_COUNT {
            self.row(
                list_off,
                header_size,
                "ProtocolList?",
                indent(depth),
                "invalid count".to_string(),
                list_vmaddr,
            );
            return;
        }
        self.row(
            list_off,
            header_size,
            "ProtocolList",
            indent(depth),
            format!("count={count}"),
            list_vmaddr,
        );
        let mut cur = list_off + header_size;
        for _ in 0..count {
            if self.full() {
                break;
            }
            let Some(protocol_ptr) = self.r.address_at(cur) else {
                break;
            };
            self.row(
                cur,
                word,
                "ProtocolRef",
                indent(depth + 1),
                String::new(),
                protocol_ptr,
            );
            self.protocol(protocol_ptr, depth + 1);
            cur += word;
        }
    }

    /// `class_t` and `class_ro_t` of the class at `class_vmaddr`, with the
    /// file offset of the former.
    fn read_class(&self, class_vmaddr: u64) -> Option<(u64, ObjcClass, Option<ObjcClassRo>)> {
        let is64 = self.r.is64();
        let off = self
            .r
            .struct_offset(class_vmaddr, self.r.layout.class_size())?;
        let cls = ObjcClass::read(&self.r, off)?;
        let ro = self
            .r
            .struct_offset(cls.ro_address(is64), self.r.layout.class_ro_size())
            .and_then(|ro_off| ObjcClassRo::read(&self.r, ro_off));
        Some((off, cls, ro))
    }

    /// Row for the class pointer stored at file offset `field_off` (a
    /// superclass or a category's class): the class name when it is in this
    /// image, the symbol when it is imported; nothing for a null pointer.
    /// Returns the address of a class of this image.
    fn class_reference(&mut self, field_off: u64, kind: &str, depth: usize) -> Option<u64> {
        let word = self.r.layout.ptr_size();
        match self.r.pointer_at(field_off)? {
            Pointer::Address(0) => None,
            Pointer::Address(address) => {
                let name = self
                    .read_class(address)
                    .and_then(|(_, _, ro)| ro)
                    .map(|ro| utf8_safe(self.r.cstring(ro.name)))
                    .unwrap_or_default();
                self.row(
                    field_off,
                    word,
                    kind,
                    format!("{}{}", indent(depth), name),
                    String::new(),
                    address,
                );
                Some(address)
            }
            import @ Pointer::Import { .. } => {
                self.t.add_data(
                    field_off,
                    word,
                    [
                        kind.to_string(),
                        format!("{}{}", indent(depth), pointer_text(import)),
                        "import".to_string(),
                        String::new(),
                    ],
                );
                None
            }
        }
    }

    /// The class at `class_vmaddr`; `with_metaclass` also expands its
    /// metaclass (which holds the class methods) below it.
    fn class(&mut self, class_vmaddr: u64, depth: usize, with_metaclass: bool) {
        if class_vmaddr == 0 || !self.visited_classes.insert(class_vmaddr) {
            return;
        }
        let class_size = self.r.layout.class_size();
        let Some((cls_off, cls, ro)) = self.read_class(class_vmaddr) else {
            self.unreadable(class_vmaddr, "Class?", indent(depth), "unmapped");
            return;
        };
        let Some(ro) = ro else {
            self.row(
                cls_off,
                class_size,
                "Class?",
                indent(depth),
                "missing class_ro".to_string(),
                class_vmaddr,
            );
            return;
        };
        let name = safe_name(self.r.cstring(ro.name), "<class>");
        let meta = if ro.is_meta() { "meta" } else { "instance" };
        self.row(
            cls_off,
            class_size,
            "Class",
            format!("{}{}", indent(depth), name),
            meta.to_string(),
            class_vmaddr,
        );
        self.class_reference(cls_off + self.r.layout.ptr_size(), "Superclass", depth + 1);
        self.method_list(ro.base_methods, depth + 1, "base");
        self.ivar_list(ro.ivars, depth + 1);
        self.property_list(ro.base_properties, depth + 1);
        self.protocol_list(ro.base_protocols, depth + 1);
        if with_metaclass && !ro.is_meta() {
            self.class(cls.isa, depth + 1, false);
        }
    }

    fn category(&mut self, category_vmaddr: u64, depth: usize) {
        if category_vmaddr == 0 {
            return;
        }
        let size = self.r.layout.category_size();
        let cat = self
            .r
            .struct_offset(category_vmaddr, size)
            .and_then(|off| Some((off, ObjcCategory::read(&self.r, off)?)));
        let Some((off, cat)) = cat else {
            self.unreadable(category_vmaddr, "Category?", indent(depth), "unmapped");
            return;
        };
        let name = safe_name(self.r.cstring(cat.name), "<category>");
        self.row(
            off,
            size,
            "Category",
            format!("{}{}", indent(depth), name),
            String::new(),
            category_vmaddr,
        );
        let class_field = off + self.r.layout.ptr_size();
        if let Some(class_vmaddr) = self.class_reference(class_field, "ClassRef", depth + 1) {
            self.class(class_vmaddr, depth + 2, true);
        }
        self.method_list(cat.instance_methods, depth + 1, "instance");
        self.method_list(cat.class_methods, depth + 1, "class");
        self.property_list(cat.instance_properties, depth + 1);
        self.protocol_list(cat.protocols, depth + 1);
    }
}

/// "ObjC2 Class Metadata" / "ObjC2 Category Metadata" / "ObjC2 Protocol
/// Metadata": one `Entry` row per pointer of the list section, each followed
/// by the indented tree of what it points to. A class or protocol is
/// expanded only the first time it is reached.
fn metadata(context: &SectionContext, section: &Section, kind: Kind) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Kind", "Name", "Details", "VM Address"]);
    t.set_widths(&[160, 360, 460, 180]);
    let r = resolver(context, section);
    let word = r.layout.ptr_size();
    let mut w = Walker {
        r,
        t,
        visited_classes: HashSet::new(),
        visited_protocols: HashSet::new(),
    };
    for (index, offset) in pointer_offsets(section).enumerate() {
        if w.full() {
            w.t.add([
                "...".to_string(),
                String::new(),
                "row limit reached".to_string(),
                String::new(),
            ]);
            break;
        }
        let Some(pointer) = w.r.pointer_at(offset) else {
            break;
        };
        let target = match pointer {
            Pointer::Address(address) => address,
            Pointer::Import { .. } => {
                w.t.add_data(
                    offset,
                    word,
                    [
                        "Entry".to_string(),
                        format!("#{index}"),
                        format!("import {}", pointer_text(pointer)),
                        String::new(),
                    ],
                );
                continue;
            }
        };
        w.row(
            offset,
            word,
            "Entry",
            format!("#{index}"),
            String::new(),
            target,
        );
        match kind {
            Kind::Classes => w.class(target, 1, true),
            Kind::Categories => w.category(target, 1),
            Kind::Protocols => w.protocol(target, 1),
        }
    }
    w.t
}
