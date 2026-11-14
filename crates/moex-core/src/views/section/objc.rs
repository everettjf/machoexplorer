//! ObjC views: image info, CFStrings, class/super reference lists and the
//! class / category / protocol metadata trees.

use super::pointer_entries;
use crate::hex::{as_address, as_hex_string, as_short_hex_string, utf8_safe};
use crate::macho::objc::{
    CfString, ObjcCategory, ObjcClass, ObjcClassRo, ObjcImageInfo, ObjcIvar, ObjcLayout,
    ObjcListHeader, ObjcMethod, ObjcProperty, ObjcProtocol, ObjcResolver, LIST_HEADER_SIZE,
};
use crate::macho::{MachHeader, Section};
use crate::view::Table;
use std::collections::HashSet;

// QUIRK(parity): the tables below that are built from individual struct
// fields have no offset resolver in the original, so their first column is
// always `00000000` instead of the field's file offset.
fn field_row(t: &mut Table, offset: u64, size: u64, desc: &str, value: String) {
    t.add_data(offset, size, [as_address(0), desc.to_string(), value]);
}

/// "ObjC2 Image Info": the `objc_image_info` at the start of the section.
pub(super) fn image_info(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    let o = section.data_offset;
    // The struct is read where the section says it is, whatever the section
    // size; nothing is shown when it does not fit in the file.
    let Some(info) = ObjcImageInfo::read(&mh.image, o) else {
        return t;
    };
    field_row(
        &mut t,
        o,
        4,
        "Version",
        as_short_hex_string(info.version as u64),
    );
    field_row(
        &mut t,
        o + 4,
        4,
        "Flags",
        as_short_hex_string(info.flags as u64),
    );
    for (bit, name) in info.flag_names() {
        t.add(["".to_string(), format!("0x{bit:x}"), name.to_string()]);
    }
    t
}

/// "ObjC CFStrings": the four words of each constant string object.
pub(super) fn cfstrings(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Index", "Offset", "Length", "String"]);
    t.set_widths(&[80, 100, 100, 80, 400]);
    let layout = ObjcLayout { is64: section.is64 };
    let (word, entry) = (layout.ptr_size(), layout.cfstring_size());
    for i in 0..section.data_size as u64 / entry {
        let o = section.data_offset + i * entry;
        let Some(s) = CfString::read(&mh.image, o, section.is64) else {
            break;
        };
        field_row(&mut t, o, word, "CFString Ptr", as_short_hex_string(s.ptr));
        field_row(&mut t, o + word, word, "Data", as_short_hex_string(s.data));
        field_row(
            &mut t,
            o + 2 * word,
            word,
            "String",
            as_short_hex_string(s.cstr),
        );
        field_row(&mut t, o + 3 * word, word, "Size", as_hex_string(s.size));
        t.separator();
    }
    t
}

/// "ObjC2 Class References" / "ObjC2 Super References": each pointer.
pub(super) fn pointer_refs(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Index", "Offset", "Length", "String"]);
    t.set_widths(&[80, 100, 100, 80, 400]);
    let size = ObjcLayout { is64: section.is64 }.ptr_size();
    for (offset, value) in pointer_entries(mh, section) {
        field_row(&mut t, offset, size, "Pointer", as_short_hex_string(value));
    }
    t
}

pub(super) fn class_metadata(mh: &MachHeader, section: &Section) -> Table {
    metadata(mh, section, Kind::Classes)
}

pub(super) fn category_metadata(mh: &MachHeader, section: &Section) -> Table {
    metadata(mh, section, Kind::Categories)
}

pub(super) fn protocol_metadata(mh: &MachHeader, section: &Section) -> Table {
    metadata(mh, section, Kind::Protocols)
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

    /// Row located by virtual address: it has bytes only when `vmaddr` is
    /// mapped.
    fn row_at_vm(&mut self, vmaddr: u64, size: u64, kind: &str, name: String, detail: &str) {
        let cells = [
            kind.to_string(),
            name,
            detail.to_string(),
            as_address(vmaddr),
        ];
        match self.r.file_offset(vmaddr) {
            Some(offset) => self.t.add_data(offset, size, cells),
            None => self.t.add(cells),
        }
    }

    fn method_list(&mut self, list_vmaddr: u64, depth: usize, method_kind: &str) {
        if list_vmaddr == 0 {
            return;
        }
        let image = self.r.image();
        let is64 = self.r.is64();
        let title = format!("{}{}", indent(depth), method_kind);
        let header = self
            .r
            .struct_offset(list_vmaddr, LIST_HEADER_SIZE)
            .and_then(|off| Some((off, ObjcListHeader::read(image, off)?)));
        let Some((list_off, list)) = header else {
            self.row_at_vm(list_vmaddr, 0, "MethodList?", title, "unmapped");
            return;
        };
        // Relative method lists (entsize flag 0x80000000) keep that bit in
        // the entry size, so their entries never fit and none is listed.
        let entry_size = list.entry_size() as u64;
        if entry_size < self.r.layout.method_size() || list.count as u64 > MAX_LIST_COUNT {
            self.row_at_vm(
                list_vmaddr,
                LIST_HEADER_SIZE,
                "MethodList?",
                title,
                "invalid entsize/count",
            );
            return;
        }
        let detail = format!("count={} entsize={}", list.count, entry_size);
        self.row_at_vm(list_vmaddr, LIST_HEADER_SIZE, "MethodList", title, &detail);
        let mut cur = list_off + LIST_HEADER_SIZE;
        for _ in 0..list.count {
            if self.full() || !image.in_file(cur, entry_size) {
                break;
            }
            let Some(m) = ObjcMethod::read(image, cur, is64) else {
                break;
            };
            let name = safe_name(self.r.cstring(m.name), "<unnamed>");
            let mut detail = utf8_safe(self.r.cstring(m.types));
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&format!("imp=0x{}", as_short_hex_string(m.imp)));
            self.row_at_vm(
                m.imp,
                0,
                "Method",
                format!("{}{}", indent(depth + 1), name),
                &detail,
            );
            cur += entry_size;
        }
    }

    fn property_list(&mut self, list_vmaddr: u64, depth: usize) {
        if list_vmaddr == 0 {
            return;
        }
        let image = self.r.image();
        let is64 = self.r.is64();
        let header = self
            .r
            .struct_offset(list_vmaddr, LIST_HEADER_SIZE)
            .and_then(|off| Some((off, ObjcListHeader::read(image, off)?)));
        let Some((list_off, list)) = header else {
            self.row_at_vm(list_vmaddr, 0, "PropertyList?", indent(depth), "unmapped");
            return;
        };
        // Unlike method and ivar lists, the entry size is used unmasked.
        let entry_size = list.entsize as u64;
        if entry_size < self.r.layout.property_size() || list.count as u64 > MAX_LIST_COUNT {
            self.row_at_vm(
                list_vmaddr,
                LIST_HEADER_SIZE,
                "PropertyList?",
                indent(depth),
                "invalid entsize/count",
            );
            return;
        }
        let detail = format!("count={} entsize={}", list.count, entry_size);
        self.row_at_vm(
            list_vmaddr,
            LIST_HEADER_SIZE,
            "PropertyList",
            indent(depth),
            &detail,
        );
        let mut cur = list_off + LIST_HEADER_SIZE;
        for _ in 0..list.count {
            if self.full() || !image.in_file(cur, entry_size) {
                break;
            }
            let Some(p) = ObjcProperty::read(image, cur, is64) else {
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
                list_vmaddr,
            );
            cur += entry_size;
        }
    }

    fn ivar_list(&mut self, list_vmaddr: u64, depth: usize) {
        if list_vmaddr == 0 {
            return;
        }
        let image = self.r.image();
        let is64 = self.r.is64();
        let header = self
            .r
            .struct_offset(list_vmaddr, LIST_HEADER_SIZE)
            .and_then(|off| Some((off, ObjcListHeader::read(image, off)?)));
        // An unreadable or implausible ivar list is skipped without a row.
        let Some((list_off, list)) = header else {
            return;
        };
        let entry_size = list.entry_size() as u64;
        if entry_size < self.r.layout.ivar_size() || list.count as u64 > MAX_LIST_COUNT {
            return;
        }
        let detail = format!("count={} entsize={}", list.count, entry_size);
        self.row_at_vm(
            list_vmaddr,
            LIST_HEADER_SIZE,
            "IvarList",
            indent(depth),
            &detail,
        );
        let mut cur = list_off + LIST_HEADER_SIZE;
        for _ in 0..list.count {
            if self.full() || !image.in_file(cur, entry_size) {
                break;
            }
            let Some(iv) = ObjcIvar::read(image, cur, is64) else {
                break;
            };
            let name = safe_name(self.r.cstring(iv.name), "<ivar>");
            let type_ = utf8_safe(self.r.cstring(iv.type_));
            // The offset variable is read as a full pointer-sized word.
            let ivar_offset = self.r.pointer(iv.offset).unwrap_or(0);
            let detail = format!("{} offset={} size={}", type_, ivar_offset, iv.size);
            self.row(
                cur,
                entry_size,
                "Ivar",
                format!("{}{}", indent(depth + 1), name),
                detail,
                list_vmaddr,
            );
            cur += entry_size;
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
            .and_then(|off| Some((off, ObjcProtocol::read(self.r.image(), off, self.r.is64())?)));
        let Some((off, proto)) = proto else {
            self.row_at_vm(protocol_vmaddr, 0, "Protocol?", indent(depth), "unmapped");
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
        let image = self.r.image();
        let word = self.r.layout.ptr_size();
        let header_size = self.r.layout.protocol_list_header_size();
        let Some(list_off) = self.r.struct_offset(list_vmaddr, header_size) else {
            return;
        };
        let read_word = |at: u64| {
            if word == 8 {
                image.u64(at)
            } else {
                image.u32(at).map(u64::from)
            }
        };
        let Some(count) = read_word(list_off) else {
            return;
        };
        if count > MAX_LIST_COUNT {
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
            let Some(protocol_ptr) = read_word(cur) else {
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

    fn class(&mut self, class_vmaddr: u64, depth: usize) {
        if class_vmaddr == 0 || !self.visited_classes.insert(class_vmaddr) {
            return;
        }
        let image = self.r.image();
        let is64 = self.r.is64();
        let class_size = self.r.layout.class_size();
        let cls = self
            .r
            .struct_offset(class_vmaddr, class_size)
            .and_then(|off| Some((off, ObjcClass::read(image, off, is64)?)));
        let Some((cls_off, cls)) = cls else {
            self.row_at_vm(class_vmaddr, 0, "Class?", indent(depth), "unmapped");
            return;
        };
        let ro = self
            .r
            .struct_offset(cls.ro_address(is64), self.r.layout.class_ro_size())
            .and_then(|off| ObjcClassRo::read(image, off, is64));
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
        if cls.superclass != 0 {
            self.row(
                cls_off,
                class_size,
                "Superclass",
                indent(depth + 1),
                String::new(),
                cls.superclass,
            );
        }
        self.method_list(ro.base_methods, depth + 1, "base");
        self.ivar_list(ro.ivars, depth + 1);
        self.property_list(ro.base_properties, depth + 1);
        self.protocol_list(ro.base_protocols, depth + 1);
    }

    fn category(&mut self, category_vmaddr: u64, depth: usize) {
        if category_vmaddr == 0 {
            return;
        }
        let size = self.r.layout.category_size();
        let cat = self
            .r
            .struct_offset(category_vmaddr, size)
            .and_then(|off| Some((off, ObjcCategory::read(self.r.image(), off, self.r.is64())?)));
        let Some((off, cat)) = cat else {
            self.row_at_vm(category_vmaddr, 0, "Category?", indent(depth), "unmapped");
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
        if cat.cls != 0 {
            self.row(
                off,
                size,
                "ClassRef",
                indent(depth + 1),
                String::new(),
                cat.cls,
            );
            self.class(cat.cls, depth + 2);
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
fn metadata(mh: &MachHeader, section: &Section, kind: Kind) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Kind", "Name", "Details", "VM Address"]);
    t.set_widths(&[160, 360, 460, 180]);
    let r = ObjcResolver::new(mh, section.is64);
    let word = r.layout.ptr_size();
    let mut w = Walker {
        r,
        t,
        visited_classes: HashSet::new(),
        visited_protocols: HashSet::new(),
    };
    for (index, (offset, target)) in pointer_entries(mh, section).enumerate() {
        if w.full() {
            w.t.add([
                "...".to_string(),
                String::new(),
                "row limit reached".to_string(),
                String::new(),
            ]);
            break;
        }
        w.row(
            offset,
            word,
            "Entry",
            format!("#{index}"),
            String::new(),
            target,
        );
        if target == 0 {
            continue;
        }
        match kind {
            Kind::Classes => w.class(target, 1),
            Kind::Categories => w.category(target, 1),
            Kind::Protocols => w.protocol(target, 1),
        }
    }
    w.t
}
