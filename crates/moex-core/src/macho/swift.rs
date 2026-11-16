//! Swift 5 reflection metadata (`__swift5_*` sections): record decoders,
//! string readers and Swift symbol demangling.

use super::ptr::{relative_target, Pointer, PointerDecoder, SliceReader};
use super::MachHeader;
use crate::hex::{as_address, utf8_safe};
use crate::image::Image;
use std::cell::{Cell, OnceCell};
use std::collections::HashSet;

/// Leading fields of every Swift context descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextDescriptorHeader {
    pub flags: u32,
    /// Relative pointer to the parent context.
    pub parent: i32,
    /// Relative pointer (from its own field, at +8) to the name.
    pub name: i32,
}

impl ContextDescriptorHeader {
    pub const SIZE: u64 = 12;

    pub fn read(image: &Image, off: u64) -> Option<Self> {
        Some(ContextDescriptorHeader {
            flags: image.u32(off)?,
            parent: image.u32(off.checked_add(4)?)? as i32,
            name: image.u32(off.checked_add(8)?)? as i32,
        })
    }

    /// Low five bits of `flags`.
    pub fn kind(&self) -> u32 {
        self.flags & 0x1f
    }
}

/// Header of one `__swift5_fieldmd` field descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDescriptorHeader {
    pub mangled_type_name: i32,
    pub superclass: i32,
    pub kind: u16,
    pub field_record_size: u16,
    pub num_fields: u32,
}

impl FieldDescriptorHeader {
    pub const SIZE: u64 = 16;

    pub fn read(image: &Image, off: u64) -> Option<Self> {
        Some(FieldDescriptorHeader {
            mangled_type_name: image.u32(off)? as i32,
            superclass: image.u32(off.checked_add(4)?)? as i32,
            kind: image.u16(off.checked_add(8)?)?,
            field_record_size: image.u16(off.checked_add(10)?)?,
            num_fields: image.u32(off.checked_add(12)?)?,
        })
    }

    /// False when the record size or field count is implausible.
    pub fn is_plausible(&self) -> bool {
        (self.field_record_size as u64) >= FieldRecord::SIZE
            && self.field_record_size <= 256
            && self.num_fields <= 65535
    }
}

/// Leading fields of one field record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRecord {
    pub flags: u32,
    /// Relative pointer from +4.
    pub mangled_type_name: i32,
    /// Relative pointer from +8.
    pub field_name: i32,
}

impl FieldRecord {
    pub const SIZE: u64 = 12;

    pub fn read(image: &Image, off: u64) -> Option<Self> {
        Some(FieldRecord {
            flags: image.u32(off)?,
            mangled_type_name: image.u32(off.checked_add(4)?)? as i32,
            field_name: image.u32(off.checked_add(8)?)? as i32,
        })
    }
}

/// Name of a context descriptor kind (`flags & 0x1f`).
pub fn context_kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "module",
        1 => "extension",
        2 => "anonymous",
        3 => "protocol",
        4 => "opaque-type",
        16 => "class",
        17 => "struct",
        18 => "enum",
        _ => "unknown",
    }
}

/// Name of a field descriptor kind.
pub fn field_descriptor_kind_name(kind: u16) -> &'static str {
    match kind {
        0 => "struct",
        1 => "class",
        2 => "enum",
        3 => "multi-payload-enum",
        4 => "protocol",
        5 => "class-protocol",
        6 => "objc-protocol",
        7 => "objc-class",
        _ => "unknown",
    }
}

fn is_printable(c: u8) -> bool {
    (0x20..=0x7e).contains(&c)
}

/// NUL-terminated string of printable ASCII at `vmaddr`, looking at no more
/// than `max_len` bytes. Empty when the address is unmapped, the string is
/// empty, contains a non-printable byte, or has no terminator in range.
pub fn read_printable_cstring(reader: &SliceReader<'_>, vmaddr: u64, max_len: u64) -> String {
    let Some(bytes) = reader.bytes(vmaddr, max_len) else {
        return String::new();
    };
    let mut len = 0usize;
    for &c in bytes {
        if c == 0 {
            break;
        }
        if !is_printable(c) {
            return String::new();
        }
        len += 1;
    }
    if len == 0 || len >= bytes.len() {
        return String::new();
    }
    bytes.get(..len).map(utf8_safe).unwrap_or_default()
}

/// One string of a `__swift5_reflstr` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectionString<'a> {
    /// Offset in the section data.
    pub offset: usize,
    pub text: &'a [u8],
    /// False for a last string that runs to the end of the data without a
    /// NUL.
    pub terminated: bool,
}

impl ReflectionString<'_> {
    /// Bytes the string occupies in the section, terminator included.
    pub fn size(&self) -> u64 {
        self.text.len() as u64 + u64::from(self.terminated)
    }
}

/// The strings of a `__swift5_reflstr` section: NUL-terminated C strings
/// (field, case and associated type names, in UTF-8) laid end to end. Empty
/// strings, which is what padding looks like, are left out.
pub fn reflection_strings(data: &[u8]) -> Vec<ReflectionString<'_>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let rest = data.get(cursor..).unwrap_or(&[]);
        let len = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        if len != 0 {
            out.push(ReflectionString {
                offset: cursor,
                text: rest.get(..len).unwrap_or(&[]),
                terminated: len < rest.len(),
            });
        }
        cursor += len + 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Reflection records (swift/RemoteInspection/Records.h)
// ---------------------------------------------------------------------------

/// Most records one section walk yields; no real section comes close.
pub const MAX_RECORDS: usize = 1_000_000;

/// The records of one section, each with its offset in the section data,
/// and why the walk ended early, if it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Records<T> {
    pub items: Vec<(u64, T)>,
    pub error: Option<&'static str>,
}

impl<T> Records<T> {
    fn new() -> Self {
        Records {
            items: Vec::new(),
            error: None,
        }
    }

    /// Adds a record; false (and the walk is over) at the row limit.
    fn push(&mut self, offset: u64, item: T) -> bool {
        if self.items.len() >= MAX_RECORDS {
            self.error = Some("row limit reached");
            return false;
        }
        self.items.push((offset, item));
        true
    }
}

/// Little-endian `u32` at `at` in `data`.
fn le32(data: &[u8], at: u64) -> Option<u32> {
    let at = usize::try_from(at).ok()?;
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Header of one `__swift5_assocty` descriptor: the associated types that
/// the conformance of `conforming_type_name` to `protocol_type_name` binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssociatedTypeDescriptor {
    /// Relative pointer from +0 to a mangled type name.
    pub conforming_type_name: i32,
    /// Relative pointer from +4 to a mangled protocol name.
    pub protocol_type_name: i32,
    pub num_associated_types: u32,
    pub associated_type_record_size: u32,
}

impl AssociatedTypeDescriptor {
    pub const SIZE: u64 = 16;
}

/// One record of an associated type descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssociatedTypeRecord {
    /// Relative pointer from +0 to the associated type's name, a C string.
    pub name: i32,
    /// Relative pointer from +4 to the mangled name of the type bound to it.
    pub substituted_type_name: i32,
}

impl AssociatedTypeRecord {
    pub const SIZE: u64 = 8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociatedTypeItem {
    Descriptor(AssociatedTypeDescriptor),
    /// `size` is the record size its descriptor declares.
    Record {
        index: u32,
        size: u32,
        record: AssociatedTypeRecord,
    },
}

/// `__swift5_assocty`: descriptors, each followed by its records.
pub fn associated_type_records(data: &[u8]) -> Records<AssociatedTypeItem> {
    const TRUNCATED_TABLE: &str = "truncated associated type record table";
    let size = data.len() as u64;
    let mut out = Records::new();
    let mut cursor = 0u64;
    while cursor < size {
        let field = |at: u64| le32(data, cursor + at);
        let (Some(conforming), Some(protocol), Some(count), Some(record_size)) =
            (field(0), field(4), field(8), field(12))
        else {
            out.error = Some("truncated associated type descriptor");
            break;
        };
        let desc = AssociatedTypeDescriptor {
            conforming_type_name: conforming as i32,
            protocol_type_name: protocol as i32,
            num_associated_types: count,
            associated_type_record_size: record_size,
        };
        if !out.push(cursor, AssociatedTypeItem::Descriptor(desc)) {
            break;
        }
        cursor += AssociatedTypeDescriptor::SIZE;
        if count != 0 && u64::from(record_size) < AssociatedTypeRecord::SIZE {
            out.error = Some("invalid associated type record size");
            break;
        }
        for index in 0..count {
            // The whole record has to be there, not just its two fields.
            let end = cursor + u64::from(record_size);
            let (Some(name), Some(substituted)) = (le32(data, cursor), le32(data, cursor + 4))
            else {
                out.error = Some(TRUNCATED_TABLE);
                return out;
            };
            if end > size {
                out.error = Some(TRUNCATED_TABLE);
                return out;
            }
            let item = AssociatedTypeItem::Record {
                index,
                size: record_size,
                record: AssociatedTypeRecord {
                    name: name as i32,
                    substituted_type_name: substituted as i32,
                },
            };
            if !out.push(cursor, item) {
                return out;
            }
            cursor = end;
        }
    }
    out
}

/// Header of one `__swift5_capture` descriptor: what a closure context (a
/// heap box) holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureDescriptor {
    pub num_capture_types: u32,
    pub num_metadata_sources: u32,
    /// Number of generic argument bindings stored at the start of the
    /// context; they have no records.
    pub num_bindings: u32,
}

impl CaptureDescriptor {
    pub const SIZE: u64 = 12;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureItem {
    Descriptor(CaptureDescriptor),
    /// A captured value's type: a relative pointer (from +0) to its mangled
    /// name.
    CaptureType {
        index: u32,
        mangled_type_name: i32,
    },
    /// How to find the metadata of a generic argument: relative pointers to
    /// the mangled type name (from +0) and to the encoded metadata source
    /// (from +4).
    MetadataSource {
        index: u32,
        mangled_type_name: i32,
        mangled_metadata_source: i32,
    },
}

impl CaptureItem {
    /// Bytes the item occupies in the section.
    pub fn size(&self) -> u64 {
        match self {
            CaptureItem::Descriptor(_) => CaptureDescriptor::SIZE,
            CaptureItem::CaptureType { .. } => 4,
            CaptureItem::MetadataSource { .. } => 8,
        }
    }
}

/// `__swift5_capture`: descriptors, each followed by its capture type
/// records and then its metadata source records.
pub fn capture_records(data: &[u8]) -> Records<CaptureItem> {
    let size = data.len() as u64;
    let mut out = Records::new();
    let mut cursor = 0u64;
    while cursor < size {
        let field = |at: u64| le32(data, cursor + at);
        let (Some(types), Some(sources), Some(bindings)) = (field(0), field(4), field(8)) else {
            out.error = Some("truncated capture descriptor");
            break;
        };
        let desc = CaptureDescriptor {
            num_capture_types: types,
            num_metadata_sources: sources,
            num_bindings: bindings,
        };
        if !out.push(cursor, CaptureItem::Descriptor(desc)) {
            break;
        }
        cursor += CaptureDescriptor::SIZE;
        for index in 0..types {
            let Some(name) = le32(data, cursor) else {
                out.error = Some("truncated capture type records");
                return out;
            };
            let item = CaptureItem::CaptureType {
                index,
                mangled_type_name: name as i32,
            };
            if !out.push(cursor, item) {
                return out;
            }
            cursor += 4;
        }
        for index in 0..sources {
            let (Some(name), Some(source)) = (le32(data, cursor), le32(data, cursor + 4)) else {
                out.error = Some("truncated metadata source records");
                return out;
            };
            let item = CaptureItem::MetadataSource {
                index,
                mangled_type_name: name as i32,
                mangled_metadata_source: source as i32,
            };
            if !out.push(cursor, item) {
                return out;
            }
            cursor += 8;
        }
    }
    out
}

/// One `__swift5_builtin` record: the layout of a type that reflection
/// cannot derive from field records (builtins, imported C types, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinTypeDescriptor {
    /// Relative pointer from +0 to the mangled type name.
    pub type_name: i32,
    pub size: u32,
    pub alignment_and_flags: u32,
    pub stride: u32,
    pub num_extra_inhabitants: u32,
}

impl BuiltinTypeDescriptor {
    pub const SIZE: u64 = 20;

    /// Low 16 bits of `alignment_and_flags`.
    pub fn alignment(&self) -> u32 {
        self.alignment_and_flags & 0xffff
    }

    /// Bit 16 of `alignment_and_flags`.
    pub fn is_bitwise_takable(&self) -> bool {
        self.alignment_and_flags & (1 << 16) != 0
    }

    /// The layout fields as `name=value` text; `flags` is the half of
    /// `alignment_and_flags` above the alignment.
    pub fn layout_text(&self) -> String {
        format!(
            "size={} alignment={} stride={} extra_inhabitants={} bitwise_takable={} flags=0x{:x}",
            self.size,
            self.alignment(),
            self.stride,
            self.num_extra_inhabitants,
            if self.is_bitwise_takable() {
                "yes"
            } else {
                "no"
            },
            self.alignment_and_flags >> 16
        )
    }
}

/// `__swift5_builtin`: an array of builtin type descriptors.
pub fn builtin_type_records(data: &[u8]) -> Records<BuiltinTypeDescriptor> {
    let size = data.len() as u64;
    let mut out = Records::new();
    let mut cursor = 0u64;
    while cursor < size {
        let field = |at: u64| le32(data, cursor + at);
        let (Some(name), Some(type_size), Some(alignment), Some(stride), Some(inhabitants)) =
            (field(0), field(4), field(8), field(12), field(16))
        else {
            out.error = Some("truncated builtin type descriptor");
            break;
        };
        let desc = BuiltinTypeDescriptor {
            type_name: name as i32,
            size: type_size,
            alignment_and_flags: alignment,
            stride,
            num_extra_inhabitants: inhabitants,
        };
        if !out.push(cursor, desc) {
            break;
        }
        cursor += BuiltinTypeDescriptor::SIZE;
    }
    out
}

/// One `__swift5_mpenum` record: a type name followed by 32-bit words, the
/// first of which holds their number (itself included) in its high half
/// and flags in its low half. The words after it describe the spare bits
/// of the payload and are not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiPayloadEnumDescriptor {
    /// Relative pointer from +0 to the mangled type name.
    pub type_name: i32,
    pub size_and_flags: u32,
}

impl MultiPayloadEnumDescriptor {
    /// Number of 32-bit words after the type name.
    pub fn words(&self) -> u32 {
        self.size_and_flags >> 16
    }

    pub fn flags(&self) -> u32 {
        self.size_and_flags & 0xffff
    }

    /// Bit 0 of the flags.
    pub fn uses_payload_spare_bits(&self) -> bool {
        self.flags() & 1 != 0
    }

    /// Bytes the descriptor occupies.
    pub fn size(&self) -> u64 {
        4 + 4 * u64::from(self.words())
    }

    /// The size and flags as `name=value` text.
    pub fn layout_text(&self) -> String {
        format!(
            "words={} flags=0x{:x} payload_spare_bits={}",
            self.words(),
            self.flags(),
            if self.uses_payload_spare_bits() {
                "yes"
            } else {
                "no"
            }
        )
    }
}

/// `__swift5_mpenum`: multi-payload enum descriptors laid end to end.
pub fn multi_payload_enum_records(data: &[u8]) -> Records<MultiPayloadEnumDescriptor> {
    let size = data.len() as u64;
    let mut out = Records::new();
    let mut cursor = 0u64;
    while cursor < size {
        let (Some(name), Some(size_and_flags)) = (le32(data, cursor), le32(data, cursor + 4))
        else {
            out.error = Some("truncated multi-payload enum descriptor");
            break;
        };
        let desc = MultiPayloadEnumDescriptor {
            type_name: name as i32,
            size_and_flags,
        };
        if desc.words() == 0 {
            // The size word counts itself.
            out.error = Some("invalid multi-payload enum descriptor size");
            break;
        }
        if cursor + desc.size() > size {
            out.error = Some("truncated multi-payload enum descriptor");
            break;
        }
        if !out.push(cursor, desc) {
            break;
        }
        cursor += desc.size();
    }
    out
}

// ---------------------------------------------------------------------------
// Mangled names with symbolic references
// ---------------------------------------------------------------------------

/// Number of bytes following the control byte `c` of a symbolic reference
/// in a mangled name: a 32-bit relative offset after 0x01–0x17, a pointer
/// after 0x18–0x1F. `None` for any other byte.
fn symbolic_reference_len(c: u8, pointer_size: usize) -> Option<usize> {
    match c {
        0x01..=0x17 => Some(4),
        0x18..=0x1f => Some(pointer_size),
        _ => None,
    }
}

/// Length, terminator excluded, of the mangled name at the start of
/// `bytes`. The bytes of a symbolic reference can be zero, so the name is
/// walked. `None` when `bytes` ends before the terminator.
pub fn mangled_name_len(bytes: &[u8], pointer_size: usize) -> Option<usize> {
    let mut i = 0usize;
    loop {
        let c = *bytes.get(i)?;
        if c == 0 {
            return Some(i);
        }
        i = i.checked_add(1 + symbolic_reference_len(c, pointer_size).unwrap_or(0))?;
    }
}

/// One mangled name of a `__swift5_typeref` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredName {
    /// Offset in the section data.
    pub offset: usize,
    /// Length without the terminator.
    pub len: usize,
}

impl StoredName {
    /// Bytes the name occupies in the section, terminator included.
    pub fn size(&self) -> u64 {
        self.len as u64 + 1
    }

    /// The name's bytes, terminator excluded, in the section `data`.
    pub fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.offset..self.offset + self.len).unwrap_or(&[])
    }
}

/// `__swift5_typeref`: mangled names laid end to end, each NUL-terminated
/// and followed by NUL padding up to the next one. A last name that the
/// end of the data cuts off is not listed; `error` says so.
pub fn mangled_names(data: &[u8], pointer_size: usize) -> Records<StoredName> {
    let mut out = Records::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let rest = data.get(cursor..).unwrap_or(&[]);
        if rest.first() == Some(&0) {
            cursor += 1;
            continue;
        }
        let Some(len) = mangled_name_len(rest, pointer_size) else {
            out.error = Some("truncated mangled name");
            break;
        };
        let name = StoredName {
            offset: cursor,
            len,
        };
        if !out.push(cursor as u64, name) {
            break;
        }
        cursor += len + 1;
    }
    out
}

/// Longest C string read for a name.
const MAX_CSTRING: u64 = 1024;

/// How many parent contexts, extended types and pointers are followed from
/// one symbolic reference.
const MAX_CONTEXT_DEPTH: u32 = 16;

/// Budget units one symbolic reference or context costs (see
/// [`TypeNames`]).
const REFERENCE_COST: u64 = 16;

/// A mangled name read from the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeName {
    pub address: u64,
    /// The name as stored: its printable characters, `\xNN` for other
    /// bytes, and each symbolic reference as `{what it refers to}`.
    pub stored: String,
    /// The demangled form, when the demangler understands the name and
    /// every symbolic reference in it could be resolved to a type.
    pub demangled: Option<String>,
    /// Addresses the symbolic references refer to (for an indirect
    /// reference, the address of the pointer).
    pub references: Vec<u64>,
}

impl TypeName {
    /// The demangled form, else the name as stored.
    pub fn text(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.stored)
    }
}

/// What a symbolic reference to a context descriptor names.
struct Context {
    /// Qualified name, `Module.Outer.Inner`.
    name: String,
    is_protocol: bool,
    /// False when the context cannot stand for a type in a mangled name
    /// (a module, an extension, an anonymous context).
    is_type: bool,
    /// The names of the nominal types the context is nested in, outermost
    /// first and ending with its own; the first carries the module name.
    /// Empty for a module, `None` when the nesting is not known.
    levels: Option<Vec<String>>,
}

impl Context {
    /// A type `name` declared in `parent`.
    fn nested(parent: Option<Context>, name: String, is_protocol: bool) -> Context {
        let (qualified, levels) = match parent {
            None => (name.clone(), Some(vec![name])),
            Some(parent) => {
                let qualified = format!("{}.{name}", parent.name);
                let levels = parent.levels.map(|mut levels| {
                    levels.push(if levels.is_empty() {
                        qualified.clone()
                    } else {
                        name
                    });
                    levels
                });
                (qualified, levels)
            }
        };
        Context {
            name: qualified,
            is_protocol,
            is_type: true,
            levels,
        }
    }
}

/// The placeholder types put in a mangled name in place of its symbolic
/// references, so that the demangler can read it, and what each one
/// stands for.
#[derive(Default)]
struct Placeholders {
    /// `(demangled placeholder, what to show in its place)`.
    replacements: Vec<(String, String)>,
}

/// The builtin types whose combinations make up the exact placeholders:
/// `(mangling, demangled form)`.
const PLACEHOLDER_DIGITS: [(&str, &str); 4] = [
    ("Bw", "Builtin.Word"),
    ("Bp", "Builtin.RawPointer"),
    ("Bb", "Builtin.BridgeObject"),
    ("Bo", "Builtin.NativeObject"),
];

impl Placeholders {
    /// Mangling of a new placeholder that is exact: like the symbolic
    /// reference it stands for, it adds one substitution to the
    /// demangler's table (and no word), so the back-references in the
    /// rest of the name keep their meaning. It is `Swift.Array` bound to
    /// two or more builtin types that spell the placeholder's number,
    /// which no real name holds. Being a bound type, it cannot stand where
    /// the demangler wants a declaration: at the head of a bound generic
    /// type or for a protocol. `None` when the numbers have run out.
    fn exact(&mut self, shown: &str) -> Option<String> {
        let id = self.replacements.len();
        if id >= 1 << 16 {
            return None;
        }
        // As few digits as the number needs (the demangler's output is
        // limited to 4095 bytes), but two at least.
        let count = (2..8).find(|count| id >> (2 * count) == 0).unwrap_or(8);
        let digits = (0..count)
            .rev()
            .filter_map(|digit| PLACEHOLDER_DIGITS.get((id >> (2 * digit)) & 3));
        let (mangled, demangled): (Vec<&str>, Vec<&str>) = digits.copied().unzip();
        self.replacements.push((
            format!("Swift.Array<{}>", demangled.join(", ")),
            shown.to_string(),
        ));
        Some(format!("Say{}G", mangled.concat()))
    }

    /// Mangling of a new placeholder that is a declaration: a struct or
    /// protocol named `_NNNNNN`, declared in the Swift module (`parent`
    /// false) or in the type mangled just before. It adds two
    /// substitutions (its name and itself) where the reference adds one,
    /// so it must not be followed by a back-reference.
    fn declaration(&mut self, parent: bool, is_protocol: bool, shown: &str) -> String {
        let id = self.replacements.len();
        let (demangled, shown) = if parent {
            (format!("._{id:06}"), format!(".{shown}"))
        } else {
            (format!("Swift._{id:06}"), shown.to_string())
        };
        self.replacements.push((demangled, shown));
        format!(
            "{}7_{id:06}{}",
            if parent { "" } else { "s" },
            if is_protocol { 'P' } else { 'V' }
        )
    }

    /// Demangles `mangled` and puts the names in place of the
    /// placeholders.
    fn demangle(&self, mangled: &str) -> Option<String> {
        let mut text = if has_swift_prefix(mangled.as_bytes()) {
            demangle(mangled.as_bytes())?
        } else {
            demangle(format!("$s{mangled}").as_bytes())?
        };
        for (placeholder, shown) in self.replacements.iter().rev() {
            text = text.replace(placeholder, shown);
        }
        // A placeholder that was printed in some other way than expected
        // must not be taken for a type of the image.
        let digits = |s: &str| s.len() >= 6 && s.bytes().take(6).all(|c| c.is_ascii_digit());
        let left_over = text.contains("Swift.Array<Builtin.")
            || text
                .match_indices("._")
                .any(|(at, _)| text.get(at + 2..).is_some_and(digits));
        (!left_over).then_some(text)
    }
}

/// A mangled name being rewritten with placeholders.
#[derive(Default)]
struct Rewritten {
    text: String,
    /// Length of `text` after the first declaration placeholder.
    declaration_end: Option<usize>,
}

impl Rewritten {
    fn declaration(&mut self, mangled: &str) {
        self.text.push_str(mangled);
        self.declaration_end.get_or_insert(self.text.len());
    }

    /// The text, unless a back-reference (`A…`) may follow a declaration
    /// placeholder. Any `A` counts: telling a back-reference from other
    /// uses of the letter would take a parser of the mangling.
    fn checked(&self) -> Option<&str> {
        let rest = self
            .text
            .get(self.declaration_end.unwrap_or(self.text.len())..)?;
        (!rest.contains('A')).then_some(self.text.as_str())
    }
}

/// Reads mangled names out of an image, resolving their symbolic
/// references to the context descriptors they point at, in this image or
/// (through a bound pointer) imported.
///
/// The work is bounded by a budget shared by all the names read: one unit
/// per byte of a name, [`REFERENCE_COST`] per context descriptor visited,
/// four times the file size plus 1 MiB in total. Once it is used up, no
/// more names are read.
pub struct TypeNames<'a> {
    reader: SliceReader<'a>,
    pointers: OnceCell<PointerDecoder<'a>>,
    budget: Cell<u64>,
}

impl<'a> TypeNames<'a> {
    pub fn new(reader: SliceReader<'a>) -> Self {
        let budget = reader
            .image()
            .len()
            .saturating_mul(4)
            .saturating_add(1 << 20);
        TypeNames {
            reader,
            pointers: OnceCell::new(),
            budget: Cell::new(budget),
        }
    }

    pub fn reader(&self) -> SliceReader<'a> {
        self.reader
    }

    fn pointer_size(&self) -> usize {
        if self.reader.mh.is64 {
            8
        } else {
            4
        }
    }

    fn charge(&self, cost: u64) -> bool {
        let left = self.budget.get().checked_sub(cost);
        self.budget.set(left.unwrap_or(0));
        left.is_some()
    }

    /// The C string at `vmaddr` (UTF-8, at most [`MAX_CSTRING`] bytes);
    /// `None` when it is unmapped, empty or not terminated in range.
    pub fn cstring(&self, vmaddr: u64) -> Option<String> {
        let bytes = self.reader.bytes(vmaddr, MAX_CSTRING)?;
        let len = bytes.iter().position(|&c| c == 0)?;
        (len != 0 && self.charge(len as u64)).then(|| utf8_safe(bytes.get(..len).unwrap_or(&[])))
    }

    /// The C string that a relative pointer stored at `field_vmaddr`
    /// refers to; `None` also when the pointer is zero.
    pub fn relative_cstring(&self, field_vmaddr: u64, rel: i32) -> Option<String> {
        (rel != 0)
            .then(|| self.cstring(relative_target(field_vmaddr, rel)))
            .flatten()
    }

    /// The mangled name at `vmaddr`. `None` when the address is unmapped,
    /// the name is empty, longer than the demangler's limit or not
    /// terminated, or the budget is used up.
    pub fn read(&self, vmaddr: u64) -> Option<TypeName> {
        self.read_at(vmaddr, 0)
    }

    /// The mangled name that a relative pointer stored at `field_vmaddr`
    /// refers to; `None` also when the pointer is zero.
    pub fn relative(&self, field_vmaddr: u64, rel: i32) -> Option<TypeName> {
        (rel != 0)
            .then(|| self.read(relative_target(field_vmaddr, rel)))
            .flatten()
    }

    /// Display text of the mangled name that a relative pointer stored at
    /// `field_vmaddr` refers to: `-` for a null pointer, `(unreadable)`
    /// when [`TypeNames::relative`] finds no name.
    pub fn relative_text(&self, field_vmaddr: u64, rel: i32) -> String {
        if rel == 0 {
            return "-".to_string();
        }
        self.relative(field_vmaddr, rel)
            .map_or_else(|| "(unreadable)".to_string(), |n| n.text().to_string())
    }

    fn read_at(&self, vmaddr: u64, depth: u32) -> Option<TypeName> {
        let bytes = self.reader.bytes(vmaddr, MAX_MANGLED_LEN as u64 + 1)?;
        let len = mangled_name_len(bytes, self.pointer_size())?;
        if len == 0 {
            return None;
        }
        self.decode_at(vmaddr, bytes.get(..len)?, depth)
    }

    /// Decodes `name`, the bytes (without terminator) of a mangled name
    /// stored at `vmaddr`. `None` when the budget is used up.
    pub fn decode(&self, vmaddr: u64, name: &[u8]) -> Option<TypeName> {
        self.decode_at(vmaddr, name, 0)
    }

    fn decode_at(&self, vmaddr: u64, name: &[u8], depth: u32) -> Option<TypeName> {
        if !self.charge(name.len() as u64) {
            return None;
        }
        let mut stored = String::new();
        // The name with a placeholder type for each symbolic reference, as
        // long as every part of it is something the demangler takes.
        // `nested` differs from `flat` in that a type declared in another
        // type gets a placeholder declared in a placeholder, which generic
        // arguments bound at several levels (`Outer<Int>.Inner`) need.
        let mut plain =
            (name.len() <= MAX_MANGLED_LEN).then(|| (Rewritten::default(), Rewritten::default()));
        let mut placeholders = Placeholders::default();
        let mut has_nested = false;
        let mut references = Vec::new();
        let mut i = 0usize;
        while let Some(&c) = name.get(i) {
            i += 1;
            let Some(len) = symbolic_reference_len(c, self.pointer_size()) else {
                if is_printable(c) {
                    stored.push(c as char);
                    if let Some((flat, nested)) = plain.as_mut() {
                        flat.text.push(c as char);
                        nested.text.push(c as char);
                    }
                } else {
                    stored.push_str(&format!("\\x{c:02x}"));
                    plain = None;
                }
                continue;
            };
            let Some(operand) = name.get(i..i + len) else {
                stored.push_str("{truncated}");
                plain = None;
                break;
            };
            let field = vmaddr.wrapping_add(i as u64);
            i += len;
            let mut value = [0u8; 8];
            if let Some(low) = value.get_mut(..len) {
                low.copy_from_slice(operand);
            }
            let value = u64::from_le_bytes(value);
            let (target, context) = self.symbolic_reference(c, field, value, depth);
            references.extend(target);
            let shown = match (&context, target) {
                (Some(context), _) => context.name.clone(),
                (None, Some(target)) => {
                    format!("{} {}", symbolic_reference_kind_name(c), as_address(target))
                }
                (None, None) => format!("{} 0x{value:x}", symbolic_reference_kind_name(c)),
            };
            stored.push('{');
            stored.push_str(&shown);
            stored.push('}');
            let Some(context) = context.filter(|context| context.is_type) else {
                plain = None;
                continue;
            };
            let Some((flat, nested)) = plain.as_mut() else {
                continue;
            };
            // A protocol, or the head of a bound generic type (`y` starts
            // the arguments), has to be a declaration.
            let protocol = context.is_protocol;
            let declaration = protocol || name.get(i) == Some(&b'y');
            let exact = if declaration {
                None
            } else {
                placeholders.exact(&context.name)
            };
            match &exact {
                Some(exact) => flat.text.push_str(exact),
                None => flat.declaration(&placeholders.declaration(false, protocol, &context.name)),
            }
            match (context.levels.as_deref(), &exact) {
                (Some(levels @ [_, _, ..]), _) => {
                    has_nested = true;
                    for (level, shown) in levels.iter().enumerate() {
                        let last = level + 1 == levels.len();
                        nested.declaration(&placeholders.declaration(
                            level != 0,
                            last && protocol,
                            shown,
                        ));
                    }
                }
                (_, Some(exact)) => nested.text.push_str(exact),
                (_, None) => {
                    nested.declaration(&placeholders.declaration(false, protocol, &context.name));
                }
            }
        }
        let demangled = plain.and_then(|(flat, nested)| {
            let demangle = |name: &Rewritten| placeholders.demangle(name.checked()?);
            demangle(&flat).or_else(|| has_nested.then(|| demangle(&nested)).flatten())
        });
        Some(TypeName {
            address: vmaddr,
            stored,
            demangled,
            references,
        })
    }

    /// `(address referred to, context found there)` for the symbolic
    /// reference with control byte `kind` whose operand `value` is stored
    /// at `field`.
    fn symbolic_reference(
        &self,
        kind: u8,
        field: u64,
        value: u64,
        depth: u32,
    ) -> (Option<u64>, Option<Context>) {
        if kind >= 0x18 {
            // An absolute pointer: only made at run time.
            return (None, None);
        }
        let target = relative_target(field, value as u32 as i32);
        let context = match kind {
            0x01 => self.context(target, depth + 1),
            0x02 => self.context_through_pointer(target, depth + 1),
            _ => None,
        };
        (Some(target), context)
    }

    /// The context whose descriptor the pointer stored at `slot` refers
    /// to: a descriptor of this image, or an imported one named by its
    /// symbol.
    fn context_through_pointer(&self, slot: u64, depth: u32) -> Option<Context> {
        let pointer_size = self.pointer_size() as u64;
        let offset = self.reader.object_offset(slot, pointer_size)?;
        let pointers = self
            .pointers
            .get_or_init(|| PointerDecoder::new(self.reader.mh));
        match pointers.read(offset, pointer_size == 8)? {
            Pointer::Address(address) => self.context(address, depth),
            Pointer::Import { name, .. } => imported_context(name),
        }
    }

    /// The context that the mangled name at `vmaddr` refers to, when the
    /// name is nothing but one symbolic reference to a context.
    fn sole_reference(&self, vmaddr: u64, depth: u32) -> Option<Context> {
        let bytes = self.reader.bytes(vmaddr, 6)?;
        let (&kind, operand) = bytes.split_first()?;
        if !matches!(kind, 0x01 | 0x02) || bytes.get(5) != Some(&0) {
            return None;
        }
        let rel = u32::from_le_bytes(operand.get(..4)?.try_into().ok()?);
        let field = vmaddr.wrapping_add(1);
        self.symbolic_reference(kind, field, u64::from(rel), depth)
            .1
    }

    /// The context described by the descriptor at `vmaddr`.
    fn context(&self, vmaddr: u64, depth: u32) -> Option<Context> {
        if depth > MAX_CONTEXT_DEPTH || !self.charge(REFERENCE_COST) {
            return None;
        }
        let offset = self
            .reader
            .object_offset(vmaddr, ContextDescriptorHeader::SIZE)?;
        let desc = ContextDescriptorHeader::read(self.reader.image(), offset)?;
        let parent = || {
            let field = vmaddr.wrapping_add(4);
            match desc.parent {
                0 => None,
                // The low bit marks a pointer to the descriptor's address.
                rel if rel & 1 != 0 => {
                    self.context_through_pointer(relative_target(field, rel & !1), depth + 1)
                }
                rel => self.context(relative_target(field, rel), depth + 1),
            }
        };
        let name_field = vmaddr.wrapping_add(8);
        let kind = desc.kind();
        match kind {
            // Module.
            0 => Some(Context {
                name: self.relative_cstring(name_field, desc.name)?,
                is_protocol: false,
                is_type: false,
                levels: Some(Vec::new()),
            }),
            // Extension: named by the mangled name of the extended type.
            1 if desc.name != 0 => {
                let extended = relative_target(name_field, desc.name);
                let context = match self.sole_reference(extended, depth + 1) {
                    Some(context) => context,
                    None => Context {
                        name: self.read_at(extended, depth + 1)?.text().to_string(),
                        is_protocol: false,
                        is_type: false,
                        levels: None,
                    },
                };
                Some(Context {
                    is_type: false,
                    ..context
                })
            }
            // Anonymous (a function body, a file's private scope): what it
            // holds is shown as a member of its parent.
            2 => parent().map(|p| Context {
                is_type: false,
                ..p
            }),
            3 | 16..=18 => {
                let name = self.relative_cstring(name_field, desc.name)?;
                Some(Context::nested(parent(), name, kind == 3))
            }
            _ => None,
        }
    }
}

/// The context that an imported descriptor symbol (`_$s…Mn`, `_$s…Mp`)
/// stands for.
fn imported_context(symbol: &[u8]) -> Option<Context> {
    let is_protocol = symbol.ends_with(b"Mp");
    if symbol.ends_with(b"MQ") {
        // An opaque result type: it has a name to show, but no mangling
        // that could stand in for it.
        let text = demangle(symbol)?;
        return Some(Context {
            name: text
                .strip_prefix("opaque type descriptor for ")?
                .to_string(),
            is_protocol: false,
            is_type: false,
            levels: None,
        });
    }
    if !is_protocol && !symbol.ends_with(b"Mn") {
        return None;
    }
    let text = demangle(symbol)?;
    let prefix = if is_protocol {
        "protocol descriptor for "
    } else {
        "nominal type descriptor for "
    };
    let name = text.strip_prefix(prefix)?;
    // `Module.Outer.Inner`; anything else (a type in an extension or in a
    // function) does not show its nesting.
    let simple = name
        .chars()
        .all(|c| c == '.' || c == '_' || c.is_alphanumeric());
    let levels = match name.split('.').collect::<Vec<_>>().as_slice() {
        [module, first, rest @ ..] if simple => Some(
            std::iter::once(format!("{module}.{first}"))
                .chain(rest.iter().map(|part| part.to_string()))
                .collect(),
        ),
        _ => None,
    };
    Some(Context {
        name: name.to_string(),
        is_protocol,
        is_type: true,
        levels,
    })
}

/// What the symbolic reference with control byte `kind` refers to
/// (`Demangler::demangleSymbolicReference` in the Swift sources).
fn symbolic_reference_kind_name(kind: u8) -> String {
    match kind {
        0x01 => "context".to_string(),
        0x02 => "indirect context".to_string(),
        // Only after a leading 0xFF, in the names of associated
        // conformances.
        0x07 => "associated conformance accessor".to_string(),
        0x09 => "accessor function".to_string(),
        0x0a => "unique existential shape".to_string(),
        0x0b => "non-unique existential shape".to_string(),
        0x0c => "objc protocol".to_string(),
        _ => format!("reference 0x{kind:02x}"),
    }
}

/// Addresses of the metadata source strings that the `__swift5_capture`
/// sections of `mh` refer to. They are stored among the mangled names of
/// `__swift5_typeref` but are not type names.
pub fn metadata_source_addresses(mh: &MachHeader) -> HashSet<u64> {
    let mut out = HashSet::new();
    for sec in mh.sections().filter(|s| s.sectname == "__swift5_capture") {
        for (offset, item) in capture_records(sec.data(&mh.image)).items {
            if let CaptureItem::MetadataSource {
                mangled_metadata_source: rel,
                ..
            } = item
            {
                if rel != 0 {
                    out.insert(relative_target(sec.addr.wrapping_add(offset + 4), rel));
                }
            }
        }
    }
    out
}

/// True for names carrying a Swift mangling prefix (`$s`, `$S`, optionally
/// after the Mach-O underscore).
pub fn has_swift_prefix(name: &[u8]) -> bool {
    [&b"_$s"[..], b"$s", b"_$S", b"$S"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// Minimal decoding of a Swift mangled name: the leading run of
/// `<length><identifier>` components (at most eight) joined with dots, e.g.
/// `_$s4Demo5ShapeV...` → `Demo.Shape`. Empty when the name has no Swift
/// prefix or no such component.
pub fn decode_mangled_components(name: &[u8]) -> String {
    let name = name.strip_prefix(b"_").unwrap_or(name);
    if name.len() < 2 || name.first() != Some(&b'$') || !matches!(name.get(1), Some(b's' | b'S')) {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut i = 2usize;
    while name.get(i).is_some_and(u8::is_ascii_digit) {
        let mut len = 0usize;
        while let Some(d) = name.get(i).filter(|c| c.is_ascii_digit()) {
            len = len * 10 + usize::from(d - b'0');
            i += 1;
            if len > 1024 {
                return String::new();
            }
        }
        let Some(part) = (len != 0).then(|| name.get(i..i + len)).flatten() else {
            break;
        };
        parts.push(utf8_safe(part));
        i += len;
        if parts.len() >= 8 {
            break;
        }
    }
    parts.join(".")
}

/// Demangled form of the Swift symbol `name`, falling back to
/// [`decode_mangled_components`] for manglings the demangler does not know.
/// Empty when `name` is not a Swift symbol.
pub fn demangle_symbol(name: &[u8]) -> String {
    demangle(name).unwrap_or_else(|| decode_mangled_components(name))
}

// ---------------------------------------------------------------------------
// Demangler
// ---------------------------------------------------------------------------

/// Longer names are not demangled: nothing real comes close, and the bound
/// keeps the work on a crafted name small.
const MAX_MANGLED_LEN: usize = 16 * 1024;

/// Demangled form of a Swift symbol name (`$s…`, `_$s…`, `$S…`, `_T0…`);
/// `None` when `name` is not one or the demangler does not understand it.
///
/// This is Swift's own demangler as bundled by the `symbolic-demangle`
/// crate, so it works on every platform and starts no process. Unlike the
/// `swift-demangle` tool it prints types without sugar
/// (`Swift.Optional<Swift.Int>`, not `Swift.Int?`), and manglings newer
/// than the bundled demangler are not understood.
pub fn demangle(name: &[u8]) -> Option<String> {
    demangle_all(&[name]).pop().flatten()
}

/// [`demangle`] for many names at once (one hand-over to the demangler
/// thread instead of one per name); results are in input order.
pub fn demangle_all<N: AsRef<[u8]>>(names: &[N]) -> Vec<Option<String>> {
    let candidates: Vec<Option<String>> = names
        .iter()
        .map(|name| {
            let name = name.as_ref();
            if !looks_mangled(name) || name.len() > MAX_MANGLED_LEN || name.contains(&0) {
                return None;
            }
            std::str::from_utf8(name).ok().map(str::to_string)
        })
        .collect();
    if candidates.iter().all(Option::is_none) {
        return candidates;
    }
    worker::run(candidates)
}

/// The mangling prefixes the demangler accepts, optionally after the
/// Mach-O underscore: `$s` / `$S` (Swift 5 / 4.2), `$e` (embedded Swift),
/// `_T0` (Swift 4.0) and `_T` (Swift 3 and earlier).
fn looks_mangled(name: &[u8]) -> bool {
    let has = |name: &[u8], prefix: &[u8]| name.len() > prefix.len() && name.starts_with(prefix);
    let bare = name.strip_prefix(b"_").unwrap_or(name);
    [&b"$s"[..], b"$S", b"$e", b"_T"]
        .iter()
        .any(|p| has(bare, p))
        || has(name, b"_T")
}

/// The demangler runs on a thread of its own: its printer recurses once
/// per nesting level of the mangled name (up to a built-in limit), which
/// takes far more stack than an arbitrary caller is sure to have left,
/// above all in unoptimised builds.
mod worker {
    use std::sync::mpsc::{channel, Sender};
    use std::sync::{Mutex, OnceLock};
    use symbolic_common::{Language, Name, NameMangling};
    use symbolic_demangle::{Demangle, DemangleOptions};

    /// The deepest nesting the demangler follows needs about 16 MiB in an
    /// unoptimised build (under 1 MiB optimised). Only the pages that are
    /// touched get committed.
    const STACK_SIZE: usize = 48 * 1024 * 1024;

    type Names = Vec<Option<String>>;
    type Request = (Names, Sender<Names>);

    fn demangle_one(mangled: &str) -> Option<String> {
        let name = Name::new(mangled, NameMangling::Mangled, Language::Swift);
        // A name the demangler does not understand comes back unchanged.
        name.demangle(DemangleOptions::complete())
            .filter(|out| out != mangled)
    }

    /// The queue of the demangler thread, which is started on first use and
    /// lives as long as the process. `None` when it cannot be started.
    fn queue() -> Option<Sender<Request>> {
        static QUEUE: OnceLock<Option<Mutex<Sender<Request>>>> = OnceLock::new();
        let queue = QUEUE.get_or_init(|| {
            let (tx, rx) = channel::<Request>();
            std::thread::Builder::new()
                .name("swift-demangle".to_string())
                .stack_size(STACK_SIZE)
                .spawn(move || {
                    for (names, reply) in rx {
                        let out = names
                            .iter()
                            .map(|n| n.as_deref().and_then(demangle_one))
                            .collect();
                        let _ = reply.send(out);
                    }
                })
                .ok()
                .map(|_| Mutex::new(tx))
        });
        Some(queue.as_ref()?.lock().ok()?.clone())
    }

    /// Demangles every `Some` entry. Nothing is demangled when the thread
    /// is not available.
    pub(super) fn run(names: Names) -> Names {
        let count = names.len();
        let (reply, result) = channel();
        queue()
            .and_then(|queue| queue.send((names, reply)).ok())
            .and_then(|()| result.recv().ok())
            .unwrap_or_else(|| vec![None; count])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::macho::ptr::Segments;
    use std::sync::Arc;

    #[test]
    fn record_decoders() {
        let mut b = Vec::new();
        for v in [0x51u32, (-48i32) as u32, 0x20] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[
            0x10, 0, 0, 0, 0xfc, 0xff, 0xff, 0xff, 2, 0, 12, 0, 3, 0, 0, 0,
        ]);
        let img = Image::from_vec(b).unwrap();
        let c = ContextDescriptorHeader::read(&img, 0).unwrap();
        assert_eq!((c.flags, c.parent, c.name, c.kind()), (0x51, -48, 0x20, 17));
        assert_eq!(context_kind_name(c.kind()), "struct");
        let f = FieldDescriptorHeader::read(&img, 12).unwrap();
        assert_eq!(
            (
                f.mangled_type_name,
                f.superclass,
                f.kind,
                f.field_record_size,
                f.num_fields
            ),
            (16, -4, 2, 12, 3)
        );
        assert!(f.is_plausible());
        assert_eq!(field_descriptor_kind_name(f.kind), "enum");
        assert!(FieldDescriptorHeader::read(&img, 13).is_none());
        let r = FieldRecord::read(&img, 0).unwrap();
        assert_eq!(
            (r.flags, r.mangled_type_name, r.field_name),
            (0x51, -48, 0x20)
        );
        assert!(ContextDescriptorHeader::read(&img, 17).is_none());

        let bad = FieldDescriptorHeader {
            mangled_type_name: 0,
            superclass: 0,
            kind: 0,
            field_record_size: 8,
            num_fields: 1,
        };
        assert!(!bad.is_plausible());
        assert!(!FieldDescriptorHeader {
            field_record_size: 300,
            ..bad
        }
        .is_plausible());
        assert!(!FieldDescriptorHeader {
            field_record_size: 12,
            num_fields: 65536,
            ..bad
        }
        .is_plausible());
        assert_eq!(context_kind_name(4), "opaque-type");
        assert_eq!(context_kind_name(5), "unknown");
        assert_eq!(field_descriptor_kind_name(9), "unknown");
    }

    #[test]
    fn reflection_string_scan() {
        let strings = |data: &'static [u8]| -> Vec<(usize, &'static [u8], u64)> {
            reflection_strings(data)
                .iter()
                .map(|s| (s.offset, s.text, s.size()))
                .collect()
        };
        assert_eq!(
            strings(b"RawValue\0r\0\0w\0"),
            [
                (0, &b"RawValue"[..], 9),
                (9, &b"r"[..], 2),
                (12, &b"w"[..], 2)
            ]
        );
        // Strings are taken as stored, whatever their bytes; a last
        // string without terminator ends with the data.
        assert_eq!(
            strings(b"na\xc3\xafve\0\x01\0ef"),
            [
                (0, &b"na\xc3\xafve"[..], 7),
                (7, &b"\x01"[..], 2),
                (9, &b"ef"[..], 2)
            ]
        );
        assert!(reflection_strings(b"").is_empty());
        assert!(reflection_strings(&[0; 4096]).is_empty());
    }

    #[test]
    fn mangled_component_decoding() {
        assert_eq!(
            decode_mangled_components(b"_$s11swift_arm646CircleV1rSdvg"),
            "swift_arm64.Circle"
        );
        assert_eq!(decode_mangled_components(b"$S4Demo3FooC"), "Demo.Foo");
        assert_eq!(decode_mangled_components(b"_$sSS6appendyySSF"), "");
        assert_eq!(decode_mangled_components(b"_main"), "");
        assert_eq!(decode_mangled_components(b"$s"), "");
        assert_eq!(decode_mangled_components(b"_"), "");
        assert_eq!(decode_mangled_components(b""), "");
        // Length running past the end stops the scan; earlier parts stay.
        assert_eq!(decode_mangled_components(b"$s1a9bc"), "a");
        assert_eq!(decode_mangled_components(b"$s0a"), "");
        assert_eq!(decode_mangled_components(b"$s99999a"), "");
        // At most eight components.
        assert_eq!(
            decode_mangled_components(b"$s1a1b1c1d1e1f1g1h1i1j"),
            "a.b.c.d.e.f.g.h"
        );
    }

    #[test]
    fn swift_prefixes() {
        assert!(has_swift_prefix(b"_$s4main"));
        assert!(has_swift_prefix(b"$S4main"));
        assert!(!has_swift_prefix(b"__$s"));
        assert!(!has_swift_prefix(b"_main"));
    }

    #[test]
    fn demangles_symbols() {
        assert_eq!(
            demangle(b"_$s7sw_main6CircleV4areaSdvg").as_deref(),
            Some("sw_main.Circle.area.getter : Swift.Double")
        );
        assert_eq!(demangle(b"$s4main5ShapeV").as_deref(), Some("main.Shape"));
        assert_eq!(demangle(b"$S4main3FooC").as_deref(), Some("main.Foo"));
        assert_eq!(demangle(b"_T0SS").as_deref(), Some("Swift.String"));
        // No type sugar.
        assert_eq!(
            demangle(b"$sSaySSSgG").as_deref(),
            Some("Swift.Array<Swift.Optional<Swift.String>>")
        );
        // Not Swift names, or not valid ones.
        for name in [
            &b"_main"[..],
            b"",
            b"$s",
            b"_$s",
            b"plain text",
            b"_ZN3fooE",
            b"-help",
            b"@/etc/passwd",
            b"$s4main\0",
            b"$s4main\xff",
            b"$s9999999999",
        ] {
            assert_eq!(demangle(name), None, "{name:?}");
        }
        assert_eq!(
            demangle_all(&[&b"_main"[..], b"$sSi", b"", b"$sSS"]),
            [
                None,
                Some("Swift.Int".to_string()),
                None,
                Some("Swift.String".to_string())
            ]
        );
        assert!(demangle_all::<&[u8]>(&[]).is_empty());
    }

    #[test]
    fn symbol_and_text_fallbacks() {
        assert_eq!(demangle_symbol(b"_$s4main5ShapeV"), "main.Shape");
        assert_eq!(demangle_symbol(b"_main"), "");
        // Undecodable tail: the leading components are still shown.
        assert_eq!(demangle_symbol(b"$s4Demo5Shape!!"), "Demo.Shape");
    }

    #[test]
    fn hostile_names_do_not_overflow_the_stack() {
        // Nesting far beyond anything real, in several shapes; whatever
        // comes back, the process must survive. Run from a thread with a
        // small stack to show the caller's stack is not what is used.
        let names: Vec<String> = vec![
            format!("$sSi{}", "Sg".repeat(5000)),
            format!("$s{}Si{}", "Say".repeat(4000), "G".repeat(4000)),
            format!("$sSi{}", "_t".repeat(5000)),
            format!("$sSi{}", "m".repeat(16000)),
            format!("$s4main{}", "1aV".repeat(5000)),
            format!("_T0{}", "GSq".repeat(5000)),
            format!("_Tt{}", "GSa".repeat(5000)),
            format!("$s{}", "9".repeat(4000)),
            format!("$sSi{}", "Sg".repeat(20000)),
        ];
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let out = demangle_all(&names);
                assert_eq!(out.len(), names.len());
                // Longer than the limit: not even tried.
                assert_eq!(out.last(), Some(&None));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn associated_type_sections() {
        use AssociatedTypeItem::{Descriptor, Record};
        // Two descriptors: one record of 8 bytes, then two of 12.
        let mut data = words(&[0x100, 0x200, 1, 8, 0x10, 0x20]);
        data.extend(words(&[0xffff_fff0, 0, 2, 12, 1, 2, 0xaaaa, 3, 4, 0xbbbb]));
        let walk = associated_type_records(&data);
        assert_eq!(walk.error, None);
        let record = |index, size, name, substituted_type_name| Record {
            index,
            size,
            record: AssociatedTypeRecord {
                name,
                substituted_type_name,
            },
        };
        assert_eq!(
            walk.items,
            [
                (
                    0,
                    Descriptor(AssociatedTypeDescriptor {
                        conforming_type_name: 0x100,
                        protocol_type_name: 0x200,
                        num_associated_types: 1,
                        associated_type_record_size: 8,
                    })
                ),
                (16, record(0, 8, 0x10, 0x20)),
                (
                    24,
                    Descriptor(AssociatedTypeDescriptor {
                        conforming_type_name: -16,
                        protocol_type_name: 0,
                        num_associated_types: 2,
                        associated_type_record_size: 12,
                    })
                ),
                (40, record(0, 12, 1, 2)),
                (52, record(1, 12, 3, 4)),
            ]
        );

        // Cut anywhere, the walk ends with an error and what came before.
        for len in 1..data.len() {
            let cut = associated_type_records(data.get(..len).unwrap());
            let (error, items) = match len {
                1..=15 => (Some("truncated associated type descriptor"), 0),
                16..=23 => (Some("truncated associated type record table"), 1),
                // Exactly the first descriptor and its record.
                24 => (None, 2),
                25..=39 => (Some("truncated associated type descriptor"), 2),
                40..=51 => (Some("truncated associated type record table"), 3),
                _ => (Some("truncated associated type record table"), 4),
            };
            assert_eq!((cut.error, cut.items.len()), (error, items), "{len}");
        }

        // A record size too small for a record; no records, any size.
        let bad = associated_type_records(&words(&[0, 0, 1, 4, 0, 0]));
        assert_eq!(bad.error, Some("invalid associated type record size"));
        assert_eq!(bad.items.len(), 1);
        let empty = associated_type_records(&words(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!((empty.error, empty.items.len()), (None, 2));
        // A count and a record size at their largest neither overflow nor
        // run long.
        let huge = associated_type_records(&words(&[0, 0, u32::MAX, u32::MAX, 0, 0]));
        assert_eq!(huge.error, Some("truncated associated type record table"));
        assert_eq!(huge.items.len(), 1);
        assert!(associated_type_records(&[]).items.is_empty());
    }

    #[test]
    fn capture_sections() {
        use CaptureItem::{CaptureType, Descriptor, MetadataSource};
        // Two capture types and a metadata source; then nothing at all.
        let data = words(&[2, 1, 3, 0x10, 0x20, 0x30, 0x40, 0, 0, 0]);
        let walk = capture_records(&data);
        assert_eq!(walk.error, None);
        assert_eq!(
            walk.items,
            [
                (
                    0,
                    Descriptor(CaptureDescriptor {
                        num_capture_types: 2,
                        num_metadata_sources: 1,
                        num_bindings: 3,
                    })
                ),
                (
                    12,
                    CaptureType {
                        index: 0,
                        mangled_type_name: 0x10
                    }
                ),
                (
                    16,
                    CaptureType {
                        index: 1,
                        mangled_type_name: 0x20
                    }
                ),
                (
                    20,
                    MetadataSource {
                        index: 0,
                        mangled_type_name: 0x30,
                        mangled_metadata_source: 0x40,
                    }
                ),
                (
                    28,
                    Descriptor(CaptureDescriptor {
                        num_capture_types: 0,
                        num_metadata_sources: 0,
                        num_bindings: 0,
                    })
                ),
            ]
        );
        assert_eq!(
            walk.items.iter().map(|(_, i)| i.size()).sum::<u64>(),
            data.len() as u64
        );

        for len in 1..data.len() {
            let cut = capture_records(data.get(..len).unwrap());
            let expected = match len {
                1..=11 | 29..=39 => Some("truncated capture descriptor"),
                12..=19 => Some("truncated capture type records"),
                20..=27 => Some("truncated metadata source records"),
                _ => None,
            };
            assert_eq!(cut.error, expected, "{len}");
        }
        let huge = capture_records(&words(&[u32::MAX, u32::MAX, 0, 1]));
        assert_eq!(huge.error, Some("truncated capture type records"));
        assert_eq!(huge.items.len(), 2);
    }

    #[test]
    fn builtin_type_sections() {
        let data = words(&[0x10, 17, 0x0001_0008, 24, 252, 0xffff_fff0, 1, 1, 1, 0]);
        let walk = builtin_type_records(&data);
        assert_eq!(walk.error, None);
        assert_eq!(walk.items.len(), 2);
        let (offset, first) = walk.items.first().copied().unwrap();
        assert_eq!(offset, 0);
        assert_eq!((first.type_name, first.size, first.stride), (0x10, 17, 24));
        assert_eq!((first.alignment(), first.is_bitwise_takable()), (8, true));
        assert_eq!(
            first.layout_text(),
            "size=17 alignment=8 stride=24 extra_inhabitants=252 bitwise_takable=yes flags=0x1"
        );
        let (offset, second) = walk.items.get(1).copied().unwrap();
        assert_eq!((offset, second.type_name), (20, -16));
        assert_eq!(
            second.layout_text(),
            "size=1 alignment=1 stride=1 extra_inhabitants=0 bitwise_takable=no flags=0x0"
        );
        for len in 1..data.len() {
            let cut = builtin_type_records(data.get(..len).unwrap());
            let whole = len % 20 == 0;
            assert_eq!(
                cut.error,
                (!whole).then_some("truncated builtin type descriptor"),
                "{len}"
            );
            assert_eq!(cut.items.len(), len / 20);
        }
    }

    #[test]
    fn multi_payload_enum_sections() {
        // One word; then three words with the spare-bits flag.
        let data = words(&[0x10, 0x0001_0000, 0x20, 0x0003_0001, 0x0004_0002, 0xff]);
        let walk = multi_payload_enum_records(&data);
        assert_eq!(walk.error, None);
        let got: Vec<(u64, u64, String)> = walk
            .items
            .iter()
            .map(|(o, d)| (*o, d.size(), d.layout_text()))
            .collect();
        assert_eq!(
            got,
            [
                (0, 8, "words=1 flags=0x0 payload_spare_bits=no".to_string()),
                (
                    8,
                    16,
                    "words=3 flags=0x1 payload_spare_bits=yes".to_string()
                ),
            ]
        );
        for len in 1..data.len() {
            let cut = multi_payload_enum_records(data.get(..len).unwrap());
            assert_eq!(
                cut.error,
                (len != 8).then_some("truncated multi-payload enum descriptor"),
                "{len}"
            );
        }
        // A size of zero would not even cover the size word.
        let zero = multi_payload_enum_records(&words(&[0x10, 0x0000_0001, 0, 0]));
        assert_eq!(
            zero.error,
            Some("invalid multi-payload enum descriptor size")
        );
        assert!(zero.items.is_empty());
    }

    #[test]
    fn mangled_name_walk() {
        // The operand of a symbolic reference may hold zero bytes.
        assert_eq!(mangled_name_len(b"Si\0", 8), Some(2));
        assert_eq!(mangled_name_len(b"\0", 8), Some(0));
        assert_eq!(mangled_name_len(b"\x01\0\0\0\0\0", 8), Some(5));
        assert_eq!(mangled_name_len(b"Say\x02\x10\0\0\0G\0rest", 8), Some(9));
        assert_eq!(mangled_name_len(b"\x17\0\0\0\0\0", 8), Some(5));
        // An absolute reference is as wide as a pointer.
        assert_eq!(mangled_name_len(b"\x18\0\0\0\0\0\0\0\0x\0", 8), Some(10));
        assert_eq!(mangled_name_len(b"\x1f\0\0\0\0x\0", 4), Some(6));
        assert_eq!(mangled_name_len(b"\x20\0", 8), Some(1));
        // Not terminated, or cut inside a reference.
        assert_eq!(mangled_name_len(b"Si", 8), None);
        assert_eq!(mangled_name_len(b"\x01\0\0\0", 8), None);
        assert_eq!(mangled_name_len(b"\x01\0\0\0\0", 8), None);
        assert_eq!(mangled_name_len(b"\x18\0\0\0\0\0", 8), None);
        assert_eq!(mangled_name_len(b"", 8), None);

        let data = b"Si\0\0Sa\x01\0\0\0\0G\0\0\0\xff\x07\x04\0\0\0\0x\0";
        let walk = mangled_names(data, 8);
        assert_eq!(walk.error, None);
        let names: Vec<(u64, usize, u64)> = walk
            .items
            .iter()
            .map(|(o, n)| (*o, n.len, n.size()))
            .collect();
        assert_eq!(names, [(0, 2, 3), (4, 8, 9), (15, 6, 7), (22, 1, 2)]);
        let (_, second) = walk.items.get(1).copied().unwrap();
        assert_eq!(second.bytes(data), b"Sa\x01\0\0\0\0G");

        // A last name without terminator is reported, not listed.
        let cut = mangled_names(b"Si\0\0Sa\x01\0\0", 8);
        assert_eq!(cut.error, Some("truncated mangled name"));
        assert_eq!(cut.items.len(), 1);
        let cut = mangled_names(b"Si", 8);
        assert_eq!((cut.error.is_some(), cut.items.len()), (true, 0));
        let empty = mangled_names(&[0; 64], 8);
        assert_eq!((empty.error, empty.items.len()), (None, 0));
        assert!(mangled_names(&[], 8).items.is_empty());
    }

    #[test]
    fn record_walks_stop_at_the_row_limit() {
        let data = vec![0u8; (MAX_RECORDS + 10) * 20];
        let walk = builtin_type_records(&data);
        assert_eq!(walk.error, Some("row limit reached"));
        assert_eq!(walk.items.len(), MAX_RECORDS);
        let walk = capture_records(&data);
        assert_eq!(walk.error, Some("row limit reached"));
        assert_eq!(walk.items.len(), MAX_RECORDS);
        let walk = associated_type_records(&data);
        assert_eq!(walk.error, Some("row limit reached"));
        let walk = mangled_names(&b"x\0".repeat(MAX_RECORDS + 1), 8);
        assert_eq!(walk.error, Some("row limit reached"));
    }

    /// A 64-bit Mach-O of 0x1000 bytes with one segment, `__TEXT`, mapping
    /// the whole file at 0x1000 (so the address of a byte is its offset
    /// plus 0x1000) and holding `sections`, `(name, file offset, size)`.
    /// `fill` writes the contents.
    pub(crate) fn image(
        sections: &[(&str, u32, u64)],
        fill: impl FnOnce(&mut Vec<u8>),
    ) -> MachHeader {
        fn name16(f: &mut Vec<u8>, name: &str) {
            let mut b = name.as_bytes().to_vec();
            b.resize(16, 0);
            f.extend_from_slice(&b);
        }
        let mut f = Vec::new();
        let cmdsize = 72 + 80 * sections.len() as u32;
        f.extend(words(&[0xfeed_facf, 0x0100_000c, 0, 2, 1, cmdsize, 0, 0]));
        f.extend(words(&[0x19, cmdsize]));
        name16(&mut f, "__TEXT");
        for v in [0x1000u64, 0x1000, 0, 0x1000] {
            f.extend(v.to_le_bytes());
        }
        f.extend(words(&[5, 5, sections.len() as u32, 0]));
        for (name, offset, size) in sections {
            name16(&mut f, name);
            name16(&mut f, "__TEXT");
            f.extend((0x1000 + u64::from(*offset)).to_le_bytes());
            f.extend(size.to_le_bytes());
            f.extend(words(&[*offset, 0, 0, 0, 0, 0, 0, 0]));
        }
        assert!(f.len() <= 0x400);
        f.resize(0x1000, 0);
        fill(&mut f);
        assert_eq!(f.len(), 0x1000);
        let image = Arc::new(Image::from_vec(f).unwrap());
        MachHeader::parse(&image, 0).unwrap()
    }

    /// Writes `bytes` at file offset `at`.
    pub(crate) fn put(f: &mut [u8], at: usize, bytes: &[u8]) {
        f.get_mut(at..at + bytes.len())
            .unwrap()
            .copy_from_slice(bytes);
    }

    /// Writes at `at` the relative pointer to `to`.
    pub(crate) fn put_rel(f: &mut [u8], at: usize, to: usize) {
        put(f, at, &((to as i32) - (at as i32)).to_le_bytes());
    }

    /// Writes at `at` a symbolic reference of `kind` to `to`; returns the
    /// offset after it.
    pub(crate) fn put_ref(f: &mut [u8], at: usize, kind: u8, to: usize) -> usize {
        put(f, at, &[kind]);
        put_rel(f, at + 1, to);
        at + 5
    }

    /// Context descriptors used by the name tests: module `Demo` (0x800),
    /// struct `Demo.Shape` (0x810), struct `Demo.Shape.Inner` (0x820),
    /// protocol `Demo.Proto` (0x830), a struct that is its own parent
    /// (0x840), an extension of `Demo.Shape` (0x850) holding struct
    /// `Deep` (0x860), and at 0x8f0 a pointer to 0x1810.
    pub(crate) fn put_contexts(f: &mut [u8]) {
        let mut descriptor = |at: usize, flags: u32, parent: Option<usize>, name: usize| {
            put(f, at, &flags.to_le_bytes());
            if let Some(parent) = parent {
                put_rel(f, at + 4, parent);
            }
            put_rel(f, at + 8, name);
        };
        descriptor(0x800, 0, None, 0x8a0);
        descriptor(0x810, 17, Some(0x800), 0x8a8);
        descriptor(0x820, 17, Some(0x810), 0x8b0);
        descriptor(0x830, 3, Some(0x800), 0x8b8);
        descriptor(0x840, 17, Some(0x840), 0x8c0);
        descriptor(0x850, 1, Some(0x800), 0x8d0);
        descriptor(0x860, 17, Some(0x850), 0x8c8);
        put(f, 0x8a0, b"Demo\0");
        put(f, 0x8a8, b"Shape\0");
        put(f, 0x8b0, b"Inner\0");
        put(f, 0x8b8, b"Proto\0");
        put(f, 0x8c0, b"Loop\0");
        put(f, 0x8c8, b"Deep\0");
        put_ref(f, 0x8d0, 1, 0x810);
        put(f, 0x8f0, &0x1810u64.to_le_bytes());
    }

    /// An image with one of each reflection section, every one of them
    /// (but `__swift5_reflstr`) ending in a record that is cut off.
    pub(crate) fn reflection_image() -> MachHeader {
        let sections = [
            ("__swift5_typeref", 0x400, 0x10),
            ("__swift5_capture", 0x440, 28),
            ("__swift5_assocty", 0x480, 28),
            ("__swift5_builtin", 0x4c0, 24),
            ("__swift5_reflstr", 0x4f0, 12),
            ("__swift5_mpenum", 0x500, 16),
            ("__swift5_fieldmd", 0x540, 32),
        ];
        image(&sections, |f| {
            put_contexts(f);
            // Names: Swift.Int, Demo.Shape, a metadata source, and one
            // that the end of the section cuts off.
            put(f, 0x400, b"Si\0");
            put_ref(f, 0x404, 1, 0x810);
            put(f, 0x40a, b"B0\0");
            put(f, 0x40e, b"Sd");
            // A capture of an Int with one metadata source.
            put(f, 0x440, &words(&[1, 1, 0]));
            put_rel(f, 0x44c, 0x400);
            put_rel(f, 0x450, 0x404);
            put_rel(f, 0x454, 0x40a);
            put(f, 0x458, &words(&[7]));
            // Demo.Shape: (Swift.Int as a stand-in protocol), Elem = Int.
            put_rel(f, 0x480, 0x404);
            put_rel(f, 0x484, 0x400);
            put(f, 0x488, &words(&[1, 8]));
            put_rel(f, 0x490, 0x4f0);
            put_rel(f, 0x494, 0x400);
            put(f, 0x498, &words(&[7]));
            put_rel(f, 0x4c0, 0x404);
            put(f, 0x4c4, &words(&[16, 0x0001_0008, 16, 0, 7]));
            put(f, 0x4f0, "Elem\0na\u{ef}ve\0".as_bytes());
            put_rel(f, 0x500, 0x404);
            put(f, 0x504, &words(&[0x0001_0000, 0, 0x0005_0000]));
            // struct Demo.Shape { var naïve: Int }
            put_rel(f, 0x540, 0x404);
            put(f, 0x548, &words(&[0x000c_0000, 1, 2]));
            put_rel(f, 0x554, 0x400);
            put_rel(f, 0x558, 0x4f5);
            put(f, 0x55c, &words(&[7]));
        })
    }

    #[test]
    fn names_with_symbolic_references() {
        let mh = image(&[], |f| {
            put_contexts(f);
            // 0x400: the type itself.
            put_ref(f, 0x400, 1, 0x810);
            // 0x410: an argument of a generic type, then a back-reference
            // to it.
            put(f, 0x410, b"Say");
            let at = put_ref(f, 0x413, 1, 0x810);
            put(f, at, b"G_AAt");
            // 0x420: generic arguments bound one level up.
            let at = put_ref(f, 0x420, 1, 0x820);
            put(f, at, b"ySi_G");
            // 0x430: the head of a generic type.
            let at = put_ref(f, 0x430, 1, 0x810);
            put(f, at, b"ySiG");
            // 0x440: the same followed by a back-reference.
            let at = put_ref(f, 0x440, 1, 0x810);
            put(f, at, b"ySiG_AAt");
            // 0x450: a protocol, as an existential.
            let at = put_ref(f, 0x450, 1, 0x830);
            put(f, at, b"_p");
            // 0x460: through a pointer.
            let at = put_ref(f, 0x460, 2, 0x8f0);
            put(f, at, b"Sg");
            // 0x470: an associated conformance, 0x478: a reference to
            // nothing known, 0x480: an absolute reference.
            put(f, 0x470, b"\xff");
            put_ref(f, 0x471, 7, 0x100);
            put_ref(f, 0x478, 1, 0xa00);
            put(f, 0x480, b"\x18\x10\x18\0\0\0\0\0\0");
            // 0x490: a type in an extension, 0x498: one that is its own
            // parent, 0x4a0: two references and a plain type.
            put_ref(f, 0x490, 1, 0x860);
            put_ref(f, 0x498, 1, 0x840);
            let at = put_ref(f, 0x4a0, 1, 0x810);
            put(f, at, b"_");
            let at = put_ref(f, at + 1, 1, 0x820);
            put(f, at, b"Sit");
            // 0x4b0: no reference at all; 0x4b8: a full symbol.
            put(f, 0x4b0, b"SaySSG");
            put(f, 0x4b8, b"$s4Demo5ShapeV");
            // The last bytes of the file: no terminator.
            put(f, 0xffe, b"Si");
        });
        let names = TypeNames::new(SliceReader::new(&mh, Segments::Any));
        let read = |offset: u64| {
            let name = names.read(0x1000 + offset).unwrap();
            assert_eq!(name.address, 0x1000 + offset);
            (name.stored, name.demangled)
        };
        let both =
            |stored: &str, demangled: &str| (stored.to_string(), Some(demangled.to_string()));
        let stored_only = |stored: &str| (stored.to_string(), None);

        assert_eq!(read(0x400), both("{Demo.Shape}", "Demo.Shape"));
        assert_eq!(
            read(0x410),
            both(
                "Say{Demo.Shape}G_AAt",
                "(Swift.Array<Demo.Shape>, Demo.Shape)"
            )
        );
        assert_eq!(
            read(0x420),
            both("{Demo.Shape.Inner}ySi_G", "Demo.Shape<Swift.Int>.Inner")
        );
        assert_eq!(
            read(0x430),
            both("{Demo.Shape}ySiG", "Demo.Shape<Swift.Int>")
        );
        // The placeholder for a head shifts what `AA` refers to, so the
        // name is left as stored rather than demangled wrongly.
        assert_eq!(read(0x440), stored_only("{Demo.Shape}ySiG_AAt"));
        assert_eq!(read(0x450), both("{Demo.Proto}_p", "Demo.Proto"));
        assert_eq!(
            read(0x460),
            both("{Demo.Shape}Sg", "Swift.Optional<Demo.Shape>")
        );
        assert_eq!(
            read(0x470),
            stored_only("\\xff{associated conformance accessor 00001100}")
        );
        assert_eq!(read(0x478), stored_only("{context 00001A00}"));
        assert_eq!(read(0x480), stored_only("{reference 0x18 0x1810}"));
        assert_eq!(read(0x490), both("{Demo.Shape.Deep}", "Demo.Shape.Deep"));
        let (stored, demangled) = read(0x498);
        assert!(stored.starts_with("{Loop.Loop.") && stored.ends_with(".Loop}"));
        assert_eq!(demangled.as_deref(), stored.get(1..stored.len() - 1));
        assert_eq!(
            read(0x4a0),
            both(
                "{Demo.Shape}_{Demo.Shape.Inner}Sit",
                "(Demo.Shape, Demo.Shape.Inner, Swift.Int)"
            )
        );
        assert_eq!(read(0x4b0), both("SaySSG", "Swift.Array<Swift.String>"));
        assert_eq!(read(0x4b8), both("$s4Demo5ShapeV", "Demo.Shape"));

        let name = names.read(0x1460).unwrap();
        assert_eq!(name.references, [0x18f0]);
        assert_eq!(name.text(), "Swift.Optional<Demo.Shape>");
        assert_eq!(names.read(0x14a0).unwrap().references, [0x1810, 0x1820]);

        // Empty, cut off by the end of the file, unmapped.
        assert_eq!(names.read(0x1500), None);
        assert_eq!(names.read(0x1ffe), None);
        assert_eq!(names.read(0x3000), None);
        assert_eq!(names.relative(0x1400, 0), None);
        assert_eq!(names.relative_text(0x1400, 0), "-");
        assert_eq!(
            names.relative_text(0x1400, 0x10),
            "(Swift.Array<Demo.Shape>, Demo.Shape)"
        );
        assert_eq!(names.relative_text(0x1400, 0x100), "(unreadable)");
        assert_eq!(names.cstring(0x18a8).as_deref(), Some("Shape"));
        assert_eq!(names.cstring(0x1500), None);
        assert_eq!(
            names.relative_cstring(0x1800, 0xa0).as_deref(),
            Some("Demo")
        );
        assert_eq!(names.relative_cstring(0x1800, 0), None);
    }

    #[test]
    fn name_reading_is_bounded() {
        let mh = image(&[], |f| {
            put_contexts(f);
            put_ref(f, 0x400, 1, 0x840);
        });
        let names = TypeNames::new(SliceReader::new(&mh, Segments::Any));
        // Each read walks the self-parent chain to the depth limit; the
        // budget (4 x 0x1000 + 1 MiB) ends that well within this loop.
        let read = (0..100_000)
            .filter(|_| names.read(0x1400).is_some())
            .count();
        assert!((100..50_000).contains(&read), "{read}");
        assert_eq!(names.read(0x1400), None);
        assert_eq!(names.relative_text(0x1400, 0x4a8), "(unreadable)");
        assert_eq!(names.cstring(0x18a8), None);
    }

    #[test]
    fn placeholders_keep_back_references() {
        // 40 exact placeholders in one name: all different, each one
        // substitution.
        let mut placeholders = Placeholders::default();
        let mut mangled = String::new();
        for i in 0..40 {
            if i == 1 {
                mangled.push('_');
            }
            mangled.push_str(&placeholders.exact(&format!("T{i}")).unwrap());
        }
        mangled.push_str("AAABt");
        let text = placeholders.demangle(&mangled).unwrap();
        let expected: Vec<String> = (0..40)
            .map(|i| format!("T{i}"))
            .chain(["T0".to_string(), "T1".to_string()])
            .collect();
        assert_eq!(text, format!("({})", expected.join(", ")));

        // A declaration followed by any `A` is not demangled.
        let mut name = Rewritten::default();
        name.text.push_str("SayAAG");
        assert_eq!(name.checked(), Some("SayAAG"));
        name.declaration("s7_000000V");
        assert_eq!(name.checked(), Some("SayAAGs7_000000V"));
        name.text.push_str("ySiG");
        assert!(name.checked().is_some());
        name.text.push_str("7AlphaXX");
        assert_eq!(name.checked(), None);

        // A placeholder that comes out unreplaced fails the name.
        let mut stray = Placeholders::default();
        stray.exact("T").unwrap();
        assert_eq!(stray.demangle("SayBwBwG").as_deref(), Some("T"));
        assert_eq!(stray.demangle("SayBwBpG"), None);
        assert_eq!(Placeholders::default().demangle("s7_000000V"), None);
    }

    #[test]
    fn metadata_sources_are_found() {
        let mh = image(&[("__swift5_capture", 0x400, 32)], |f| {
            put(f, 0x400, &words(&[1, 2, 2]));
            put_rel(f, 0x40c, 0x500);
            put_rel(f, 0x410, 0x504);
            put_rel(f, 0x414, 0x508);
            put_rel(f, 0x418, 0x504);
            // A null source.
        });
        let mut found: Vec<u64> = metadata_source_addresses(&mh).into_iter().collect();
        found.sort_unstable();
        assert_eq!(found, [0x1508]);
    }
}
