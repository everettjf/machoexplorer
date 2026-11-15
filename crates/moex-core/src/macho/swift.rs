//! Swift 5 reflection metadata (`__swift5_*` sections): record decoders,
//! string readers and Swift symbol demangling.

use super::ptr::{relative_target, SliceReader};
use crate::hex::utf8_safe;
use crate::image::Image;

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

/// Longest prefix at `vmaddr` (at most `max_len` bytes) made of identifier
/// characters: ASCII alphanumerics and `_ $ . : < > ?` and space.
pub fn read_identifier_text(reader: &SliceReader<'_>, vmaddr: u64, max_len: u64) -> String {
    let Some(bytes) = reader.bytes(vmaddr, max_len) else {
        return String::new();
    };
    let ok = |c: u8| {
        c.is_ascii_alphanumeric()
            || matches!(c, b'_' | b'$' | b'.' | b':' | b'<' | b'>' | b' ' | b'?')
    };
    let len = bytes.iter().position(|&c| !ok(c)).unwrap_or(bytes.len());
    bytes.get(..len).map(utf8_safe).unwrap_or_default()
}

/// String a relative pointer refers to: `None` when `rel` is 0 or the
/// target is unmapped, otherwise the target address and the printable
/// C string there (possibly empty; at most 512 bytes are examined).
pub fn relative_cstring(
    reader: &SliceReader<'_>,
    field_vmaddr: u64,
    rel: i32,
) -> Option<(u64, String)> {
    if rel == 0 {
        return None;
    }
    let target = relative_target(field_vmaddr, rel);
    reader.file_offset(target)?;
    Some((target, read_printable_cstring(reader, target, 512)))
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

/// The printable strings of a `__swift5_reflstr` section. A string ends at
/// a NUL or at the end of the data; a run holding a non-printable byte is
/// resumed after that byte.
pub fn reflection_strings(data: &[u8]) -> Vec<ReflectionString<'_>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let rest = data.get(cursor..).unwrap_or(&[]);
        let len = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        let run = rest.get(..len).unwrap_or(&[]);
        match run.iter().rposition(|&c| !is_printable(c)) {
            // Every start up to the last bad byte yields a rejected string.
            Some(bad) => cursor += bad + 1,
            None if len == 0 => cursor += 1,
            None => {
                out.push(ReflectionString {
                    offset: cursor,
                    text: run,
                    terminated: len < rest.len(),
                });
                cursor += len + 1;
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

/// Display text for a string found in Swift metadata that may be a mangled
/// name: `-` when empty, the demangled form when there is one,
/// `(mangled) <text>` for a symbol name that cannot be decoded at all,
/// otherwise the text itself.
pub fn decode_swift_like_text(text: &str) -> String {
    if text.is_empty() {
        return "-".to_string();
    }
    if let Some(demangled) = demangle_type_or_symbol(text) {
        return demangled;
    }
    if has_swift_prefix(text.as_bytes()) {
        let components = decode_mangled_components(text.as_bytes());
        return if components.is_empty() {
            format!("(mangled) {text}")
        } else {
            components
        };
    }
    text.to_string()
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

/// Demangled form of a string stored in Swift metadata: either a symbol
/// name or a bare mangled type (`SS`, `4main5ShapeV`), which is what
/// `__swift5_typeref` and field records hold. `None` when it is neither.
///
/// A bare type is only tried when the text consists of mangling characters
/// (ASCII alphanumerics and `_`), and only believed when the result names
/// a qualified type, so ordinary words are left alone.
pub fn demangle_type_or_symbol(text: &str) -> Option<String> {
    if let Some(demangled) = demangle(text.as_bytes()) {
        return Some(demangled);
    }
    let plausible = !text.is_empty()
        && !looks_mangled(text.as_bytes())
        && text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    if !plausible {
        return None;
    }
    demangle(format!("$s{text}").as_bytes()).filter(|d| d.contains('.') || d.contains('('))
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
mod tests {
    use super::*;

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
        // A bad byte hides everything before it in the same run; a last
        // string without terminator ends with the data.
        assert_eq!(
            strings(b"ab\x01cd\0\x7f\0ef"),
            [(3, &b"cd"[..], 3), (8, &b"ef"[..], 2)]
        );
        // A bad byte right before the terminator leaves nothing.
        assert!(reflection_strings(b"ab\xff\0").is_empty());
        assert!(reflection_strings(b"").is_empty());
        assert!(reflection_strings(&[0x80; 4096]).is_empty());
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
        assert_eq!(decode_swift_like_text(""), "-");
        assert_eq!(decode_swift_like_text("$sSi"), "Swift.Int");
        assert_eq!(decode_swift_like_text("$s4Demo5Shape!!"), "Demo.Shape");
        assert_eq!(decode_swift_like_text("$s!!"), "(mangled) $s!!");
        assert_eq!(decode_swift_like_text("XPC error '%@'"), "XPC error '%@'");
    }

    #[test]
    fn bare_types_in_metadata() {
        assert_eq!(
            demangle_type_or_symbol("SS").as_deref(),
            Some("Swift.String")
        );
        assert_eq!(
            demangle_type_or_symbol("4main5ShapeV").as_deref(),
            Some("main.Shape")
        );
        assert_eq!(
            demangle_type_or_symbol("SaySiG").as_deref(),
            Some("Swift.Array<Swift.Int>")
        );
        assert_eq!(
            demangle_type_or_symbol("$s4main5ShapeV").as_deref(),
            Some("main.Shape")
        );
        // Ordinary words and text are not types.
        for text in ["", "name", "value", "hello world", "x", "RawValue", "a.b"] {
            assert_eq!(demangle_type_or_symbol(text), None, "{text}");
        }
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
}
