//! Swift 5 reflection metadata (`__swift5_*` sections): record decoders,
//! string readers and Swift symbol demangling.

use super::vmaddr::{relative_target, VmReader};
use crate::hex::utf8_safe;
use crate::image::Image;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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
pub fn read_printable_cstring(reader: &VmReader<'_>, vmaddr: u64, max_len: u64) -> String {
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
pub fn read_identifier_text(reader: &VmReader<'_>, vmaddr: u64, max_len: u64) -> String {
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
    reader: &VmReader<'_>,
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

/// The printable strings of a `__swift5_reflstr` section as
/// `(offset in data, bytes)`. A string ends at a NUL or at the end of the
/// data; a run holding a non-printable byte is resumed after that byte.
pub fn reflection_strings(data: &[u8]) -> Vec<(usize, &[u8])> {
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
                out.push((cursor, run));
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

/// What the `swift-demangle` tool says about `name` (see
/// [`demangle_external`]), falling back to
/// [`decode_mangled_components`] when the tool gives nothing.
pub fn demangle_symbol(name: &[u8]) -> String {
    let external = demangle_external(name);
    if external.is_empty() {
        decode_mangled_components(name)
    } else {
        external
    }
}

/// Display text for a string found in Swift metadata: `-` when empty, the
/// demangled form when there is one, `(mangled) <text>` for an undecodable
/// mangled name, otherwise the text itself.
pub fn decode_swift_like_text(text: &str) -> String {
    if text.is_empty() {
        return "-".to_string();
    }
    let demangled = demangle_symbol(text.as_bytes());
    if !demangled.is_empty() {
        return demangled;
    }
    if has_swift_prefix(text.as_bytes()) {
        return format!("(mangled) {text}");
    }
    text.to_string()
}

// ---------------------------------------------------------------------------
// External demangler
// ---------------------------------------------------------------------------

/// Results of the external demangler, keyed by the exact input bytes.
fn cache() -> &'static Mutex<HashMap<Vec<u8>, String>> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Entries kept before the cache is dropped and refilled.
const CACHE_LIMIT: usize = 500_000;

fn cache_get(name: &[u8]) -> Option<String> {
    cache().lock().ok()?.get(name).cloned()
}

fn cache_put(name: &[u8], value: String) {
    if let Ok(mut map) = cache().lock() {
        if map.len() >= CACHE_LIMIT {
            map.clear();
        }
        map.insert(name.to_vec(), value);
    }
}

/// Whether the external tool may be asked about `name` at all.
// Names starting with `-` or `@` would be taken as an option or a response
// file by the tool; they are never passed (see docs/rust-port-quirks.md).
fn may_ask_tool(name: &[u8]) -> bool {
    !name.is_empty() && !name.contains(&0) && !matches!(name.first(), Some(b'-' | b'@'))
}

/// Whether `name` can share one tool invocation with other names: its
/// output must be exactly one recognisable line.
fn can_batch(name: &[u8]) -> bool {
    name.iter().all(|&c| is_printable(c)) && !name.windows(MARKER.len()).any(|w| w == MARKER)
}

const MARKER: &[u8] = b" ---> ";

/// The demangled part of the tool's output for one name
/// (`<mangled> ---> <demangled>`), or the whole output when it has no
/// marker or nothing after it.
fn parse_tool_output(output: &[u8]) -> String {
    let mut out = output;
    while let Some((&last, rest)) = out.split_last() {
        if last != b'\n' && last != b'\r' {
            break;
        }
        out = rest;
    }
    let after = out
        .windows(MARKER.len())
        .position(|w| w == MARKER)
        .map(|pos| pos + MARKER.len())
        .filter(|&start| start < out.len())
        .and_then(|start| out.get(start..));
    utf8_safe(after.unwrap_or(out))
}

/// Runs `xcrun swift-demangle <names...>` and returns its standard output;
/// `None` when the tool cannot be started.
#[cfg(target_os = "macos")]
fn run_tool(names: &[&[u8]]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    if std::env::var_os("MOEX_NO_SWIFT_DEMANGLE").is_some() {
        return None;
    }
    let output = Command::new("xcrun")
        .arg("swift-demangle")
        .args(names.iter().map(|n| std::ffi::OsStr::from_bytes(n)))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some(output.stdout)
}

#[cfg(not(target_os = "macos"))]
fn run_tool(_names: &[&[u8]]) -> Option<Vec<u8>> {
    None
}

fn ask_tool_one(name: &[u8]) -> String {
    run_tool(&[name])
        .map(|out| parse_tool_output(&out))
        .unwrap_or_default()
}

/// Demangled form of `name` according to the `swift-demangle` tool of the
/// active Xcode toolchain (macOS only). The tool echoes names it does not
/// recognise, so the result is empty only when the tool is unavailable or
/// refused the name. Results are cached for the life of the process.
///
/// Set `MOEX_NO_SWIFT_DEMANGLE` to never start the tool.
pub fn demangle_external(name: &[u8]) -> String {
    if !cfg!(target_os = "macos") || !may_ask_tool(name) {
        return String::new();
    }
    if let Some(hit) = cache_get(name) {
        return hit;
    }
    let result = ask_tool_one(name);
    cache_put(name, result.clone());
    result
}

/// The single argument a POSIX shell makes of `'<name>'` when `name` itself
/// may contain single quotes: text between a pair of embedded quotes is
/// unquoted and the quotes disappear (`a'b'c` → `abc`). `None` when the
/// quotes do not pair up (a syntax error for the shell) or the unquoted
/// text holds anything a shell would interpret or split on.
pub fn shell_single_quoted_word(name: &[u8]) -> Option<Vec<u8>> {
    if !name.contains(&b'\'') {
        return Some(name.to_vec());
    }
    let segments: Vec<&[u8]> = name.split(|&c| c == b'\'').collect();
    // An odd number of segments means an even number of quotes.
    if segments.len().is_multiple_of(2) {
        return None;
    }
    let inert = |c: &u8| c.is_ascii_alphanumeric() || b"%@_.,:/+=^-".contains(c);
    let mut word = Vec::with_capacity(name.len());
    for (i, segment) in segments.iter().enumerate() {
        if i % 2 == 1 && !segment.iter().all(inert) {
            return None;
        }
        word.extend_from_slice(segment);
    }
    Some(word)
}

/// [`demangle_external`] for a name that the original passes to the tool
/// between single quotes without escaping it.
// QUIRK(parity): embedded single quotes therefore vanish from the name the
// tool sees (`XPC error '%@'` is demangled as `XPC error %@`). Names whose
// quoting would make the shell do anything else are not passed at all; see
// "Intentional differences" in docs/rust-port-quirks.md.
pub fn demangle_external_shell_quoted(name: &[u8]) -> String {
    shell_single_quoted_word(name)
        .map(|word| demangle_external(&word))
        .unwrap_or_default()
}

/// Names per tool invocation and total argument bytes per invocation.
const BATCH_NAMES: usize = 2000;
const BATCH_BYTES: usize = 96 * 1024;

/// Resolves many names with as few tool invocations as possible and stores
/// the results in the cache, so later [`demangle_external`] /
/// [`demangle_symbol`] calls for them are lookups.
pub fn prefetch_demangled<N: AsRef<[u8]>>(names: &[N]) {
    if !cfg!(target_os = "macos") {
        return;
    }
    let mut seen = std::collections::HashSet::new();
    let mut pending: Vec<&[u8]> = Vec::new();
    for name in names.iter().map(AsRef::as_ref) {
        if may_ask_tool(name) && seen.insert(name) && cache_get(name).is_none() {
            if can_batch(name) {
                pending.push(name);
            } else {
                cache_put(name, ask_tool_one(name));
            }
        }
    }
    let mut start = 0usize;
    while start < pending.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < pending.len() && end - start < BATCH_NAMES {
            let len = pending.get(end).map_or(0, |n| n.len() + 1);
            if end > start && bytes + len > BATCH_BYTES {
                break;
            }
            bytes += len;
            end += 1;
        }
        let chunk = pending.get(start..end).unwrap_or(&[]);
        start = end;
        let lines: Vec<Vec<u8>> = match run_tool(chunk) {
            Some(out) => {
                let mut lines: Vec<Vec<u8>> =
                    out.split(|&c| c == b'\n').map(<[u8]>::to_vec).collect();
                if lines.last().is_some_and(Vec::is_empty) {
                    lines.pop();
                }
                lines
            }
            None => Vec::new(),
        };
        if lines.len() == chunk.len() {
            for (name, line) in chunk.iter().zip(&lines) {
                cache_put(name, parse_tool_output(line));
            }
        } else if lines.is_empty() {
            // Tool unavailable: every name resolves to nothing.
            for name in chunk {
                cache_put(name, String::new());
            }
        } else {
            // Unexpected shape (a name the tool rejected): ask one by one.
            for name in chunk {
                cache_put(name, ask_tool_one(name));
            }
        }
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
        let got = reflection_strings(b"RawValue\0r\0\0w\0");
        assert_eq!(
            got,
            [(0, &b"RawValue"[..]), (9, &b"r"[..]), (12, &b"w"[..])]
        );
        // A bad byte hides everything before it in the same run.
        let got = reflection_strings(b"ab\x01cd\0\x7f\0ef");
        assert_eq!(got, [(3, &b"cd"[..]), (8, &b"ef"[..])]);
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
    fn tool_output_parsing() {
        assert_eq!(parse_tool_output(b"_$s1a ---> a.b\n"), "a.b");
        assert_eq!(parse_tool_output(b"x ---> y ---> z\r\n\n"), "y ---> z");
        assert_eq!(parse_tool_output(b"plain\n"), "plain");
        // Nothing after the marker: the whole line is kept.
        assert_eq!(parse_tool_output(b"x ---> \n"), "x ---> ");
        assert_eq!(parse_tool_output(b""), "");
        assert_eq!(parse_tool_output(b"a ---> \xff"), "?");
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(
            shell_single_quoted_word(b"plain text").as_deref(),
            Some(&b"plain text"[..])
        );
        assert_eq!(
            shell_single_quoted_word(b"XPC error '%@'").as_deref(),
            Some(&b"XPC error %@"[..])
        );
        assert_eq!(
            shell_single_quoted_word(b"a''b").as_deref(),
            Some(&b"ab"[..])
        );
        // Unbalanced quote.
        assert_eq!(shell_single_quoted_word(b"it's"), None);
        // Unquoted text the shell would split or interpret.
        assert_eq!(shell_single_quoted_word(b"a'b c'd"), None);
        assert_eq!(shell_single_quoted_word(b"a';id;'"), None);
        assert_eq!(shell_single_quoted_word(b"a'$(id)'"), None);
        assert_eq!(shell_single_quoted_word(b"a'`id`'b"), None);
        assert_eq!(shell_single_quoted_word(b"a'>x'"), None);
        assert_eq!(demangle_external_shell_quoted(b"x';id;'"), "");
    }

    #[test]
    fn tool_argument_rules() {
        assert!(may_ask_tool(b"_$s1a"));
        assert!(!may_ask_tool(b""));
        assert!(!may_ask_tool(b"-help"));
        assert!(!may_ask_tool(b"@/etc/passwd"));
        assert!(can_batch(b"Swift.Int <A>"));
        assert!(!can_batch(b"a\nb"));
        assert!(!can_batch(b"a ---> b"));
        assert!(!can_batch(b"caf\xc3\xa9"));
        assert_eq!(demangle_external(b"-x"), "");
        assert_eq!(decode_swift_like_text(""), "-");
    }
}
