//! `ar` archive (`.a`) parser: the common format with both the BSD
//! (`#1/NN` inline long names, `__.SYMDEF` symbol table; what Apple's tools
//! write) and the GNU/System V conventions (`/` symbol table, `//` long-name
//! string table, `/NN` references into it, names terminated by `/`).

use super::header::MachHeader;
use crate::error::{err, Result};
use crate::image::Image;
use std::sync::Arc;

pub const ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";
/// Size of the global magic.
const MAGIC_SIZE: u64 = 8;
/// `name[16] mtime[12] uid[6] gid[6] mode[8] size[10] fmag[2]`
pub const AR_HEADER_SIZE: u64 = 60;
const AR_NAME_SIZE: usize = 16;
const AR_SIZE_OFFSET: usize = 48;
const AR_SIZE_LEN: usize = 10;
const AR_FMAG_OFFSET: usize = 58;

/// What a member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// The archive symbol table: GNU `/` or `/SYM64/`, BSD `__.SYMDEF*`.
    SymbolTable,
    /// The GNU long-name string table `//`.
    StringTable,
    /// An ordinary member (Mach-O when `ArchiveMember::mh` is set).
    File,
}

pub struct ArchiveMember {
    /// Member name with long names resolved (raw bytes: may be non-UTF-8).
    /// The special GNU members keep their on-disk names `/`, `/SYM64/`, `//`.
    pub name: Vec<u8>,
    pub kind: MemberKind,
    /// File offset of the 60-byte member header.
    pub header_offset: u64,
    /// File offset of the member contents (after a BSD inline long name).
    pub data_offset: u64,
    pub data_size: u64,
    /// Present when the contents start with a thin Mach-O magic.
    pub mh: Option<Arc<MachHeader>>,
}

impl ArchiveMember {
    pub fn is_macho(&self) -> bool {
        self.mh.is_some()
    }

    /// Text for the "Type" column.
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            MemberKind::SymbolTable => "symbol table",
            MemberKind::StringTable => "string table",
            MemberKind::File if self.is_macho() => "Mach-O",
            MemberKind::File => "data",
        }
    }
}

pub struct Archive {
    pub image: Arc<Image>,
    pub members: Vec<ArchiveMember>,
}

pub fn is_archive_magic(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == ARCHIVE_MAGIC
}

/// Drops trailing padding of a header field (spaces, tabs, newlines).
fn trim_right(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && matches!(s[end - 1], b' ' | b'\t' | b'\n') {
        end -= 1;
    }
    &s[..end]
}

/// A BSD inline long name is padded with NULs to a multiple of 4 or 8.
fn trim_nuls(s: &[u8]) -> &[u8] {
    let end = s.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
    &s[..end]
}

/// `strtoull(s, NULL, 10)`: optional leading whitespace and sign, then
/// digits; 0 when there are none, saturating on overflow. Parsing stops at
/// the first other byte (including NUL).
fn strtoull(s: &[u8]) -> u64 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut negative = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        negative = s[i] == b'-';
        i += 1;
    }
    let mut value: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        let digit = (s[i] - b'0') as u64;
        match value.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(v) => value = v,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        u64::MAX
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// The decimal `size` field. `None` when it holds anything but digits and
/// trailing padding.
fn parse_size(field: &[u8]) -> Option<u64> {
    let s = trim_right(field);
    if s.is_empty() {
        return Some(0);
    }
    if !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(strtoull(s))
}

/// The 16-byte name field of a member header, classified.
#[derive(Debug, PartialEq, Eq)]
enum NameField<'a> {
    /// `/` or `/SYM64/`: GNU symbol table.
    GnuSymbolTable(&'a [u8]),
    /// `//`: GNU long-name string table.
    GnuStringTable,
    /// `/NN`: name at offset NN of the GNU string table.
    GnuLong(u64),
    /// `#1/NN`: the name is the first NN bytes of the member data.
    BsdLong(u64),
    /// A name stored in the field itself (GNU `/` terminator removed).
    Short(&'a [u8]),
}

fn all_digits(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(u8::is_ascii_digit)
}

fn classify_name(field: &[u8]) -> NameField<'_> {
    let raw = trim_right(field);
    match raw {
        b"/" | b"/SYM64/" => return NameField::GnuSymbolTable(raw),
        b"//" => return NameField::GnuStringTable,
        _ => {}
    }
    if let Some(digits) = raw.strip_prefix(b"#1/").filter(|d| all_digits(d)) {
        return NameField::BsdLong(strtoull(digits));
    }
    if let Some(digits) = raw.strip_prefix(b"/").filter(|d| all_digits(d)) {
        return NameField::GnuLong(strtoull(digits));
    }
    // GNU ar terminates a short name with '/', which lets it contain spaces.
    NameField::Short(raw.strip_suffix(b"/").unwrap_or(raw))
}

/// Name at `off` in the GNU string table: entries end with `/\n` (or a bare
/// newline / NUL in older variants). `None` when `off` is outside the table.
fn gnu_long_name(strtab: &[u8], off: u64) -> Option<&[u8]> {
    let rest = strtab.get(usize::try_from(off).ok()?..)?;
    if rest.is_empty() {
        return None;
    }
    let end = rest
        .iter()
        .position(|&c| c == b'\n' || c == 0)
        .unwrap_or(rest.len());
    let name = &rest[..end];
    Some(name.strip_suffix(b"/").unwrap_or(name))
}

impl Archive {
    pub fn parse(image: &Arc<Image>) -> Result<Self> {
        let file_size = image.len();
        if !is_archive_magic(image.bytes()) {
            return err("Not an archive file");
        }
        if file_size < MAGIC_SIZE + AR_HEADER_SIZE {
            return err("Malformed archive file: truncated after global magic");
        }

        let mut members = Vec::new();
        let mut strtab: &[u8] = &[];
        let mut cur = MAGIC_SIZE;
        // `cur` never exceeds `file_size + 1`, so these sums cannot overflow.
        while cur + AR_HEADER_SIZE <= file_size {
            let Some(hdr) = image.slice(cur, AR_HEADER_SIZE) else {
                break;
            };
            if &hdr[AR_FMAG_OFFSET..AR_FMAG_OFFSET + 2] != b"`\n" {
                return err("Malformed archive file: invalid member header trailer");
            }
            let Some(member_size) = parse_size(&hdr[AR_SIZE_OFFSET..AR_SIZE_OFFSET + AR_SIZE_LEN])
            else {
                return err("Malformed archive file: non-decimal member size");
            };
            let mut data_offset = cur + AR_HEADER_SIZE;
            // `member_size` has at most 10 decimal digits.
            if data_offset + member_size > file_size {
                return err("Malformed archive file: member payload out of range");
            }

            let field = &hdr[..AR_NAME_SIZE];
            let mut payload_size = member_size;
            let (name, kind) = match classify_name(field) {
                NameField::GnuSymbolTable(raw) => (raw.to_vec(), MemberKind::SymbolTable),
                NameField::GnuStringTable => {
                    strtab = image.slice(data_offset, member_size).unwrap_or(&[]);
                    (b"//".to_vec(), MemberKind::StringTable)
                }
                // An unresolvable reference keeps the raw `/NN` text.
                NameField::GnuLong(off) => (
                    gnu_long_name(strtab, off)
                        .unwrap_or_else(|| trim_right(field))
                        .to_vec(),
                    MemberKind::File,
                ),
                NameField::BsdLong(len) => {
                    if len > payload_size {
                        return err("Malformed archive file: long member name out of range");
                    }
                    let ext = image.slice(data_offset, len).unwrap_or(&[]);
                    data_offset += len;
                    payload_size -= len;
                    (trim_nuls(ext).to_vec(), MemberKind::File)
                }
                NameField::Short(name) => (name.to_vec(), MemberKind::File),
            };
            // BSD symbol tables are ordinary members with a reserved name.
            let kind = if kind == MemberKind::File && name.starts_with(b"__.SYMDEF") {
                MemberKind::SymbolTable
            } else {
                kind
            };

            let mut mh = None;
            if kind == MemberKind::File && payload_size >= 4 {
                let magic = image.u32(data_offset).unwrap_or(0);
                if super::is_valid_magic(magic) && !super::is_fat_magic(magic) {
                    mh = Some(Arc::new(MachHeader::parse_slice(
                        image,
                        data_offset,
                        payload_size,
                    )?));
                }
            }
            members.push(ArchiveMember {
                name,
                kind,
                header_offset: cur,
                data_offset,
                data_size: payload_size,
                mh,
            });

            cur = data_offset + payload_size;
            if cur & 1 != 0 {
                cur += 1;
            }
        }
        if members.iter().all(|m| m.kind != MemberKind::File) {
            return err("Malformed archive file: no valid members");
        }
        Ok(Archive {
            image: image.clone(),
            members,
        })
    }

    /// Mach-O headers of the members that are Mach-O objects.
    pub fn headers(&self) -> Vec<Arc<MachHeader>> {
        self.members.iter().filter_map(|m| m.mh.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, size: &str) -> Vec<u8> {
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name, "0", "0", "0", "100644", size
        )
        .into_bytes()
    }

    fn archive(parts: &[&[u8]]) -> Result<Archive> {
        let mut data = ARCHIVE_MAGIC.to_vec();
        for p in parts {
            data.extend_from_slice(p);
        }
        Archive::parse(&Arc::new(Image::from_vec(data).unwrap()))
    }

    fn error(parts: &[&[u8]]) -> String {
        archive(parts).err().map(|e| e.0).unwrap_or_default()
    }

    /// Minimal 64-bit Mach-O header with no load commands.
    fn macho64() -> Vec<u8> {
        let mut v = Vec::new();
        for w in [0xfeedfacfu32, 0x0100000c, 0, 1, 0, 0, 0, 0] {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    #[test]
    fn size_field() {
        assert_eq!(parse_size(b"92        "), Some(92));
        assert_eq!(parse_size(b"          "), Some(0));
        assert_eq!(parse_size(b"4294967296"), Some(4294967296));
        assert_eq!(parse_size(b"12x       "), None);
        assert_eq!(parse_size(b" 12       "), None);
        assert_eq!(parse_size(b"-1        "), None);
        assert_eq!(parse_size(b"12\0       "), None);
    }

    #[test]
    fn strtoull_like_c() {
        assert_eq!(strtoull(b"20"), 20);
        assert_eq!(strtoull(b"  7x"), 7);
        assert_eq!(strtoull(b"/12"), 0);
        assert_eq!(strtoull(b""), 0);
        assert_eq!(strtoull(b"99999999999999999999999"), u64::MAX);
        assert_eq!(strtoull(b"-1"), u64::MAX);
    }

    #[test]
    fn name_fields() {
        use NameField::*;
        assert_eq!(classify_name(b"foo.o/          "), Short(b"foo.o"));
        assert_eq!(classify_name(b"foo.o           "), Short(b"foo.o"));
        assert_eq!(classify_name(b"two words.o/    "), Short(b"two words.o"));
        assert_eq!(classify_name(b"/               "), GnuSymbolTable(b"/"));
        assert_eq!(
            classify_name(b"/SYM64/         "),
            GnuSymbolTable(b"/SYM64/")
        );
        assert_eq!(classify_name(b"//              "), GnuStringTable);
        assert_eq!(classify_name(b"#1/20           "), BsdLong(20));
        assert_eq!(classify_name(b"/4              "), GnuLong(4));
        // Not references: kept as plain names.
        assert_eq!(classify_name(b"#1/x            "), Short(b"#1/x"));
        assert_eq!(classify_name(b"/4x             "), Short(b"/4x"));
        assert_eq!(classify_name(b"                "), Short(b""));

        let strtab = b"abc.o/\nlong_name.o/\nlast";
        assert_eq!(gnu_long_name(strtab, 0), Some(&b"abc.o"[..]));
        assert_eq!(gnu_long_name(strtab, 7), Some(&b"long_name.o"[..]));
        assert_eq!(gnu_long_name(strtab, 20), Some(&b"last"[..]));
        assert_eq!(gnu_long_name(strtab, 24), None);
        assert_eq!(gnu_long_name(strtab, u64::MAX), None);
        assert_eq!(gnu_long_name(b"", 0), None);
    }

    #[test]
    fn members_and_padding() {
        let obj = macho64();
        let a = archive(&[&header("a.o/", "3"), b"abc\n", &header("b.o/", "32"), &obj]).unwrap();
        assert_eq!(a.members.len(), 2);
        assert_eq!(a.members[0].name, b"a.o");
        assert_eq!(
            (
                a.members[0].header_offset,
                a.members[0].data_offset,
                a.members[0].data_size
            ),
            (8, 68, 3)
        );
        assert!(!a.members[0].is_macho());
        // odd payload size is padded to an even offset
        assert_eq!(a.members[1].header_offset, 72);
        assert!(a.members[1].is_macho());
        assert_eq!(a.headers().len(), 1);
        assert_eq!(a.headers()[0].offset, 132);
    }

    #[test]
    fn bsd_long_name_member_is_macho() {
        let mut payload = b"long_member_name.o\0\0".to_vec();
        payload.extend_from_slice(&macho64());
        let a = archive(&[
            &header("#1/20", "24"),
            b"__.SYMDEF SORTED\0\0\0\0\0\0\0\0",
            &header("#1/20", "52"),
            &payload,
        ])
        .unwrap();
        assert_eq!(a.members.len(), 2);
        assert_eq!(a.members[0].name, b"__.SYMDEF SORTED");
        assert_eq!(a.members[0].kind, MemberKind::SymbolTable);
        assert_eq!(a.members[0].type_name(), "symbol table");
        let m = &a.members[1];
        assert_eq!(m.name, b"long_member_name.o");
        assert_eq!((m.data_offset, m.data_size), (8 + 60 + 24 + 60 + 20, 32));
        assert!(m.is_macho());
        assert_eq!(m.type_name(), "Mach-O");
        let mh = &a.headers()[0];
        assert_eq!((mh.offset, mh.size), (m.data_offset, 32));
    }

    #[test]
    fn gnu_tables_and_long_names() {
        let obj = macho64();
        let a = archive(&[
            &header("/", "4"),
            &[0, 0, 0, 0],
            &header("//", "22"),
            b"a_rather_long_name.o/\n",
            &header("/0", "32"),
            &obj,
            &header("/99", "2"),
            b"hi",
            &header("short.o/", "2"),
            b"yo",
        ])
        .unwrap();
        let got: Vec<_> = a
            .members
            .iter()
            .map(|m| (String::from_utf8_lossy(&m.name).into_owned(), m.type_name()))
            .collect();
        assert_eq!(
            got,
            [
                ("/".to_string(), "symbol table"),
                ("//".to_string(), "string table"),
                ("a_rather_long_name.o".to_string(), "Mach-O"),
                // Reference outside the string table: raw text kept.
                ("/99".to_string(), "data"),
                ("short.o".to_string(), "data"),
            ]
        );
    }

    #[test]
    fn only_tables_is_error() {
        assert_eq!(
            error(&[&header("/", "0"), &header("//", "0")]),
            "Malformed archive file: no valid members"
        );
        assert_eq!(
            error(&[&header("#1/8", "4"), b"abcd"]),
            "Malformed archive file: long member name out of range"
        );
    }

    #[test]
    fn malformed() {
        assert_eq!(
            error(&[]),
            "Malformed archive file: truncated after global magic"
        );
        assert_eq!(
            error(&[&header("bad.o/", "12x")]),
            "Malformed archive file: non-decimal member size"
        );
        assert_eq!(
            error(&[&header("big.o/", "9999999999")]),
            "Malformed archive file: member payload out of range"
        );
        assert_eq!(
            error(&[&header("a.o/", "1")]),
            "Malformed archive file: member payload out of range"
        );
        let mut bad = header("a.o/", "0");
        bad[59] = b'x';
        assert_eq!(
            error(&[&bad]),
            "Malformed archive file: invalid member header trailer"
        );
        // a member whose Mach-O header is truncated fails the whole archive
        assert!(archive(&[&header("a.o/", "4"), &0xfeedfacfu32.to_le_bytes()]).is_err());
        let not_archive =
            Archive::parse(&Arc::new(Image::from_vec(b"hello world".to_vec()).unwrap()));
        assert_eq!(
            not_archive.err().map(|e| e.0).unwrap_or_default(),
            "Not an archive file"
        );
    }

    #[test]
    fn empty_member_list_is_error() {
        // 60 bytes of header are required; fewer trailing bytes end the loop.
        let mut data = ARCHIVE_MAGIC.to_vec();
        data.extend_from_slice(&header("a.o/", "0"));
        data.truncate(8 + 59);
        data.push(0);
        // file_size == 68 so the size check passes, but fmag is wrong
        let r = Archive::parse(&Arc::new(Image::from_vec(data).unwrap()));
        assert!(r.is_err());
    }
}
