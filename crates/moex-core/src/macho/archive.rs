//! `ar` archive (`.a`) parser.
//!
//! This mirrors the original parser closely, including the way it derives
//! member names (see the `QUIRK(parity)` notes): the resulting member list is
//! part of the golden output.

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

pub struct ArchiveMember {
    /// Raw member name bytes (may contain NULs or non-UTF-8 bytes).
    pub name: Vec<u8>,
    /// File offset of the 60-byte member header.
    pub header_offset: u64,
    /// File offset of the member payload.
    pub data_offset: u64,
    pub data_size: u64,
    /// Present when the payload starts with a thin Mach-O magic.
    pub mh: Option<Arc<MachHeader>>,
}

impl ArchiveMember {
    pub fn is_macho(&self) -> bool {
        self.mh.is_some()
    }
}

pub struct Archive {
    pub image: Arc<Image>,
    pub members: Vec<ArchiveMember>,
}

pub fn is_archive_magic(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == ARCHIVE_MAGIC
}

/// Drops trailing spaces, tabs, newlines and slashes.
fn trim_right(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && matches!(s[end - 1], b' ' | b'\t' | b'\n' | b'/') {
        end -= 1;
    }
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

fn parse_name(field: &[u8], strtab: &[u8]) -> Vec<u8> {
    let raw = trim_right(field);
    if raw.starts_with(b"/#1/") {
        return raw.to_vec();
    }
    // GNU long name: "/<decimal offset into the // string table>".
    if raw.len() > 1 && raw[0] == b'/' && raw[1].is_ascii_digit() && !strtab.is_empty() {
        let off = strtoull(&raw[1..]);
        if off < strtab.len() as u64 {
            let rest = &strtab[off as usize..];
            let end = rest
                .iter()
                .position(|&c| c == b'\n' || c == 0)
                .unwrap_or(rest.len());
            return trim_right(&rest[..end]).to_vec();
        }
    }
    raw.to_vec()
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

            // QUIRK(parity): the name is trimmed of trailing '/' before any
            // comparison, so the "//" (GNU string table) and "/" (symbol
            // table) checks below never match, and BSD long names are tested
            // as "/#1/NN" rather than "#1/NN". In practice: the GNU string
            // table is never loaded ("/NN" names stay unresolved), the symbol
            // table shows up as a member with an empty name, and BSD
            // long-name members keep the name "#1/NN" with the inline name
            // left in the payload (so they are never detected as Mach-O).
            let mut name = parse_name(&hdr[..AR_NAME_SIZE], strtab);
            let mut payload_size = member_size;

            if name == b"//" {
                strtab = image.slice(data_offset, member_size).unwrap_or(&[]);
            } else {
                if name.starts_with(b"/#1/") {
                    let ext_name_size = strtoull(&name[3..]);
                    if ext_name_size <= payload_size {
                        let ext = image.slice(data_offset, ext_name_size).unwrap_or(&[]);
                        name = trim_right(ext).to_vec();
                        data_offset += ext_name_size;
                        payload_size -= ext_name_size;
                    }
                }
                if name != b"/" {
                    let mut mh = None;
                    if payload_size >= 4 {
                        let magic = image.u32(data_offset).unwrap_or(0);
                        if super::is_valid_magic(magic) && !super::is_fat_magic(magic) {
                            mh = Some(Arc::new(MachHeader::parse(image, data_offset)?));
                        }
                    }
                    members.push(ArchiveMember {
                        name,
                        header_offset: cur,
                        data_offset,
                        data_size: payload_size,
                        mh,
                    });
                }
            }

            cur = data_offset + payload_size;
            if cur & 1 != 0 {
                cur += 1;
            }
        }
        if members.is_empty() {
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
    fn names() {
        assert_eq!(parse_name(b"foo.o/          ", b""), b"foo.o");
        assert_eq!(parse_name(b"/               ", b""), b"");
        assert_eq!(parse_name(b"//              ", b""), b"");
        assert_eq!(parse_name(b"#1/20           ", b""), b"#1/20");
        assert_eq!(parse_name(b"/4              ", b""), b"/4");
        assert_eq!(
            parse_name(b"/4              ", b"abc\nlong_name.o/\n"),
            b"long_name.o"
        );
        assert_eq!(parse_name(b"/99             ", b"abc\n"), b"/99");
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
    fn bsd_long_name_stays_data() {
        let mut payload = b"long_member_name.o\0\0".to_vec();
        payload.extend_from_slice(&macho64());
        let a = archive(&[&header("#1/20", "52"), &payload]).unwrap();
        assert_eq!(a.members[0].name, b"#1/20");
        assert_eq!(a.members[0].data_size, 52);
        assert!(!a.members[0].is_macho());
    }

    #[test]
    fn slash_hash_name_consumes_nothing() {
        let a = archive(&[&header("/#1/4", "4"), b"abcd"]).unwrap();
        assert_eq!(a.members[0].name, b"");
        assert_eq!(a.members[0].data_size, 4);
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
