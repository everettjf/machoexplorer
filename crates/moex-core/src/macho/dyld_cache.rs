//! Minimal dyld shared cache parser: the legacy header fields, the mapping
//! table and the image list.
//!
//! Only the file handed to [`DyldSharedCache::parse`] is read (sub-cache
//! files `.01`, `.02`, ... are not followed). Modern caches keep their image
//! list out of the legacy header fields; for those the list is recovered
//! from the sibling `<cache>.map` text file when present.

use crate::error::{err, Result};
use crate::image::Image;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;

/// `sizeof(dyld_cache_header_min)`.
pub const CACHE_HEADER_SIZE: u64 = 112;
/// `sizeof(dyld_cache_mapping_info)`.
pub const MAPPING_INFO_SIZE: u64 = 32;
/// `sizeof(dyld_cache_image_info)`.
pub const IMAGE_INFO_SIZE: u64 = 32;

const MAX_MAPPING_COUNT: u32 = 1_000_000;
const MAX_IMAGE_COUNT: u32 = 10_000_000;
/// Longest image path accepted by [`DyldSharedCache::read_path_by_offset`].
const MAX_PATH_SCAN: u64 = 4096;

// Field offsets inside the header.
pub const OFF_MAPPING_OFFSET: u64 = 16;
pub const OFF_MAPPING_COUNT: u64 = 20;
pub const OFF_IMAGES_OFFSET: u64 = 24;
pub const OFF_IMAGES_COUNT: u64 = 28;
pub const OFF_DYLD_BASE_ADDRESS: u64 = 32;
pub const OFF_CODE_SIGNATURE_OFFSET: u64 = 40;
pub const OFF_CODE_SIGNATURE_SIZE: u64 = 48;
pub const OFF_LOCAL_SYMBOLS_OFFSET: u64 = 72;
pub const OFF_LOCAL_SYMBOLS_SIZE: u64 = 80;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheHeader {
    pub magic: [u8; 16],
    pub mapping_offset: u32,
    pub mapping_count: u32,
    pub images_offset: u32,
    pub images_count: u32,
    pub dyld_base_address: u64,
    pub code_signature_offset: u64,
    pub code_signature_size: u64,
    pub local_symbols_offset: u64,
    pub local_symbols_size: u64,
    pub uuid: [u8; 16],
    pub cache_type: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}

/// One `dyld_cache_image_info` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheImageInfo {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path_file_offset: u32,
}

/// An image of the cache: its unslid load address and install path (raw
/// bytes; usually ASCII).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheImage {
    pub address: u64,
    pub path: Vec<u8>,
}

impl CacheImage {
    /// The path as displayable text (malformed UTF-8 bytes become `?`).
    pub fn path_str(&self) -> String {
        crate::hex::utf8_safe(&self.path)
    }
}

pub struct DyldSharedCache {
    pub image: Arc<Image>,
    pub header: CacheHeader,
    pub mappings: Vec<CacheMapping>,
    /// Images listed in the sibling `.map` file; only filled when the header
    /// lists no images.
    pub map_images: Vec<CacheImage>,
}

pub fn is_shared_cache_magic(data: &[u8]) -> bool {
    data.len() >= 16 && &data[..7] == b"dyld_v1"
}

impl DyldSharedCache {
    /// `filepath` is the path the cache was opened from, used to locate the
    /// `.map` file; pass `None` for in-memory buffers.
    pub fn parse(image: &Arc<Image>, filepath: Option<&Path>) -> Result<Self> {
        let size = image.len();
        if size < CACHE_HEADER_SIZE {
            return err("Malformed dyld shared cache: header truncated");
        }
        let u32_ = |o: u64| image.u32(o).unwrap_or(0);
        let u64_ = |o: u64| image.u64(o).unwrap_or(0);
        let bytes16 = |o: u64| {
            let mut b = [0u8; 16];
            if let Some(s) = image.slice(o, 16) {
                b.copy_from_slice(s);
            }
            b
        };
        let header = CacheHeader {
            magic: bytes16(0),
            mapping_offset: u32_(OFF_MAPPING_OFFSET),
            mapping_count: u32_(OFF_MAPPING_COUNT),
            images_offset: u32_(OFF_IMAGES_OFFSET),
            images_count: u32_(OFF_IMAGES_COUNT),
            dyld_base_address: u64_(OFF_DYLD_BASE_ADDRESS),
            code_signature_offset: u64_(OFF_CODE_SIGNATURE_OFFSET),
            code_signature_size: u64_(OFF_CODE_SIGNATURE_SIZE),
            local_symbols_offset: u64_(OFF_LOCAL_SYMBOLS_OFFSET),
            local_symbols_size: u64_(OFF_LOCAL_SYMBOLS_SIZE),
            uuid: bytes16(88),
            cache_type: u64_(104),
        };

        if header.mapping_count > MAX_MAPPING_COUNT || header.images_count > MAX_IMAGE_COUNT {
            return err("Malformed dyld shared cache: unreasonable mapping/image count");
        }
        if header.mapping_count == 0 {
            return err("Malformed dyld shared cache: empty mapping table");
        }
        if (header.mapping_offset as u64) < CACHE_HEADER_SIZE {
            return err("Malformed dyld shared cache: mapping offset overlaps header");
        }
        if header.images_count > 0 && (header.images_offset as u64) < CACHE_HEADER_SIZE {
            return err("Malformed dyld shared cache: images offset overlaps header");
        }

        // Counts are capped above, so these products cannot overflow.
        let map_bytes = header.mapping_count as u64 * MAPPING_INFO_SIZE;
        if !image.in_file(header.mapping_offset as u64, map_bytes) {
            return err("Malformed dyld shared cache: mapping array out of range");
        }
        // The table lies inside the file, which bounds this allocation.
        let mut mappings = Vec::with_capacity(header.mapping_count as usize);
        for i in 0..header.mapping_count as u64 {
            let at = header.mapping_offset as u64 + i * MAPPING_INFO_SIZE;
            let m = CacheMapping {
                address: u64_(at),
                size: u64_(at + 8),
                file_offset: u64_(at + 16),
                max_prot: u32_(at + 24),
                init_prot: u32_(at + 28),
            };
            if !image.in_file(m.file_offset, m.size) {
                return err("Malformed dyld shared cache: mapping entry file range out of bounds");
            }
            mappings.push(m);
        }

        let image_bytes = header.images_count as u64 * IMAGE_INFO_SIZE;
        if !image.in_file(header.images_offset as u64, image_bytes) {
            return err("Malformed dyld shared cache: image array out of range");
        }

        let mut map_images = Vec::new();
        if header.images_count == 0 {
            if let Some(path) = filepath {
                let mut map_path = path.as_os_str().to_os_string();
                map_path.push(".map");
                if let Ok(file) = std::fs::File::open(&map_path) {
                    map_images = parse_map_file(BufReader::new(file));
                }
            }
        }

        Ok(DyldSharedCache {
            image: image.clone(),
            header,
            mappings,
            map_images,
        })
    }

    /// Entry `index` of the header's image table (entries are read from the
    /// file on demand rather than copied).
    pub fn image_info(&self, index: u32) -> Option<CacheImageInfo> {
        if index >= self.header.images_count {
            return None;
        }
        let at = self.header.images_offset as u64 + index as u64 * IMAGE_INFO_SIZE;
        Some(CacheImageInfo {
            address: self.image.u64(at)?,
            mod_time: self.image.u64(at + 8)?,
            inode: self.image.u64(at + 16)?,
            path_file_offset: self.image.u32(at + 24)?,
        })
    }

    /// The header's image table.
    pub fn image_infos(&self) -> impl Iterator<Item = CacheImageInfo> + '_ {
        (0..self.header.images_count).filter_map(|i| self.image_info(i))
    }

    /// NUL-terminated path at `file_offset`. Empty when out of range,
    /// unterminated within 4096 bytes, or containing control characters.
    pub fn read_path_by_offset(&self, file_offset: u32) -> &[u8] {
        let off = file_offset as u64;
        if off >= self.image.len() {
            return &[];
        }
        let max_scan = (self.image.len() - off).min(MAX_PATH_SCAN);
        let Some(window) = self.image.slice(off, max_scan) else {
            return &[];
        };
        let Some(len) = window.iter().position(|&c| c == 0) else {
            return &[];
        };
        let s = &window[..len];
        if s.iter().any(|&c| c < 0x20 || c == 0x7f) {
            return &[];
        }
        s
    }

    /// All images in file order: the header's table when it has entries,
    /// otherwise the `.map` file's list.
    pub fn images(&self) -> Box<dyn Iterator<Item = CacheImage> + '_> {
        if self.header.images_count > 0 {
            Box::new(self.image_infos().map(|info| CacheImage {
                address: info.address,
                path: self.read_path_by_offset(info.path_file_offset).to_vec(),
            }))
        } else {
            Box::new(self.map_images.iter().cloned())
        }
    }

    /// File offset backing `vmaddr`, per the first mapping that contains it.
    pub fn vm_to_file_offset(&self, vmaddr: u64) -> Option<u64> {
        for m in &self.mappings {
            // Wrapping like the original's unsigned arithmetic.
            if vmaddr >= m.address && vmaddr < m.address.wrapping_add(m.size) {
                return Some(m.file_offset.wrapping_add(vmaddr - m.address));
            }
        }
        None
    }
}

fn is_regex_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Matches `^\s*__TEXT\s+0x([0-9A-Fa-f]+)` and returns the address. Values
/// too large for 64 bits saturate.
fn parse_text_line(line: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < line.len() && is_regex_space(line[i]) {
        i += 1;
    }
    let rest = line[i..].strip_prefix(b"__TEXT")?;
    let spaces = rest.iter().take_while(|&&c| is_regex_space(c)).count();
    if spaces == 0 {
        return None;
    }
    let rest = rest[spaces..].strip_prefix(b"0x")?;
    let digits = rest.iter().take_while(|c| c.is_ascii_hexdigit()).count();
    if digits == 0 {
        return None;
    }
    let mut value: u64 = 0;
    for &c in &rest[..digits] {
        let d = (c as char).to_digit(16).unwrap_or(0) as u64;
        if value > (u64::MAX >> 4) {
            return Some(u64::MAX);
        }
        value = (value << 4) | d;
    }
    Some(value)
}

/// Longest `.map` line kept in memory; real lines are a few hundred bytes.
const MAX_MAP_LINE: u64 = 64 * 1024;

/// Discards input up to and including the next newline. False on a read
/// error.
fn skip_line(reader: &mut impl BufRead) -> bool {
    loop {
        let (consumed, done) = match reader.fill_buf() {
            Ok([]) => return true,
            Ok(buf) => match buf.iter().position(|&c| c == b'\n') {
                Some(pos) => (pos + 1, true),
                None => (buf.len(), false),
            },
            Err(_) => return false,
        };
        reader.consume(consumed);
        if done {
            return true;
        }
    }
}

/// Reads the image list out of a dyld `.map` file: every line starting with
/// `/` names an image, and the next `__TEXT 0x...` line gives its address.
fn parse_map_file(mut reader: impl BufRead) -> Vec<CacheImage> {
    let mut out: Vec<CacheImage> = Vec::new();
    let mut pending = false;
    let mut line = Vec::new();
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_MAP_LINE)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        } else if line.len() as u64 == MAX_MAP_LINE && !skip_line(&mut reader) {
            // Over-long line: keep its first MAX_MAP_LINE bytes, drop the rest.
            break;
        }
        if line.is_empty() {
            continue;
        }
        if line[0] == b'/' {
            out.push(CacheImage {
                address: 0,
                path: line.clone(),
            });
            pending = true;
            continue;
        }
        if !pending {
            continue;
        }
        if let Some(addr) = parse_text_line(&line) {
            if let Some(last) = out.last_mut() {
                last.address = addr;
            }
            pending = false;
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Synthetic single-file cache: header, `mappings`, an image table for
    /// `images` (address, path) and the path strings, padded to `size`.
    pub fn build_cache(mappings: &[CacheMapping], images: &[(u64, &str)], size: usize) -> Vec<u8> {
        let mut d = vec![0u8; CACHE_HEADER_SIZE as usize];
        d[..16].copy_from_slice(b"dyld_v1  arm64e\0");
        let mapping_offset = d.len() as u32;
        for m in mappings {
            d.extend_from_slice(&m.address.to_le_bytes());
            d.extend_from_slice(&m.size.to_le_bytes());
            d.extend_from_slice(&m.file_offset.to_le_bytes());
            d.extend_from_slice(&m.max_prot.to_le_bytes());
            d.extend_from_slice(&m.init_prot.to_le_bytes());
        }
        let images_offset = d.len() as u32;
        let mut path_off = images_offset as usize + images.len() * IMAGE_INFO_SIZE as usize;
        for (addr, path) in images {
            d.extend_from_slice(&addr.to_le_bytes());
            d.extend_from_slice(&[0u8; 16]);
            d.extend_from_slice(&(path_off as u32).to_le_bytes());
            d.extend_from_slice(&[0u8; 4]);
            path_off += path.len() + 1;
        }
        for (_, path) in images {
            d.extend_from_slice(path.as_bytes());
            d.push(0);
        }
        d[16..20].copy_from_slice(&mapping_offset.to_le_bytes());
        d[20..24].copy_from_slice(&(mappings.len() as u32).to_le_bytes());
        d[24..28].copy_from_slice(&images_offset.to_le_bytes());
        d[28..32].copy_from_slice(&(images.len() as u32).to_le_bytes());
        if d.len() < size {
            d.resize(size, 0);
        }
        d
    }

    pub fn parse(data: Vec<u8>) -> Result<DyldSharedCache> {
        DyldSharedCache::parse(&Arc::new(Image::from_vec(data).unwrap()), None)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    const MAP: CacheMapping = CacheMapping {
        address: 0x1_8000_0000,
        size: 0x1000,
        file_offset: 0,
        max_prot: 5,
        init_prot: 5,
    };

    fn error(data: Vec<u8>) -> String {
        parse(data).err().map(|e| e.0).unwrap_or_default()
    }

    #[test]
    fn parses_header_mappings_and_images() {
        let data = build_cache(
            &[MAP],
            &[
                (0x1_8000_0400, "/usr/lib/libfoo.dylib"),
                (0x1_8000_0800, "/usr/lib/libbar.dylib"),
            ],
            0x1000,
        );
        let c = parse(data).unwrap();
        assert_eq!(&c.header.magic, b"dyld_v1  arm64e\0");
        assert_eq!(
            (
                c.header.mapping_offset,
                c.header.mapping_count,
                c.header.images_count
            ),
            (112, 1, 2)
        );
        assert_eq!(c.mappings, vec![MAP]);
        let images: Vec<_> = c.images().collect();
        assert_eq!(images.len(), 2);
        assert_eq!(
            images[1],
            CacheImage {
                address: 0x1_8000_0800,
                path: b"/usr/lib/libbar.dylib".to_vec()
            }
        );
        assert_eq!(c.vm_to_file_offset(0x1_8000_0400), Some(0x400));
        assert_eq!(c.vm_to_file_offset(0x1_8000_1000), None);
        assert_eq!(c.vm_to_file_offset(0), None);
        assert!(c.image_info(2).is_none());
    }

    #[test]
    fn header_bounds() {
        assert_eq!(
            error(b"dyld_v1   arm64e".to_vec()),
            "Malformed dyld shared cache: header truncated"
        );

        let good = build_cache(&[MAP], &[(1, "/a")], 0x1000);
        let patch = |off: usize, v: u32| {
            let mut d = good.clone();
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
            d
        };
        assert_eq!(
            error(patch(20, u32::MAX)),
            "Malformed dyld shared cache: unreasonable mapping/image count"
        );
        assert_eq!(
            error(patch(28, 10_000_001)),
            "Malformed dyld shared cache: unreasonable mapping/image count"
        );
        assert_eq!(
            error(patch(20, 0)),
            "Malformed dyld shared cache: empty mapping table"
        );
        assert_eq!(
            error(patch(16, 111)),
            "Malformed dyld shared cache: mapping offset overlaps header"
        );
        assert_eq!(
            error(patch(24, 8)),
            "Malformed dyld shared cache: images offset overlaps header"
        );
        assert_eq!(
            error(patch(16, 0x1000 - 16)),
            "Malformed dyld shared cache: mapping array out of range"
        );
        assert_eq!(
            error(patch(16, u32::MAX)),
            "Malformed dyld shared cache: mapping array out of range"
        );
        assert_eq!(
            error(patch(20, 1_000_000)),
            "Malformed dyld shared cache: mapping array out of range"
        );
        assert_eq!(
            error(patch(24, 0x1000 - 8)),
            "Malformed dyld shared cache: image array out of range"
        );
        assert_eq!(
            error(patch(28, 10_000_000)),
            "Malformed dyld shared cache: image array out of range"
        );

        let bad_map = CacheMapping {
            size: 0x1001,
            ..MAP
        };
        assert_eq!(
            error(build_cache(&[bad_map], &[], 0x1000)),
            "Malformed dyld shared cache: mapping entry file range out of bounds"
        );
        let huge = CacheMapping {
            file_offset: u64::MAX,
            size: u64::MAX,
            ..MAP
        };
        assert_eq!(
            error(build_cache(&[huge], &[], 0x1000)),
            "Malformed dyld shared cache: mapping entry file range out of bounds"
        );
        // images offset is not checked when there are no images
        assert!(parse(build_cache(&[MAP], &[], 0x1000)).is_ok());
    }

    #[test]
    fn path_reading() {
        let mut data = build_cache(&[MAP], &[(1, "/ok"), (2, "/bad\x01path")], 0x3000);
        // an unterminated run of 4096 printable bytes
        for b in &mut data[0x1000..0x2000] {
            *b = b'a';
        }
        let c = parse(data).unwrap();
        let infos: Vec<_> = c.image_infos().collect();
        assert_eq!(c.read_path_by_offset(infos[0].path_file_offset), b"/ok");
        assert_eq!(c.read_path_by_offset(infos[1].path_file_offset), b"");
        assert_eq!(c.read_path_by_offset(0x1000), b"");
        assert_eq!(c.read_path_by_offset(0x1001).len(), 4095);
        assert_eq!(c.read_path_by_offset(0x3000), b"");
        assert_eq!(c.read_path_by_offset(u32::MAX), b"");
        // last byte of the file without a terminator
        assert_eq!(c.read_path_by_offset(0x2fff), b"");
    }

    #[test]
    fn wrapping_mapping_does_not_panic() {
        let m = CacheMapping {
            address: u64::MAX - 1,
            size: 0x10,
            file_offset: 0,
            max_prot: 0,
            init_prot: 0,
        };
        let c = parse(build_cache(&[m], &[], 0x1000)).unwrap();
        assert_eq!(c.vm_to_file_offset(u64::MAX), None);
    }

    #[test]
    fn text_line() {
        assert_eq!(
            parse_text_line(b"\t__TEXT 0x180404000 -> 0x18044F000"),
            Some(0x180404000)
        );
        assert_eq!(parse_text_line(b"__TEXT\t \t0xabcDEF"), Some(0xabcdef));
        assert_eq!(parse_text_line(b"__TEXT0x10"), None);
        assert_eq!(parse_text_line(b"__TEXT 10"), None);
        assert_eq!(parse_text_line(b"__TEXT 0x"), None);
        assert_eq!(parse_text_line(b"x __TEXT 0x10"), None);
        assert_eq!(parse_text_line(b"__DATA 0x10"), None);
        assert_eq!(
            parse_text_line(b"__TEXT 0x11112222333344445"),
            Some(u64::MAX)
        );
        assert_eq!(
            parse_text_line(b"__TEXT 0xFFFFFFFFFFFFFFFF"),
            Some(u64::MAX)
        );
    }

    #[test]
    fn map_file() {
        let text = b"mapping  EX   0MB 0x180000000 -> 0x1800B4000\n\n\
            /usr/lib/libobjc.A.dylib\n\t__TEXT 0x180404000 -> 0x18044F000\n\t__DATA 0x200000000 -> 0x200000100\n\
            /usr/lib/no_text.dylib\n\
            /usr/lib/dyld\n  __LINKEDIT 0x1 -> 0x2\n  __TEXT 0x180482000 -> 0x1\n  __TEXT 0x999 -> 0x1\n/last";
        let images = parse_map_file(&text[..]);
        let got: Vec<(u64, &[u8])> = images
            .iter()
            .map(|i| (i.address, i.path.as_slice()))
            .collect();
        assert_eq!(
            got,
            vec![
                (0x180404000, &b"/usr/lib/libobjc.A.dylib"[..]),
                (0, b"/usr/lib/no_text.dylib"),
                (0x180482000, b"/usr/lib/dyld"),
                (0, b"/last"),
            ]
        );

        // an over-long line is cut, and parsing resumes on the next line
        let mut long = vec![b'/'; MAX_MAP_LINE as usize + 10];
        long.extend_from_slice(b"\n__TEXT 0x10\n/b\n");
        let images = parse_map_file(std::io::BufReader::with_capacity(16, &long[..]));
        assert_eq!(images.len(), 2);
        assert_eq!(
            (images[0].path.len() as u64, images[0].address),
            (MAX_MAP_LINE, 0x10)
        );
        assert_eq!(images[1].path, b"/b");
        // a line of exactly the limit followed by a newline is not cut short
        let mut exact = vec![b'/'; MAX_MAP_LINE as usize];
        exact.extend_from_slice(b"\n/c");
        let images = parse_map_file(&exact[..]);
        assert_eq!(
            images.iter().map(|i| i.path.len()).collect::<Vec<_>>(),
            [MAX_MAP_LINE as usize, 2]
        );
    }
}
