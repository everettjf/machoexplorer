//! The mapped input file plus bounds-checked readers.
//!
//! Every read goes through these helpers; an out-of-range access is an
//! `Err`/`None`, never undefined behaviour.
//!
//! Multi-byte values are little-endian unless the image is a
//! [big-endian view](Image::big_endian_view) of the file, which is what
//! the header of a byte-swapped Mach-O (PowerPC and older) reads through:
//! everything decoded from such a Mach-O then comes out in its byte order
//! without the decoders knowing.

use crate::error::{err, Error, Result};
use std::path::Path;
use std::sync::Arc;

enum Backing {
    Mmap(memmap2::Mmap),
    Vec(Vec<u8>),
}

pub struct Image {
    backing: Arc<Backing>,
    /// `u16` / `u32` / `u64` read big-endian values.
    big_endian: bool,
}

impl Image {
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return err("invalid file path");
        }
        let meta = std::fs::metadata(path)
            .map_err(|e| Error(format!("cannot stat path: {}", strerror(&e))))?;
        if meta.is_dir() {
            let is_app = path.to_string_lossy().ends_with(".app");
            return err(if is_app {
                "Application bundles are directories; open the Mach-O inside .app/Contents/MacOS instead"
            } else {
                "Path is a directory, not a binary file"
            });
        }
        if !meta.is_file() {
            return err("Path is not a regular file");
        }
        let file = std::fs::File::open(path).map_err(|_| Error::new("Can not open file"))?;
        if meta.len() == 0 {
            return err("File is empty");
        }
        // SAFETY: the mapping is read-only and private to this process. If
        // another process truncates the file while mapped, reads may fault;
        // that is the same contract the previous implementation had.
        let map =
            unsafe { memmap2::Mmap::map(&file) }.map_err(|_| Error::new("Can not map file"))?;
        if map.is_empty() {
            return err("File is empty");
        }
        Ok(Image {
            backing: Arc::new(Backing::Mmap(map)),
            big_endian: false,
        })
    }

    pub fn from_vec(data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return err("File is empty");
        }
        Ok(Image {
            backing: Arc::new(Backing::Vec(data)),
            big_endian: false,
        })
    }

    /// The same bytes, with `u16` / `u32` / `u64` reading big-endian
    /// values. Nothing is copied.
    pub fn big_endian_view(&self) -> Image {
        Image {
            backing: self.backing.clone(),
            big_endian: true,
        }
    }

    /// Whether multi-byte values are read big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match &*self.backing {
            Backing::Mmap(m) => m,
            Backing::Vec(v) => v,
        }
    }

    #[inline]
    pub fn len(&self) -> u64 {
        self.bytes().len() as u64
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }

    /// True when `[off, off+size)` lies entirely within the file.
    #[inline]
    pub fn in_file(&self, off: u64, size: u64) -> bool {
        off <= self.len() && size <= self.len() - off
    }

    #[inline]
    pub fn slice(&self, off: u64, size: u64) -> Option<&[u8]> {
        if !self.in_file(off, size) {
            return None;
        }
        Some(&self.bytes()[off as usize..(off + size) as usize])
    }

    #[inline]
    pub fn u8(&self, off: u64) -> Option<u8> {
        self.slice(off, 1).map(|b| b[0])
    }

    /// 16-bit value at `off` in the image's byte order.
    #[inline]
    pub fn u16(&self, off: u64) -> Option<u16> {
        let b = self.slice(off, 2)?;
        let b = [b[0], b[1]];
        Some(if self.big_endian {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    /// 32-bit value at `off` in the image's byte order.
    #[inline]
    pub fn u32(&self, off: u64) -> Option<u32> {
        let b = self.slice(off, 4)?;
        let b = [b[0], b[1], b[2], b[3]];
        Some(if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    /// 64-bit value at `off` in the image's byte order.
    #[inline]
    pub fn u64(&self, off: u64) -> Option<u64> {
        let b = self.slice(off, 8)?;
        let b = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        Some(if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }

    /// Big-endian 32-bit value at `off`, whatever the image's byte order
    /// (fat headers, code signatures).
    #[inline]
    pub fn u32_be(&self, off: u64) -> Option<u32> {
        self.slice(off, 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Big-endian 64-bit value at `off`, whatever the image's byte order.
    #[inline]
    pub fn u64_be(&self, off: u64) -> Option<u64> {
        self.slice(off, 8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// The value of the first 2, 4 or 8 bytes of `bytes` in the image's
    /// byte order (for data already sliced out of the file); `None` for
    /// other lengths.
    pub fn value_of(&self, bytes: &[u8]) -> Option<u64> {
        let mut wide = [0u8; 8];
        let n = bytes.len();
        if !matches!(n, 1 | 2 | 4 | 8) {
            return None;
        }
        if self.big_endian {
            wide.get_mut(8 - n..)?.copy_from_slice(bytes);
            Some(u64::from_be_bytes(wide))
        } else {
            wide.get_mut(..n)?.copy_from_slice(bytes);
            Some(u64::from_le_bytes(wide))
        }
    }

    /// NUL-terminated byte string starting at `off`, limited to `max` bytes
    /// and to the end of the file. The terminator is not included.
    pub fn cstr(&self, off: u64, max: u64) -> Option<&[u8]> {
        if off > self.len() {
            return None;
        }
        let avail = (self.len() - off).min(max);
        let s = &self.bytes()[off as usize..(off + avail) as usize];
        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        Some(&s[..end])
    }
}

/// `strerror`-style text (without Rust's " (os error N)" suffix).
fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_order_views() {
        let image = Image::from_vec(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        let big = image.big_endian_view();
        assert!(!image.is_big_endian() && big.is_big_endian());
        assert_eq!((image.u16(0), big.u16(0)), (Some(0x0201), Some(0x0102)));
        assert_eq!(
            (image.u32(1), big.u32(1)),
            (Some(0x0504_0302), Some(0x0203_0405))
        );
        assert_eq!(
            (image.u64(0), big.u64(0)),
            (Some(0x0807_0605_0403_0201), Some(0x0102_0304_0506_0708))
        );
        // The explicit big-endian readers do not depend on the view.
        assert_eq!(image.u32_be(0), big.u32_be(0));
        assert_eq!(image.u32_be(0), Some(0x0102_0304));
        assert_eq!(image.u64_be(1), Some(0x0203_0405_0607_0809));
        // Bytes and bounds are shared.
        assert_eq!(big.bytes(), image.bytes());
        assert_eq!((big.u32(6), big.u64(2), big.u16(8)), (None, None, None));
        assert_eq!(big.len(), 9);
    }

    #[test]
    fn values_of_sliced_bytes() {
        let image = Image::from_vec(vec![0]).unwrap();
        let big = image.big_endian_view();
        assert_eq!(image.value_of(&[0x12, 0x34]), Some(0x3412));
        assert_eq!(big.value_of(&[0x12, 0x34]), Some(0x1234));
        assert_eq!(image.value_of(&[1, 0, 0, 0]), Some(1));
        assert_eq!(big.value_of(&[0, 0, 0, 1]), Some(1));
        assert_eq!(big.value_of(&[0, 0, 0, 0, 0, 0, 1, 2]), Some(0x102));
        assert_eq!(image.value_of(&[7]), Some(7));
        assert_eq!(big.value_of(&[7]), Some(7));
        assert_eq!(image.value_of(&[1, 2, 3]), None);
        assert_eq!(image.value_of(&[]), None);
    }
}
