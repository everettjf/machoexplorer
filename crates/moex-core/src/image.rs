//! The mapped input file plus bounds-checked little-endian readers.
//!
//! Every read goes through these helpers; an out-of-range access is an
//! `Err`/`None`, never undefined behaviour.

use crate::error::{err, Error, Result};
use std::path::Path;

enum Backing {
    Mmap(memmap2::Mmap),
    Vec(Vec<u8>),
}

pub struct Image {
    backing: Backing,
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
            backing: Backing::Mmap(map),
        })
    }

    pub fn from_vec(data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return err("File is empty");
        }
        Ok(Image {
            backing: Backing::Vec(data),
        })
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match &self.backing {
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

    #[inline]
    pub fn u16(&self, off: u64) -> Option<u16> {
        self.slice(off, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn u32(&self, off: u64) -> Option<u32> {
        self.slice(off, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn u64(&self, off: u64) -> Option<u64> {
        self.slice(off, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    #[inline]
    pub fn u32_be(&self, off: u64) -> Option<u32> {
        self.u32(off).map(u32::swap_bytes)
    }

    #[inline]
    pub fn u64_be(&self, off: u64) -> Option<u64> {
        self.u64(off).map(u64::swap_bytes)
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
