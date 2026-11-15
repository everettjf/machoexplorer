//! `LC_SYMTAB`: the symbol table (`nlist` / `nlist_64` entries) and the
//! string table.

use super::header::{LoadCommand, MachHeader};
use crate::consts::LC_SYMTAB;
use crate::hex::utf8_safe;

pub const NLIST_SIZE: u64 = 12;
pub const NLIST_64_SIZE: u64 = 16;

/// One symbol table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbol {
    /// Position in the symbol table.
    pub index: u32,
    /// File offset of the `nlist` entry. Fields live at fixed deltas from
    /// it: `n_strx` +0, `n_type` +4, `n_sect` +5, `n_desc` +6, `n_value` +8.
    pub offset: u64,
    pub is64: bool,
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    /// A bit field (`REFERENCE_TYPE`, `N_WEAK_DEF`, library ordinal, ...),
    /// so always treated as unsigned.
    pub n_desc: u16,
    /// Zero-extended for 32-bit entries.
    pub n_value: u64,
}

impl Symbol {
    /// Size in bytes of the `n_value` field.
    pub fn value_size(&self) -> u64 {
        if self.is64 {
            8
        } else {
            4
        }
    }
}

/// The first `LC_SYMTAB` command of a Mach-O header.
#[derive(Clone, Copy)]
pub struct Symtab<'a> {
    mh: &'a MachHeader,
    pub lc: LoadCommand,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

impl MachHeader {
    /// The first `LC_SYMTAB` command, if any.
    pub fn symtab(&self) -> Option<Symtab<'_>> {
        let lc = *self.find_load_command(&[LC_SYMTAB])?;
        Some(Symtab {
            mh: self,
            lc,
            symoff: self.lc_u32(&lc, 8),
            nsyms: self.lc_u32(&lc, 12),
            stroff: self.lc_u32(&lc, 16),
            strsize: self.lc_u32(&lc, 20),
        })
    }
}

impl<'a> Symtab<'a> {
    pub fn entry_size(&self) -> u64 {
        if self.mh.is64 {
            NLIST_64_SIZE
        } else {
            NLIST_SIZE
        }
    }

    /// File offset of the first `nlist` entry.
    pub fn symbol_table_offset(&self) -> u64 {
        self.mh.offset.saturating_add(self.symoff as u64)
    }

    /// `nsyms * entry size` (the declared size; it may exceed the file).
    pub fn symbol_table_total_bytes(&self) -> u64 {
        self.nsyms as u64 * self.entry_size()
    }

    /// File offset of the string table.
    pub fn string_table_offset(&self) -> u64 {
        self.mh.offset.saturating_add(self.stroff as u64)
    }

    /// String table size clipped to the file (0 when it starts at or past
    /// the end of the file).
    pub fn string_table_size_in_file(&self) -> u64 {
        let off = self.string_table_offset();
        let len = self.mh.image.len();
        if off >= len {
            0
        } else {
            (self.strsize as u64).min(len - off)
        }
    }

    /// Number of entries that actually fit in the file (at most `nsyms`).
    pub fn symbol_count(&self) -> u32 {
        let off = self.symbol_table_offset();
        let len = self.mh.image.len();
        let avail = if off <= len {
            (len - off) / self.entry_size()
        } else {
            0
        };
        (self.nsyms as u64).min(avail) as u32
    }

    /// Entry `index`, or `None` when it is past the (file-clipped) table.
    pub fn symbol(&self, index: u32) -> Option<Symbol> {
        if index >= self.symbol_count() {
            return None;
        }
        let image = &self.mh.image;
        let is64 = self.mh.is64;
        let offset = self
            .symbol_table_offset()
            .checked_add((index as u64).checked_mul(self.entry_size())?)?;
        Some(Symbol {
            index,
            offset,
            is64,
            n_strx: image.u32(offset)?,
            n_type: image.u8(offset.checked_add(4)?)?,
            n_sect: image.u8(offset.checked_add(5)?)?,
            n_desc: image.u16(offset.checked_add(6)?)?,
            n_value: if is64 {
                image.u64(offset.checked_add(8)?)?
            } else {
                image.u32(offset.checked_add(8)?)? as u64
            },
        })
    }

    /// All entries in table order. Nothing is allocated.
    pub fn symbols(&self) -> impl Iterator<Item = Symbol> + 'a {
        let this = *self;
        (0..this.symbol_count()).filter_map(move |i| this.symbol(i))
    }

    /// Raw bytes of the string at string-table index `strx`, without the
    /// terminator. Empty when `strx` is outside the string table or the
    /// file; an unterminated string ends at the table/file end.
    pub fn string_bytes(&self, strx: u32) -> &'a [u8] {
        if strx >= self.strsize {
            return &[];
        }
        let start = self.string_table_offset().saturating_add(strx as u64);
        let image: &'a crate::image::Image = &self.mh.image;
        if start >= image.len() {
            return &[];
        }
        image
            .cstr(start, (self.strsize - strx) as u64)
            .unwrap_or(&[])
    }

    /// [`string_bytes`](Self::string_bytes) as display text.
    pub fn string(&self, strx: u32) -> String {
        utf8_safe(self.string_bytes(strx))
    }

    /// Name of the symbol at `index`; `None` when the index is out of range.
    pub fn symbol_name(&self, index: u32) -> Option<String> {
        self.symbol(index).map(|s| self.string(s.n_strx))
    }
}

#[cfg(test)]
mod tests {
    use crate::image::Image;
    use crate::macho::MachHeader;
    use std::sync::Arc;

    /// Minimal 64-bit Mach-O with one `LC_SYMTAB`, `nsyms` claimed symbols
    /// (two present) and a short string table.
    pub(crate) fn tiny(nsyms: u32, strsize: u32) -> Arc<MachHeader> {
        let mut f = Vec::new();
        let put = |f: &mut Vec<u8>, v: u32| f.extend_from_slice(&v.to_le_bytes());
        for v in [0xfeedfacf, 0x0100_0007, 3, 1, 1, 24, 0, 0] {
            put(&mut f, v);
        }
        // LC_SYMTAB: symoff 56, stroff 88
        for v in [2, 24, 56, nsyms, 88, strsize] {
            put(&mut f, v);
        }
        // two nlist_64
        put(&mut f, 1);
        f.extend_from_slice(&[0x0f, 1, 0x10, 0x00]);
        f.extend_from_slice(&0x1000u64.to_le_bytes());
        put(&mut f, 4);
        f.extend_from_slice(&[0x01, 0, 0x00, 0x01]);
        f.extend_from_slice(&0u64.to_le_bytes());
        f.extend_from_slice(b"\0_a\0_bc");
        let image = Arc::new(Image::from_vec(f).unwrap());
        Arc::new(MachHeader::parse(&image, 0).unwrap())
    }

    #[test]
    fn symbols_and_names() {
        let mh = tiny(2, 8);
        let st = mh.symtab().unwrap();
        assert_eq!(st.symbol_count(), 2);
        let syms: Vec<_> = st.symbols().collect();
        assert_eq!(syms.len(), 2);
        assert_eq!(
            (
                syms[0].offset,
                syms[0].n_type,
                syms[0].n_sect,
                syms[0].n_desc
            ),
            (56, 0x0f, 1, 0x10)
        );
        assert_eq!(syms[0].n_value, 0x1000);
        assert_eq!(syms[1].n_desc, 0x100);
        assert_eq!(st.symbol_name(0).as_deref(), Some("_a"));
        // Unterminated: stops at the end of the string table / file.
        assert_eq!(st.symbol_name(1).as_deref(), Some("_bc"));
        assert_eq!(st.symbol_name(2), None);
        assert_eq!(st.symbol(u32::MAX), None);
    }

    #[test]
    fn clipped_to_file() {
        // Claims far more symbols and strings than the file holds.
        let mh = tiny(u32::MAX, u32::MAX);
        let st = mh.symtab().unwrap();
        // 39 bytes after symoff: two whole entries.
        assert_eq!(st.symbol_count(), 2);
        assert_eq!(st.symbol_table_total_bytes(), 0xFFFF_FFFF * 16);
        assert_eq!(st.string_table_size_in_file(), 7);
        assert_eq!(st.string(1), "_a");
        assert_eq!(st.string(7), "");
        assert_eq!(st.string(1 << 20), "");
        // Out of the declared table.
        let st = tiny(2, 3);
        let st = st.symtab().unwrap();
        assert_eq!(st.string(1), "_a");
        assert_eq!(st.string(3), "");
        assert_eq!(st.string(4), "");
    }
}
