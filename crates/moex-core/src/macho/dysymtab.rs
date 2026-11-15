//! `LC_DYSYMTAB`: dynamic symbol table, indirect symbols and relocations.

use super::header::{LoadCommand, MachHeader};
use crate::consts::LC_DYSYMTAB;

pub const RELOCATION_INFO_SIZE: u64 = 8;
const DYLIB_TABLE_OF_CONTENTS_SIZE: u64 = 8;
const DYLIB_MODULE_SIZE: u64 = 52;
const DYLIB_MODULE_64_SIZE: u64 = 56;
const DYLIB_REFERENCE_SIZE: u64 = 4;

/// One entry of the indirect symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectSymbol {
    /// File offset of the 32-bit entry.
    pub offset: u64,
    /// Index into the symbol table (or `INDIRECT_SYMBOL_LOCAL`/`_ABS`).
    pub symbol_index: u32,
}

/// One raw `relocation_info` / `scattered_relocation_info` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub index: u32,
    /// File offset of the 8-byte entry.
    pub offset: u64,
    pub word0: u32,
    pub word1: u32,
}

/// The first `LC_DYSYMTAB` command of a Mach-O header.
#[derive(Clone, Copy)]
pub struct Dysymtab<'a> {
    mh: &'a MachHeader,
    pub lc: LoadCommand,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

impl MachHeader {
    /// The first `LC_DYSYMTAB` command, if any.
    pub fn dysymtab(&self) -> Option<Dysymtab<'_>> {
        let lc = *self.find_load_command(&[LC_DYSYMTAB])?;
        let f = |i: u64| self.lc_u32(&lc, 8 + 4 * i);
        Some(Dysymtab {
            mh: self,
            lc,
            ilocalsym: f(0),
            nlocalsym: f(1),
            iextdefsym: f(2),
            nextdefsym: f(3),
            iundefsym: f(4),
            nundefsym: f(5),
            tocoff: f(6),
            ntoc: f(7),
            modtaboff: f(8),
            nmodtab: f(9),
            extrefsymoff: f(10),
            nextrefsyms: f(11),
            indirectsymoff: f(12),
            nindirectsyms: f(13),
            extreloff: f(14),
            nextrel: f(15),
            locreloff: f(16),
            nlocrel: f(17),
        })
    }

    /// `size` clipped so that `[offset, offset+size)` stays in the file
    /// (0 when `offset` is at or past the end of the file).
    pub fn clamp_size_to_file(&self, offset: u64, size: u64) -> u64 {
        let len = self.image.len();
        if offset >= len {
            0
        } else {
            size.min(len - offset)
        }
    }
}

impl<'a> Dysymtab<'a> {
    /// `(offset relative to the Mach-O header, byte size)` of each table
    /// that is present (non-zero offset and count), in the order toc,
    /// modtab, extrefsym, indirectsym, extrel, locrel.
    pub fn tables(&self) -> Vec<(u64, u64)> {
        let module = if self.mh.is64 {
            DYLIB_MODULE_64_SIZE
        } else {
            DYLIB_MODULE_SIZE
        };
        [
            (self.tocoff, self.ntoc, DYLIB_TABLE_OF_CONTENTS_SIZE),
            (self.modtaboff, self.nmodtab, module),
            (self.extrefsymoff, self.nextrefsyms, DYLIB_REFERENCE_SIZE),
            (self.indirectsymoff, self.nindirectsyms, 4),
            (self.extreloff, self.nextrel, RELOCATION_INFO_SIZE),
            (self.locreloff, self.nlocrel, RELOCATION_INFO_SIZE),
        ]
        .into_iter()
        .filter(|&(off, count, _)| off > 0 && count > 0)
        .map(|(off, count, unit)| (off as u64, count as u64 * unit))
        .collect()
    }

    /// `(offset relative to the Mach-O header, size)` of the smallest range
    /// that covers every table present. The tables need not be adjacent
    /// (the symbol table often sits between the relocations and the
    /// indirect symbols), so the range can include unrelated bytes.
    pub fn data_range(&self) -> Option<(u64, u64)> {
        let tables = self.tables();
        let start = tables.iter().map(|&(off, _)| off).min()?;
        let end = tables.iter().map(|&(off, size)| off + size).max()?;
        Some((start, end - start))
    }

    pub fn has_indirect_symbols(&self) -> bool {
        self.nindirectsyms > 0
    }

    pub fn has_external_relocations(&self) -> bool {
        self.extreloff > 0 && self.nextrel > 0
    }

    pub fn has_local_relocations(&self) -> bool {
        self.locreloff > 0 && self.nlocrel > 0
    }

    /// File offset of the indirect symbol table.
    pub fn indirect_symbols_offset(&self) -> u64 {
        self.mh.offset.saturating_add(self.indirectsymoff as u64)
    }

    /// Number of indirect symbol entries that fit in the file.
    pub fn indirect_symbol_count(&self) -> u32 {
        let size = self.mh.clamp_size_to_file(
            self.indirect_symbols_offset(),
            self.nindirectsyms as u64 * 4,
        );
        (size / 4) as u32
    }

    /// Entry `index` of the indirect symbol table.
    pub fn indirect_symbol(&self, index: u32) -> Option<IndirectSymbol> {
        if index >= self.indirect_symbol_count() {
            return None;
        }
        let offset = self
            .indirect_symbols_offset()
            .checked_add(index as u64 * 4)?;
        Some(IndirectSymbol {
            offset,
            symbol_index: self.mh.image.u32(offset)?,
        })
    }

    /// The indirect symbol table in file order. Nothing is allocated.
    pub fn indirect_symbols(&self) -> impl Iterator<Item = IndirectSymbol> + 'a {
        let this = *self;
        (0..this.indirect_symbol_count()).filter_map(move |i| this.indirect_symbol(i))
    }

    fn relocations(
        &self,
        present: bool,
        reloff: u32,
        nreloc: u32,
    ) -> impl Iterator<Item = Relocation> + 'a {
        let mh = self.mh;
        let base = mh.offset.saturating_add(reloff as u64);
        let count = if present {
            mh.clamp_size_to_file(base, nreloc as u64 * RELOCATION_INFO_SIZE) / RELOCATION_INFO_SIZE
        } else {
            0
        };
        (0..count).filter_map(move |i| {
            let offset = base.checked_add(i.checked_mul(RELOCATION_INFO_SIZE)?)?;
            Some(Relocation {
                index: i as u32,
                offset,
                word0: mh.image.u32(offset)?,
                word1: mh.image.u32(offset.checked_add(4)?)?,
            })
        })
    }

    /// External relocation entries that fit in the file.
    pub fn external_relocations(&self) -> impl Iterator<Item = Relocation> + 'a {
        self.relocations(
            self.has_external_relocations(),
            self.extreloff,
            self.nextrel,
        )
    }

    /// Local relocation entries that fit in the file.
    pub fn local_relocations(&self) -> impl Iterator<Item = Relocation> + 'a {
        self.relocations(self.has_local_relocations(), self.locreloff, self.nlocrel)
    }
}
