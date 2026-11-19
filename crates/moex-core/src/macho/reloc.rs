//! Section relocation entries (`relocation_info` and
//! `scattered_relocation_info`), as object files carry them.

use super::header::MachHeader;
use super::segment::Section;
use crate::consts::{CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_X86_64};

/// Size of one entry in the file.
pub const ENTRY_SIZE: u64 = 8;

// `r_type` values this crate interprets.
/// Every architecture: a plain pointer (`*_RELOC_VANILLA` / `_UNSIGNED`).
pub const RELOC_UNSIGNED: u8 = 0;
/// Every architecture with scattered entries: the second entry of a pair.
pub const RELOC_PAIR: u8 = 1;
pub const GENERIC_RELOC_SECTDIFF: u8 = 2;
pub const GENERIC_RELOC_PB_LA_PTR: u8 = 3;
pub const GENERIC_RELOC_LOCAL_SECTDIFF: u8 = 4;
pub const ARM_RELOC_SECTDIFF: u8 = 2;
pub const ARM_RELOC_LOCAL_SECTDIFF: u8 = 3;
pub const ARM_RELOC_BR24: u8 = 5;
pub const ARM_THUMB_RELOC_BR22: u8 = 6;
pub const ARM_RELOC_HALF: u8 = 8;
pub const ARM_RELOC_HALF_SECTDIFF: u8 = 9;
pub const X86_64_RELOC_SIGNED: u8 = 1;
pub const X86_64_RELOC_BRANCH: u8 = 2;
pub const X86_64_RELOC_GOT_LOAD: u8 = 3;
pub const X86_64_RELOC_GOT: u8 = 4;
pub const X86_64_RELOC_SIGNED_1: u8 = 6;
pub const X86_64_RELOC_SIGNED_2: u8 = 7;
pub const X86_64_RELOC_SIGNED_4: u8 = 8;
pub const ARM64_RELOC_BRANCH26: u8 = 2;
pub const ARM64_RELOC_PAGE21: u8 = 3;
pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
pub const ARM64_RELOC_ADDEND: u8 = 10;
pub const ARM64_RELOC_AUTHENTICATED_POINTER: u8 = 11;

/// One relocation entry of a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    /// Offset into the section of what is patched.
    pub address: u32,
    /// Symbol table index when `external`, otherwise a section ordinal; for
    /// `ARM64_RELOC_ADDEND` the addend itself. Unused when `scattered`.
    pub symbolnum: u32,
    pub pcrel: bool,
    /// log2 of the width in bytes of what is patched.
    pub length: u8,
    /// `symbolnum` names a symbol (`r_extern`).
    pub external: bool,
    pub kind: u8,
    /// A `scattered_relocation_info`: the entry carries the address of the
    /// target (`value`) instead of a symbol or section number.
    pub scattered: bool,
    pub value: u32,
}

impl Reloc {
    /// Decodes the two words of an entry. `allow_scattered`: the
    /// architecture has scattered entries, marked by the top bit of the
    /// first word. `big_endian`: the bit fields are laid out from the most
    /// significant bit, as compilers for big-endian targets do.
    pub fn decode(word0: u32, word1: u32, allow_scattered: bool, big_endian: bool) -> Reloc {
        if allow_scattered && word0 & 0x8000_0000 != 0 {
            return Reloc {
                address: word0 & 0x00ff_ffff,
                symbolnum: 0,
                pcrel: word0 & 0x4000_0000 != 0,
                length: ((word0 >> 28) & 3) as u8,
                external: false,
                kind: ((word0 >> 24) & 0xf) as u8,
                scattered: true,
                value: word1,
            };
        }
        let (symbolnum, pcrel, length, external, kind) = if big_endian {
            (
                word1 >> 8,
                word1 & 0x80 != 0,
                (word1 >> 5) & 3,
                word1 & 0x10 != 0,
                word1 & 0xf,
            )
        } else {
            (
                word1 & 0x00ff_ffff,
                word1 & 0x0100_0000 != 0,
                (word1 >> 25) & 3,
                word1 & 0x0800_0000 != 0,
                word1 >> 28,
            )
        };
        Reloc {
            address: word0,
            symbolnum,
            pcrel,
            length: length as u8,
            external,
            kind: kind as u8,
            scattered: false,
            value: 0,
        }
    }
}

/// True when the architecture of `mh` uses scattered entries: every one
/// but x86-64 and arm64, whose `r_address` is a full 32 bits.
pub fn has_scattered(mh: &MachHeader) -> bool {
    !matches!(
        mh.cputype,
        CPU_TYPE_X86_64 | CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32
    )
}

/// The relocation entries of `sect` in table order: at most `limit`, and
/// only those that lie in the file.
pub fn section_relocs(mh: &MachHeader, sect: &Section, limit: u64) -> Vec<Reloc> {
    let mut out = Vec::new();
    let Some(table) = mh.offset.checked_add(u64::from(sect.reloff)) else {
        return out;
    };
    let scattered = has_scattered(mh);
    for i in 0..u64::from(sect.nreloc).min(limit) {
        let Some(at) = table.checked_add(i * ENTRY_SIZE) else {
            break;
        };
        let (Some(word0), Some(word1)) = (mh.image.u32(at), mh.image.u32(at + 4)) else {
            break;
        };
        out.push(Reloc::decode(word0, word1, scattered, mh.big_endian));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_fields() {
        // r_symbolnum 5, pcrel, length 2, extern, type 2 (a branch).
        let word1 = 5 | 1 << 24 | 2 << 25 | 1 << 27 | 2 << 28;
        let r = Reloc::decode(0x40, word1, false, false);
        assert_eq!(
            (
                r.address,
                r.symbolnum,
                r.pcrel,
                r.length,
                r.external,
                r.kind
            ),
            (0x40, 5, true, 2, true, 2)
        );
        assert!(!r.scattered);
        // The same fields in big-endian bit order.
        let word1 = 5 << 8 | 0x80 | 2 << 5 | 0x10 | 2;
        assert_eq!(Reloc::decode(0x40, word1, true, true), r);
        // Scattered: type 4, length 2, address 0x123456, value 0x2000.
        let word0 = 0x8000_0000 | 4 << 24 | 2 << 28 | 0x12_3456;
        let s = Reloc::decode(word0, 0x2000, true, false);
        assert!(s.scattered && !s.pcrel && !s.external);
        assert_eq!(
            (s.address, s.kind, s.length, s.value),
            (0x12_3456, 4, 2, 0x2000)
        );
        // Where there are no scattered entries the word is an address.
        let plain = Reloc::decode(word0, 0, false, false);
        assert!(!plain.scattered);
        assert_eq!(plain.address, word0);
    }
}
