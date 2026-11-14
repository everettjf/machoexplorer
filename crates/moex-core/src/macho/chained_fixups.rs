//! `LC_DYLD_CHAINED_FIXUPS` structures and chained pointer decoding, as
//! the original `ModernChainedFixupsViewNode` understands them.

use crate::image::Image;
use std::fmt;

pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
pub const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_32: u16 = 3;
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

pub const CHAINED_FIXUPS_HEADER_SIZE: u64 = 28;
/// `sizeof(dyld_chained_starts_in_segment)` without its trailing array:
/// 22 bytes of fields rounded up to the 8-byte alignment.
pub const CHAINED_STARTS_IN_SEGMENT_SIZE: u64 = 24;

pub fn pointer_format_name(format: u16) -> &'static str {
    match format {
        DYLD_CHAINED_PTR_ARM64E => "ARM64E",
        DYLD_CHAINED_PTR_64 => "64",
        DYLD_CHAINED_PTR_32 => "32",
        DYLD_CHAINED_PTR_32_CACHE => "32_CACHE",
        DYLD_CHAINED_PTR_32_FIRMWARE => "32_FIRMWARE",
        DYLD_CHAINED_PTR_64_OFFSET => "64_OFFSET",
        DYLD_CHAINED_PTR_ARM64E_KERNEL => "ARM64E_KERNEL",
        DYLD_CHAINED_PTR_64_KERNEL_CACHE => "64_KERNEL_CACHE",
        DYLD_CHAINED_PTR_ARM64E_USERLAND => "ARM64E_USERLAND",
        DYLD_CHAINED_PTR_ARM64E_FIRMWARE => "ARM64E_FIRMWARE",
        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => "X86_64_KERNEL_CACHE",
        DYLD_CHAINED_PTR_ARM64E_USERLAND24 => "ARM64E_USERLAND24",
        _ => "UNKNOWN",
    }
}

pub fn import_format_name(format: u32) -> &'static str {
    match format {
        DYLD_CHAINED_IMPORT => "DYLD_CHAINED_IMPORT",
        DYLD_CHAINED_IMPORT_ADDEND => "DYLD_CHAINED_IMPORT_ADDEND",
        DYLD_CHAINED_IMPORT_ADDEND64 => "DYLD_CHAINED_IMPORT_ADDEND64",
        _ => "UNKNOWN",
    }
}

/// True for the formats whose fixups are 8 bytes wide. Every other value,
/// including unknown ones, is walked as 4-byte fixups.
pub fn is_64bit_pointer_format(format: u16) -> bool {
    matches!(
        format,
        DYLD_CHAINED_PTR_64
            | DYLD_CHAINED_PTR_64_OFFSET
            | DYLD_CHAINED_PTR_ARM64E
            | DYLD_CHAINED_PTR_ARM64E_KERNEL
            | DYLD_CHAINED_PTR_64_KERNEL_CACHE
            | DYLD_CHAINED_PTR_ARM64E_USERLAND
            | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
            | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
            | DYLD_CHAINED_PTR_ARM64E_USERLAND24
    )
}

/// The "next" field of a chained pointer, in 4-byte units.
///
/// QUIRK(parity): one layout is used per pointer width: bits 26..31 for
/// 4-byte formats and bits 51..62 for 8-byte formats, whatever the format's
/// real layout or stride is.
pub fn decode_next(format: u16, raw: u64) -> u64 {
    if is_64bit_pointer_format(format) {
        (raw >> 51) & 0x7FF
    } else {
        (raw >> 26) & 0x1F
    }
}

/// A decoded 8-byte chained pointer. `Display` gives the text the fixup
/// table shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedPointer {
    Bind {
        ordinal: u64,
        addend: u64,
    },
    /// `file_offset` is set for `DYLD_CHAINED_PTR_64_OFFSET`.
    Rebase {
        target: u64,
        high8: u64,
        file_offset: bool,
    },
    Arm64eBind {
        ordinal: u64,
        addend: u64,
    },
    Arm64eRebase {
        target: u64,
        high8: u64,
    },
    Arm64eAuthBind {
        ordinal: u64,
        key: u64,
        addr_div: u64,
        diversity: u64,
    },
    Arm64eAuthRebase {
        target: u64,
        key: u64,
        addr_div: u64,
        diversity: u64,
    },
    /// Format without a decoder.
    Raw(u64),
}

pub fn decode_pointer(format: u16, raw: u64) -> ChainedPointer {
    match format {
        DYLD_CHAINED_PTR_64
        | DYLD_CHAINED_PTR_64_OFFSET
        | DYLD_CHAINED_PTR_64_KERNEL_CACHE
        | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => {
            if (raw >> 63) & 1 != 0 {
                ChainedPointer::Bind {
                    ordinal: raw & 0x00FF_FFFF,
                    addend: (raw >> 24) & 0xFF,
                }
            } else {
                ChainedPointer::Rebase {
                    target: raw & 0x0000_000F_FFFF_FFFF,
                    high8: (raw >> 36) & 0xFF,
                    file_offset: format == DYLD_CHAINED_PTR_64_OFFSET,
                }
            }
        }
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE => {
            let auth = (raw >> 63) & 1 != 0;
            let bind = (raw >> 62) & 1 != 0;
            let diversity = (raw >> 32) & 0xFFFF;
            let addr_div = (raw >> 48) & 1;
            let key = (raw >> 49) & 3;
            match (auth, bind) {
                (false, true) => ChainedPointer::Arm64eBind {
                    ordinal: raw & 0xFFFF,
                    addend: (raw >> 32) & 0x7FFFF,
                },
                (false, false) => ChainedPointer::Arm64eRebase {
                    target: raw & ((1u64 << 43) - 1),
                    high8: (raw >> 43) & 0xFF,
                },
                (true, true) => ChainedPointer::Arm64eAuthBind {
                    ordinal: raw & 0xFFFF,
                    key,
                    addr_div,
                    diversity,
                },
                (true, false) => ChainedPointer::Arm64eAuthRebase {
                    target: raw & 0xFFFF_FFFF,
                    key,
                    addr_div,
                    diversity,
                },
            }
        }
        _ => ChainedPointer::Raw(raw),
    }
}

impl fmt::Display for ChainedPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ChainedPointer::Bind { ordinal, addend } => {
                write!(f, "bind ordinal={ordinal} addend={addend}")
            }
            ChainedPointer::Rebase {
                target,
                high8,
                file_offset: true,
            } => {
                write!(f, "rebase target-fileoff=0x{target:X} high8=0x{high8:X}")
            }
            ChainedPointer::Rebase {
                target,
                high8,
                file_offset: false,
            } => {
                write!(f, "rebase target-vm=0x{target:X} high8=0x{high8:X}")
            }
            ChainedPointer::Arm64eBind { ordinal, addend } => {
                write!(f, "arm64e bind ordinal={ordinal} addend={addend}")
            }
            ChainedPointer::Arm64eRebase { target, high8 } => {
                write!(f, "arm64e rebase target=0x{target:X} high8=0x{high8:X}")
            }
            ChainedPointer::Arm64eAuthBind {
                ordinal,
                key,
                addr_div,
                diversity,
            } => {
                write!(f, "arm64e auth-bind ordinal={ordinal} key={key} addrDiv={addr_div} diversity=0x{diversity:X}")
            }
            ChainedPointer::Arm64eAuthRebase {
                target,
                key,
                addr_div,
                diversity,
            } => {
                write!(f, "arm64e auth-rebase target=0x{target:X} key={key} addrDiv={addr_div} diversity=0x{diversity:X}")
            }
            ChainedPointer::Raw(raw) => write!(f, "raw=0x{raw:X}"),
        }
    }
}

/// `dyld_chained_fixups_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedFixupsHeader {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: u32,
    pub symbols_format: u32,
}

impl ChainedFixupsHeader {
    /// Read the header at file offset `at`; `None` when it does not fit in
    /// the file.
    pub fn read(image: &Image, at: u64) -> Option<Self> {
        if !image.in_file(at, CHAINED_FIXUPS_HEADER_SIZE) {
            return None;
        }
        let f = |i: u64| image.u32(at.checked_add(4 * i)?);
        Some(ChainedFixupsHeader {
            fixups_version: f(0)?,
            starts_offset: f(1)?,
            imports_offset: f(2)?,
            symbols_offset: f(3)?,
            imports_count: f(4)?,
            imports_format: f(5)?,
            symbols_format: f(6)?,
        })
    }
}

/// The fixed part of `dyld_chained_starts_in_segment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedStartsInSegment {
    pub size: u32,
    pub page_size: u16,
    pub pointer_format: u16,
    pub segment_offset: u64,
    pub max_valid_pointer: u32,
    pub page_count: u16,
}

impl ChainedStartsInSegment {
    /// Read the struct at file offset `at`; `None` unless all 24 bytes of
    /// the padded struct are in the file.
    pub fn read(image: &Image, at: u64) -> Option<Self> {
        if !image.in_file(at, CHAINED_STARTS_IN_SEGMENT_SIZE) {
            return None;
        }
        Some(ChainedStartsInSegment {
            size: image.u32(at)?,
            page_size: image.u16(at.checked_add(4)?)?,
            pointer_format: image.u16(at.checked_add(6)?)?,
            segment_offset: image.u64(at.checked_add(8)?)?,
            max_valid_pointer: image.u32(at.checked_add(16)?)?,
            page_count: image.u16(at.checked_add(20)?)?,
        })
    }
}

/// Addend of an import entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAddend {
    /// `DYLD_CHAINED_IMPORT` has none.
    None,
    Signed32(i32),
    Unsigned64(u64),
}

/// One entry of the imports table, in any of the three formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedImport {
    pub lib_ordinal: u64,
    pub weak_import: u64,
    pub name_offset: u64,
    pub addend: ImportAddend,
}

impl ChainedImport {
    /// Size in bytes of one entry; `None` for an unknown format.
    pub fn entry_size(format: u32) -> Option<u64> {
        match format {
            DYLD_CHAINED_IMPORT => Some(4),
            DYLD_CHAINED_IMPORT_ADDEND => Some(8),
            DYLD_CHAINED_IMPORT_ADDEND64 => Some(16),
            _ => None,
        }
    }

    /// Read the entry at file offset `at`.
    pub fn read(image: &Image, at: u64, format: u32) -> Option<Self> {
        match format {
            DYLD_CHAINED_IMPORT | DYLD_CHAINED_IMPORT_ADDEND => {
                let v = image.u32(at)? as u64;
                let addend = if format == DYLD_CHAINED_IMPORT {
                    ImportAddend::None
                } else {
                    ImportAddend::Signed32(image.u32(at.checked_add(4)?)? as i32)
                };
                Some(ChainedImport {
                    lib_ordinal: v & 0xFF,
                    weak_import: (v >> 8) & 1,
                    name_offset: v >> 9,
                    addend,
                })
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let v = image.u64(at)?;
                Some(ChainedImport {
                    lib_ordinal: v & 0xFFFF,
                    weak_import: (v >> 16) & 1,
                    name_offset: v >> 32,
                    addend: ImportAddend::Unsigned64(image.u64(at.checked_add(8)?)?),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(bytes: &[u8]) -> Image {
        Image::from_vec(bytes.to_vec()).unwrap()
    }

    #[test]
    fn names_and_widths() {
        assert_eq!(pointer_format_name(1), "ARM64E");
        assert_eq!(pointer_format_name(6), "64_OFFSET");
        assert_eq!(pointer_format_name(12), "ARM64E_USERLAND24");
        assert_eq!(pointer_format_name(0), "UNKNOWN");
        assert_eq!(pointer_format_name(13), "UNKNOWN");
        assert_eq!(import_format_name(2), "DYLD_CHAINED_IMPORT_ADDEND");
        assert_eq!(import_format_name(0), "UNKNOWN");
        for format in 0..=13u16 {
            let narrow = matches!(format, 0 | 3 | 4 | 5 | 13);
            assert_eq!(is_64bit_pointer_format(format), !narrow, "format {format}");
        }
    }

    #[test]
    fn next_field() {
        assert_eq!(decode_next(DYLD_CHAINED_PTR_64, 0x0010_0000_0000_066B), 2);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_64, 0x8010_0000_0000_0000), 2);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_ARM64E, u64::MAX), 0x7FF);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_32, 0x7100_1000), 28);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_32_CACHE, 0xFFFF_FFFF), 0x1F);
        assert_eq!(decode_next(0, 0x1900_0000), 6);
    }

    #[test]
    fn pointers_64() {
        for format in [
            DYLD_CHAINED_PTR_64,
            DYLD_CHAINED_PTR_64_KERNEL_CACHE,
            DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE,
        ] {
            assert_eq!(
                decode_pointer(format, 0x8010_0000_0500_0003).to_string(),
                "bind ordinal=3 addend=5"
            );
            assert_eq!(
                decode_pointer(format, 0x0010_0AB0_0000_066B).to_string(),
                "rebase target-vm=0x66B high8=0xAB"
            );
        }
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_64_OFFSET, 0x0000_0000_0000_4000).to_string(),
            "rebase target-fileoff=0x4000 high8=0x0"
        );
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_64_OFFSET, 0x8000_0000_00FF_FFFF),
            ChainedPointer::Bind {
                ordinal: 0xFF_FFFF,
                addend: 0
            }
        );
    }

    #[test]
    fn pointers_arm64e() {
        for format in [
            DYLD_CHAINED_PTR_ARM64E,
            DYLD_CHAINED_PTR_ARM64E_KERNEL,
            DYLD_CHAINED_PTR_ARM64E_USERLAND,
            DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
            DYLD_CHAINED_PTR_ARM64E_USERLAND24,
        ] {
            // bind: bit 62, ordinal 7, addend 0x12345
            assert_eq!(
                decode_pointer(format, 0x4000_0000_0000_0007 | (0x12345 << 32)).to_string(),
                "arm64e bind ordinal=7 addend=74565"
            );
            // rebase: target 43 bits, high8 at 43
            assert_eq!(
                decode_pointer(format, 0x0000_0000_0001_2340 | (0x5A << 43)).to_string(),
                "arm64e rebase target=0x12340 high8=0x5A"
            );
            // auth bind: bits 63+62, key 2, addrDiv 1, diversity 0xBEEF
            assert_eq!(
                decode_pointer(
                    format,
                    0xC000_0000_0000_0009 | (2 << 49) | (1 << 48) | (0xBEEF << 32)
                )
                .to_string(),
                "arm64e auth-bind ordinal=9 key=2 addrDiv=1 diversity=0xBEEF"
            );
            // auth rebase: bit 63, key 3
            assert_eq!(
                decode_pointer(format, 0x8000_0000_0000_3F00 | (3 << 49) | (0x1 << 32)).to_string(),
                "arm64e auth-rebase target=0x3F00 key=3 addrDiv=0 diversity=0x1"
            );
        }
    }

    #[test]
    fn pointers_without_decoder() {
        for format in [
            0,
            DYLD_CHAINED_PTR_32,
            DYLD_CHAINED_PTR_32_CACHE,
            DYLD_CHAINED_PTR_32_FIRMWARE,
            13,
        ] {
            assert_eq!(decode_pointer(format, 0xABCD).to_string(), "raw=0xABCD");
        }
    }

    #[test]
    fn header_and_segment_structs() {
        let mut b = Vec::new();
        for v in [0u32, 0x20, 0x68, 0x74, 3, 1, 0] {
            b.extend(v.to_le_bytes());
        }
        let img = image(&b);
        let h = ChainedFixupsHeader::read(&img, 0).unwrap();
        assert_eq!(
            (
                h.starts_offset,
                h.imports_offset,
                h.symbols_offset,
                h.imports_count
            ),
            (0x20, 0x68, 0x74, 3)
        );
        assert!(ChainedFixupsHeader::read(&img, 1).is_none());
        assert!(ChainedFixupsHeader::read(&img, u64::MAX).is_none());

        let mut s = Vec::new();
        s.extend(0x18u32.to_le_bytes());
        s.extend(0x4000u16.to_le_bytes());
        s.extend(6u16.to_le_bytes());
        s.extend(0x4000u64.to_le_bytes());
        s.extend(0u32.to_le_bytes());
        s.extend(1u16.to_le_bytes());
        s.extend(0u16.to_le_bytes());
        let seg = ChainedStartsInSegment::read(&image(&s), 0).unwrap();
        assert_eq!(
            (
                seg.page_size,
                seg.pointer_format,
                seg.segment_offset,
                seg.page_count
            ),
            (0x4000, 6, 0x4000, 1)
        );
        // The padded 24 bytes must all be present.
        assert!(ChainedStartsInSegment::read(&image(&s[..23]), 0).is_none());
    }

    #[test]
    fn imports() {
        // lib 2, weak, name offset 0x123
        let v: u32 = 2 | (1 << 8) | (0x123 << 9);
        let mut b = v.to_le_bytes().to_vec();
        b.extend((-5i32).to_le_bytes());
        let img = image(&b);
        let plain = ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT).unwrap();
        assert_eq!(
            plain,
            ChainedImport {
                lib_ordinal: 2,
                weak_import: 1,
                name_offset: 0x123,
                addend: ImportAddend::None
            }
        );
        let addend = ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT_ADDEND).unwrap();
        assert_eq!(addend.addend, ImportAddend::Signed32(-5));
        assert!(ChainedImport::read(&img, 4, DYLD_CHAINED_IMPORT_ADDEND).is_none());

        let v: u64 = 0xFFFE | (1 << 16) | (0x7FFF << 17) | (0x9876_5432 << 32);
        let mut b = v.to_le_bytes().to_vec();
        b.extend(0x1122_3344_5566_7788u64.to_le_bytes());
        let wide = ChainedImport::read(&image(&b), 0, DYLD_CHAINED_IMPORT_ADDEND64).unwrap();
        assert_eq!(
            wide,
            ChainedImport {
                lib_ordinal: 0xFFFE,
                weak_import: 1,
                name_offset: 0x9876_5432,
                addend: ImportAddend::Unsigned64(0x1122_3344_5566_7788),
            }
        );
        assert!(ChainedImport::read(&image(&b), 0, 4).is_none());
        assert_eq!(ChainedImport::entry_size(3), Some(16));
        assert_eq!(ChainedImport::entry_size(0), None);
    }
}
