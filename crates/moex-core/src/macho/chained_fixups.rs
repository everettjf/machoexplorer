//! `LC_DYLD_CHAINED_FIXUPS` structures and chained pointer decoding, per
//! `<mach-o/fixup-chains.h>`.

use crate::image::Image;

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
pub const DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE: u16 = 13;
pub const DYLD_CHAINED_PTR_ARM64E_SEGMENTED: u16 = 14;
pub const DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3: u16 = 15;
pub const DYLD_CHAINED_PTR_SHARED_CACHE_V2: u16 = 16;

pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

pub const CHAINED_FIXUPS_HEADER_SIZE: u64 = 28;
/// Offset of `page_start[]` in `dyld_chained_starts_in_segment`, i.e. the
/// size of its fixed fields. (`sizeof` the C struct is 24 because of
/// alignment padding, but the array starts right after `page_count`.)
pub const CHAINED_STARTS_PAGE_START_OFFSET: u64 = 22;

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
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => "ARM64E_SHARED_CACHE",
        DYLD_CHAINED_PTR_ARM64E_SEGMENTED => "ARM64E_SEGMENTED",
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3 => "ARM64E_SHARED_CACHE_V3",
        DYLD_CHAINED_PTR_SHARED_CACHE_V2 => "SHARED_CACHE_V2",
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

/// How the fixups of one pointer format are laid out in a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerLayout {
    /// Size in bytes of one fixup (4 or 8).
    pub width: u64,
    /// Unit of the `next` field in bytes.
    pub stride: u64,
}

/// Layout of `format`; `None` for a format this decoder does not know, whose
/// chains cannot be walked.
pub fn pointer_layout(format: u16) -> Option<PointerLayout> {
    let (width, stride) = match format {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
        | DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3 => (8, 8),
        DYLD_CHAINED_PTR_64
        | DYLD_CHAINED_PTR_64_OFFSET
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_64_KERNEL_CACHE
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
        | DYLD_CHAINED_PTR_ARM64E_SEGMENTED
        | DYLD_CHAINED_PTR_SHARED_CACHE_V2 => (8, 4),
        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => (8, 1),
        DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE | DYLD_CHAINED_PTR_32_FIRMWARE => (4, 4),
        _ => return None,
    };
    Some(PointerLayout { width, stride })
}

fn bits(raw: u64, shift: u32, count: u32) -> u64 {
    (raw >> shift) & ((1u64 << count) - 1)
}

/// The `next` field of a chained pointer, in units of the format's stride
/// (0 ends the chain). 0 for an unknown format.
pub fn decode_next(format: u16, raw: u64) -> u64 {
    match format {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3 => bits(raw, 51, 11),
        DYLD_CHAINED_PTR_64
        | DYLD_CHAINED_PTR_64_OFFSET
        | DYLD_CHAINED_PTR_64_KERNEL_CACHE
        | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
        | DYLD_CHAINED_PTR_ARM64E_SEGMENTED => bits(raw, 51, 12),
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => bits(raw, 52, 11),
        DYLD_CHAINED_PTR_SHARED_CACHE_V2 => bits(raw, 40, 16),
        DYLD_CHAINED_PTR_32 => bits(raw, 26, 5),
        DYLD_CHAINED_PTR_32_CACHE => bits(raw, 30, 2),
        DYLD_CHAINED_PTR_32_FIRMWARE => bits(raw, 26, 6),
        _ => 0,
    }
}

/// Pointer authentication parameters of an authenticated fixup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerAuth {
    /// 0 = IA, 1 = IB, 2 = DA, 3 = DB.
    pub key: u8,
    pub addr_div: bool,
    pub diversity: u16,
}

impl PointerAuth {
    pub fn key_name(&self) -> &'static str {
        ["IA", "IB", "DA", "DB"][(self.key & 3) as usize]
    }

    /// `diversity:16, addrDiv:1, key:2` starting at bit 32.
    fn at_bit_32(raw: u64) -> Self {
        PointerAuth {
            key: bits(raw, 49, 2) as u8,
            addr_div: bits(raw, 48, 1) != 0,
            diversity: bits(raw, 32, 16) as u16,
        }
    }
}

/// A decoded chained pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedPointer {
    /// Pointer to a location in this image (or, for the shared-cache
    /// formats, in the cache).
    Rebase {
        target: u64,
        /// Goes into the top byte of the final pointer.
        high8: u8,
        /// `target` is an offset from the image (or cache) base rather than
        /// an unslid virtual address.
        vm_offset: bool,
        auth: Option<PointerAuth>,
    },
    /// Pointer to the import with index `ordinal`.
    Bind {
        ordinal: u32,
        addend: i64,
        auth: Option<PointerAuth>,
    },
    /// `DYLD_CHAINED_PTR_64_KERNEL_CACHE` / `..._X86_64_KERNEL_CACHE`:
    /// `target` is an offset from the base of cache level `cache_level`.
    KernelCacheRebase {
        target: u64,
        cache_level: u8,
        auth: Option<PointerAuth>,
    },
    /// `DYLD_CHAINED_PTR_ARM64E_SEGMENTED`: an offset into a segment.
    SegmentedRebase {
        segment_index: u8,
        segment_offset: u32,
        auth: Option<PointerAuth>,
    },
    /// Format without a decoder.
    Unknown,
}

/// Decode `raw` (zero-extended for the 4-byte formats) as a fixup of
/// `format`.
pub fn decode_pointer(format: u16, raw: u64) -> ChainedPointer {
    let rebase = |target, high8: u64, vm_offset| ChainedPointer::Rebase {
        target,
        high8: high8 as u8,
        vm_offset,
        auth: None,
    };
    match format {
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
            if bits(raw, 63, 1) != 0 {
                ChainedPointer::Bind {
                    ordinal: bits(raw, 0, 24) as u32,
                    addend: bits(raw, 24, 8) as i64,
                    auth: None,
                }
            } else {
                rebase(
                    bits(raw, 0, 36),
                    bits(raw, 36, 8),
                    format == DYLD_CHAINED_PTR_64_OFFSET,
                )
            }
        }
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
            let is_auth = bits(raw, 63, 1) != 0;
            let is_bind = bits(raw, 62, 1) != 0;
            let auth = is_auth.then(|| PointerAuth::at_bit_32(raw));
            if is_bind {
                let ordinal_bits = if format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
                    24
                } else {
                    16
                };
                // The 19-bit addend is signed; authenticated binds have none.
                let addend = if is_auth {
                    0
                } else {
                    ((bits(raw, 32, 19) << 45) as i64) >> 45
                };
                ChainedPointer::Bind {
                    ordinal: bits(raw, 0, ordinal_bits) as u32,
                    addend,
                    auth,
                }
            } else if is_auth {
                // An authenticated target is always an offset from the base.
                ChainedPointer::Rebase {
                    target: bits(raw, 0, 32),
                    high8: 0,
                    vm_offset: true,
                    auth,
                }
            } else {
                let vm_offset = !matches!(
                    format,
                    DYLD_CHAINED_PTR_ARM64E | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
                );
                rebase(bits(raw, 0, 43), bits(raw, 43, 8), vm_offset)
            }
        }
        DYLD_CHAINED_PTR_64_KERNEL_CACHE | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => {
            ChainedPointer::KernelCacheRebase {
                target: bits(raw, 0, 30),
                cache_level: bits(raw, 30, 2) as u8,
                auth: (bits(raw, 63, 1) != 0).then(|| PointerAuth::at_bit_32(raw)),
            }
        }
        DYLD_CHAINED_PTR_32 => {
            if bits(raw, 31, 1) != 0 {
                ChainedPointer::Bind {
                    ordinal: bits(raw, 0, 20) as u32,
                    addend: bits(raw, 20, 6) as i64,
                    auth: None,
                }
            } else {
                rebase(bits(raw, 0, 26), 0, false)
            }
        }
        DYLD_CHAINED_PTR_32_CACHE => rebase(bits(raw, 0, 30), 0, false),
        DYLD_CHAINED_PTR_32_FIRMWARE => rebase(bits(raw, 0, 26), 0, false),
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => {
            if bits(raw, 63, 1) != 0 {
                ChainedPointer::Rebase {
                    target: bits(raw, 0, 34),
                    high8: 0,
                    vm_offset: true,
                    // Only the A keys exist: `keyIsData` picks DA over IA.
                    auth: Some(PointerAuth {
                        key: (bits(raw, 51, 1) as u8) << 1,
                        addr_div: bits(raw, 50, 1) != 0,
                        diversity: bits(raw, 34, 16) as u16,
                    }),
                }
            } else {
                rebase(bits(raw, 0, 34), bits(raw, 34, 8), true)
            }
        }
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3 => {
            if bits(raw, 63, 1) != 0 {
                ChainedPointer::Rebase {
                    target: bits(raw, 0, 32),
                    high8: 0,
                    vm_offset: true,
                    auth: Some(PointerAuth::at_bit_32(raw)),
                }
            } else {
                rebase(bits(raw, 0, 51), 0, false)
            }
        }
        DYLD_CHAINED_PTR_SHARED_CACHE_V2 => rebase(bits(raw, 0, 40), bits(raw, 56, 8), true),
        DYLD_CHAINED_PTR_ARM64E_SEGMENTED => ChainedPointer::SegmentedRebase {
            segment_index: bits(raw, 28, 4) as u8,
            segment_offset: bits(raw, 0, 28) as u32,
            auth: (bits(raw, 63, 1) != 0).then(|| PointerAuth::at_bit_32(raw)),
        },
        _ => ChainedPointer::Unknown,
    }
}

impl ChainedPointer {
    /// Text for the fixup table. `base` is the image's preferred load
    /// address (added to offset targets); `symbol` the name of the bound
    /// import, when it could be resolved.
    pub fn describe(&self, base: u64, symbol: Option<&str>) -> String {
        let auth_text = |auth: &Option<PointerAuth>| match auth {
            Some(a) => format!(
                " key={} addrDiv={} diversity=0x{:04X}",
                a.key_name(),
                a.addr_div as u8,
                a.diversity
            ),
            None => String::new(),
        };
        let prefix = |auth: &Option<PointerAuth>| if auth.is_some() { "auth-" } else { "" };
        match self {
            ChainedPointer::Rebase {
                target,
                high8,
                vm_offset,
                auth,
            } => {
                let address = if *vm_offset {
                    base.wrapping_add(*target)
                } else {
                    *target
                };
                let mut s = format!("{}rebase target=0x{:X}", prefix(auth), address);
                if *high8 != 0 {
                    s.push_str(&format!(" high8=0x{high8:02X}"));
                }
                s + &auth_text(auth)
            }
            ChainedPointer::Bind {
                ordinal,
                addend,
                auth,
            } => {
                let mut s = format!("{}bind ordinal={}", prefix(auth), ordinal);
                if let Some(symbol) = symbol {
                    s.push_str(&format!(" symbol={symbol}"));
                }
                if *addend != 0 {
                    s.push_str(&format!(" addend={addend}"));
                }
                s + &auth_text(auth)
            }
            ChainedPointer::KernelCacheRebase {
                target,
                cache_level,
                auth,
            } => format!(
                "{}rebase target=0x{:X} cacheLevel={}{}",
                prefix(auth),
                target,
                cache_level,
                auth_text(auth)
            ),
            ChainedPointer::SegmentedRebase {
                segment_index,
                segment_offset,
                auth,
            } => format!(
                "{}rebase segment={} offset=0x{:X}{}",
                prefix(auth),
                segment_index,
                segment_offset,
                auth_text(auth)
            ),
            ChainedPointer::Unknown => "(unknown pointer format)".to_string(),
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

/// The fixed part of `dyld_chained_starts_in_segment`; `page_start[]`
/// follows at [`CHAINED_STARTS_PAGE_START_OFFSET`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedStartsInSegment {
    pub size: u32,
    pub page_size: u16,
    pub pointer_format: u16,
    /// Offset of the segment from the image's load address.
    pub segment_offset: u64,
    pub max_valid_pointer: u32,
    pub page_count: u16,
}

impl ChainedStartsInSegment {
    /// Read the struct at file offset `at`; `None` unless its 22 bytes of
    /// fixed fields are in the file.
    pub fn read(image: &Image, at: u64) -> Option<Self> {
        if !image.in_file(at, CHAINED_STARTS_PAGE_START_OFFSET) {
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
    /// Ordinal of the dylib the symbol comes from. The top 15 values of the
    /// field are the special ordinals -15..-1 (`BIND_SPECIAL_DYLIB_*`).
    pub lib_ordinal: i32,
    pub weak_import: bool,
    /// Offset of the name in the symbols pool.
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
                let ordinal = bits(v, 0, 8);
                Some(ChainedImport {
                    lib_ordinal: if ordinal > 0xF0 {
                        ordinal as u8 as i8 as i32
                    } else {
                        ordinal as i32
                    },
                    weak_import: bits(v, 8, 1) != 0,
                    name_offset: v >> 9,
                    addend,
                })
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let v = image.u64(at)?;
                let ordinal = bits(v, 0, 16);
                Some(ChainedImport {
                    lib_ordinal: if ordinal > 0xFFF0 {
                        ordinal as u16 as i16 as i32
                    } else {
                        ordinal as i32
                    },
                    weak_import: bits(v, 16, 1) != 0,
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
    fn names_and_layouts() {
        assert_eq!(pointer_format_name(12), "ARM64E_USERLAND24");
        assert_eq!(pointer_format_name(16), "SHARED_CACHE_V2");
        assert_eq!(pointer_format_name(0), "UNKNOWN");
        assert_eq!(import_format_name(3), "DYLD_CHAINED_IMPORT_ADDEND64");
        assert_eq!(import_format_name(9), "UNKNOWN");
        let layout = |f| pointer_layout(f).map(|l| (l.width, l.stride));
        // Strides from the comments in <mach-o/fixup-chains.h>.
        assert_eq!(layout(DYLD_CHAINED_PTR_ARM64E), Some((8, 8)));
        assert_eq!(layout(DYLD_CHAINED_PTR_64), Some((8, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_64_OFFSET), Some((8, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_32), Some((4, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_32_CACHE), Some((4, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_32_FIRMWARE), Some((4, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_ARM64E_KERNEL), Some((8, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_ARM64E_USERLAND), Some((8, 8)));
        assert_eq!(layout(DYLD_CHAINED_PTR_ARM64E_FIRMWARE), Some((8, 4)));
        assert_eq!(layout(DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE), Some((8, 1)));
        assert_eq!(layout(DYLD_CHAINED_PTR_ARM64E_USERLAND24), Some((8, 8)));
        assert_eq!(layout(DYLD_CHAINED_PTR_ARM64E_SEGMENTED), Some((8, 4)));
        assert_eq!(layout(0), None);
        assert_eq!(layout(17), None);
    }

    #[test]
    fn next_field() {
        // 64-bit generic: 12 bits at 51.
        assert_eq!(decode_next(DYLD_CHAINED_PTR_64, 0xFFFu64 << 51), 0xFFF);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_64_OFFSET, 1u64 << 63), 0);
        // arm64e: 11 bits at 51; bit 62 is `bind`.
        assert_eq!(decode_next(DYLD_CHAINED_PTR_ARM64E, 0xFFFu64 << 51), 0x7FF);
        assert_eq!(
            decode_next(DYLD_CHAINED_PTR_ARM64E_USERLAND24, 0xC009_0000_0000_0000),
            1
        );
        // 32-bit formats.
        assert_eq!(decode_next(DYLD_CHAINED_PTR_32, 0x7C00_0000), 0x1F);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_32, 0x8000_0000), 0);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_32_CACHE, 0xC000_0000), 3);
        assert_eq!(decode_next(DYLD_CHAINED_PTR_32_FIRMWARE, 0xFC00_0000), 0x3F);
        assert_eq!(
            decode_next(DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE, 0x7FFu64 << 52),
            0x7FF
        );
        assert_eq!(
            decode_next(DYLD_CHAINED_PTR_SHARED_CACHE_V2, 0xFFFFu64 << 40),
            0xFFFF
        );
        assert_eq!(decode_next(99, u64::MAX), 0);
    }

    #[test]
    fn pointers_64() {
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_64, 0x8000_0000_0500_0003),
            ChainedPointer::Bind {
                ordinal: 3,
                addend: 5,
                auth: None
            }
        );
        // target 0x2_0000_4000, high8 1, next 2.
        let p = decode_pointer(DYLD_CHAINED_PTR_64, 0x0010_0012_0000_4000);
        assert_eq!(
            p,
            ChainedPointer::Rebase {
                target: 0x2_0000_4000,
                high8: 0x01,
                vm_offset: false,
                auth: None
            }
        );
        assert_eq!(
            p.describe(0x1_0000_0000, None),
            "rebase target=0x200004000 high8=0x01"
        );
        let p = decode_pointer(DYLD_CHAINED_PTR_64_OFFSET, 0x4000);
        assert_eq!(p.describe(0x1_0000_0000, None), "rebase target=0x100004000");
        let p = decode_pointer(DYLD_CHAINED_PTR_64, 0x8000_0000_0000_0002);
        assert_eq!(p.describe(0, Some("_puts")), "bind ordinal=2 symbol=_puts");
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_64, 0x8000_0000_0500_0003).describe(0, None),
            "bind ordinal=3 addend=5"
        );
    }

    #[test]
    fn pointers_arm64e() {
        // Values from `dyld_info -fixup_chain_details` of an arm64e binary
        // (DYLD_CHAINED_PTR_ARM64E_USERLAND24).
        let f = DYLD_CHAINED_PTR_ARM64E_USERLAND24;
        assert_eq!(
            decode_pointer(f, 0x0008_0000_0000_067B).describe(0x1_0000_0000, None),
            "rebase target=0x10000067B"
        );
        assert_eq!(
            decode_pointer(f, 0xC009_0000_0000_0000).describe(0, Some("_printf")),
            "auth-bind ordinal=0 symbol=_printf key=IA addrDiv=1 diversity=0x0000"
        );
        assert_eq!(
            decode_pointer(f, 0xC000_0000_0000_0002),
            ChainedPointer::Bind {
                ordinal: 2,
                addend: 0,
                auth: Some(PointerAuth {
                    key: 0,
                    addr_div: false,
                    diversity: 0
                })
            }
        );
        // 24-bit ordinals only in USERLAND24.
        let raw = 0x4000_0000_00AB_CDEF;
        assert!(matches!(
            decode_pointer(f, raw),
            ChainedPointer::Bind {
                ordinal: 0xAB_CDEF,
                ..
            }
        ));
        assert!(matches!(
            decode_pointer(DYLD_CHAINED_PTR_ARM64E, raw),
            ChainedPointer::Bind {
                ordinal: 0xCDEF,
                ..
            }
        ));
        // Signed 19-bit addend.
        let raw = 0x4000_0000_0000_0001 | (0x7FFFFu64 << 32);
        assert!(matches!(
            decode_pointer(f, raw),
            ChainedPointer::Bind { addend: -1, .. }
        ));
        // Auth rebase: 32-bit offset target, key DB, diversity 0xBEEF.
        let raw = 0x8000_0000_0000_1234 | (0xBEEFu64 << 32) | (1u64 << 48) | (3u64 << 49);
        assert_eq!(
            decode_pointer(f, raw).describe(0x1_0000_0000, None),
            "auth-rebase target=0x100001234 key=DB addrDiv=1 diversity=0xBEEF"
        );
        // Plain ARM64E: unauthenticated targets are vm addresses, with high8.
        let raw = 0x1_0000_4000 | (0x80u64 << 43);
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_ARM64E, raw).describe(0x1_0000_0000, None),
            "rebase target=0x100004000 high8=0x80"
        );
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_ARM64E_KERNEL, 0x4000).describe(0x1000, None),
            "rebase target=0x5000"
        );
    }

    #[test]
    fn pointers_32_and_others() {
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_32, 0x8450_0007),
            ChainedPointer::Bind {
                ordinal: 0x7,
                addend: 5,
                auth: None
            }
        );
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_32, 0x0400_1000).describe(0, None),
            "rebase target=0x1000"
        );
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_32_CACHE, 0xFFFF_FFFF).describe(0, None),
            "rebase target=0x3FFFFFFF"
        );
        assert_eq!(
            decode_pointer(
                DYLD_CHAINED_PTR_64_KERNEL_CACHE,
                0x4000_1000 | (1u64 << 63) | (2u64 << 49)
            )
            .describe(0, None),
            "auth-rebase target=0x1000 cacheLevel=1 key=DA addrDiv=0 diversity=0x0000"
        );
        assert_eq!(
            decode_pointer(DYLD_CHAINED_PTR_ARM64E_SEGMENTED, 0x3000_0040).describe(0, None),
            "rebase segment=3 offset=0x40"
        );
        // Shared cache: keyIsData selects DA.
        assert_eq!(
            decode_pointer(
                DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
                0x8000_0000_0000_0010 | (1u64 << 51)
            )
            .describe(0x1_8000_0000, None),
            "auth-rebase target=0x180000010 key=DA addrDiv=0 diversity=0x0000"
        );
        assert_eq!(decode_pointer(0, 5), ChainedPointer::Unknown);
        assert_eq!(decode_pointer(99, 5), ChainedPointer::Unknown);
    }

    #[test]
    fn header_and_segment_structs() {
        let mut b = Vec::new();
        for v in [0u32, 0x20, 0x48, 0x50, 2, 1, 0] {
            b.extend(v.to_le_bytes());
        }
        let img = image(&b);
        let h = ChainedFixupsHeader::read(&img, 0).unwrap();
        assert_eq!(
            (h.starts_offset, h.imports_offset, h.symbols_offset),
            (0x20, 0x48, 0x50)
        );
        assert_eq!((h.imports_count, h.imports_format), (2, 1));
        assert!(ChainedFixupsHeader::read(&img, 1).is_none());

        let mut s = Vec::new();
        s.extend(0x18u32.to_le_bytes());
        s.extend(0x4000u16.to_le_bytes());
        s.extend(6u16.to_le_bytes());
        s.extend(0x8000u64.to_le_bytes());
        s.extend(0u32.to_le_bytes());
        s.extend(1u16.to_le_bytes());
        // Exactly the 22 fixed bytes are enough.
        let img = image(&s);
        assert_eq!(
            ChainedStartsInSegment::read(&img, 0),
            Some(ChainedStartsInSegment {
                size: 0x18,
                page_size: 0x4000,
                pointer_format: 6,
                segment_offset: 0x8000,
                max_valid_pointer: 0,
                page_count: 1,
            })
        );
        assert!(ChainedStartsInSegment::read(&img, 1).is_none());
    }

    #[test]
    fn imports() {
        // lib 2, weak, name offset 5
        let v: u32 = 2 | (1 << 8) | (5 << 9);
        let mut b = v.to_le_bytes().to_vec();
        b.extend((-3i32).to_le_bytes());
        let img = image(&b);
        assert_eq!(
            ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT),
            Some(ChainedImport {
                lib_ordinal: 2,
                weak_import: true,
                name_offset: 5,
                addend: ImportAddend::None
            })
        );
        assert_eq!(
            ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT_ADDEND)
                .unwrap()
                .addend,
            ImportAddend::Signed32(-3)
        );
        assert!(ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT_ADDEND64).is_none());
        assert!(ChainedImport::read(&img, 0, 7).is_none());
        // Special ordinals: 0xFE is BIND_SPECIAL_DYLIB_FLAT_LOOKUP (-2);
        // 0xF0 is still an ordinary ordinal.
        let img = image(&0xFEu32.to_le_bytes());
        assert_eq!(
            ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT)
                .unwrap()
                .lib_ordinal,
            -2
        );
        let img = image(&0xF0u32.to_le_bytes());
        assert_eq!(
            ChainedImport::read(&img, 0, DYLD_CHAINED_IMPORT)
                .unwrap()
                .lib_ordinal,
            240
        );

        let v: u64 = 0xFFFF | (7u64 << 32);
        let mut b = v.to_le_bytes().to_vec();
        b.extend(0x1234u64.to_le_bytes());
        assert_eq!(
            ChainedImport::read(&image(&b), 0, DYLD_CHAINED_IMPORT_ADDEND64),
            Some(ChainedImport {
                lib_ordinal: -1,
                weak_import: false,
                name_offset: 7,
                addend: ImportAddend::Unsigned64(0x1234)
            })
        );
        assert_eq!(ChainedImport::entry_size(1), Some(4));
        assert_eq!(ChainedImport::entry_size(2), Some(8));
        assert_eq!(ChainedImport::entry_size(3), Some(16));
        assert_eq!(ChainedImport::entry_size(0), None);
    }
}
