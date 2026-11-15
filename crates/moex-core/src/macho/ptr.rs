//! Reading data through virtual addresses, and decoding the pointers a
//! linker leaves in data sections.
//!
//! [`SliceReader`] translates a virtual address to a file offset relative
//! to the Mach-O header it belongs to, so it reads the right bytes inside a
//! fat file or an archive member too.
//!
//! [`PointerDecoder`] turns a stored pointer into what it will be at run
//! time. With `LC_DYLD_CHAINED_FIXUPS` a pointer slot holds a packed
//! rebase (target, plus pointer-authentication data on arm64e) or bind
//! (import ordinal) and the link to the next slot; with `LC_DYLD_INFO` the
//! bind opcodes name the symbol of a bound slot (which holds zero, or the
//! address of its stub helper when it is bound lazily).

use super::header::MachHeader;
use super::segment::Segment;
use crate::consts::{LC_DYLD_CHAINED_FIXUPS, LC_DYLD_INFO, LC_DYLD_INFO_ONLY};
use crate::image::Image;
use crate::leb::{read_sleb128, read_uleb128};
use std::sync::Arc;

/// Which segment commands a [`SliceReader`] searches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segments {
    /// Only `LC_SEGMENT` (`false`) or only `LC_SEGMENT_64` (`true`).
    Only64(bool),
    /// 64-bit segments first, then 32-bit ones.
    Any,
}

/// Where a virtual address lives in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mapped {
    offset: u64,
    /// Bytes from `offset` to the end of the segment's file contents,
    /// clipped to the end of the file.
    available: u64,
}

/// Looks `vmaddr` up in `segments`. `None`: no segment contains it.
/// `Some(None)`: the first containing segment has no file bytes there.
fn lookup<'a>(
    segments: impl Iterator<Item = &'a Segment>,
    slice_offset: u64,
    file_len: u64,
    vmaddr: u64,
) -> Option<Option<Mapped>> {
    for seg in segments {
        if vmaddr < seg.vmaddr || vmaddr - seg.vmaddr >= seg.vmsize {
            continue;
        }
        let delta = vmaddr - seg.vmaddr;
        if delta >= seg.filesize {
            return Some(None);
        }
        let offset = slice_offset
            .checked_add(seg.fileoff)
            .and_then(|o| o.checked_add(delta))
            .filter(|&o| o < file_len);
        return Some(offset.map(|offset| Mapped {
            offset,
            available: (seg.filesize - delta).min(file_len - offset),
        }));
    }
    None
}

/// Bounds-checked reads addressed by virtual address.
#[derive(Clone, Copy)]
pub struct SliceReader<'a> {
    pub mh: &'a MachHeader,
    pub segments: Segments,
}

impl<'a> SliceReader<'a> {
    pub fn new(mh: &'a MachHeader, segments: Segments) -> Self {
        SliceReader { mh, segments }
    }

    pub fn image(&self) -> &'a Image {
        &self.mh.image
    }

    fn mapped(&self, vmaddr: u64) -> Option<Mapped> {
        let (mh, len) = (self.mh, self.mh.image.len());
        let of = |is64: bool| mh.segments.iter().filter(move |s| s.is64 == is64);
        match self.segments {
            Segments::Only64(is64) => lookup(of(is64), mh.offset, len, vmaddr).flatten(),
            Segments::Any => match lookup(of(true), mh.offset, len, vmaddr) {
                Some(found) => found,
                None => lookup(of(false), mh.offset, len, vmaddr).flatten(),
            },
        }
    }

    /// File offset backing `vmaddr`: the first segment whose VM range
    /// contains the address decides. `None` when it has no file bytes there
    /// or they lie past the end of the file.
    pub fn file_offset(&self, vmaddr: u64) -> Option<u64> {
        self.mapped(vmaddr).map(|m| m.offset)
    }

    /// File offset of a `size`-byte object at `vmaddr`: `None` when the
    /// address is 0 or unmapped, or the object does not fit in the file
    /// contents of its segment.
    pub fn object_offset(&self, vmaddr: u64, size: u64) -> Option<u64> {
        if vmaddr == 0 {
            return None;
        }
        let m = self.mapped(vmaddr)?;
        (size <= m.available).then_some(m.offset)
    }

    /// Little-endian `u32` at `vmaddr`.
    pub fn u32(&self, vmaddr: u64) -> Option<u32> {
        self.mh.image.u32(self.object_offset(vmaddr, 4)?)
    }

    /// Up to `max` bytes starting at `vmaddr`, clipped to the file contents
    /// of the segment. `None` when the address is unmapped.
    pub fn bytes(&self, vmaddr: u64, max: u64) -> Option<&'a [u8]> {
        let m = self.mapped(vmaddr)?;
        let image: &'a Image = &self.mh.image;
        image.slice(m.offset, max.min(m.available))
    }
}

/// `field_vmaddr + rel` for a 32-bit relative pointer stored at
/// `field_vmaddr` (two's-complement wraparound).
pub fn relative_target(field_vmaddr: u64, rel: i32) -> u64 {
    field_vmaddr.wrapping_add(rel as i64 as u64)
}

/// What a pointer slot holds once the image is loaded at its preferred
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pointer<'a> {
    /// A plain value or the target of a rebase; 0 is null.
    Address(u64),
    /// Bound by dyld to an imported symbol (plus `addend`). The name is
    /// empty when the import table does not hold it.
    Import { name: &'a [u8], addend: i64 },
}

impl Pointer<'_> {
    /// The address, with an import counting as "not in this image" (0).
    pub fn address(&self) -> u64 {
        match self {
            Pointer::Address(a) => *a,
            Pointer::Import { .. } => 0,
        }
    }
}

// `dyld_chained_starts_in_segment.pointer_format` values.
const PTR_ARM64E: u16 = 1;
const PTR_64: u16 = 2;
const PTR_32: u16 = 3;
const PTR_32_CACHE: u16 = 4;
const PTR_32_FIRMWARE: u16 = 5;
const PTR_64_OFFSET: u16 = 6;
const PTR_ARM64E_KERNEL: u16 = 7;
const PTR_64_KERNEL_CACHE: u16 = 8;
const PTR_ARM64E_USERLAND: u16 = 9;
const PTR_ARM64E_FIRMWARE: u16 = 10;
const PTR_X86_64_KERNEL_CACHE: u16 = 11;
const PTR_ARM64E_USERLAND24: u16 = 12;

const PAGE_START_NONE: u16 = 0xFFFF;
const PAGE_START_MULTI: u16 = 0x8000;
const PAGE_START_LAST: u16 = 0x8000;

/// `(slot width, chain stride)` in bytes of a pointer format; `None` for
/// formats this decoder does not know.
fn format_layout(format: u16) -> Option<(u64, u64)> {
    Some(match format {
        PTR_ARM64E | PTR_ARM64E_USERLAND | PTR_ARM64E_USERLAND24 => (8, 8),
        PTR_ARM64E_KERNEL | PTR_ARM64E_FIRMWARE => (8, 4),
        PTR_64 | PTR_64_OFFSET | PTR_64_KERNEL_CACHE => (8, 4),
        PTR_X86_64_KERNEL_CACHE => (8, 1),
        PTR_32 | PTR_32_CACHE | PTR_32_FIRMWARE => (4, 4),
        _ => return None,
    })
}

/// The "next" field of a chained pointer, in strides; 0 ends the chain.
fn chain_next(format: u16, raw: u64) -> u64 {
    match format {
        PTR_ARM64E
        | PTR_ARM64E_KERNEL
        | PTR_ARM64E_USERLAND
        | PTR_ARM64E_FIRMWARE
        | PTR_ARM64E_USERLAND24 => (raw >> 51) & 0x7ff,
        PTR_64 | PTR_64_OFFSET | PTR_64_KERNEL_CACHE | PTR_X86_64_KERNEL_CACHE => {
            (raw >> 51) & 0xfff
        }
        PTR_32 => (raw >> 26) & 0x1f,
        PTR_32_CACHE => (raw >> 30) & 0x3,
        PTR_32_FIRMWARE => (raw >> 26) & 0x3f,
        _ => 0,
    }
}

/// A chained pointer with its packing undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chained {
    /// Absolute address (`base` already added for offset formats).
    Rebase(u64),
    Bind {
        ordinal: u32,
        addend: i64,
    },
}

fn decode_chained(format: u16, raw: u64, base: u64) -> Chained {
    let bits = |shift: u32, count: u32| (raw >> shift) & ((1u64 << count) - 1);
    match format {
        PTR_ARM64E
        | PTR_ARM64E_KERNEL
        | PTR_ARM64E_USERLAND
        | PTR_ARM64E_FIRMWARE
        | PTR_ARM64E_USERLAND24 => {
            let (auth, bind) = (bits(63, 1) != 0, bits(62, 1) != 0);
            if bind {
                let ordinal_bits = if format == PTR_ARM64E_USERLAND24 {
                    24
                } else {
                    16
                };
                // An authenticated bind has no addend; a plain one has a
                // signed 19-bit addend.
                let addend = if auth {
                    0
                } else {
                    ((bits(32, 19) << 45) as i64) >> 45
                };
                Chained::Bind {
                    ordinal: bits(0, ordinal_bits) as u32,
                    addend,
                }
            } else if auth {
                // Always an offset from the image base.
                Chained::Rebase(base.wrapping_add(bits(0, 32)))
            } else {
                let target = bits(0, 43) | (bits(43, 8) << 56);
                let is_offset = matches!(
                    format,
                    PTR_ARM64E_KERNEL | PTR_ARM64E_USERLAND | PTR_ARM64E_USERLAND24
                );
                Chained::Rebase(if is_offset {
                    base.wrapping_add(target)
                } else {
                    target
                })
            }
        }
        PTR_64 | PTR_64_OFFSET => {
            if bits(63, 1) != 0 {
                Chained::Bind {
                    ordinal: bits(0, 24) as u32,
                    addend: bits(24, 8) as i64,
                }
            } else {
                let target = bits(0, 36) | (bits(36, 8) << 56);
                Chained::Rebase(if format == PTR_64_OFFSET {
                    base.wrapping_add(target)
                } else {
                    target
                })
            }
        }
        PTR_64_KERNEL_CACHE | PTR_X86_64_KERNEL_CACHE | PTR_32_CACHE => {
            Chained::Rebase(base.wrapping_add(bits(0, 30)))
        }
        PTR_32 => {
            if bits(31, 1) != 0 {
                Chained::Bind {
                    ordinal: bits(0, 20) as u32,
                    addend: bits(20, 6) as i64,
                }
            } else {
                Chained::Rebase(bits(0, 26))
            }
        }
        PTR_32_FIRMWARE => Chained::Rebase(bits(0, 26)),
        _ => Chained::Rebase(raw),
    }
}

/// The import table of `LC_DYLD_CHAINED_FIXUPS`.
#[derive(Debug, Clone, Copy, Default)]
struct Imports {
    /// File offset of the first entry.
    table: u64,
    count: u32,
    /// `DYLD_CHAINED_IMPORT` (1), `_ADDEND` (2) or `_ADDEND64` (3).
    format: u32,
    /// File offset of the symbol strings; `None` when they are compressed.
    symbols: Option<u64>,
}

impl Imports {
    /// `(name, addend)` of import `ordinal`.
    fn get<'a>(&self, image: &'a Image, ordinal: u32) -> Option<(&'a [u8], i64)> {
        if ordinal >= self.count {
            return None;
        }
        let entry_size = match self.format {
            1 => 4,
            2 => 8,
            3 => 16,
            _ => return None,
        };
        let at = self.table.checked_add(u64::from(ordinal) * entry_size)?;
        let (name_offset, addend) = match self.format {
            1 => (u64::from(image.u32(at)? >> 9), 0),
            2 => (
                u64::from(image.u32(at)? >> 9),
                i64::from(image.u32(at + 4)? as i32),
            ),
            _ => (image.u64(at)? >> 32, image.u64(at + 8)? as i64),
        };
        let name_at = self.symbols?.checked_add(name_offset)?;
        let name = image
            .cstr(name_at, MAX_NAME)
            .filter(|_| name_at < image.len())?;
        Some((name, addend))
    }
}

/// Longest symbol name read from an import or bind table.
const MAX_NAME: u64 = 4096;

/// One slot bound by the `LC_DYLD_INFO` bind opcodes.
#[derive(Debug, Clone, Copy)]
struct ClassicBind {
    /// File offset of the slot.
    slot: u64,
    /// File offset of the symbol name.
    name: u64,
    addend: i64,
}

/// Which pointer slots of one Mach-O image dyld fixes up, and how: read
/// once from `LC_DYLD_CHAINED_FIXUPS` and `LC_DYLD_INFO`. Building it walks
/// every fixup chain, so share one per image (see
/// [`PointerDecoder::with_fixups`]) rather than reading it per use.
pub struct Fixups {
    /// Preferred load address: what offset-based formats are relative to.
    base: u64,
    /// `(file offset, pointer format)` of every slot on a fixup chain,
    /// sorted by offset.
    chained: Vec<(u64, u16)>,
    imports: Imports,
    /// Sorted by slot.
    classic: Vec<ClassicBind>,
}

impl Fixups {
    pub fn read(mh: &MachHeader) -> Self {
        let mut d = Fixups {
            base: mh.base_address(),
            chained: Vec::new(),
            imports: Imports::default(),
            classic: Vec::new(),
        };
        // The work is bounded by the file size: a crafted file can make
        // chains, page tables or bind runs revisit the same slots, and no
        // real image has more slots than this.
        let mut budget = mh.image.len() / 4 + 1024;
        d.read_chained_fixups(mh, &mut budget);
        d.read_classic_binds(mh, &mut budget);
        d.chained.sort_unstable();
        d.chained.dedup_by_key(|e| e.0);
        // A stable sort: of several binds of one slot the first stays.
        d.classic.sort_by_key(|b| b.slot);
        d.classic.dedup_by_key(|b| b.slot);
        d
    }

    fn read_chained_fixups(&mut self, mh: &MachHeader, budget: &mut u64) {
        let image: &Image = &mh.image;
        let Some(lc) = mh.find_load_command(&[LC_DYLD_CHAINED_FIXUPS]) else {
            return;
        };
        let (dataoff, datasize) = (mh.lc_u32(lc, 8), mh.lc_u32(lc, 12));
        let blob = mh.offset.saturating_add(u64::from(dataoff));
        if datasize < 28 || !image.in_file(blob, 28) {
            return;
        }
        let field = |i: u64| image.u32(blob + 4 * i).unwrap_or(0);
        let (starts_offset, imports_offset, symbols_offset) = (field(1), field(2), field(3));
        self.imports = Imports {
            table: blob + u64::from(imports_offset),
            count: field(4),
            format: field(5),
            symbols: (field(6) == 0).then_some(blob + u64::from(symbols_offset)),
        };

        // dyld_chained_starts_in_image: seg_count, seg_info_offset[].
        let starts = blob + u64::from(starts_offset);
        let seg_count = image.u32(starts).unwrap_or(0);
        // Entry `i` describes the `i`-th segment load command.
        for (seg, segment) in (0..u64::from(seg_count)).zip(&mh.segments) {
            let Some(info_offset) = image.u32(starts + 4 + 4 * seg) else {
                break;
            };
            if info_offset == 0 {
                continue;
            }
            // File offset of an address inside this segment's contents.
            let file_offset = |vmaddr: u64| {
                let delta = vmaddr.checked_sub(segment.vmaddr)?;
                (delta < segment.filesize)
                    .then(|| mh.offset.checked_add(segment.fileoff)?.checked_add(delta))
                    .flatten()
            };
            // dyld_chained_starts_in_segment.
            let info = starts + u64::from(info_offset);
            let (Some(page_size), Some(format), Some(segment_offset), Some(page_count)) = (
                image.u16(info + 4),
                image.u16(info + 6),
                image.u64(info + 8),
                image.u16(info + 20),
            ) else {
                continue;
            };
            let Some((width, stride)) = format_layout(format) else {
                continue;
            };
            let page_start = |index: u64| image.u16(info + 22 + 2 * index);
            let segment_vmaddr = self.base.wrapping_add(segment_offset);
            for page in 0..u64::from(page_count) {
                if *budget == 0 {
                    return;
                }
                *budget -= 1;
                let Some(start) = page_start(page) else { break };
                if start == PAGE_START_NONE {
                    continue;
                }
                let page_vmaddr = segment_vmaddr.wrapping_add(page * u64::from(page_size));
                let walk = |start: u16, d: &mut Self, budget: &mut u64| {
                    let first = page_vmaddr.wrapping_add(u64::from(start));
                    if let Some(offset) = file_offset(first) {
                        d.walk_chain(image, offset, format, width, stride, budget);
                    }
                };
                if start & PAGE_START_MULTI == 0 {
                    walk(start, self, budget);
                    continue;
                }
                // Several chains in one page (32-bit formats): the entry
                // indexes a run of starts that ends at the one flagged
                // "last".
                let mut index = u64::from(start & !PAGE_START_MULTI);
                while let Some(entry) = page_start(index) {
                    if *budget == 0 {
                        break;
                    }
                    *budget -= 1;
                    walk(entry & !PAGE_START_LAST, self, budget);
                    if entry & PAGE_START_LAST != 0 {
                        break;
                    }
                    index += 1;
                }
            }
        }
    }

    fn walk_chain(
        &mut self,
        image: &Image,
        start: u64,
        format: u16,
        width: u64,
        stride: u64,
        budget: &mut u64,
    ) {
        let mut at = start;
        while *budget > 0 {
            *budget -= 1;
            let raw = if width == 8 {
                image.u64(at)
            } else {
                image.u32(at).map(u64::from)
            };
            let Some(raw) = raw else { break };
            self.chained.push((at, format));
            let next = chain_next(format, raw);
            if next == 0 {
                break;
            }
            at += next * stride;
        }
    }

    fn read_classic_binds(&mut self, mh: &MachHeader, budget: &mut u64) {
        let Some(lc) = mh.find_load_command(&[LC_DYLD_INFO, LC_DYLD_INFO_ONLY]) else {
            return;
        };
        // `bind_off` / `bind_size`, then `lazy_bind_off` / `lazy_bind_size`.
        // (Weak binds only say which definitions may be coalesced.)
        for field in [16, 32] {
            let (off, size) = (mh.lc_u32(lc, field), mh.lc_u32(lc, field + 4));
            self.read_bind_opcodes(mh, off, size, budget);
        }
    }

    /// Runs one bind opcode stream, recording the slots it binds. A lazy
    /// stream is a series of single binds, each ended by `DONE`.
    fn read_bind_opcodes(&mut self, mh: &MachHeader, off: u32, size: u32, budget: &mut u64) {
        let start = mh.offset.saturating_add(u64::from(off));
        let image: &Image = &mh.image;
        let Some(ops) = image.slice(start, u64::from(size)) else {
            return;
        };
        let word: u64 = if mh.is64 { 8 } else { 4 };
        let (mut segment, mut offset) = (0usize, 0u64);
        let (mut name, mut addend) = (None::<u64>, 0i64);
        let mut pos = 0usize;
        let uleb = |pos: &mut usize| {
            let (value, len) = read_uleb128(ops.get(*pos..)?)?;
            *pos += len as usize;
            Some(value)
        };
        let mut bind = |segment: usize, offset: u64, name: Option<u64>, addend: i64| {
            let slot = mh.segments.get(segment).and_then(|seg| {
                (offset < seg.filesize)
                    .then(|| mh.offset.checked_add(seg.fileoff)?.checked_add(offset))
                    .flatten()
            });
            if let (Some(slot), Some(name)) = (slot, name) {
                self.classic.push(ClassicBind { slot, name, addend });
            }
        };
        while let Some(&byte) = ops.get(pos) {
            pos += 1;
            let imm = u64::from(byte & 0x0f);
            if *budget == 0 {
                break;
            }
            *budget -= 1;
            match byte & 0xf0 {
                // DONE, SET_DYLIB_ORDINAL_IMM, SET_DYLIB_SPECIAL_IMM,
                // SET_TYPE_IMM: nothing to track.
                0x00 | 0x10 | 0x30 | 0x50 => {}
                // SET_DYLIB_ORDINAL_ULEB
                0x20 => {
                    if uleb(&mut pos).is_none() {
                        break;
                    }
                }
                // SET_SYMBOL_TRAILING_FLAGS_IMM: a C string follows.
                0x40 => {
                    let rest = ops.get(pos..).unwrap_or(&[]);
                    let Some(len) = rest.iter().position(|&c| c == 0) else {
                        break;
                    };
                    name = Some(start + pos as u64);
                    pos += len + 1;
                }
                // SET_ADDEND_SLEB
                0x60 => {
                    let Some((value, len)) = ops.get(pos..).and_then(read_sleb128) else {
                        break;
                    };
                    addend = value;
                    pos += len as usize;
                }
                // SET_SEGMENT_AND_OFFSET_ULEB
                0x70 => {
                    let Some(value) = uleb(&mut pos) else { break };
                    (segment, offset) = (imm as usize, value);
                }
                // ADD_ADDR_ULEB
                0x80 => {
                    let Some(value) = uleb(&mut pos) else { break };
                    offset = offset.wrapping_add(value);
                }
                // DO_BIND
                0x90 => {
                    bind(segment, offset, name, addend);
                    offset = offset.wrapping_add(word);
                }
                // DO_BIND_ADD_ADDR_ULEB
                0xa0 => {
                    bind(segment, offset, name, addend);
                    let Some(value) = uleb(&mut pos) else { break };
                    offset = offset.wrapping_add(value).wrapping_add(word);
                }
                // DO_BIND_ADD_ADDR_IMM_SCALED
                0xb0 => {
                    bind(segment, offset, name, addend);
                    offset = offset.wrapping_add((imm + 1) * word);
                }
                // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                0xc0 => {
                    let (Some(count), Some(skip)) = (uleb(&mut pos), uleb(&mut pos)) else {
                        break;
                    };
                    for _ in 0..count {
                        if *budget == 0 {
                            break;
                        }
                        *budget -= 1;
                        bind(segment, offset, name, addend);
                        offset = offset.wrapping_add(skip).wrapping_add(word);
                    }
                }
                // Threaded binds (old arm64e) and anything unknown.
                _ => break,
            }
        }
    }
}

/// Decodes the pointers stored in the data of one Mach-O image.
pub struct PointerDecoder<'a> {
    image: &'a Image,
    fixups: Arc<Fixups>,
}

impl<'a> PointerDecoder<'a> {
    /// A decoder with fixup tables of its own, read now.
    pub fn new(mh: &'a MachHeader) -> Self {
        Self::with_fixups(mh, Arc::new(Fixups::read(mh)))
    }

    /// A decoder using the already read `fixups` of `mh`.
    pub fn with_fixups(mh: &'a MachHeader, fixups: Arc<Fixups>) -> Self {
        PointerDecoder {
            image: &mh.image,
            fixups,
        }
    }

    /// The pointer whose stored value `raw` was read at file offset `at`.
    pub fn decode(&self, at: u64, raw: u64) -> Pointer<'a> {
        let fixups = &self.fixups;
        if let Ok(i) = fixups.chained.binary_search_by_key(&at, |e| e.0) {
            let format = fixups.chained.get(i).map_or(0, |e| e.1);
            return match decode_chained(format, raw, fixups.base) {
                Chained::Rebase(address) => Pointer::Address(address),
                Chained::Bind { ordinal, addend } => {
                    let (name, import_addend) =
                        fixups.imports.get(self.image, ordinal).unwrap_or((&[], 0));
                    Pointer::Import {
                        name,
                        addend: addend.wrapping_add(import_addend),
                    }
                }
            };
        }
        if let Ok(i) = fixups.classic.binary_search_by_key(&at, |b| b.slot) {
            if let Some(b) = fixups.classic.get(i) {
                return Pointer::Import {
                    name: self.image.cstr(b.name, MAX_NAME).unwrap_or(&[]),
                    addend: b.addend,
                };
            }
        }
        Pointer::Address(raw)
    }

    /// The pointer stored at file offset `at` (8 bytes when `is64`, else 4).
    pub fn read(&self, at: u64, is64: bool) -> Option<Pointer<'a>> {
        let raw = if is64 {
            self.image.u64(at)?
        } else {
            u64::from(self.image.u32(at)?)
        };
        Some(self.decode(at, raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn put32(f: &mut Vec<u8>, v: u32) {
        f.extend_from_slice(&v.to_le_bytes());
    }

    fn put64(f: &mut Vec<u8>, v: u64) {
        f.extend_from_slice(&v.to_le_bytes());
    }

    fn name16(f: &mut Vec<u8>, name: &str) {
        let mut b = name.as_bytes().to_vec();
        b.resize(16, 0);
        f.extend_from_slice(&b);
    }

    /// 64-bit Mach-O of 0x400 bytes placed `slice` bytes into the file:
    /// `__TEXT` (vm 0x1000, file 0..0x200) and `__DATA` (vm 0x2000, file
    /// 0x200..0x300, VM size 0x1000), followed by `extra` load commands.
    fn macho(slice: usize, extra: &[u8], ncmds_extra: u32) -> Vec<u8> {
        let mut f = Vec::new();
        let sizeofcmds = 2 * 72 + extra.len() as u32;
        for v in [
            0xfeedfacfu32,
            0x0100_000c,
            0,
            2,
            2 + ncmds_extra,
            sizeofcmds,
            0,
            0,
        ] {
            put32(&mut f, v);
        }
        for (name, vmaddr, vmsize, fileoff, filesize) in [
            ("__TEXT", 0x1000u64, 0x1000u64, 0u64, 0x200u64),
            ("__DATA", 0x2000, 0x1000, 0x200, 0x100),
        ] {
            put32(&mut f, 0x19);
            put32(&mut f, 72);
            name16(&mut f, name);
            for v in [vmaddr, vmsize, fileoff, filesize] {
                put64(&mut f, v);
            }
            for v in [7u32, 3, 0, 0] {
                put32(&mut f, v);
            }
        }
        f.extend_from_slice(extra);
        f.resize(0x400, 0);
        let mut file = vec![0xEE; slice];
        file.extend(f);
        file
    }

    fn parse(file: Vec<u8>, slice: usize) -> MachHeader {
        let image = Arc::new(Image::from_vec(file).unwrap());
        MachHeader::parse(&image, slice as u64).unwrap()
    }

    #[test]
    fn addresses_are_relative_to_the_slice() {
        for slice in [0usize, 0x1000] {
            let mh = parse(macho(slice, &[], 0), slice);
            let r = SliceReader::new(&mh, Segments::Only64(true));
            let s = slice as u64;
            assert_eq!(r.file_offset(0x1008), Some(s + 8));
            assert_eq!(r.file_offset(0x2010), Some(s + 0x210));
            // Inside the VM range but past the file contents.
            assert_eq!(r.file_offset(0x2100), None);
            assert_eq!(r.file_offset(0x3000), None);
            assert_eq!(r.file_offset(0xfff), None);
            assert_eq!(r.object_offset(0, 4), None);
            assert_eq!(r.object_offset(0x20f8, 8), Some(s + 0x2f8));
            // Does not fit in the segment's file contents.
            assert_eq!(r.object_offset(0x20f8, 9), None);
            assert_eq!(r.bytes(0x20fe, 100).map(<[u8]>::len), Some(2));
            assert_eq!(r.bytes(0x5000, 4), None);
            assert_eq!(r.u32(0x1000), Some(0xfeedfacf));
            let none = SliceReader::new(&mh, Segments::Only64(false));
            assert_eq!(none.file_offset(0x1008), None);
            let any = SliceReader::new(&mh, Segments::Any);
            assert_eq!(any.file_offset(0x1008), Some(s + 8));
        }
    }

    #[test]
    fn relative_targets_wrap() {
        assert_eq!(relative_target(0x1000, -16), 0xff0);
        assert_eq!(relative_target(0x1000, 0x20), 0x1020);
        assert_eq!(relative_target(4, -8), u64::MAX - 3);
        assert_eq!(relative_target(u64::MAX, 2), 1);
    }

    #[test]
    fn chained_pointer_formats() {
        let base = 0x1_0000_0000;
        // DYLD_CHAINED_PTR_64_OFFSET rebase: target 0x4010, high8 0x80.
        let raw = 0x4010 | (0x80u64 << 36) | (3u64 << 51);
        assert_eq!(
            decode_chained(PTR_64_OFFSET, raw, base),
            Chained::Rebase(0x8000_0001_0000_4010)
        );
        assert_eq!(
            decode_chained(PTR_64, raw, base),
            Chained::Rebase(0x8000_0000_0000_4010)
        );
        assert_eq!(chain_next(PTR_64, raw), 3);
        // Bind: ordinal 5, addend 7.
        let raw = (1u64 << 63) | 5 | (7 << 24);
        assert_eq!(
            decode_chained(PTR_64, raw, base),
            Chained::Bind {
                ordinal: 5,
                addend: 7
            }
        );
        // arm64e authenticated rebase: 32-bit offset from the base.
        let raw = (1u64 << 63) | 0x8370 | (0xabcd << 32) | (1 << 48) | (2 << 51);
        assert_eq!(
            decode_chained(PTR_ARM64E_USERLAND24, raw, base),
            Chained::Rebase(base + 0x8370)
        );
        assert_eq!(chain_next(PTR_ARM64E_USERLAND24, raw), 2);
        // arm64e plain rebase: offset for userland, address for format 1.
        let raw = 0x4000 | (0x12u64 << 43);
        assert_eq!(
            decode_chained(PTR_ARM64E_USERLAND, raw, base),
            Chained::Rebase(0x1200_0001_0000_4000)
        );
        assert_eq!(
            decode_chained(PTR_ARM64E, raw, base),
            Chained::Rebase(0x1200_0000_0000_4000)
        );
        // arm64e bind: 24-bit ordinal only for USERLAND24; signed addend.
        let raw = (1u64 << 62) | 0x12_3456 | (0x7ffffu64 << 32);
        assert_eq!(
            decode_chained(PTR_ARM64E_USERLAND24, raw, base),
            Chained::Bind {
                ordinal: 0x12_3456,
                addend: -1
            }
        );
        assert_eq!(
            decode_chained(PTR_ARM64E_USERLAND, raw, base),
            Chained::Bind {
                ordinal: 0x3456,
                addend: -1
            }
        );
        // Authenticated bind: no addend.
        assert_eq!(
            decode_chained(PTR_ARM64E, raw | (1 << 63), base),
            Chained::Bind {
                ordinal: 0x3456,
                addend: 0
            }
        );
        // 32-bit.
        assert_eq!(
            decode_chained(PTR_32, 0x8000_0003 | (2 << 20), 0),
            Chained::Bind {
                ordinal: 3,
                addend: 2
            }
        );
        assert_eq!(
            decode_chained(PTR_32, 0x1234 | (1 << 26), 0),
            Chained::Rebase(0x1234)
        );
        assert_eq!(chain_next(PTR_32, 0x1234 | (1 << 26)), 1);
        assert_eq!(format_layout(PTR_ARM64E), Some((8, 8)));
        assert_eq!(format_layout(PTR_64_OFFSET), Some((8, 4)));
        assert_eq!(format_layout(99), None);
    }

    /// `LC_DYLD_CHAINED_FIXUPS` blob at slice offset 0x300 describing one
    /// chain in `__DATA` (segment 1) that starts at page offset 0x10.
    fn chained_file(slice: usize) -> Vec<u8> {
        let mut lc = Vec::new();
        for v in [0x8000_0034u32, 16, 0x300, 0x80] {
            put32(&mut lc, v);
        }
        let mut file = macho(slice, &lc, 1);
        let mut blob = Vec::new();
        // Header: version, starts, imports, symbols, count, format, zlib.
        for v in [0u32, 0x20, 0x50, 0x58, 2, 1, 0] {
            put32(&mut blob, v);
        }
        blob.resize(0x20, 0);
        // starts_in_image: 2 segments, only the second has fixups.
        for v in [2u32, 0, 0x10] {
            put32(&mut blob, v);
        }
        blob.resize(0x30, 0);
        // starts_in_segment: size, page_size, format, segment_offset,
        // max_valid_pointer, page_count, page_start[0].
        put32(&mut blob, 24);
        blob.extend_from_slice(&0x1000u16.to_le_bytes());
        blob.extend_from_slice(&PTR_64_OFFSET.to_le_bytes());
        put64(&mut blob, 0x1000);
        put32(&mut blob, 0);
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.extend_from_slice(&0x10u16.to_le_bytes());
        blob.resize(0x50, 0);
        // Imports: name offsets 1 and 6.
        put32(&mut blob, 1 << 9);
        put32(&mut blob, 6 << 9);
        blob.extend_from_slice(b"\0_one\0_two\0");
        let at = slice + 0x300;
        file[at..at + blob.len()].copy_from_slice(&blob);
        // The chain: rebase to base+0x40 at 0x210, bind #1 at 0x218, and
        // a plain value at 0x220 that is not on the chain.
        let data = slice + 0x200;
        let rebase = 0x40u64 | (2 << 51);
        let bind = (1u64 << 63) | 1 | (3 << 24);
        file[data + 0x10..data + 0x18].copy_from_slice(&rebase.to_le_bytes());
        file[data + 0x18..data + 0x20].copy_from_slice(&bind.to_le_bytes());
        file[data + 0x20..data + 0x28].copy_from_slice(&0x77u64.to_le_bytes());
        file
    }

    #[test]
    fn chained_fixups_are_followed() {
        for slice in [0usize, 0x800] {
            let mh = parse(chained_file(slice), slice);
            let d = PointerDecoder::new(&mh);
            let s = slice as u64;
            assert_eq!(d.read(s + 0x210, true), Some(Pointer::Address(0x1040)));
            assert_eq!(
                d.read(s + 0x218, true),
                Some(Pointer::Import {
                    name: b"_two",
                    addend: 3
                })
            );
            assert_eq!(d.read(s + 0x220, true), Some(Pointer::Address(0x77)));
            assert_eq!(d.read(s + 0x208, true), Some(Pointer::Address(0)));
            assert_eq!(d.read(u64::MAX - 3, true), None);
            assert_eq!(Pointer::Address(5).address(), 5);
            assert_eq!(d.read(s + 0x218, true).map(|p| p.address()), Some(0));
        }
    }

    #[test]
    fn chain_that_never_ends_is_cut() {
        // A bind opcode stream that binds 2^60 slots.
        let mut lc = Vec::new();
        for v in [0x8000_0022u32, 48, 0, 0, 0x300, 0x40, 0, 0, 0, 0, 0, 0] {
            put32(&mut lc, v);
        }
        let mut file = macho(0, &lc, 1);
        let mut ops = vec![0x71, 0x08, 0x40];
        ops.extend_from_slice(b"_sym\0");
        ops.push(0x90);
        ops.extend_from_slice(&[
            0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00,
        ]);
        file[0x300..0x300 + ops.len()].copy_from_slice(&ops);
        let mh = parse(file, 0);
        let d = PointerDecoder::new(&mh);
        assert_eq!(
            d.read(0x208, true),
            Some(Pointer::Import {
                name: b"_sym",
                addend: 0
            })
        );
        assert_eq!(
            d.read(0x210, true),
            Some(Pointer::Import {
                name: b"_sym",
                addend: 0
            })
        );
        // Past the segment's file contents nothing is bound.
        assert_eq!(
            d.read(0x300, true),
            Some(Pointer::Address(0x006d_7973_5f40_0871))
        );
    }
}
