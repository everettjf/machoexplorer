//! `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`: the rebase, bind, weak-bind and
//! lazy-bind opcode streams (the export trie lives in `export_trie`).
//!
//! The walkers follow dyld's interpretation of the streams (see
//! `<mach-o/loader.h>` and dyld's `MachOAnalyzer`), reporting every opcode
//! with its operands and the location it applies to.

use super::header::{LoadCommand, MachHeader};
use crate::consts::{LC_DYLD_INFO, LC_DYLD_INFO_ONLY};
use crate::leb::{read_sleb128, read_uleb128};

pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

pub const BIND_OPCODE_MASK: u8 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
pub const BIND_OPCODE_THREADED: u8 = 0xD0;
pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: u8 = 0x00;
pub const BIND_SUBOPCODE_THREADED_APPLY: u8 = 0x01;

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// Most trie nodes one walk visits.
pub const MAX_TRIE_NODES: usize = 200_000;
/// Most child edges one trie walk reports. A well-formed trie has fewer
/// edges than nodes; only overlapping, crafted nodes get near this.
pub const MAX_TRIE_EDGES: usize = 500_000;
/// Most opcodes one stream walk reports (a safety net against a stream
/// whose size field spans a huge file).
pub const MAX_OPCODES: usize = 8_000_000;

/// The `dyld_info_command` fields. Offsets are relative to the start of the
/// Mach-O header. Field `i` (0 = `rebase_off`) lives at `lc.offset + 8 + 4*i`.
#[derive(Debug, Clone, Copy)]
pub struct DyldInfo {
    pub lc: LoadCommand,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// Which bind stream to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    Bind,
    WeakBind,
    LazyBind,
}

impl DyldInfo {
    /// `(offset, size)` of a bind stream, as stored.
    pub fn bind_range(&self, kind: BindKind) -> (u32, u32) {
        match kind {
            BindKind::Bind => (self.bind_off, self.bind_size),
            BindKind::WeakBind => (self.weak_bind_off, self.weak_bind_size),
            BindKind::LazyBind => (self.lazy_bind_off, self.lazy_bind_size),
        }
    }
}

/// A LEB128 operand: its value and the bytes it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leb<T> {
    pub value: T,
    /// File offset of the first byte.
    pub offset: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseOp {
    Done,
    SetTypeImm {
        rebase_type: u8,
    },
    SetSegmentAndOffsetUleb {
        segment_index: u8,
        offset: Leb<u64>,
    },
    AddAddrUleb {
        offset: Leb<u64>,
    },
    /// Advance by `scale` pointers.
    AddAddrImmScaled {
        scale: u8,
    },
    DoRebaseImmTimes {
        count: u8,
    },
    DoRebaseUlebTimes {
        count: Leb<u64>,
    },
    DoRebaseAddAddrUleb {
        offset: Leb<u64>,
    },
    DoRebaseUlebTimesSkippingUleb {
        count: Leb<u64>,
        skip: Leb<u64>,
    },
    /// An opcode `<mach-o/loader.h>` does not define. Ends the walk.
    Unknown,
    /// A known opcode whose operand is cut off or malformed. Ends the walk.
    Truncated,
}

/// One decoded rebase opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebaseOpcode {
    /// File offset of the opcode byte.
    pub offset: u64,
    pub byte: u8,
    /// The location (virtual address) the stream points at before this
    /// opcode runs: for a `DO_REBASE_*` opcode, the first pointer it
    /// rebases. `None` until a valid segment has been set.
    pub address: Option<u64>,
    pub op: RebaseOp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOp {
    Done,
    SetDylibOrdinalImm {
        ordinal: u8,
    },
    SetDylibOrdinalUleb {
        ordinal: Leb<u64>,
    },
    /// 0 (`BIND_SPECIAL_DYLIB_SELF`) or a negative special ordinal.
    SetDylibSpecialImm {
        ordinal: i8,
    },
    SetSymbolTrailingFlagsImm {
        flags: u8,
        /// Name bytes without the terminator.
        name: Vec<u8>,
        /// File offset of the name.
        name_offset: u64,
        /// Name length including the terminator.
        name_size: u64,
    },
    SetTypeImm {
        bind_type: u8,
    },
    SetAddendSleb {
        addend: Leb<i64>,
    },
    SetSegmentAndOffsetUleb {
        segment_index: u8,
        offset: Leb<u64>,
    },
    AddAddrUleb {
        offset: Leb<u64>,
    },
    DoBind,
    DoBindAddAddrUleb {
        offset: Leb<u64>,
    },
    /// Bind, then advance by `scale` further pointers.
    DoBindAddAddrImmScaled {
        scale: u8,
    },
    DoBindUlebTimesSkippingUleb {
        count: Leb<u64>,
        skip: Leb<u64>,
    },
    /// `BIND_OPCODE_THREADED` / `SET_BIND_ORDINAL_TABLE_SIZE_ULEB`.
    ThreadedSetBindOrdinalTableSizeUleb {
        count: Leb<u64>,
    },
    /// `BIND_OPCODE_THREADED` / `THREADED_APPLY`: walk the fixup chain that
    /// starts at the current location.
    ThreadedApply,
    /// An opcode (or threaded sub-opcode) `<mach-o/loader.h>` does not
    /// define. Ends the walk.
    Unknown,
    /// A known opcode whose operand is cut off or malformed. Ends the walk.
    Truncated,
}

/// One decoded bind opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindOpcode {
    /// File offset of the opcode byte.
    pub offset: u64,
    pub byte: u8,
    /// The location (virtual address) the stream points at before this
    /// opcode runs: for a `DO_BIND*` opcode, the (first) pointer it binds.
    /// `None` until a valid segment has been set.
    pub address: Option<u64>,
    pub op: BindOp,
}

pub fn rebase_opcode_name(byte: u8) -> &'static str {
    match byte & REBASE_OPCODE_MASK {
        REBASE_OPCODE_DONE => "REBASE_OPCODE_DONE",
        REBASE_OPCODE_SET_TYPE_IMM => "REBASE_OPCODE_SET_TYPE_IMM",
        REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
        REBASE_OPCODE_ADD_ADDR_ULEB => "REBASE_OPCODE_ADD_ADDR_ULEB",
        REBASE_OPCODE_ADD_ADDR_IMM_SCALED => "REBASE_OPCODE_ADD_ADDR_IMM_SCALED",
        REBASE_OPCODE_DO_REBASE_IMM_TIMES => "REBASE_OPCODE_DO_REBASE_IMM_TIMES",
        REBASE_OPCODE_DO_REBASE_ULEB_TIMES => "REBASE_OPCODE_DO_REBASE_ULEB_TIMES",
        REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => "REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB",
        REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
            "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB"
        }
        _ => "REBASE_OPCODE_UNKNOWN",
    }
}

pub fn bind_opcode_name(byte: u8) -> &'static str {
    match byte & BIND_OPCODE_MASK {
        BIND_OPCODE_DONE => "BIND_OPCODE_DONE",
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM",
        BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => "BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB",
        BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM",
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM",
        BIND_OPCODE_SET_TYPE_IMM => "BIND_OPCODE_SET_TYPE_IMM",
        BIND_OPCODE_SET_ADDEND_SLEB => "BIND_OPCODE_SET_ADDEND_SLEB",
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
        BIND_OPCODE_ADD_ADDR_ULEB => "BIND_OPCODE_ADD_ADDR_ULEB",
        BIND_OPCODE_DO_BIND => "BIND_OPCODE_DO_BIND",
        BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB",
        BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED",
        BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
            "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB"
        }
        BIND_OPCODE_THREADED => match byte & BIND_IMMEDIATE_MASK {
            BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB => {
                "BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB"
            }
            BIND_SUBOPCODE_THREADED_APPLY => "BIND_SUBOPCODE_THREADED_APPLY",
            _ => "BIND_OPCODE_THREADED",
        },
        _ => "BIND_OPCODE_UNKNOWN",
    }
}

pub fn rebase_type_name(t: u8) -> &'static str {
    match t {
        1 => "REBASE_TYPE_POINTER",
        2 => "REBASE_TYPE_TEXT_ABSOLUTE32",
        3 => "REBASE_TYPE_TEXT_PCREL32",
        _ => "Unknown",
    }
}

pub fn bind_type_name(t: u8) -> &'static str {
    match t {
        1 => "BIND_TYPE_POINTER",
        2 => "BIND_TYPE_TEXT_ABSOLUTE32",
        3 => "BIND_TYPE_TEXT_PCREL32",
        _ => "Unknown",
    }
}

/// Name of a special (non-positive) dylib ordinal; `None` for the ones
/// `<mach-o/loader.h>` does not define.
pub fn special_dylib_name(ordinal: i64) -> Option<&'static str> {
    Some(match ordinal {
        0 => "BIND_SPECIAL_DYLIB_SELF",
        -1 => "BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE",
        -2 => "BIND_SPECIAL_DYLIB_FLAT_LOOKUP",
        -3 => "BIND_SPECIAL_DYLIB_WEAK_LOOKUP",
        _ => return None,
    })
}

/// What the opcode walkers need to know about the image.
#[derive(Debug, Clone, Default)]
pub struct WalkContext {
    pub is64: bool,
    /// vmaddr of every segment command of the header's word size, in
    /// load-command order (the order segment indexes refer to).
    pub segment_vmaddrs: Vec<u64>,
}

impl WalkContext {
    fn pointer_size(&self) -> u64 {
        if self.is64 {
            8
        } else {
            4
        }
    }

    /// Location after a `SET_SEGMENT_AND_OFFSET_ULEB`; `None` for a
    /// segment index the image does not have.
    fn segment_address(&self, segment_index: u8, offset: u64) -> Option<u64> {
        self.segment_vmaddrs
            .get(segment_index as usize)
            .map(|vmaddr| vmaddr.wrapping_add(offset))
    }
}

/// `location + delta` in the image's address space (wrapping: the streams
/// encode backwards moves as large unsigned values).
fn advance(location: Option<u64>, delta: u64) -> Option<u64> {
    location.map(|l| l.wrapping_add(delta))
}

/// Cursor over an opcode stream. `base` is the file offset of `bytes[0]`.
struct Stream<'a> {
    bytes: &'a [u8],
    base: u64,
    pos: usize,
}

impl Stream<'_> {
    fn offset(&self) -> u64 {
        self.base.wrapping_add(self.pos as u64)
    }

    fn rest(&self) -> &[u8] {
        self.bytes.get(self.pos..).unwrap_or(&[])
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// `None` for an operand that is cut off by the end of the stream or
    /// does not fit in 64 bits; the cursor is then left where it was.
    fn uleb(&mut self) -> Option<Leb<u64>> {
        let offset = self.offset();
        let (value, size) = read_uleb128(self.rest())?;
        self.pos += size as usize;
        Some(Leb {
            value,
            offset,
            size,
        })
    }

    fn sleb(&mut self) -> Option<Leb<i64>> {
        let offset = self.offset();
        let (value, size) = read_sleb128(self.rest())?;
        self.pos += size as usize;
        Some(Leb {
            value,
            offset,
            size,
        })
    }
}

/// Decode a rebase opcode stream. `base` is the file offset of `bytes[0]`.
/// The walk ends at `REBASE_OPCODE_DONE`, at the end of the stream, or with
/// an [`RebaseOp::Unknown`] / [`RebaseOp::Truncated`] entry.
pub fn walk_rebase_opcodes(bytes: &[u8], base: u64, ctx: &WalkContext) -> Vec<RebaseOpcode> {
    let pointer_size = ctx.pointer_size();
    let mut out = Vec::new();
    let mut location: Option<u64> = None;
    let mut s = Stream {
        bytes,
        base,
        pos: 0,
    };
    while out.len() < MAX_OPCODES {
        let offset = s.offset();
        let Some(byte) = s.byte() else { break };
        let immediate = byte & REBASE_IMMEDIATE_MASK;
        let address = location;
        // `None`: an operand could not be read.
        let op = (|| {
            Some(match byte & REBASE_OPCODE_MASK {
                REBASE_OPCODE_DONE => RebaseOp::Done,
                REBASE_OPCODE_SET_TYPE_IMM => RebaseOp::SetTypeImm {
                    rebase_type: immediate,
                },
                REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    let off = s.uleb()?;
                    location = ctx.segment_address(immediate, off.value);
                    RebaseOp::SetSegmentAndOffsetUleb {
                        segment_index: immediate,
                        offset: off,
                    }
                }
                REBASE_OPCODE_ADD_ADDR_ULEB => {
                    let off = s.uleb()?;
                    location = advance(location, off.value);
                    RebaseOp::AddAddrUleb { offset: off }
                }
                REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                    location = advance(location, immediate as u64 * pointer_size);
                    RebaseOp::AddAddrImmScaled { scale: immediate }
                }
                REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                    location = advance(location, immediate as u64 * pointer_size);
                    RebaseOp::DoRebaseImmTimes { count: immediate }
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                    let count = s.uleb()?;
                    location = advance(location, count.value.wrapping_mul(pointer_size));
                    RebaseOp::DoRebaseUlebTimes { count }
                }
                REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                    let off = s.uleb()?;
                    location = advance(location, pointer_size.wrapping_add(off.value));
                    RebaseOp::DoRebaseAddAddrUleb { offset: off }
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = s.uleb()?;
                    let skip = s.uleb()?;
                    let step = pointer_size.wrapping_add(skip.value);
                    location = advance(location, count.value.wrapping_mul(step));
                    RebaseOp::DoRebaseUlebTimesSkippingUleb { count, skip }
                }
                _ => RebaseOp::Unknown,
            })
        })()
        .unwrap_or(RebaseOp::Truncated);
        out.push(RebaseOpcode {
            offset,
            byte,
            address,
            op,
        });
        if matches!(op, RebaseOp::Done | RebaseOp::Unknown | RebaseOp::Truncated) {
            break;
        }
    }
    out
}

/// Decode a bind opcode stream. `base` is the file offset of `bytes[0]`.
/// `BIND_OPCODE_DONE` ends the walk except in a lazy-bind stream, where it
/// separates entries. The walk also ends at the end of the stream or with
/// a [`BindOp::Unknown`] / [`BindOp::Truncated`] entry.
pub fn walk_bind_opcodes(
    bytes: &[u8],
    base: u64,
    kind: BindKind,
    ctx: &WalkContext,
) -> Vec<BindOpcode> {
    let pointer_size = ctx.pointer_size();
    let mut out = Vec::new();
    let mut location: Option<u64> = None;
    let mut s = Stream {
        bytes,
        base,
        pos: 0,
    };
    while out.len() < MAX_OPCODES {
        let offset = s.offset();
        let Some(byte) = s.byte() else { break };
        let immediate = byte & BIND_IMMEDIATE_MASK;
        let address = location;
        // `None`: an operand could not be read.
        let op = (|| {
            Some(match byte & BIND_OPCODE_MASK {
                BIND_OPCODE_DONE => BindOp::Done,
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                    BindOp::SetDylibOrdinalImm { ordinal: immediate }
                }
                BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                    BindOp::SetDylibOrdinalUleb { ordinal: s.uleb()? }
                }
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => BindOp::SetDylibSpecialImm {
                    // The immediate is the low nibble of a negative number.
                    ordinal: if immediate == 0 {
                        0
                    } else {
                        (immediate | BIND_OPCODE_MASK) as i8
                    },
                },
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    let name_offset = s.offset();
                    let rest = s.rest();
                    let len = rest.iter().position(|&c| c == 0)?;
                    let name = rest.get(..len)?.to_vec();
                    s.pos += len + 1;
                    BindOp::SetSymbolTrailingFlagsImm {
                        flags: immediate,
                        name,
                        name_offset,
                        name_size: len as u64 + 1,
                    }
                }
                BIND_OPCODE_SET_TYPE_IMM => BindOp::SetTypeImm {
                    bind_type: immediate,
                },
                BIND_OPCODE_SET_ADDEND_SLEB => BindOp::SetAddendSleb { addend: s.sleb()? },
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    let off = s.uleb()?;
                    location = ctx.segment_address(immediate, off.value);
                    BindOp::SetSegmentAndOffsetUleb {
                        segment_index: immediate,
                        offset: off,
                    }
                }
                BIND_OPCODE_ADD_ADDR_ULEB => {
                    let off = s.uleb()?;
                    location = advance(location, off.value);
                    BindOp::AddAddrUleb { offset: off }
                }
                BIND_OPCODE_DO_BIND => {
                    location = advance(location, pointer_size);
                    BindOp::DoBind
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    let off = s.uleb()?;
                    location = advance(location, pointer_size.wrapping_add(off.value));
                    BindOp::DoBindAddAddrUleb { offset: off }
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                    location = advance(location, (immediate as u64 + 1) * pointer_size);
                    BindOp::DoBindAddAddrImmScaled { scale: immediate }
                }
                BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = s.uleb()?;
                    let skip = s.uleb()?;
                    let step = pointer_size.wrapping_add(skip.value);
                    location = advance(location, count.value.wrapping_mul(step));
                    BindOp::DoBindUlebTimesSkippingUleb { count, skip }
                }
                BIND_OPCODE_THREADED => match immediate {
                    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB => {
                        BindOp::ThreadedSetBindOrdinalTableSizeUleb { count: s.uleb()? }
                    }
                    BIND_SUBOPCODE_THREADED_APPLY => BindOp::ThreadedApply,
                    _ => BindOp::Unknown,
                },
                _ => BindOp::Unknown,
            })
        })()
        .unwrap_or(BindOp::Truncated);
        let stop = match &op {
            BindOp::Done => kind != BindKind::LazyBind,
            BindOp::Unknown | BindOp::Truncated => true,
            _ => false,
        };
        out.push(BindOpcode {
            offset,
            byte,
            address,
            op,
        });
        if stop {
            break;
        }
    }
    out
}

impl MachHeader {
    /// The first `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` command, if any.
    pub fn dyld_info(&self) -> Option<DyldInfo> {
        let lc = *self.find_load_command(&[LC_DYLD_INFO, LC_DYLD_INFO_ONLY])?;
        let f = |i: u64| self.lc_u32(&lc, 8 + 4 * i);
        Some(DyldInfo {
            lc,
            rebase_off: f(0),
            rebase_size: f(1),
            bind_off: f(2),
            bind_size: f(3),
            weak_bind_off: f(4),
            weak_bind_size: f(5),
            lazy_bind_off: f(6),
            lazy_bind_size: f(7),
            export_off: f(8),
            export_size: f(9),
        })
    }

    /// File offset of a blob stored `off` bytes after the Mach-O header.
    pub fn dyld_info_file_offset(&self, off: u32) -> u64 {
        self.offset.saturating_add(off as u64)
    }

    /// Bytes of an opcode stream, clipped to the file (empty when the
    /// stream starts past the end of the file), and their file offset.
    fn opcode_stream(&self, off: u32, size: u32) -> (&[u8], u64) {
        let begin = self.dyld_info_file_offset(off);
        let len = self.image.len();
        if begin > len {
            return (&[], begin);
        }
        (
            self.image
                .slice(begin, (size as u64).min(len - begin))
                .unwrap_or(&[]),
            begin,
        )
    }

    pub fn dyld_walk_context(&self) -> WalkContext {
        WalkContext {
            is64: self.is64,
            segment_vmaddrs: self
                .segments
                .iter()
                .filter(|s| s.is64 == self.is64)
                .map(|s| s.vmaddr)
                .collect(),
        }
    }

    /// The decoded rebase opcodes of `info`.
    pub fn rebase_opcodes(&self, info: &DyldInfo) -> Vec<RebaseOpcode> {
        let (bytes, base) = self.opcode_stream(info.rebase_off, info.rebase_size);
        walk_rebase_opcodes(bytes, base, &self.dyld_walk_context())
    }

    /// The decoded opcodes of one of the three bind streams of `info`.
    pub fn bind_opcodes(&self, info: &DyldInfo, kind: BindKind) -> Vec<BindOpcode> {
        let (off, size) = info.bind_range(kind);
        let (bytes, base) = self.opcode_stream(off, size);
        walk_bind_opcodes(bytes, base, kind, &self.dyld_walk_context())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx64() -> WalkContext {
        WalkContext {
            is64: true,
            segment_vmaddrs: vec![0, 0x1_0000_0000, 0x1_0000_4000],
        }
    }

    fn leb<T>(value: T, offset: u64, size: u32) -> Leb<T> {
        Leb {
            value,
            offset,
            size,
        }
    }

    #[test]
    fn rebase_stream() {
        // SET_TYPE(1), SET_SEGMENT(2)+uleb 0x10, DO_REBASE_IMM_TIMES(3),
        // ADD_ADDR_ULEB 0x80 0x01, DO_REBASE_ULEB_TIMES_SKIPPING 2 8, DONE,
        // trailing byte that must not be decoded.
        let bytes = [
            0x11, 0x22, 0x10, 0x53, 0x30, 0x80, 0x01, 0x80, 0x02, 0x08, 0x00, 0x11,
        ];
        let ops = walk_rebase_opcodes(&bytes, 0x3000, &ctx64());
        assert_eq!(ops.len(), 6);
        assert_eq!(
            (ops[0].offset, ops[0].byte, ops[0].address),
            (0x3000, 0x11, None)
        );
        assert_eq!(ops[0].op, RebaseOp::SetTypeImm { rebase_type: 1 });
        assert_eq!(
            ops[1].op,
            RebaseOp::SetSegmentAndOffsetUleb {
                segment_index: 2,
                offset: leb(0x10, 0x3002, 1)
            }
        );
        // The segment offset counts in 64-bit images too.
        assert_eq!(ops[2].address, Some(0x1_0000_4010));
        assert_eq!(ops[2].op, RebaseOp::DoRebaseImmTimes { count: 3 });
        assert_eq!(ops[3].address, Some(0x1_0000_4028));
        assert_eq!(
            ops[3].op,
            RebaseOp::AddAddrUleb {
                offset: leb(0x80, 0x3005, 2)
            }
        );
        // The operands have their own offsets.
        assert_eq!(ops[4].address, Some(0x1_0000_40a8));
        assert_eq!(
            ops[4].op,
            RebaseOp::DoRebaseUlebTimesSkippingUleb {
                count: leb(2, 0x3008, 1),
                skip: leb(8, 0x3009, 1),
            }
        );
        assert_eq!(ops[5].op, RebaseOp::Done);
        assert_eq!(ops[5].address, Some(0x1_0000_40c8));
    }

    #[test]
    fn rebase_truncated_operand_and_unknown_opcode() {
        // ADD_ADDR_ULEB with an unterminated operand ends the walk.
        let ops = walk_rebase_opcodes(&[0x11, 0x30, 0x80], 10, &ctx64());
        assert_eq!(ops.len(), 2);
        assert_eq!((ops[1].offset, ops[1].op), (11, RebaseOp::Truncated));
        // So does an undefined opcode; nothing after it is decoded.
        let ops = walk_rebase_opcodes(&[0xF3, 0x11, 0x00], 0, &ctx64());
        assert_eq!(ops.len(), 1);
        assert_eq!((ops[0].byte, ops[0].op), (0xF3, RebaseOp::Unknown));
        assert_eq!(rebase_opcode_name(0xF3), "REBASE_OPCODE_UNKNOWN");
        assert!(walk_rebase_opcodes(&[], 0, &ctx64()).is_empty());
    }

    #[test]
    fn rebase_32bit_and_huge_counts_wrap() {
        let ctx = WalkContext {
            is64: false,
            segment_vmaddrs: vec![0x1000, 0x2000],
        };
        // SET_SEGMENT(1) + 0x20, DO_REBASE_ULEB_TIMES u64::MAX, DONE.
        let mut bytes = vec![0x21, 0x20, 0x60];
        bytes.extend([0xff; 9]);
        bytes.extend([0x01, 0x00]);
        let ops = walk_rebase_opcodes(&bytes, 0, &ctx);
        assert_eq!(ops[1].address, Some(0x2020));
        assert_eq!(
            ops[1].op,
            RebaseOp::DoRebaseUlebTimes {
                count: leb(u64::MAX, 3, 10)
            }
        );
        assert_eq!(ops[2].op, RebaseOp::Done);
        assert_eq!(
            ops[2].address,
            Some(0x2020u64.wrapping_add(u64::MAX.wrapping_mul(4)))
        );
        // A segment index the image does not have: no location.
        let ops = walk_rebase_opcodes(&[0x2f, 0x08, 0x51, 0x00], 0, &ctx);
        assert_eq!(ops[1].address, None);
        assert_eq!(ops[2].address, None);
    }

    #[test]
    fn bind_stream() {
        let mut bytes = vec![0x12, 0x40 | 0x1];
        bytes.extend(b"_puts\0");
        bytes.extend([
            0x51, 0x72, 0x08, 0x60, 0x7e, 0x90, 0x3f, 0x20, 0x85, 0x01, 0xB2, 0xC0, 0x03, 0x10,
            0xD0, 0x04, 0xD1, 0x00, 0x90,
        ]);
        let ops = walk_bind_opcodes(&bytes, 0x100, BindKind::Bind, &ctx64());
        let bytes_seen: Vec<u8> = ops.iter().map(|o| o.byte).collect();
        // The walk ends at DONE.
        assert_eq!(
            bytes_seen,
            [0x12, 0x41, 0x51, 0x72, 0x60, 0x90, 0x3f, 0x20, 0xB2, 0xC0, 0xD0, 0xD1, 0x00]
        );
        assert_eq!(ops[0].op, BindOp::SetDylibOrdinalImm { ordinal: 2 });
        assert_eq!(
            ops[1].op,
            BindOp::SetSymbolTrailingFlagsImm {
                flags: 1,
                name: b"_puts".to_vec(),
                name_offset: 0x102,
                name_size: 6
            }
        );
        assert_eq!(ops[2].op, BindOp::SetTypeImm { bind_type: 1 });
        assert_eq!(
            ops[4].op,
            BindOp::SetAddendSleb {
                addend: leb(-2, 0x10c, 1)
            }
        );
        // DO_BIND reports the location it binds.
        assert_eq!(ops[5].op, BindOp::DoBind);
        assert_eq!(ops[5].address, Some(0x1_0000_4008));
        assert_eq!(ops[6].op, BindOp::SetDylibSpecialImm { ordinal: -1 });
        assert_eq!(ops[6].address, Some(0x1_0000_4010));
        assert_eq!(
            ops[7].op,
            BindOp::SetDylibOrdinalUleb {
                ordinal: leb(0x85, 0x110, 2)
            }
        );
        // DO_BIND_ADD_ADDR_IMM_SCALED(2): the bind plus two more pointers.
        assert_eq!(ops[8].op, BindOp::DoBindAddAddrImmScaled { scale: 2 });
        assert_eq!(ops[9].address, Some(0x1_0000_4028));
        assert_eq!(
            ops[9].op,
            BindOp::DoBindUlebTimesSkippingUleb {
                count: leb(3, 0x114, 1),
                skip: leb(0x10, 0x115, 1),
            }
        );
        assert_eq!(ops[10].address, Some(0x1_0000_4028 + 3 * (8 + 0x10)));
        assert_eq!(
            ops[10].op,
            BindOp::ThreadedSetBindOrdinalTableSizeUleb {
                count: leb(4, 0x117, 1)
            }
        );
        assert_eq!(ops[11].op, BindOp::ThreadedApply);
        assert_eq!(ops[12].op, BindOp::Done);
    }

    #[test]
    fn bind_special_ordinals() {
        let ops = walk_bind_opcodes(&[0x30, 0x3f, 0x3e, 0x3d], 0, BindKind::Bind, &ctx64());
        let ordinals: Vec<i8> = ops
            .iter()
            .map(|o| match o.op {
                BindOp::SetDylibSpecialImm { ordinal } => ordinal,
                _ => panic!("unexpected op"),
            })
            .collect();
        assert_eq!(ordinals, [0, -1, -2, -3]);
        assert_eq!(special_dylib_name(0), Some("BIND_SPECIAL_DYLIB_SELF"));
        assert_eq!(
            special_dylib_name(-2),
            Some("BIND_SPECIAL_DYLIB_FLAT_LOOKUP")
        );
        assert_eq!(special_dylib_name(-9), None);
    }

    #[test]
    fn lazy_bind_continues_past_done() {
        let bytes = [0x90, 0x00, 0x90, 0x00];
        assert_eq!(
            walk_bind_opcodes(&bytes, 0, BindKind::LazyBind, &ctx64()).len(),
            4
        );
        assert_eq!(
            walk_bind_opcodes(&bytes, 0, BindKind::WeakBind, &ctx64()).len(),
            2
        );
    }

    #[test]
    fn bind_malformed_streams_end_the_walk() {
        // Unterminated symbol name.
        let ops = walk_bind_opcodes(&[0x11, 0x40, b'a', b'b'], 0, BindKind::Bind, &ctx64());
        assert_eq!(ops.len(), 2);
        assert_eq!((ops[1].offset, &ops[1].op), (1, &BindOp::Truncated));
        // Name opcode as the very last byte.
        let ops = walk_bind_opcodes(&[0x40], 0, BindKind::LazyBind, &ctx64());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, BindOp::Truncated);
        // Undefined opcode and undefined threaded sub-opcode.
        for byte in [0xE0u8, 0xD2] {
            let ops = walk_bind_opcodes(&[byte, 0x90], 0, BindKind::LazyBind, &ctx64());
            assert_eq!(ops.len(), 1);
            assert_eq!(ops[0].op, BindOp::Unknown);
        }
        assert_eq!(bind_opcode_name(0xE0), "BIND_OPCODE_UNKNOWN");
        assert_eq!(bind_opcode_name(0xD1), "BIND_SUBOPCODE_THREADED_APPLY");
        assert_eq!(
            bind_opcode_name(0xC0),
            "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB"
        );
    }

    #[test]
    fn type_names() {
        assert_eq!(rebase_type_name(2), "REBASE_TYPE_TEXT_ABSOLUTE32");
        assert_eq!(bind_type_name(0), "Unknown");
    }
}
