//! `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`: the rebase, bind, weak-bind and
//! lazy-bind opcode streams and the classic export trie.
//!
//! The walkers mirror `LoadCommand_DYLD_INFO.cpp`, including where it gives
//! up and what it keeps going on, because the views show every step.

use super::header::{LoadCommand, MachHeader};
use crate::consts::{LC_DYLD_INFO, LC_DYLD_INFO_ONLY};
use crate::leb::{read_sleb128, read_uleb128};
use std::collections::{HashSet, VecDeque};

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

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// Most trie nodes one walk visits (same limit as the original).
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

/// A LEB128 operand: its value and the bytes it was read from. A malformed
/// or truncated operand has `value == 0` and `size == 0`.
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
    SetTypeImm,
    SetSegmentAndOffsetUleb {
        segment_index: u32,
        offset: Leb<u64>,
    },
    AddAddrUleb {
        offset: Leb<u64>,
    },
    AddAddrImmScaled {
        scale: u32,
    },
    DoRebaseImmTimes {
        count: u32,
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
}

/// One decoded rebase opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebaseOpcode {
    /// File offset of the opcode byte.
    pub offset: u64,
    pub byte: u8,
    pub opcode: u8,
    pub immediate: u8,
    /// The immediate of `SET_TYPE_IMM`; 0 for every other opcode.
    pub rebase_type: u8,
    /// The walker's running address when the opcode was reported.
    pub address: u64,
    pub op: RebaseOp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOp {
    Done,
    SetDylibOrdinalImm {
        ordinal: u64,
    },
    SetDylibOrdinalUleb {
        ordinal: Leb<u64>,
    },
    SetDylibSpecialImm {
        ordinal: u64,
    },
    SetSymbolTrailingFlagsImm {
        flags: u64,
        /// Name bytes without the terminator.
        name: Vec<u8>,
        /// File offset of the name.
        name_offset: u64,
        /// Name length including the terminator.
        name_size: u32,
    },
    SetTypeImm,
    SetAddendSleb {
        addend: Leb<i64>,
    },
    SetSegmentAndOffsetUleb {
        segment_index: u32,
        offset: Leb<u64>,
    },
    AddAddrUleb {
        offset: Leb<u64>,
    },
    DoBind,
    DoBindAddAddrUleb {
        offset: Leb<u64>,
    },
    DoBindAddAddrImmScaled {
        scale: u32,
    },
    DoBindUlebTimesSkippingUleb {
        count: Leb<u64>,
        skip: Leb<u64>,
    },
}

/// One decoded bind opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindOpcode {
    /// File offset of the opcode byte.
    pub offset: u64,
    pub byte: u8,
    pub opcode: u8,
    pub immediate: u8,
    /// The immediate of `SET_TYPE_IMM`; 0 for every other opcode.
    pub bind_type: u8,
    /// The walker's running address when the opcode was reported.
    pub address: u64,
    pub op: BindOp,
}

/// One child edge of a classic export trie node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportChild {
    /// Edge label without the terminator.
    pub label: Vec<u8>,
    pub label_offset: u64,
    /// Label length including the terminator.
    pub label_size: u32,
    /// Offset of the child node from the start of the trie.
    pub skip: Leb<u64>,
}

/// One node of the classic export trie as the original walker reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportNode {
    pub terminal_size: u8,
    pub terminal_size_offset: u64,
    /// Present when `terminal_size > 0`.
    pub flags: Option<Leb<u64>>,
    /// Present when `terminal_size > 0`.
    pub symbol_offset: Option<Leb<u64>>,
    pub child_count: u8,
    pub child_count_offset: u64,
    pub children: Vec<ExportChild>,
}

impl ExportNode {
    /// `(hex value, name)` of every flag set in `flags`.
    pub fn flag_names(&self) -> Vec<(&'static str, &'static str)> {
        export_flag_names(self.flags.map(|f| f.value).unwrap_or(0))
    }
}

pub fn export_flag_names(flags: u64) -> Vec<(&'static str, &'static str)> {
    let mut res = Vec::new();
    if flags & EXPORT_SYMBOL_FLAGS_KIND_MASK == EXPORT_SYMBOL_FLAGS_KIND_REGULAR {
        res.push(("00", "EXPORT_SYMBOL_FLAGS_KIND_REGULAR"));
    }
    if flags & EXPORT_SYMBOL_FLAGS_KIND_MASK == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL {
        res.push(("01", "EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL"));
    }
    if flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0 {
        res.push(("04", "EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION"));
    }
    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        res.push(("08", "EXPORT_SYMBOL_FLAGS_REEXPORT"));
    }
    if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        res.push(("10", "EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER"));
    }
    res
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

/// What the opcode walkers need to know about the image.
#[derive(Debug, Clone, Default)]
pub struct WalkContext {
    pub is64: bool,
    pub base_address: u64,
    /// vmaddr of every segment command of the header's word size, in order.
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

    /// Address after a `SET_SEGMENT_AND_OFFSET_ULEB`.
    fn segment_address(&self, current: u64, segment_index: u32, offset: u64) -> u64 {
        match self.segment_vmaddrs.get(segment_index as usize) {
            // QUIRK(parity): the 64-bit path drops the segment offset.
            Some(&vmaddr) if self.is64 => vmaddr,
            Some(&vmaddr) => vmaddr.wrapping_add(offset),
            None => current,
        }
    }
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

    fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.bytes.len());
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// A malformed operand reads as value 0 occupying 0 bytes, and the walk
    /// carries on with the next byte as an opcode.
    fn uleb(&mut self) -> Leb<u64> {
        let offset = self.offset();
        let (value, size) = read_uleb128(self.rest()).unwrap_or((0, 0));
        self.advance(size as usize);
        Leb {
            value,
            offset,
            size,
        }
    }

    fn sleb(&mut self) -> Leb<i64> {
        let offset = self.offset();
        let (value, size) = read_sleb128(self.rest()).unwrap_or((0, 0));
        self.advance(size as usize);
        Leb {
            value,
            offset,
            size,
        }
    }
}

/// Decode a rebase opcode stream. `base` is the file offset of `bytes[0]`.
/// Unknown opcodes are skipped without being reported.
pub fn walk_rebase_opcodes(bytes: &[u8], base: u64, ctx: &WalkContext) -> Vec<RebaseOpcode> {
    let pointer_size = ctx.pointer_size();
    let mut out = Vec::new();
    let mut address = ctx.base_address;
    let mut s = Stream {
        bytes,
        base,
        pos: 0,
    };
    loop {
        let offset = s.offset();
        let Some(byte) = s.byte() else { break };
        let opcode = byte & REBASE_OPCODE_MASK;
        let immediate = byte & REBASE_IMMEDIATE_MASK;
        let mut rebase_type = 0;
        // `address_after` is applied once the opcode has been reported.
        let (op, address_after) = match opcode {
            REBASE_OPCODE_DONE => (RebaseOp::Done, address),
            REBASE_OPCODE_SET_TYPE_IMM => {
                rebase_type = immediate;
                (RebaseOp::SetTypeImm, address)
            }
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                let segment_index = immediate as u32;
                let off = s.uleb();
                address = ctx.segment_address(address, segment_index, off.value);
                (
                    RebaseOp::SetSegmentAndOffsetUleb {
                        segment_index,
                        offset: off,
                    },
                    address,
                )
            }
            REBASE_OPCODE_ADD_ADDR_ULEB => {
                let off = s.uleb();
                (
                    RebaseOp::AddAddrUleb { offset: off },
                    address.wrapping_add(off.value),
                )
            }
            REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                let scale = immediate as u32;
                (
                    RebaseOp::AddAddrImmScaled { scale },
                    address.wrapping_add((scale as u64).wrapping_mul(pointer_size)),
                )
            }
            REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                let count = immediate as u32;
                (
                    RebaseOp::DoRebaseImmTimes { count },
                    address.wrapping_add((count as u64).wrapping_mul(pointer_size)),
                )
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let count = s.uleb();
                (
                    RebaseOp::DoRebaseUlebTimes { count },
                    address.wrapping_add(count.value.wrapping_mul(pointer_size)),
                )
            }
            REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                let off = s.uleb();
                (
                    RebaseOp::DoRebaseAddAddrUleb { offset: off },
                    address.wrapping_add(pointer_size).wrapping_add(off.value),
                )
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let count = s.uleb();
                let skip = s.uleb();
                let step = pointer_size.wrapping_add(skip.value);
                (
                    RebaseOp::DoRebaseUlebTimesSkippingUleb { count, skip },
                    address.wrapping_add(count.value.wrapping_mul(step)),
                )
            }
            _ => continue,
        };
        out.push(RebaseOpcode {
            offset,
            byte,
            opcode,
            immediate,
            rebase_type,
            address,
            op,
        });
        address = address_after;
        if opcode == REBASE_OPCODE_DONE || out.len() >= MAX_OPCODES {
            break;
        }
    }
    out
}

/// Decode a bind opcode stream. `base` is the file offset of `bytes[0]`.
/// `BIND_OPCODE_DONE` ends the walk except in a lazy-bind stream, where it
/// separates entries. Unknown opcodes are skipped without being reported.
pub fn walk_bind_opcodes(
    bytes: &[u8],
    base: u64,
    kind: BindKind,
    ctx: &WalkContext,
) -> Vec<BindOpcode> {
    let pointer_size = ctx.pointer_size();
    let mut out = Vec::new();
    let mut address = ctx.base_address;
    let mut s = Stream {
        bytes,
        base,
        pos: 0,
    };
    loop {
        let offset = s.offset();
        let Some(byte) = s.byte() else { break };
        let opcode = byte & BIND_OPCODE_MASK;
        let immediate = byte & BIND_IMMEDIATE_MASK;
        let mut bind_type = 0;
        let mut done = false;
        // `address_after` is applied once the opcode has been reported.
        let (op, address_after) = match opcode {
            BIND_OPCODE_DONE => {
                done = kind != BindKind::LazyBind;
                (BindOp::Done, address)
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => (
                BindOp::SetDylibOrdinalImm {
                    ordinal: immediate as u64,
                },
                address,
            ),
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                (BindOp::SetDylibOrdinalUleb { ordinal: s.uleb() }, address)
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                // QUIRK(parity): the sign-extended special ordinal (-1, -2,
                // ...) is stored in an unsigned 64-bit field.
                let ordinal = if immediate == 0 {
                    0
                } else {
                    (immediate | BIND_OPCODE_MASK) as i8 as i64 as u64
                };
                (BindOp::SetDylibSpecialImm { ordinal }, address)
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let name_offset = s.offset();
                let rest = s.rest();
                // An unterminated name ends the walk without a report.
                let Some(len) = rest.iter().position(|&c| c == 0) else {
                    break;
                };
                let name = rest.get(..len).unwrap_or(&[]).to_vec();
                s.advance(len.saturating_add(1));
                let name_size = (len as u64).wrapping_add(1) as u32;
                (
                    BindOp::SetSymbolTrailingFlagsImm {
                        flags: immediate as u64,
                        name,
                        name_offset,
                        name_size,
                    },
                    address,
                )
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = immediate;
                (BindOp::SetTypeImm, address)
            }
            BIND_OPCODE_SET_ADDEND_SLEB => (BindOp::SetAddendSleb { addend: s.sleb() }, address),
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                let segment_index = immediate as u32;
                let off = s.uleb();
                address = ctx.segment_address(address, segment_index, off.value);
                (
                    BindOp::SetSegmentAndOffsetUleb {
                        segment_index,
                        offset: off,
                    },
                    address,
                )
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                let off = s.uleb();
                address = address.wrapping_add(off.value);
                (BindOp::AddAddrUleb { offset: off }, address)
            }
            BIND_OPCODE_DO_BIND => {
                address = address.wrapping_add(pointer_size);
                (BindOp::DoBind, address)
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                let off = s.uleb();
                (
                    BindOp::DoBindAddAddrUleb { offset: off },
                    address.wrapping_add(pointer_size).wrapping_add(off.value),
                )
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                let scale = immediate as u32;
                (
                    BindOp::DoBindAddAddrImmScaled { scale },
                    address.wrapping_add((scale as u64).wrapping_mul(pointer_size)),
                )
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = s.uleb();
                let skip = s.uleb();
                let step = pointer_size.wrapping_add(skip.value);
                (
                    BindOp::DoBindUlebTimesSkippingUleb { count, skip },
                    address.wrapping_add(count.value.wrapping_mul(step)),
                )
            }
            _ => continue,
        };
        out.push(BindOpcode {
            offset,
            byte,
            opcode,
            immediate,
            bind_type,
            address,
            op,
        });
        address = address_after;
        if done || out.len() >= MAX_OPCODES {
            break;
        }
    }
    out
}

/// Walk a classic export trie breadth-first. `base` is the file offset of
/// `blob[0]`.
///
/// QUIRK(parity): this is not a faithful trie decoder. The terminal size is
/// read as a single byte rather than a ULEB128, and the child count is read
/// right after the first two terminal values instead of at
/// `terminal start + terminal size`, so nodes with a longer payload
/// (re-exports, stub-and-resolver) are misread.
pub fn walk_classic_export_trie(blob: &[u8], base: u64) -> Vec<ExportNode> {
    let mut out = Vec::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut children_total = 0usize;
    let size = blob.len() as u64;
    let at = |pos: usize| base.wrapping_add(pos as u64);
    queue.push_back(0);
    let mut guard = 0usize;
    'nodes: while guard < MAX_TRIE_NODES {
        let Some(node_off) = queue.pop_front() else {
            break;
        };
        guard += 1;
        if node_off >= size || !visited.insert(node_off) {
            continue;
        }
        let Ok(mut cur) = usize::try_from(node_off) else {
            continue;
        };
        let Some(&terminal_size) = blob.get(cur) else {
            continue;
        };
        let terminal_size_offset = at(cur);
        cur += 1;

        let (mut flags, mut symbol_offset) = (None, None);
        if terminal_size > 0 {
            for slot in [&mut flags, &mut symbol_offset] {
                let Some((value, used)) = read_uleb128(blob.get(cur..).unwrap_or(&[])) else {
                    continue 'nodes;
                };
                *slot = Some(Leb {
                    value,
                    offset: at(cur),
                    size: used,
                });
                cur = cur.saturating_add(used as usize);
            }
        }

        let Some(&child_count) = blob.get(cur) else {
            continue;
        };
        let child_count_offset = at(cur);
        cur += 1;

        let mut children = Vec::new();
        for _ in 0..child_count {
            let rest = blob.get(cur..).unwrap_or(&[]);
            let Some(len) = rest.iter().position(|&c| c == 0) else {
                break;
            };
            let label = rest.get(..len).unwrap_or(&[]).to_vec();
            let label_offset = at(cur);
            cur = cur.saturating_add(len).saturating_add(1);
            let Some((skip, used)) = read_uleb128(blob.get(cur..).unwrap_or(&[])) else {
                break;
            };
            let skip = Leb {
                value: skip,
                offset: at(cur),
                size: used,
            };
            cur = cur.saturating_add(used as usize);
            children.push(ExportChild {
                label,
                label_offset,
                label_size: (len as u64).wrapping_add(1) as u32,
                skip,
            });
            if skip.value < size {
                queue.push_back(skip.value);
            }
        }
        children_total = children_total.saturating_add(children.len());
        out.push(ExportNode {
            terminal_size,
            terminal_size_offset,
            flags,
            symbol_offset,
            child_count,
            child_count_offset,
            children,
        });
        if children_total > MAX_TRIE_EDGES {
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
            base_address: self.base_address(),
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
        let (off, size) = match kind {
            BindKind::Bind => (info.bind_off, info.bind_size),
            BindKind::WeakBind => (info.weak_bind_off, info.weak_bind_size),
            BindKind::LazyBind => (info.lazy_bind_off, info.lazy_bind_size),
        };
        let (bytes, base) = self.opcode_stream(off, size);
        walk_bind_opcodes(bytes, base, kind, &self.dyld_walk_context())
    }

    /// The classic export trie of `info`. Empty when the trie does not lie
    /// entirely inside the file.
    pub fn export_trie_nodes(&self, info: &DyldInfo) -> Vec<ExportNode> {
        if info.export_size == 0 {
            return Vec::new();
        }
        // QUIRK(parity): the range check uses the header-relative offset, so
        // it is too lax inside a fat file. Out-of-file reads were undefined
        // there; here such a trie is simply not walked.
        if info.export_off as u64 + info.export_size as u64 > self.image.len() {
            return Vec::new();
        }
        let begin = self.dyld_info_file_offset(info.export_off);
        match self.image.slice(begin, info.export_size as u64) {
            Some(blob) => walk_classic_export_trie(blob, begin),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx64() -> WalkContext {
        WalkContext {
            is64: true,
            base_address: 0x1_0000_0000,
            segment_vmaddrs: vec![0, 0x1_0000_0000, 0x1_0000_4000],
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
            (ops[0].offset, ops[0].byte, ops[0].rebase_type),
            (0x3000, 0x11, 1)
        );
        assert_eq!(
            ops[1].op,
            RebaseOp::SetSegmentAndOffsetUleb {
                segment_index: 2,
                offset: Leb {
                    value: 0x10,
                    offset: 0x3002,
                    size: 1
                }
            }
        );
        // 64-bit: segment offset is dropped.
        assert_eq!(ops[1].address, 0x1_0000_4000);
        assert_eq!(ops[2].op, RebaseOp::DoRebaseImmTimes { count: 3 });
        assert_eq!(ops[3].address, 0x1_0000_4018);
        assert_eq!(
            ops[3].op,
            RebaseOp::AddAddrUleb {
                offset: Leb {
                    value: 0x80,
                    offset: 0x3005,
                    size: 2
                }
            }
        );
        assert_eq!(ops[4].address, 0x1_0000_4098);
        assert_eq!(
            ops[4].op,
            RebaseOp::DoRebaseUlebTimesSkippingUleb {
                count: Leb {
                    value: 2,
                    offset: 0x3008,
                    size: 1
                },
                skip: Leb {
                    value: 8,
                    offset: 0x3009,
                    size: 1
                },
            }
        );
        assert_eq!(ops[5].op, RebaseOp::Done);
        assert_eq!(ops[5].address, 0x1_0000_40b8);
        assert_eq!(ops[5].rebase_type, 0);
    }

    #[test]
    fn rebase_truncated_operand_and_unknown_opcode() {
        // ADD_ADDR_ULEB with an unterminated operand: reported with size 0,
        // then the operand byte is decoded as an opcode (0x80 = ULEB_TIMES_
        // SKIPPING with two empty operands). 0xF0 is unknown and skipped.
        let ops = walk_rebase_opcodes(&[0xF0, 0x30, 0x80], 10, &ctx64());
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0].op,
            RebaseOp::AddAddrUleb {
                offset: Leb {
                    value: 0,
                    offset: 12,
                    size: 0
                }
            }
        );
        assert_eq!(
            ops[1].op,
            RebaseOp::DoRebaseUlebTimesSkippingUleb {
                count: Leb {
                    value: 0,
                    offset: 13,
                    size: 0
                },
                skip: Leb {
                    value: 0,
                    offset: 13,
                    size: 0
                },
            }
        );
        assert!(walk_rebase_opcodes(&[], 0, &ctx64()).is_empty());
    }

    #[test]
    fn rebase_32bit_keeps_segment_offset_and_huge_counts_wrap() {
        let ctx = WalkContext {
            is64: false,
            base_address: 0x1000,
            segment_vmaddrs: vec![0x1000, 0x2000],
        };
        // SET_SEGMENT(1) + 0x20, DO_REBASE_ULEB_TIMES u64::MAX, DONE.
        let mut bytes = vec![0x21, 0x20, 0x60];
        bytes.extend([0xff; 9]);
        bytes.extend([0x01, 0x00]);
        let ops = walk_rebase_opcodes(&bytes, 0, &ctx);
        assert_eq!(ops[0].address, 0x2020);
        assert_eq!(ops[2].op, RebaseOp::Done);
        assert_eq!(
            ops[2].address,
            0x2020u64.wrapping_add(u64::MAX.wrapping_mul(4))
        );
        // Segment index out of range leaves the address alone.
        let ops = walk_rebase_opcodes(&[0x2f, 0x08, 0x00], 0, &ctx);
        assert_eq!(ops[0].address, 0x1000);
    }

    #[test]
    fn bind_stream() {
        let mut bytes = vec![0x12, 0x40 | 0x1];
        bytes.extend(b"_puts\0");
        bytes.extend([
            0x51, 0x72, 0x08, 0x60, 0x7e, 0x90, 0x3f, 0x20, 0x85, 0x01, 0xB2, 0xC0, 0x03, 0x10,
            0xD0, 0x00, 0x90,
        ]);
        let ops = walk_bind_opcodes(&bytes, 0x100, BindKind::Bind, &ctx64());
        let kinds: Vec<u8> = ops.iter().map(|o| o.opcode).collect();
        // 0xD0 (unknown) is not reported; the walk ends at DONE.
        assert_eq!(
            kinds,
            [0x10, 0x40, 0x50, 0x70, 0x60, 0x90, 0x30, 0x20, 0xB0, 0xC0, 0x00]
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
        assert_eq!((ops[2].bind_type, ops[3].bind_type), (1, 0));
        assert_eq!(
            ops[4].op,
            BindOp::SetAddendSleb {
                addend: Leb {
                    value: -2,
                    offset: 0x10c,
                    size: 1
                }
            }
        );
        // DO_BIND reports the address after the bind.
        assert_eq!(ops[5].address, 0x1_0000_4008);
        assert_eq!(ops[6].op, BindOp::SetDylibSpecialImm { ordinal: u64::MAX });
        assert_eq!(
            ops[7].op,
            BindOp::SetDylibOrdinalUleb {
                ordinal: Leb {
                    value: 0x85,
                    offset: 0x110,
                    size: 2
                }
            }
        );
        assert_eq!(ops[8].op, BindOp::DoBindAddAddrImmScaled { scale: 2 });
        assert_eq!(ops[9].address, 0x1_0000_4018);
        assert_eq!(ops[10].address, 0x1_0000_4018 + 3 * (8 + 0x10));
    }

    #[test]
    fn bind_special_ordinals() {
        let ops = walk_bind_opcodes(&[0x30, 0x3e, 0x3d], 0, BindKind::Bind, &ctx64());
        let ordinals: Vec<u64> = ops
            .iter()
            .map(|o| match o.op {
                BindOp::SetDylibSpecialImm { ordinal } => ordinal,
                _ => panic!("unexpected op"),
            })
            .collect();
        assert_eq!(ordinals, [0, (-2i64) as u64, (-3i64) as u64]);
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
    fn bind_unterminated_name_ends_walk() {
        let ops = walk_bind_opcodes(&[0x11, 0x40, b'a', b'b'], 0, BindKind::Bind, &ctx64());
        assert_eq!(ops.len(), 1);
        // Name opcode as the very last byte.
        assert_eq!(
            walk_bind_opcodes(&[0x40], 0, BindKind::LazyBind, &ctx64()).len(),
            0
        );
    }

    /// root -> "_a" (terminal, flags 0, offset 0x10) and "_b" (no terminal).
    fn small_trie() -> Vec<u8> {
        let mut t = vec![0x00, 0x02];
        t.extend(b"_a\0");
        t.push(10);
        t.extend(b"_b\0");
        t.push(14);
        assert_eq!(t.len(), 10);
        t.extend([0x02, 0x00, 0x10, 0x00]); // node @10
        t.extend([0x00, 0x00]); // node @14
        t
    }

    #[test]
    fn export_trie_walk() {
        let nodes = walk_classic_export_trie(&small_trie(), 0x4000);
        assert_eq!(nodes.len(), 3);
        assert_eq!(
            (
                nodes[0].terminal_size,
                nodes[0].child_count,
                nodes[0].child_count_offset
            ),
            (0, 2, 0x4001)
        );
        assert_eq!(nodes[0].children[0].label, b"_a");
        assert_eq!(
            (
                nodes[0].children[0].label_offset,
                nodes[0].children[0].label_size
            ),
            (0x4002, 3)
        );
        assert_eq!(
            nodes[0].children[1].skip,
            Leb {
                value: 14,
                offset: 0x4009,
                size: 1
            }
        );
        assert_eq!(nodes[1].terminal_size_offset, 0x400a);
        assert_eq!(
            nodes[1].flags,
            Some(Leb {
                value: 0,
                offset: 0x400b,
                size: 1
            })
        );
        assert_eq!(
            nodes[1].symbol_offset,
            Some(Leb {
                value: 0x10,
                offset: 0x400c,
                size: 1
            })
        );
        assert_eq!(
            nodes[1].flag_names(),
            [("00", "EXPORT_SYMBOL_FLAGS_KIND_REGULAR")]
        );
        assert_eq!(
            (nodes[2].terminal_size, nodes[2].flags, nodes[2].child_count),
            (0, None, 0)
        );
    }

    #[test]
    fn export_trie_cycles_terminate() {
        // Root with one child pointing back at the root, and one at itself.
        let mut t = vec![0x00, 0x02, b'a', 0x00, 0x00, b'b', 0x00, 0x08];
        t.extend([0x00, 0x01, b'c', 0x00, 0x08]);
        let nodes = walk_classic_export_trie(&t, 0);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].children.len(), 1);
    }

    #[test]
    fn export_trie_truncated() {
        assert!(walk_classic_export_trie(&[], 0).is_empty());
        // Terminal payload cut short: the node is dropped.
        assert!(walk_classic_export_trie(&[0x02, 0x80], 0).is_empty());
        assert!(walk_classic_export_trie(&[0x02, 0x00, 0x10], 0).is_empty());
        // Child label without terminator / without skip: children stop.
        let nodes = walk_classic_export_trie(&[0x00, 0x03, b'a', 0x00, 0x09, b'b'], 0);
        assert_eq!(nodes.len(), 1);
        assert_eq!((nodes[0].child_count, nodes[0].children.len()), (3, 1));
        let nodes = walk_classic_export_trie(&[0x00, 0x01, b'a', 0x00], 0);
        assert_eq!(nodes[0].children.len(), 0);
    }

    #[test]
    fn export_trie_overlapping_nodes_are_capped() {
        // Every byte is a node with 0x41 children labelled "A..."; the walk
        // must stay bounded.
        let mut t = vec![0x00];
        for i in 0..4000u32 {
            t.extend([0x00, 0x41, 0x00, (i % 100) as u8]);
        }
        let nodes = walk_classic_export_trie(&t, 0);
        assert!(nodes.len() <= MAX_TRIE_NODES);
        let edges: usize = nodes.iter().map(|n| n.children.len()).sum();
        assert!(edges <= MAX_TRIE_EDGES + 255);
    }

    #[test]
    fn flag_names() {
        assert_eq!(
            export_flag_names(0x1d),
            [
                ("01", "EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL"),
                ("04", "EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION"),
                ("08", "EXPORT_SYMBOL_FLAGS_REEXPORT"),
                ("10", "EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER"),
            ]
        );
        assert!(export_flag_names(0x02).is_empty());
        assert_eq!(rebase_type_name(2), "REBASE_TYPE_TEXT_ABSOLUTE32");
        assert_eq!(bind_type_name(0), "Unknown");
    }
}
