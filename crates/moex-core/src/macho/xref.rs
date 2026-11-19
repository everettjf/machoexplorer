//! Cross references: pointer values stored in pointer-like sections plus
//! what the code sections (`__text`, `__stubs`, `__stub_helper`, ...) refer
//! to.
//!
//! The code is decoded by Capstone (see [`super::disasm`]) region by region:
//! decoding restarts at every symbol and function start and steps over
//! data-in-code ranges and undecodable bytes. Per instruction the
//! architecture modules ([`arm64`], [`x86`], [`arm`]) turn Capstone's
//! groups, operands and register access lists into a [`Step`]; the sweep
//! follows the values of the general registers through straight-line code
//! to complete addresses that take more than one instruction (`adrp` +
//! `add`, `adrp` + `ldr`, loads through a pointer slot).
//!
//! Register values are followed within one run of code at a time (the
//! instructions between two places where decoding restarts: in practice a
//! function), along every path: at a label, what a register holds is what
//! it holds on all the ways of getting there, loops included. Nothing is
//! known at the start of a run, at a label that is also reached from
//! elsewhere, across calls (caller-saved registers) and whenever an
//! instruction writes a register in a way the sweep does not model.
//!
//! A jump through a jump table goes to every case of the table, and what
//! is known at the jump is known in the cases. The shapes clang gives a
//! `switch` on arm64 and x86-64 are recognised: the address of the table,
//! an entry loaded at an index (32-bit offsets, or bytes and halfwords
//! counted in instructions), added to the table's address or to another
//! address of the function, and a jump to the sum. The number of entries
//! is what the range check of the index allows (`cmp` and an unsigned
//! conditional jump, or the `csel` that clamps the index); without one the
//! table ends where something else is known to start. A table counts only
//! when every entry leads to an instruction of the same run. Other
//! indirect jumps are not followed: code reached only through one starts
//! with nothing known.
//!
//! In an object file the operands of an instruction a relocation patches
//! are placeholders; the relocation entry supplies the symbol, and with it
//! the address when the symbol is defined in the file. On 32-bit x86 and
//! ARM that covers branches, absolute operands, the two halves of an
//! address (`movw` / `movt`) and the differences that
//! position-independent code adds to the program counter.

mod arm;
mod arm64;
mod x86;

use super::chained_fixups::{
    ChainedFixupsHeader, ChainedStartsInSegment, DYLD_CHAINED_PTR_32, DYLD_CHAINED_PTR_64,
    DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
    DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_ARM64E_USERLAND,
    DYLD_CHAINED_PTR_ARM64E_USERLAND24,
};
use super::disasm::{self, Disassembler, Item};
use super::header::MachHeader;
use super::ptr::{Pointer as Decoded, PointerDecoder};
use super::reloc;
use super::segment::Section;
use crate::consts::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_I386, CPU_TYPE_X86_64,
    LC_DYLD_CHAINED_FIXUPS, MH_OBJECT,
};
use capstone::{Capstone, Insn, InsnGroupType};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const SECTION_TYPE: u32 = 0x0000_00ff;
const S_CSTRING_LITERALS: u32 = 0x2;
const S_LITERAL_POINTERS: u32 = 0x5;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;

/// A general register, numbered per architecture. Every width of a register
/// has the same number (`x8`/`w8`, `rax`/`eax`/`al`).
type Reg = u8;

/// A set of [`Reg`]s.
type RegSet = u32;

fn bit(reg: Reg) -> RegSet {
    1u32.checked_shl(reg as u32).unwrap_or(0)
}

/// A memory operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mem {
    /// Base register; `None` when `offset` is the whole address
    /// (pc-relative and absolute operands).
    base: Option<Reg>,
    offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemUse {
    Load,
    Store,
    /// The address is taken, the memory is not touched (`lea`).
    Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Flow {
    #[default]
    None,
    Jump {
        conditional: bool,
    },
    Call,
    Return,
}

/// Where a jump or call goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Target {
    #[default]
    None,
    Address(u64),
    Reg(Reg),
    /// Through the pointer stored at `Step::mem`.
    Mem,
}

/// The value an instruction gives its destination register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Def {
    /// Not something the sweep follows.
    #[default]
    None,
    Const(u64),
    /// The page of an address (`adrp`), to be completed.
    Page(u64),
    /// A complete pc-relative address (`adr`).
    Address(u64),
    /// `src + imm`.
    Add {
        src: Reg,
        imm: u64,
    },
    Copy {
        src: Reg,
    },
    /// Replace 16 bits of the destination.
    MovK {
        imm16: u64,
        shift: u32,
    },
    /// The address of `Step::mem` (`lea`).
    Lea,
    /// The `size` bytes stored at `Step::mem`.
    Load {
        size: u8,
        signed: bool,
    },
    /// The return address pushed by a preceding call to the next
    /// instruction (the 32-bit x86 way of reading the program counter).
    Pop,
    /// The `size` bytes at `base + index * size`: an entry of a table.
    LoadIndex {
        base: Reg,
        index: Reg,
        size: u8,
        signed: bool,
    },
    /// `a + (b << shift)`.
    AddReg {
        a: Reg,
        b: Reg,
        shift: u8,
    },
    /// `src` when the comparison before it found it within the bound
    /// (`Step::cond`), otherwise zero (`csel x16, x16, xzr, ls`).
    Clamp {
        src: Reg,
    },
}

/// An unsigned condition on the flags a comparison `reg ? imm` left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cond {
    /// `reg > imm`
    Above,
    /// `reg <= imm`
    NotAbove,
    /// `reg >= imm`
    NotBelow,
    /// `reg < imm`
    Below,
}

impl Cond {
    /// The greatest value of the register when the condition holds
    /// (`holds`) or does not, if that bounds it.
    fn max(self, imm: u64, holds: bool) -> Option<u64> {
        match (self, holds) {
            (Cond::NotAbove, true) | (Cond::Above, false) => Some(imm),
            (Cond::Below, true) | (Cond::NotBelow, false) => imm.checked_sub(1),
            _ => None,
        }
    }
}

/// What the sweep needs to know about one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Step {
    flow: Flow,
    target: Target,
    /// The memory operand, when its address can be told from at most one
    /// register.
    mem: Option<(Mem, MemUse)>,
    def: Def,
    dst: Option<Reg>,
    /// The destination is the 32-bit form of the register: the result is
    /// zero-extended.
    narrow: bool,
    /// Every general register the instruction may change.
    writes: RegSet,
    /// A comparison of a register with a number (`cmp w8, #5`).
    compare: Option<(Reg, u64)>,
    /// The instruction changes the condition flags.
    flags: bool,
    /// The condition a conditional jump is taken on, or a `Def::Clamp`
    /// selects on, when it is an unsigned comparison.
    cond: Option<Cond>,
}

/// Capstone's architecture-independent groups an instruction belongs to.
#[derive(Debug, Clone, Copy, Default)]
struct Groups {
    jump: bool,
    call: bool,
    ret: bool,
}

impl Groups {
    fn of(detail: &capstone::InsnDetail<'_>) -> Self {
        let mut g = Groups::default();
        for group in detail.groups() {
            match group.0 as u32 {
                InsnGroupType::CS_GRP_JUMP => g.jump = true,
                InsnGroupType::CS_GRP_CALL => g.call = true,
                InsnGroupType::CS_GRP_RET | InsnGroupType::CS_GRP_IRET => g.ret = true,
                _ => {}
            }
        }
        g
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86,
    X64,
    Arm64,
    Arm,
}

impl Arch {
    fn of(cputype: u32) -> Option<Arch> {
        match cputype {
            CPU_TYPE_I386 => Some(Arch::X86),
            CPU_TYPE_X86_64 => Some(Arch::X64),
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => Some(Arch::Arm64),
            CPU_TYPE_ARM => Some(Arch::Arm),
            _ => None,
        }
    }

    fn step(self, cs: &Capstone, insn: &Insn<'_>) -> Option<Step> {
        let detail = cs.insn_detail(insn).ok()?;
        Some(match self {
            Arch::Arm64 => arm64::step(insn, &detail),
            Arch::X64 | Arch::X86 => x86::step(insn, &detail),
            Arch::Arm => arm::step(insn, &detail),
        })
    }

    /// Registers a called function may change.
    fn caller_saved(self) -> RegSet {
        match self {
            // x0-x18 and the link register.
            Arch::Arm64 => 0x4007_ffff,
            // rax, rcx, rdx, rsi, rdi, r8-r11.
            Arch::X64 => 0x0fc7,
            // eax, ecx, edx.
            Arch::X86 => 0x0007,
            Arch::Arm => 0,
        }
    }
}

/// How a reference was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    /// A pointer stored in a pointer section.
    Pointer,
    /// Direct call or jump.
    Call,
    Jump,
    /// Call or jump through a pointer at a pc-relative or absolute address.
    CallRipMem,
    JumpRipMem,
    /// Call or jump through a pointer at register + displacement.
    CallRegMem,
    JumpRegMem,
    /// Call or jump to the address in a register.
    CallReg,
    JumpReg,
    /// The address is computed (`adr`, `adrp` + `add`, `lea`).
    Address,
    /// The memory at the address is read or written.
    Load,
    Store,
    /// One of the targets of a jump through a jump table.
    JumpTable,
}

impl RefKind {
    pub fn name(self) -> &'static str {
        match self {
            RefKind::Pointer => "pointer",
            RefKind::Call => "call",
            RefKind::Jump => "jump",
            RefKind::CallRipMem => "call-ripmem",
            RefKind::JumpRipMem => "jump-ripmem",
            RefKind::CallRegMem => "call-regmem",
            RefKind::JumpRegMem => "jump-regmem",
            RefKind::CallReg => "call-reg",
            RefKind::JumpReg => "jump-reg",
            RefKind::JumpTable => "jump-table",
            RefKind::Address => "addr",
            RefKind::Load => "load",
            RefKind::Store => "store",
        }
    }

    /// True for references found in instructions.
    pub fn is_code(self) -> bool {
        self != RefKind::Pointer
    }

    /// True for calls and jumps.
    pub fn is_branch(self) -> bool {
        !matches!(
            self,
            RefKind::Pointer | RefKind::Address | RefKind::Load | RefKind::Store
        )
    }
}

/// One reference to a target address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefItem {
    /// Index into [`Xrefs::sources`].
    pub source: u32,
    pub kind: RefKind,
    /// File offset of the referring pointer or instruction.
    pub ref_raw: u64,
    /// Address of the referring instruction; 0 for pointers.
    pub ref_vm: u64,
}

/// All references of one Mach-O header, grouped by target address.
#[derive(Debug, Default)]
pub struct Xrefs {
    /// `segment/section` names referred to by [`RefItem::source`].
    pub sources: Vec<String>,
    /// Target address to its references, in discovery order.
    pub targets: BTreeMap<u64, Vec<RefItem>>,
    source_index: HashMap<String, u32>,
    seen: HashSet<(u64, u32, RefKind, u64, u64)>,
}

impl Xrefs {
    fn source(&mut self, name: String) -> u32 {
        if let Some(i) = self.source_index.get(&name) {
            return *i;
        }
        let i = self.sources.len() as u32;
        self.source_index.insert(name.clone(), i);
        self.sources.push(name);
        i
    }

    fn add(&mut self, target: u64, item: RefItem) {
        if self
            .seen
            .insert((target, item.source, item.kind, item.ref_raw, item.ref_vm))
        {
            self.targets.entry(target).or_default().push(item);
        }
    }

    pub fn source_name(&self, item: &RefItem) -> &str {
        self.sources
            .get(item.source as usize)
            .map(String::as_str)
            .unwrap_or("")
    }
}

/// How the contents of a section are scanned for pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerScan {
    No,
    /// A pointer section: every slot is a pointer.
    All,
    /// ObjC metadata: structures that mix pointers with other fields. Only
    /// values that point into the image count.
    Mapped,
}

fn pointer_scan(flags: u32, sectname: &str) -> PointerScan {
    match flags & SECTION_TYPE {
        S_LITERAL_POINTERS
        | S_NON_LAZY_SYMBOL_POINTERS
        | S_LAZY_SYMBOL_POINTERS
        | S_LAZY_DYLIB_SYMBOL_POINTERS
        | S_MOD_INIT_FUNC_POINTERS
        | S_MOD_TERM_FUNC_POINTERS => PointerScan::All,
        // `__objc_methname` and the like hold strings.
        S_CSTRING_LITERALS => PointerScan::No,
        _ if sectname.starts_with("__objc_") => PointerScan::Mapped,
        _ => PointerScan::No,
    }
}

/// What a stored pointer means once the loader has processed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pointer {
    /// Points at this address.
    Target(u64),
    /// Bound to a symbol of another image at load time.
    Bind,
}

/// Decodes a pointer slot of a segment whose fixups are chained in
/// `format`. Formats without a decoder are taken as plain addresses.
fn decode_chained(format: u16, raw: u64, image_base: u64) -> Pointer {
    match format {
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
            if raw >> 63 != 0 {
                return Pointer::Bind;
            }
            let target = (raw & 0x0000_000f_ffff_ffff) | ((raw >> 36) & 0xff) << 56;
            Pointer::Target(if format == DYLD_CHAINED_PTR_64_OFFSET {
                image_base.wrapping_add(target)
            } else {
                target
            })
        }
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE => {
            let auth = raw >> 63 != 0;
            if (raw >> 62) & 1 != 0 {
                Pointer::Bind
            } else if auth {
                // Authenticated rebases are always offsets from the image.
                Pointer::Target(image_base.wrapping_add(raw & 0xffff_ffff))
            } else {
                let target = (raw & ((1 << 43) - 1)) | ((raw >> 43) & 0xff) << 56;
                let absolute = matches!(
                    format,
                    DYLD_CHAINED_PTR_ARM64E | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
                );
                Pointer::Target(if absolute {
                    target
                } else {
                    image_base.wrapping_add(target)
                })
            }
        }
        DYLD_CHAINED_PTR_32 => {
            if (raw >> 31) & 1 != 0 {
                Pointer::Bind
            } else {
                Pointer::Target(raw & 0x03ff_ffff)
            }
        }
        _ => Pointer::Target(raw),
    }
}

/// Reads of the Mach-O's contents by virtual address.
struct Memory<'a> {
    mh: &'a MachHeader,
    /// Size of a pointer in bytes.
    pointer_size: u8,
    image_base: u64,
    /// Chained pointer format per segment (by load command order), from
    /// `LC_DYLD_CHAINED_FIXUPS`; `None` for segments without fixups.
    chained: Vec<Option<u16>>,
    /// For the slots of object-file relocations and threaded binds.
    decoder: PointerDecoder<'a>,
    /// Addresses of the symbols defined in the file, sorted; read when the
    /// first jump table without a visible bound is met.
    symbols: std::cell::OnceCell<Vec<u64>>,
    /// Address and length of what the relocation entries of an object
    /// file patch, sorted; read when the first jump table is met.
    relocated: std::cell::OnceCell<Vec<(u64, u8)>>,
    /// Address ranges of the sections, sorted; read when the first jump
    /// table without a visible bound is met.
    sections: std::cell::OnceCell<Vec<(u64, u64)>>,
}

impl<'a> Memory<'a> {
    fn new(mh: &'a MachHeader) -> Self {
        Memory {
            mh,
            pointer_size: if mh.is64 { 8 } else { 4 },
            image_base: mh.base_address(),
            chained: chained_formats(mh),
            decoder: PointerDecoder::new(mh),
            symbols: std::cell::OnceCell::new(),
            relocated: std::cell::OnceCell::new(),
            sections: std::cell::OnceCell::new(),
        }
    }

    /// Where the section that holds `address` ends.
    fn section_end(&self, address: u64) -> Option<u64> {
        let sections = self.sections.get_or_init(|| {
            let mut out: Vec<(u64, u64)> = self
                .mh
                .sections()
                .map(|s| (s.addr, s.addr.saturating_add(s.size)))
                .collect();
            out.sort_unstable();
            out
        });
        // The last section that starts at or before the address.
        let (_, end) = *sections.get(
            sections
                .partition_point(|s| s.0 <= address)
                .checked_sub(1)?,
        )?;
        (address < end).then_some(end)
    }

    /// True when a relocation entry of an object file patches one of the
    /// `size` bytes at `vmaddr`, so that they do not hold their final
    /// value.
    fn is_relocated(&self, vmaddr: u64, size: u64) -> bool {
        if self.mh.filetype != MH_OBJECT {
            return false;
        }
        let relocated = self.relocated.get_or_init(|| {
            // No more entries than fit in the file.
            let mut left = self.mh.image.len() / reloc::ENTRY_SIZE;
            let mut out = Vec::new();
            for sect in self.mh.sections() {
                let entries = reloc::section_relocs(self.mh, sect, left);
                left -= entries.len() as u64;
                out.extend(
                    entries
                        .iter()
                        .map(|r| (sect.addr.wrapping_add(u64::from(r.address)), 1 << r.length)),
                );
            }
            out.sort_unstable();
            out
        });
        // An entry patches at most eight bytes from its address on.
        let from = relocated.partition_point(|r| r.0 < vmaddr.saturating_sub(7));
        relocated
            .get(from..)
            .unwrap_or(&[])
            .iter()
            .take_while(|r| r.0 < vmaddr.saturating_add(size))
            .any(|r| r.0.saturating_add(u64::from(r.1)) > vmaddr)
    }

    /// The address of the first symbol defined after `address`.
    fn next_symbol(&self, address: u64) -> Option<u64> {
        let symbols = self.symbols.get_or_init(|| {
            let mut out: Vec<u64> = self
                .mh
                .symtab()
                .map(|symtab| {
                    symtab
                        .symbols()
                        .filter(|s| s.n_type & 0xe0 == 0 && s.n_type & 0x0e == 0x0e)
                        .map(|s| s.n_value)
                        .collect()
                })
                .unwrap_or_default();
            out.sort_unstable();
            out.dedup();
            out
        });
        symbols
            .get(symbols.partition_point(|s| *s <= address))
            .copied()
    }

    /// True when `vmaddr` lies in a segment the program can access (not
    /// `__PAGEZERO`).
    fn is_mapped(&self, vmaddr: u64) -> bool {
        self.mh.segments.iter().any(|s| {
            (s.initprot | s.maxprot) != 0 && vmaddr >= s.vmaddr && vmaddr - s.vmaddr < s.vmsize
        })
    }

    /// Index of the segment mapping `vmaddr` and the file offset of the
    /// `size` bytes there. Segment offsets count from the Mach-O header,
    /// which is not the start of the file inside a fat file or an archive.
    fn locate(&self, vmaddr: u64, size: u64) -> Option<(usize, u64)> {
        let (index, seg) = self
            .mh
            .segments
            .iter()
            .enumerate()
            .find(|(_, s)| vmaddr >= s.vmaddr && vmaddr - s.vmaddr < s.vmsize)?;
        let delta = vmaddr - seg.vmaddr;
        if delta > seg.filesize || size > seg.filesize - delta {
            return None;
        }
        let offset = self
            .mh
            .offset
            .checked_add(seg.fileoff)?
            .checked_add(delta)?;
        Some((index, offset))
    }

    /// The value of `size` (1, 2, 4 or 8) bytes at `vmaddr`, in the byte
    /// order of the file.
    fn read(&self, vmaddr: u64, size: u8) -> Option<u64> {
        let (_, offset) = self.locate(vmaddr, size as u64)?;
        let image = &self.mh.image;
        match size {
            1 => image.u8(offset).map(u64::from),
            2 => image.u16(offset).map(u64::from),
            4 => image.u32(offset).map(u64::from),
            8 => image.u64(offset),
            _ => None,
        }
    }

    /// What the raw pointer value `raw`, stored at file offset `at` in
    /// segment `segment`, will point at. `None` for null and for pointers
    /// bound at load time.
    fn resolve(&self, segment: Option<usize>, at: u64, raw: u64) -> Option<u64> {
        // A relocation of an object file or a threaded fixup decides.
        match self.decoder.relocated_or_threaded(at, raw) {
            // An object file can define a symbol at address 0.
            Some(Decoded::Address(address)) => {
                return (address != 0 || self.mh.filetype == MH_OBJECT).then_some(address)
            }
            Some(Decoded::Import { .. }) => return None,
            None => {}
        }
        if raw == 0 {
            return None;
        }
        let format = segment.and_then(|i| self.chained.get(i).copied().flatten());
        match format {
            Some(format) => match decode_chained(format, raw, self.image_base) {
                Pointer::Target(t) => Some(t),
                Pointer::Bind => None,
            },
            None => Some(raw),
        }
    }

    /// The address the pointer stored at `vmaddr` will hold.
    fn pointer(&self, vmaddr: u64) -> Option<u64> {
        let (segment, at) = self.locate(vmaddr, self.pointer_size as u64)?;
        self.resolve(Some(segment), at, self.read(vmaddr, self.pointer_size)?)
    }
}

/// The chained pointer format of each segment, in load command order.
fn chained_formats(mh: &MachHeader) -> Vec<Option<u16>> {
    let mut out = Vec::new();
    let Some(data) = mh.linkedit_data(LC_DYLD_CHAINED_FIXUPS) else {
        return out;
    };
    let image = &mh.image;
    let Some(header) = ChainedFixupsHeader::read(image, data.file_offset) else {
        return out;
    };
    // dyld_chained_starts_in_image: seg_count, then one offset per segment.
    let Some(starts) = data.file_offset.checked_add(header.starts_offset as u64) else {
        return out;
    };
    let seg_count = image.u32(starts).unwrap_or(0) as usize;
    for i in 0..seg_count.min(mh.segments.len()) {
        let info = starts
            .checked_add(4 + 4 * i as u64)
            .and_then(|at| image.u32(at))
            .filter(|off| *off != 0)
            .and_then(|off| starts.checked_add(off as u64))
            .and_then(|at| ChainedStartsInSegment::read(image, at));
        out.push(info.map(|s| s.pointer_format));
    }
    out
}

/// Upper bound on the bytes scanned per Mach-O header. Sections of a
/// well-formed file do not overlap, so it never comes close; it only stops a
/// crafted file whose sections all alias the same bytes. Sweeping a code
/// section costs a quarter of the file size on top of its bytes.
fn scan_budget(mh: &MachHeader) -> u64 {
    mh.image.len().saturating_mul(4).saturating_add(4096)
}

/// What a relocation entry of an object file does to the instruction it
/// patches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Patch {
    /// The operands already hold the address (section-relative entries:
    /// the assembler wrote the value the linker would).
    Keep,
    /// Not resolved: an undefined symbol, a difference of two addresses, a
    /// thread-local or other special entry.
    Drop,
    /// x86-64, pc-relative, to a symbol defined at `symbol`. The decoded
    /// operand is `bias + addend`. `got`: through the symbol's GOT slot.
    X64 { symbol: u64, bias: u64, got: bool },
    /// arm64 entry of type `kind` whose target (symbol plus addend) is
    /// `target`.
    A64 { kind: u8, target: u64 },
    /// 32-bit x86 and ARM: a pc-relative branch to a symbol
    /// defined at `symbol`. The decoded target is the addend.
    Branch { symbol: u64 },
    /// 32-bit x86: an absolute operand naming a symbol defined at
    /// `symbol`. The decoded operand is the addend.
    Absolute { symbol: u64 },
    /// 32-bit x86: an absolute operand that already holds the address
    /// (a section-relative entry). An immediate is therefore an address
    /// (`mov eax, offset L`), not just a number.
    Immediate,
    /// 32-bit ARM: one of the two instructions that build the address
    /// `target` from its halves (`movw` / `movt`).
    /// `low`: the one with the low half, where the address is reported.
    Half { target: u64, low: bool },
}

/// The 16-bit immediate of the 32-bit ARM `movw` / `movt` at `offset`.
fn arm_imm16(code: &[u8], offset: u32, thumb: bool) -> Option<u64> {
    let at = offset as usize;
    let bytes = code.get(at..at.checked_add(4)?)?;
    Some(if thumb {
        let first = u64::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let second = u64::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        (first & 0xf) << 12 | (first >> 10 & 1) << 11 | (second >> 12 & 7) << 8 | (second & 0xff)
    } else {
        let word = u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        (word >> 16 & 0xf) << 12 | (word & 0xfff)
    })
}

/// How far ahead of the 32-bit ARM instruction at `offset` the program
/// counter reads, when that instruction adds a register to it: `add rN, pc`
/// (Thumb), `add rN, pc, rM` or `ldr rN, [pc, rM]` (ARM).
fn arm_pc_ahead(code: &[u8], offset: u64, thumb: bool) -> Option<u64> {
    let at = usize::try_from(offset).ok()?;
    if thumb {
        let bytes = code.get(at..at.checked_add(2)?)?;
        let half = u16::from_le_bytes([bytes[0], bytes[1]]);
        (half & 0xff78 == 0x4478).then_some(4)
    } else {
        let bytes = code.get(at..at.checked_add(4)?)?;
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // `add rN, pc, rM`, or a load or store at `[pc, rM]`.
        (word & 0x0fef_0ff0 == 0x008f_0000 || word & 0x0f2f_0ff0 == 0x070f_0000).then_some(8)
    }
}

/// The patches of a code section whose contents are `code`, sorted by the
/// section offset they apply to. Charges `budget` 8 bytes per entry read.
fn code_patches(
    mh: &MachHeader,
    sect: &Section,
    code: &[u8],
    budget: &mut u64,
) -> Vec<(u32, Patch)> {
    use reloc::*;
    let entries = section_relocs(mh, sect, *budget / ENTRY_SIZE);
    *budget -= entries.len() as u64 * ENTRY_SIZE;
    let symtab = mh.symtab();
    // Address of a symbol defined in this file.
    let defined = |index: u32| {
        let symbol = symtab.as_ref()?.symbol(index)?;
        let here = symbol.n_type & 0xe0 == 0 && matches!(symbol.n_type & 0x0e, 0x0e | 0x02);
        here.then_some(symbol.n_value)
    };
    // Addresses of the Thumb functions of a 32-bit ARM file: a pointer to
    // one has its low bit set, which is not part of the address.
    let thumb_functions: HashSet<u64> = match (mh.cputype, symtab.as_ref()) {
        (CPU_TYPE_ARM, Some(symtab)) if !entries.is_empty() => symtab
            .symbols()
            .filter(|s| s.n_type & 0xe0 == 0 && s.n_type & 0x0e == 0x0e && s.n_desc & 0x8 != 0)
            .map(|s| s.n_value)
            .collect(),
        _ => HashSet::new(),
    };
    let mut out: Vec<(u32, Patch)> = Vec::with_capacity(entries.len());
    // `ARM64_RELOC_ADDEND` applies to the entry after it.
    let mut addend: Option<(u32, i64)> = None;
    // A branch of the 32-bit architectures: a section-relative or scattered
    // entry leaves the displacement in the instruction, an external one
    // leaves the addend there.
    let branch = |r: &Reloc| {
        if r.scattered || !r.external {
            Patch::Keep
        } else {
            defined(r.symbolnum).map_or(Patch::Drop, |symbol| Patch::Branch { symbol })
        }
    };
    // What a `*_SECTDIFF` or half entry and its `PAIR` say about the
    // address `value` the instruction (and the pair) holds: for a
    // difference it counts from the address the pair names, for a symbol
    // from the symbol.
    let half = |r: &Reloc, pair: Option<Reloc>, difference: bool, value: u64, low: bool| {
        let base = match pair {
            Some(pair) if difference && r.scattered && pair.scattered => {
                Some(u64::from(pair.value))
            }
            Some(_) if difference => None,
            Some(_) if r.external && !r.scattered => defined(r.symbolnum),
            Some(_) => Some(0),
            None => None,
        };
        base.map_or(Patch::Drop, |base| Patch::Half {
            target: base.wrapping_add(value) & 0xffff_ffff,
            low,
        })
    };
    let mut entries = entries.into_iter().peekable();
    while let Some(r) = entries.next() {
        // The second entry of a pair, wherever the first needs one. Its
        // address field is not an address.
        let mut pair = || entries.next_if(|next| next.kind == RELOC_PAIR);
        let patch = match mh.cputype {
            CPU_TYPE_I386 => match r.kind {
                RELOC_PAIR => continue,
                // The difference of two addresses in the file, which the
                // operand holds: position-independent code adds it to the
                // address it counts from.
                GENERIC_RELOC_SECTDIFF | GENERIC_RELOC_LOCAL_SECTDIFF => {
                    pair();
                    Patch::Keep
                }
                RELOC_UNSIGNED if (r.scattered || !r.external) && !r.pcrel && r.length == 2 => {
                    Patch::Immediate
                }
                RELOC_UNSIGNED if r.scattered || !r.external => Patch::Keep,
                RELOC_UNSIGNED if r.length == 2 => match (defined(r.symbolnum), r.pcrel) {
                    (Some(symbol), true) => Patch::Branch { symbol },
                    (Some(symbol), false) => Patch::Absolute { symbol },
                    (None, _) => Patch::Drop,
                },
                _ => Patch::Drop,
            },
            CPU_TYPE_ARM => match r.kind {
                RELOC_PAIR => continue,
                RELOC_UNSIGNED if r.scattered || !r.external => Patch::Keep,
                ARM_RELOC_BR24 | ARM_THUMB_RELOC_BR22 => branch(&r),
                ARM_RELOC_HALF | ARM_RELOC_HALF_SECTDIFF => {
                    // The length field says which half the instruction
                    // holds and whether it is a Thumb instruction; the
                    // pair's address field holds the other half.
                    let (high, thumb) = (r.length & 1 != 0, r.length & 2 != 0);
                    let pair = pair();
                    let other = pair.map_or(0, |p| u64::from(p.address) & 0xffff);
                    let difference = r.kind == ARM_RELOC_HALF_SECTDIFF;
                    // A difference counts from the `add rN, pc` that turns
                    // it into an address, where the program counter reads
                    // 4 (Thumb) or 8 bytes ahead.
                    let ahead = match pair {
                        Some(pair) if difference => u64::from(pair.value)
                            .checked_sub(sect.addr)
                            .and_then(|offset| arm_pc_ahead(code, offset, thumb)),
                        _ => Some(0),
                    };
                    let patch = match (arm_imm16(code, r.address, thumb), ahead) {
                        (Some(imm), Some(ahead)) => half(
                            &r,
                            pair,
                            difference,
                            if high {
                                imm << 16 | other
                            } else {
                                other << 16 | imm
                            }
                            .wrapping_add(ahead),
                            !high,
                        ),
                        _ => Patch::Drop,
                    };
                    match patch {
                        Patch::Half { target, low }
                            if target & 1 != 0 && thumb_functions.contains(&(target - 1)) =>
                        {
                            Patch::Half {
                                target: target - 1,
                                low,
                            }
                        }
                        other => other,
                    }
                }
                ARM_RELOC_SECTDIFF | ARM_RELOC_LOCAL_SECTDIFF => {
                    pair();
                    Patch::Drop
                }
                _ => Patch::Drop,
            },
            _ if r.scattered => {
                // The entry names the target's address, which the operand
                // holds too; section differences are not addresses.
                if r.kind == RELOC_UNSIGNED {
                    Patch::Keep
                } else {
                    Patch::Drop
                }
            }
            CPU_TYPE_X86_64 => match (r.kind, r.external, r.pcrel) {
                (
                    X86_64_RELOC_SIGNED
                    | X86_64_RELOC_SIGNED_1
                    | X86_64_RELOC_SIGNED_2
                    | X86_64_RELOC_SIGNED_4
                    | X86_64_RELOC_BRANCH,
                    false,
                    true,
                ) => Patch::Keep,
                (
                    kind @ (X86_64_RELOC_SIGNED
                    | X86_64_RELOC_SIGNED_1
                    | X86_64_RELOC_SIGNED_2
                    | X86_64_RELOC_SIGNED_4
                    | X86_64_RELOC_BRANCH
                    | X86_64_RELOC_GOT_LOAD
                    | X86_64_RELOC_GOT),
                    true,
                    true,
                ) if r.length == 2 => match defined(r.symbolnum) {
                    Some(symbol) => Patch::X64 {
                        symbol,
                        // The stored displacement counts from the end of
                        // its own four bytes.
                        bias: sect.addr.wrapping_add(u64::from(r.address)).wrapping_add(4),
                        got: matches!(kind, X86_64_RELOC_GOT_LOAD | X86_64_RELOC_GOT),
                    },
                    None => Patch::Drop,
                },
                _ => Patch::Drop,
            },
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => {
                if r.kind == ARM64_RELOC_ADDEND {
                    // A signed 24-bit number in place of the symbol.
                    let value = ((r.symbolnum << 8) as i32 >> 8) as i64;
                    addend = Some((r.address, value));
                    continue;
                }
                let extra = match addend.take() {
                    Some((address, value)) if address == r.address => value,
                    _ => 0,
                };
                match r.kind {
                    ARM64_RELOC_BRANCH26
                    | ARM64_RELOC_PAGE21
                    | ARM64_RELOC_PAGEOFF12
                    | ARM64_RELOC_GOT_LOAD_PAGEOFF12
                        if r.external =>
                    {
                        match defined(r.symbolnum) {
                            Some(symbol) => Patch::A64 {
                                kind: r.kind,
                                target: symbol.wrapping_add(extra as u64),
                            },
                            None => Patch::Drop,
                        }
                    }
                    ARM64_RELOC_BRANCH26 | ARM64_RELOC_PAGE21 | ARM64_RELOC_PAGEOFF12 => {
                        Patch::Keep
                    }
                    _ => Patch::Drop,
                }
            }
            // Other architectures: a section-relative entry leaves the
            // address in the instruction.
            _ => {
                if !r.external && r.kind == RELOC_UNSIGNED {
                    Patch::Keep
                } else {
                    Patch::Drop
                }
            }
        };
        out.push((r.address, patch));
    }
    // Stable, so entries for one offset stay in table order.
    out.sort_by_key(|p| p.0);
    out
}

/// The patch of the instruction of `len` bytes at section offset `offset`,
/// from the sorted `patches` of the section; `Drop` when several entries
/// patch it.
fn patch_at(patches: &[(u32, Patch)], offset: u64, len: u64) -> Option<Patch> {
    let i = patches.partition_point(|p| u64::from(p.0) < offset);
    let end = offset.saturating_add(len);
    let mut inside = patches
        .get(i..)
        .unwrap_or(&[])
        .iter()
        .take_while(|p| u64::from(p.0) < end);
    let first = inside.next()?.1;
    Some(if inside.next().is_some() {
        Patch::Drop
    } else {
        first
    })
}

/// Targets of the direct jumps and calls of a code section, sorted, one
/// entry per instruction. The sweep uses them to know every way a label is
/// reached; calls are included so that a label that is called is never
/// taken for one that is only fallen into. Where a relocation of an object
/// file supplies the target (`patches`), the target is the symbol's
/// address, or none when the symbol is not defined in the file: the
/// operand is a placeholder then.
fn branch_targets(
    mh: &MachHeader,
    arch: Arch,
    code: &[u8],
    base: u64,
    regions: &[disasm::Region],
    patches: &[(u32, Patch)],
) -> Vec<u64> {
    let mut out = Vec::new();
    // The target of the branch of `len` bytes at `at` whose operand reads
    // `decoded`.
    let patched =
        |at: u64, len: u64, decoded: u64| match patch_at(patches, at.wrapping_sub(base), len) {
            None | Some(Patch::Keep | Patch::Immediate) => Some(decoded),
            Some(Patch::A64 {
                kind: reloc::ARM64_RELOC_BRANCH26,
                target,
            }) => Some(target),
            Some(Patch::X64 {
                symbol,
                bias,
                got: false,
            }) => Some(symbol.wrapping_add(decoded.wrapping_sub(bias))),
            Some(Patch::Branch { symbol }) => Some(symbol.wrapping_add(decoded) & 0xffff_ffff),
            Some(_) => None,
        };
    match arch {
        // Fixed-width instructions: the branch encodings are recognised
        // directly. A word Capstone would not decode can add a label, which
        // only makes the sweep more careful.
        Arch::Arm64 => {
            for region in regions {
                if !matches!(region.kind, disasm::RegionKind::Code { .. }) {
                    continue;
                }
                let Some(chunk) = code.get(region.start..region.end) else {
                    continue;
                };
                for (i, word) in chunk.chunks_exact(4).enumerate() {
                    let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                    let field = |shift: u32, bits: u32| {
                        let value = (word >> shift) & ((1 << bits) - 1);
                        // Sign-extend and scale by the instruction size.
                        (((value << (32 - bits)) as i32) >> (32 - bits)) as i64 * 4
                    };
                    let offset = if word & 0x7c00_0000 == 0x1400_0000 {
                        // b, bl
                        field(0, 26)
                    } else if word & 0xff00_0000 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000
                    {
                        // b.cond, bc.cond, cbz, cbnz
                        field(5, 19)
                    } else if word & 0x7e00_0000 == 0x3600_0000 {
                        // tbz, tbnz
                        field(5, 14)
                    } else {
                        continue;
                    };
                    let at = base.wrapping_add((region.start + 4 * i) as u64);
                    out.extend(patched(at, 4, at.wrapping_add(offset as u64)));
                }
            }
        }
        // Variable-width: decoded without operand details, the target read
        // from the text of the one operand a direct branch has.
        Arch::X64 | Arch::X86 => {
            if let Ok(plain) = Disassembler::new(mh.cputype, mh.cpusubtype, false) {
                let _ = plain.run(code, base, regions, |item| {
                    let Item::Code { insn, .. } = item else {
                        return;
                    };
                    let mnemonic = insn.mnemonic().unwrap_or("");
                    if !(mnemonic.starts_with('j')
                        || mnemonic.starts_with("loop")
                        || mnemonic == "call")
                    {
                        return;
                    }
                    let target = insn
                        .op_str()
                        .and_then(|text| text.strip_prefix("0x"))
                        .and_then(|digits| u64::from_str_radix(digits, 16).ok());
                    // `call next` only reads the program counter (32-bit
                    // position-independent code): nothing arrives there
                    // from elsewhere.
                    let next = insn.address().wrapping_add(insn.len() as u64);
                    let reads_pc = arch == Arch::X86 && mnemonic == "call" && target == Some(next);
                    if let Some(target) = target.filter(|_| !reads_pc) {
                        out.extend(patched(insn.address(), insn.len() as u64, target));
                    }
                });
            }
        }
        // No registers are followed for 32-bit ARM, so labels do not
        // matter.
        Arch::Arm => {}
    }
    out.sort_unstable();
    out
}

/// Addresses that `adrp` and the instruction after it compute together
/// (`adrp` + `add`, `adrp` + a load or store), sorted: places where
/// something starts, as far as that can be told without following the
/// code. A jump table whose length the code does not show ends at the
/// next one at the latest. Only for linked arm64 images: in an object file
/// the operands are placeholders and the symbols do this job, and x86-64
/// jump tables lie in the code section, marked as data.
fn computed_addresses(
    mh: &MachHeader,
    arch: Arch,
    code: &[u8],
    base: u64,
    regions: &[disasm::Region],
) -> Vec<u64> {
    let mut out = Vec::new();
    if arch != Arch::Arm64 || mh.filetype == MH_OBJECT {
        return out;
    }
    for region in regions {
        if !matches!(region.kind, disasm::RegionKind::Code { .. }) {
            continue;
        }
        let Some(chunk) = code.get(region.start..region.end) else {
            continue;
        };
        let word = |i: usize| {
            let bytes = chunk.get(4 * i..4 * i + 4)?;
            Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        };
        for i in 0..chunk.len() / 4 {
            let (Some(first), Some(second)) = (word(i), word(i + 1)) else {
                continue;
            };
            if first & 0x9f00_0000 != 0x9000_0000 || (second >> 5) & 31 != first & 31 {
                continue;
            }
            // adrp: a signed 21-bit number of pages from this one.
            let pages = ((first >> 5) & 0x7_ffff) << 2 | (first >> 29) & 3;
            let pages = i64::from((pages << 11) as i32 >> 11);
            let at = base.wrapping_add((region.start + 4 * i) as u64);
            let page = (at & !0xfff).wrapping_add((pages << 12) as u64);
            let imm12 = u64::from((second >> 10) & 0xfff);
            let offset = if second & 0xffc0_0000 == 0x9100_0000 {
                // add xN, xN, #imm12
                imm12
            } else if second & 0x3b00_0000 == 0x3900_0000 {
                // A load or store of 1 << size bytes at [xN, #imm12 * size];
                // 16 bytes for the 128-bit form of the vector registers.
                let vector16 = second & 0x0480_0000 == 0x0480_0000;
                imm12 << if vector16 { 4 } else { second >> 30 }
            } else {
                continue;
            };
            out.push(page.wrapping_add(offset));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Collect every reference of `mh`.
pub fn collect(mh: &MachHeader) -> Xrefs {
    let mut refs = Xrefs::default();
    let mut budget = scan_budget(mh);
    let memory = Memory::new(mh);
    let object = mh.filetype == MH_OBJECT;

    // 32-bit segments first, then 64-bit ones.
    for want64 in [false, true] {
        for (seg_index, seg) in mh.segments.iter().enumerate() {
            if seg.is64 != want64 {
                continue;
            }
            for sect in &seg.sections {
                let scan = pointer_scan(sect.flags, &sect.sectname);
                if scan == PointerScan::No {
                    continue;
                }
                let data = sect.data(&mh.image);
                let data = data
                    .get(..(budget.min(data.len() as u64)) as usize)
                    .unwrap_or(&[]);
                budget -= data.len() as u64;
                let source = refs.source(format!("{}/{}", sect.segname, sect.sectname));
                let width = if sect.is64 { 8 } else { 4 };
                for (i, chunk) in data.chunks_exact(width).enumerate() {
                    let raw = mh.image.value_of(chunk).unwrap_or(0);
                    let ref_raw = sect.data_offset.wrapping_add((i * width) as u64);
                    // In an object file addresses start at 0, so any small
                    // number looks mapped; there the relocation entries
                    // say which slots are pointers.
                    let is_pointer = |target: u64| match scan {
                        PointerScan::All => true,
                        _ if object => memory.decoder.has_relocation(ref_raw),
                        _ => memory.is_mapped(target),
                    };
                    let Some(target) = memory
                        .resolve(Some(seg_index), ref_raw, raw)
                        .filter(|t| is_pointer(*t))
                    else {
                        continue;
                    };
                    refs.add(
                        target,
                        RefItem {
                            source,
                            kind: RefKind::Pointer,
                            ref_raw,
                            ref_vm: 0,
                        },
                    );
                }
            }
        }
    }

    let engine = Arch::of(mh.cputype).and_then(|arch| {
        Some((
            arch,
            Disassembler::new(mh.cputype, mh.cpusubtype, true).ok()?,
        ))
    });
    if let Some((arch, disassembler)) = engine {
        for want64 in [false, true] {
            for sect in mh
                .segments
                .iter()
                .filter(|s| s.is64 == want64)
                .flat_map(|s| s.sections.iter())
            {
                if !disasm::is_code_section(sect) {
                    continue;
                }
                let code = sect.data(&mh.image);
                let code = code
                    .get(..(budget.min(code.len() as u64)) as usize)
                    .unwrap_or(&[]);
                if code.is_empty() {
                    continue;
                }
                // Besides its bytes, a swept section costs a walk over the
                // symbols, function starts and relocations; charging for
                // that keeps a file with thousands of code sections
                // from repeating it for each.
                budget = (budget - code.len() as u64).saturating_sub(mh.image.len() / 4);
                let regions = disasm::regions(mh, sect, code.len());
                let patches = code_patches(mh, sect, code, &mut budget);
                let mut sweep = Sweep {
                    memory: &memory,
                    arch,
                    source: refs.source(format!("{}/{}", sect.segname, sect.sectname)),
                    base: sect.addr,
                    end: sect.addr.saturating_add(code.len() as u64),
                    raw_base: sect.data_offset,
                    targets: branch_targets(mh, arch, code, sect.addr, &regions, &patches),
                    patches,
                    starts: regions
                        .iter()
                        .map(|r| sect.addr.wrapping_add(r.start as u64))
                        .collect(),
                    tables: BTreeSet::new(),
                    addresses: computed_addresses(mh, arch, code, sect.addr, &regions),
                    table_budget: code.len() as u64,
                    run: Vec::new(),
                };
                // An engine failure only loses the rest of this section.
                let _ = disassembler.run(code, sect.addr, &regions, |item| match item {
                    Item::Code {
                        cs,
                        insn,
                        region_start,
                    } => {
                        if region_start {
                            sweep.flush(&mut refs);
                        }
                        sweep.instruction(cs, insn, &mut refs);
                    }
                    Item::Extra {
                        address,
                        insn,
                        region_start,
                        ..
                    } => {
                        if region_start {
                            sweep.flush(&mut refs);
                        }
                        sweep.extra(address, insn, &mut refs);
                    }
                    Item::Data { .. } => sweep.flush(&mut refs),
                });
                sweep.flush(&mut refs);
            }
        }
    }
    // Only needed while collecting.
    refs.seen = HashSet::new();
    refs.source_index = HashMap::new();
    refs
}

/// What a register is known to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Value {
    value: u64,
    /// Derived from the program counter or read from a pointer slot, so it
    /// is an address (or the page of one) rather than just a number.
    address: bool,
}

/// A jump table as the code reads it: entry `i` is the `size` bytes at
/// `base + i * size` and leads to `anchor + (entry << shift)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Table {
    base: u64,
    anchor: u64,
    /// Number of entries, from the range check of the index; 0 when none
    /// was seen.
    count: u32,
    size: u8,
    signed: bool,
    shift: u8,
}

/// What is known about a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Unknown,
    Known(Value),
    /// Some number that is not greater than this one: an index after its
    /// range check.
    Max(u64),
    /// An entry of a jump table (`Table::anchor` and `shift` not yet set).
    Entry(Table),
    /// The address one of the entries of a jump table leads to.
    Case(Table),
}

/// What is known at one point of the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    regs: [Slot; 32],
    /// Return address pushed by a call to the next instruction.
    pushed_pc: Option<u64>,
    /// The comparison the condition flags come from: a register, unchanged
    /// since, with a number.
    compare: Option<(Reg, u64)>,
    /// Two registers that hold the same number: the last copy, neither
    /// side changed since (`mov w19, w0` before `cmp w0, #30`).
    same: Option<(Reg, Reg)>,
}

impl State {
    /// Nothing is known.
    const UNKNOWN: State = State {
        regs: [Slot::Unknown; 32],
        pushed_pc: None,
        compare: None,
        same: None,
    };

    fn slot(&self, reg: Reg) -> Slot {
        self.regs
            .get(reg as usize)
            .copied()
            .unwrap_or(Slot::Unknown)
    }

    /// The value of a register, when it is known.
    fn reg(&self, reg: Reg) -> Option<Value> {
        match self.slot(reg) {
            Slot::Known(value) => Some(value),
            _ => None,
        }
    }

    /// What holds whichever of the two states the code came from.
    fn meet(&self, other: &State) -> State {
        let mut out = State::UNKNOWN;
        for ((slot, a), b) in out.regs.iter_mut().zip(&self.regs).zip(&other.regs) {
            if a == b {
                *slot = *a;
            }
        }
        if self.pushed_pc == other.pushed_pc {
            out.pushed_pc = self.pushed_pc;
        }
        if self.compare == other.compare {
            out.compare = self.compare;
        }
        if self.same == other.same {
            out.same = self.same;
        }
        out
    }

    /// Notes that `reg` is at most `max`, and so is the register that
    /// holds the same number, where nothing more precise is known.
    fn bound(&mut self, reg: Reg, max: u64) {
        let other = match self.same {
            Some((a, b)) if a == reg => Some(b),
            Some((a, b)) if b == reg => Some(a),
            _ => None,
        };
        for reg in [Some(reg), other].into_iter().flatten() {
            if let Some(slot) = self.regs.get_mut(reg as usize) {
                match *slot {
                    Slot::Unknown => *slot = Slot::Max(max),
                    Slot::Max(known) => *slot = Slot::Max(known.min(max)),
                    _ => {}
                }
            }
        }
    }
}

/// One instruction of a run, as the sweep sees it.
#[derive(Debug, Clone, Copy)]
struct Seen {
    address: u64,
    len: u8,
    step: Step,
    /// A relocation changed where it points.
    patched: bool,
}

/// Longest run analysed as one piece. A longer stretch without a symbol or
/// function start is cut; labels reached from the other piece are then
/// treated as reached from outside.
const MAX_RUN: usize = 1 << 16;

/// Passes over a run before giving up on loops: each pass can only lose
/// knowledge at a label, and there are 32 registers to lose. Half of them
/// go to each of the two ways a run is gone over (see [`Sweep::flush`]);
/// one more pass reports.
const MAX_PASSES: usize = 40;

/// Most entries read from one jump table.
const MAX_TABLE: u32 = 1 << 16;

/// A jump table is padded with fewer bytes than this before whatever
/// follows it.
const MAX_PADDING: u64 = 16;

/// Sweep over one code section, one run at a time. A run is the code
/// between two places where decoding restarts (symbols, function starts,
/// data): in practice a function. Within a run the values of the general
/// registers are followed along every path: at a label the sweep knows
/// what holds on all the ways of reaching it (falling in from above and
/// each jump to it, loops included). A label that is also reached from
/// another run, by a call, or by a jump whose target a relocation supplies
/// starts with nothing known, as does every run.
struct Sweep<'a> {
    memory: &'a Memory<'a>,
    arch: Arch,
    /// Source index of the section.
    source: u32,
    /// Address of the first byte.
    base: u64,
    /// Address after the last byte.
    end: u64,
    /// File offset of the first byte.
    raw_base: u64,
    /// What relocations do, by section offset, sorted.
    patches: Vec<(u32, Patch)>,
    /// Every direct jump and call target of the section, sorted.
    targets: Vec<u64>,
    /// Addresses where the regions of the section start, sorted.
    starts: Vec<u64>,
    /// Addresses of the jump tables found so far.
    tables: BTreeSet<u64>,
    /// Addresses the code of the section computes, sorted.
    addresses: Vec<u64>,
    /// Jump table entries that may still be read for this section: one per
    /// byte of code.
    table_budget: u64,
    /// The instructions of the current run.
    run: Vec<Seen>,
}

impl Sweep<'_> {
    /// The address of a memory operand, when the base register is known.
    fn address_of(state: &State, mem: Mem) -> Option<Value> {
        match mem.base {
            None => Some(Value {
                value: mem.offset,
                address: true,
            }),
            Some(base) => state.reg(base).map(|v| Value {
                value: v.value.wrapping_add(mem.offset),
                address: v.address,
            }),
        }
    }

    /// The patch of the instruction at section offset `offset`; `Drop` when
    /// several entries patch it.
    fn patch(&self, offset: u64, len: u64) -> Option<Patch> {
        patch_at(&self.patches, offset, len)
    }

    /// Applies a relocation to what was decoded. True when the step now
    /// points somewhere the bytes alone do not say.
    fn apply_patch(step: &mut Step, patch: Patch) -> bool {
        let drop = |step: &mut Step| {
            step.target = Target::None;
            step.mem = None;
            step.def = Def::None;
        };
        match patch {
            Patch::Keep => return false,
            Patch::Drop => drop(step),
            Patch::X64 { symbol, bias, got } => {
                let moved = |decoded: u64| symbol.wrapping_add(decoded.wrapping_sub(bias));
                match (step.flow, step.target, step.mem) {
                    (Flow::Call | Flow::Jump { .. }, Target::Address(decoded), _) if !got => {
                        step.target = Target::Address(moved(decoded));
                    }
                    // `call [rip + sym@GOTPCREL]` calls the symbol.
                    (Flow::Call | Flow::Jump { .. }, Target::Mem, Some((mem, _)))
                        if got && mem.base.is_none() =>
                    {
                        step.target = Target::Address(moved(mem.offset));
                        step.mem = None;
                    }
                    (Flow::None, _, Some((mem, usage))) if mem.base.is_none() => {
                        let address = moved(mem.offset);
                        if got {
                            // Loading the GOT slot yields the address.
                            step.mem = None;
                            step.def = match step.def {
                                Def::Load { size: 8, .. } => Def::Address(address),
                                _ => Def::None,
                            };
                        } else {
                            step.mem = Some((
                                Mem {
                                    base: None,
                                    offset: address,
                                },
                                usage,
                            ));
                        }
                    }
                    _ => drop(step),
                }
            }
            Patch::A64 { kind, target } => match (kind, step.flow, step.def, step.mem) {
                (reloc::ARM64_RELOC_BRANCH26, Flow::Call | Flow::Jump { .. }, _, _) => {
                    step.target = Target::Address(target);
                }
                (reloc::ARM64_RELOC_PAGE21, Flow::None, Def::Page(_), _) => {
                    step.def = Def::Page(target & !0xfff);
                }
                (reloc::ARM64_RELOC_PAGEOFF12, Flow::None, Def::Add { src, .. }, _) => {
                    step.def = Def::Add {
                        src,
                        imm: target & 0xfff,
                    };
                }
                (reloc::ARM64_RELOC_PAGEOFF12, Flow::None, _, Some((mem, usage)))
                    if mem.base.is_some() =>
                {
                    step.mem = Some((
                        Mem {
                            offset: target & 0xfff,
                            ..mem
                        },
                        usage,
                    ));
                }
                // Loading the GOT slot yields the address.
                (
                    reloc::ARM64_RELOC_GOT_LOAD_PAGEOFF12,
                    Flow::None,
                    Def::Load { size: 8, .. },
                    _,
                ) => {
                    step.mem = None;
                    step.def = Def::Address(target);
                }
                _ => drop(step),
            },
            Patch::Branch { symbol } => match (step.flow, step.target) {
                (Flow::Call | Flow::Jump { .. }, Target::Address(addend)) => {
                    step.target = Target::Address(symbol.wrapping_add(addend) & 0xffff_ffff);
                }
                _ => drop(step),
            },
            Patch::Immediate => match (step.def, step.mem, step.flow) {
                (Def::Const(address), None, Flow::None) => step.def = Def::Address(address),
                _ => return false,
            },
            Patch::Absolute { symbol } => match (step.def, step.mem) {
                // `mov eax, offset symbol`
                (Def::Const(addend), None) if step.flow == Flow::None => {
                    step.def = Def::Address(symbol.wrapping_add(addend) & 0xffff_ffff);
                }
                (_, Some((mem, usage))) if mem.base.is_none() => {
                    step.mem = Some((
                        Mem {
                            base: None,
                            offset: symbol.wrapping_add(mem.offset) & 0xffff_ffff,
                        },
                        usage,
                    ));
                }
                _ => drop(step),
            },
            Patch::Half { target, low } => {
                let usage = step.mem.map(|(_, usage)| usage);
                let flow = step.flow;
                drop(step);
                match (low && flow == Flow::None, usage) {
                    (false, _) => {}
                    // `lwz r3, lo16(symbol)(r3)` reads the symbol.
                    (true, Some(usage)) => {
                        step.mem = Some((
                            Mem {
                                base: None,
                                offset: target,
                            },
                            usage,
                        ));
                    }
                    (true, None) => step.def = Def::Address(target),
                }
            }
        }
        true
    }

    fn push(&mut self, seen: Seen, refs: &mut Xrefs) {
        if self.run.len() >= MAX_RUN {
            self.flush(refs);
        }
        self.run.push(seen);
    }

    fn instruction(&mut self, cs: &Capstone, insn: &Insn<'_>, refs: &mut Xrefs) {
        let address = insn.address();
        let len = insn.len() as u64;
        let Some(mut step) = self.arch.step(cs, insn) else {
            // Nothing is known about what it does.
            self.flush(refs);
            return;
        };
        let patched = self
            .patch(address.wrapping_sub(self.base), len)
            .is_some_and(|patch| Self::apply_patch(&mut step, patch));
        self.push(
            Seen {
                address,
                len: len as u8,
                step,
                patched,
            },
            refs,
        );
    }

    /// An instruction decoded outside Capstone: it refers to nothing, but
    /// what it writes is no longer known and a return ends the path.
    fn extra(&mut self, address: u64, insn: &disasm::extra::Extra, refs: &mut Xrefs) {
        let step = Step {
            flow: if insn.returns {
                Flow::Return
            } else {
                Flow::None
            },
            writes: insn.writes.map_or(0, bit),
            flags: true,
            ..Step::default()
        };
        self.push(
            Seen {
                address,
                len: insn.len as u8,
                step,
                patched: false,
            },
            refs,
        );
    }

    /// Number of direct jumps and calls of the section that go to `address`.
    fn branches_to(&self, address: u64) -> usize {
        let from = self.targets.partition_point(|t| *t < address);
        self.targets
            .get(from..)
            .unwrap_or(&[])
            .iter()
            .take_while(|t| **t == address)
            .count()
    }

    /// Analyses the current run and reports its references.
    fn flush(&mut self, refs: &mut Xrefs) {
        let run = std::mem::take(&mut self.run);
        if run.is_empty() {
            return;
        }
        // Index of the instruction at an address of the run.
        let index_of = |address: u64| run.binary_search_by_key(&address, |s| s.address).ok();
        let jump_to = |seen: &Seen| match (seen.step.flow, seen.step.target) {
            (Flow::Jump { .. }, Target::Address(target)) => index_of(target),
            _ => None,
        };

        // Labels: instructions something branches to. `inside` counts the
        // jumps of this run whose target the bytes give; when the section
        // has more branches to the label than that, some come from
        // elsewhere and nothing is assumed there.
        let mut labels: HashMap<usize, Label> = HashMap::new();
        for seen in &run {
            if let Some(target) = jump_to(seen) {
                let label = labels.entry(target).or_default();
                if seen.patched {
                    label.outside = true;
                } else {
                    label.inside += 1;
                }
            }
        }
        for (index, seen) in run.iter().enumerate() {
            let branches = self.branches_to(seen.address);
            if branches == 0 && !labels.contains_key(&index) {
                continue;
            }
            let label = labels.entry(index).or_default();
            if branches != label.inside || index == 0 {
                label.outside = true;
            }
        }

        // Passes until what is known at the labels no longer changes. The
        // first pass takes a loop's head as reached from above only; the
        // jump back then takes away whatever the loop body changes.
        //
        // Code that nothing seen so far leads to (it follows a return or
        // an unconditional jump, and no jump met yet goes there) is left
        // out until something does: a jump further down, or a jump table.
        // What is still not reached when the labels have settled is
        // reached in a way the sweep does not see, so nothing is known
        // where it starts, and the passes go on from there.
        //
        // Reaching code only by jumps back can take a pass per jump. When
        // half the passes are used up, the run is done again the plain
        // way: code that direct jumps and falling through lead to is taken
        // as reached from the first pass on, with nothing known where no
        // way in has been seen yet.
        let direct = Self::directly_reached(&run, &labels, &jump_to);
        let initial = labels;
        let mut labels = HashMap::new();
        let mut cases: HashMap<usize, (Table, Vec<u32>)> = HashMap::new();
        let mut unreached: Vec<usize> = Vec::new();
        let mut settled = false;
        for direct in [None, Some(&direct[..])] {
            labels = initial.clone();
            cases.clear();
            for _ in 0..MAX_PASSES / 2 {
                let mut pass = Pass {
                    labels: &mut labels,
                    cases: &mut cases,
                    direct,
                    unreached: &mut unreached,
                    report: false,
                };
                if self.pass(&run, &mut pass, &jump_to, refs) {
                    continue;
                }
                if unreached.is_empty() {
                    settled = true;
                    break;
                }
                for index in unreached.drain(..) {
                    labels.entry(index).or_default().outside = true;
                }
            }
            if settled {
                break;
            }
        }
        if !settled {
            for label in labels.values_mut() {
                label.outside = true;
            }
        }
        let mut pass = Pass {
            labels: &mut labels,
            cases: &mut cases,
            direct: None,
            unreached: &mut unreached,
            report: true,
        };
        self.pass(&run, &mut pass, &jump_to, refs);
    }

    /// Which instructions of `run` are reached from its start, or from a
    /// label that is reached from elsewhere, by falling through and by
    /// direct jumps.
    fn directly_reached(
        run: &[Seen],
        labels: &HashMap<usize, Label>,
        jump_to: &impl Fn(&Seen) -> Option<usize>,
    ) -> Vec<bool> {
        let mut reached = vec![false; run.len()];
        let mut pending: Vec<usize> = labels
            .iter()
            .filter(|(_, label)| label.outside)
            .map(|(index, _)| *index)
            .collect();
        pending.push(0);
        while let Some(start) = pending.pop() {
            for (index, seen) in run.iter().enumerate().skip(start) {
                if std::mem::replace(&mut reached[index], true) {
                    break;
                }
                pending.extend(jump_to(seen));
                if matches!(
                    seen.step.flow,
                    Flow::Return | Flow::Jump { conditional: false }
                ) {
                    break;
                }
            }
        }
        reached
    }

    /// Where a jump table whose index has no visible bound must end at the
    /// latest: where something else is known to start. That is the end of
    /// its section, the next place decoding restarts when the table lies
    /// in the code section, the next symbol, the next jump table found so
    /// far, the next address the code of the section computes (see
    /// [`computed_addresses`]) and the next address anything seen so far
    /// refers to.
    fn table_end(&self, base: u64, refs: &Xrefs) -> u64 {
        let after = base.saturating_add(1);
        let mut end = u64::MAX;
        if base >= self.base && base < self.end {
            let next = self.starts.partition_point(|start| *start <= base);
            end = self.starts.get(next).copied().unwrap_or(self.end);
        }
        let next = self.addresses.partition_point(|address| *address <= base);
        let known = [
            self.memory.section_end(base),
            self.tables.range(after..).next().copied(),
            self.memory.next_symbol(base),
            self.addresses.get(next).copied(),
            refs.targets
                .range(after..)
                .next()
                .map(|(target, _)| *target),
        ];
        known.into_iter().flatten().fold(end, u64::min)
    }

    /// The instructions of `run` the entries of `table` lead to, as sorted
    /// indices. The table counts only when every entry leads to an
    /// instruction of the run: all the entries the range check of the
    /// index allows or, when no check was seen, all up to where something
    /// else starts ([`Self::table_end`]), less the zero bytes that pad the
    /// table to that place. Empty when it is not a jump table of this run.
    fn cases(&mut self, run: &[Seen], table: Table, refs: &Xrefs) -> Vec<u32> {
        let size = u64::from(table.size);
        let bounded = table.count != 0;
        let count = if bounded {
            u64::from(table.count)
        } else {
            self.table_end(table.base, refs).saturating_sub(table.base) / size
        };
        if count == 0 || count > u64::from(MAX_TABLE) || count > self.table_budget {
            return Vec::new();
        }
        self.table_budget -= count;
        let mut out = Vec::new();
        for i in 0..count {
            let at = table.base.wrapping_add(i * size);
            let entry = self.table_entry(at, table);
            let target = entry.and_then(|entry| {
                let target = table
                    .anchor
                    .wrapping_add(entry.checked_shl(u32::from(table.shift))?);
                run.binary_search_by_key(&target, |s| s.address).ok()
            });
            match target {
                Some(index) => out.push(index as u32),
                // Padding before whatever comes next.
                None if !bounded
                    && (count - i) * size < MAX_PADDING
                    && (i..count).all(|rest| {
                        self.memory
                            .read(table.base.wrapping_add(rest * size), table.size)
                            == Some(0)
                    }) =>
                {
                    break
                }
                None => return Vec::new(),
            }
        }
        if !out.is_empty() {
            self.tables.insert(table.base);
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The entry of `table` stored at `at`, sign-extended when the code
    /// reads it so. `None` when it is not in the file or a relocation
    /// changes it.
    fn table_entry(&self, at: u64, table: Table) -> Option<u64> {
        if self.memory.is_relocated(at, u64::from(table.size)) {
            return None;
        }
        let raw = self.memory.read(at, table.size)?;
        let bits = 8 * u32::from(table.size);
        Some(if table.signed && bits < 64 && raw >> (bits - 1) != 0 {
            raw | u64::MAX << bits
        } else {
            raw
        })
    }

    /// One pass over a run in address order. Returns whether a jump back
    /// lowered what is known at its label, so that another pass is needed.
    /// With `refs`, reports the references instead.
    fn pass(
        &mut self,
        run: &[Seen],
        pass: &mut Pass<'_>,
        jump_to: &impl Fn(&Seen) -> Option<usize>,
        refs: &mut Xrefs,
    ) -> bool {
        let Pass {
            labels,
            cases,
            direct,
            unreached,
            report,
        } = pass;
        let report = *report;
        unreached.clear();
        let mut changed = false;
        // The state falling into the next instruction; `None` after a
        // return or an unconditional jump.
        let mut falling: Option<State> = Some(State::UNKNOWN);
        // Whether an instruction that is not reached starts a stretch of
        // such instructions.
        let mut entry = true;
        for (index, seen) in run.iter().enumerate() {
            let state = match labels.get(&index) {
                Some(label) if label.outside => Some(State::UNKNOWN),
                Some(label) => match (falling, label.jumped) {
                    (Some(a), Some(b)) => Some(a.meet(&b)),
                    (a, b) => a.or(b),
                },
                // Not a label: reached from above or, after a return or a
                // jump, not by anything seen so far.
                None => falling,
            };
            let state = match state {
                Some(state) => state,
                // Only reached by direct jumps that come later.
                None if direct.is_some_and(|direct| direct.get(index) == Some(&true)) => {
                    State::UNKNOWN
                }
                // When reporting, every way of getting here that the
                // passes found has been followed.
                None if report => State::UNKNOWN,
                None => {
                    // The first of a stretch: what is before it is
                    // reached, or does not lead to it.
                    if entry {
                        unreached.push(index);
                    }
                    entry = matches!(
                        seen.step.flow,
                        Flow::Return | Flow::Jump { conditional: false }
                    );
                    continue;
                }
            };
            entry = true;
            let after = self.transfer(&state, seen, report.then_some(&mut *refs));
            // A conditional jump on an unsigned comparison bounds the
            // compared register on one of its two ways out.
            let (mut taken, mut fall) = (after, after);
            if let (Flow::Jump { conditional: true }, Some(cond), Some((reg, imm))) =
                (seen.step.flow, seen.step.cond, state.compare)
            {
                if let Some(max) = cond.max(imm, true) {
                    taken.bound(reg, max);
                }
                if let Some(max) = cond.max(imm, false) {
                    fall.bound(reg, max);
                }
            }
            if let Some(target) = jump_to(seen) {
                if let Some(label) = labels.get_mut(&target) {
                    let merged = label.jumped.map_or(taken, |known| known.meet(&taken));
                    if label.jumped != Some(merged) {
                        label.jumped = Some(merged);
                        // A label at or before the jump has already been
                        // passed with what was known until now.
                        changed |= target <= index && !label.outside;
                    }
                }
            }
            if let (Flow::Jump { conditional: false }, Target::Reg(reg)) =
                (seen.step.flow, seen.step.target)
            {
                // A jump through a jump table goes to each of its cases.
                let table = match state.slot(reg) {
                    Slot::Case(table) => Some(table),
                    _ => None,
                };
                if cases.get(&index).map(|known| known.0) != table {
                    // What an earlier pass took for the cases here no
                    // longer holds: nothing is assumed at them.
                    if let Some((_, old)) = cases.remove(&index) {
                        for target in old {
                            if let Some(label) = labels.get_mut(&(target as usize)) {
                                label.outside = true;
                            }
                        }
                        changed = true;
                    }
                    // Kept even when it is not a jump table, so that it
                    // is read once.
                    if let Some(table) = table {
                        let found = self.cases(run, table, refs);
                        cases.insert(index, (table, found));
                    }
                }
                let ref_raw = self
                    .raw_base
                    .wrapping_add(seen.address.wrapping_sub(self.base));
                for target in cases.get(&index).map_or(&[][..], |known| &known.1) {
                    let target = *target as usize;
                    if let (true, Some(case)) = (report, run.get(target)) {
                        refs.add(
                            case.address,
                            RefItem {
                                source: self.source,
                                kind: RefKind::JumpTable,
                                ref_raw,
                                ref_vm: seen.address,
                            },
                        );
                    }
                    let new = !labels.contains_key(&target);
                    let label = labels.entry(target).or_default();
                    // The first instruction of a run is reached from
                    // elsewhere too.
                    label.outside |= target == 0;
                    let merged = label.jumped.map_or(after, |known| known.meet(&after));
                    if new || label.jumped != Some(merged) {
                        label.jumped = Some(merged);
                        changed |= target <= index && !label.outside;
                    }
                }
            }
            falling = (!matches!(
                seen.step.flow,
                Flow::Return | Flow::Jump { conditional: false }
            ))
            .then_some(fall);
        }
        changed
    }

    /// The state after an instruction executed in `state`. With `refs`,
    /// also reports what the instruction refers to.
    fn transfer(&self, state: &State, seen: &Seen, refs: Option<&mut Xrefs>) -> State {
        let step = &seen.step;
        let address = seen.address;
        let next = address.wrapping_add(u64::from(seen.len));
        let source = self.source;
        let ref_raw = self.raw_base.wrapping_add(address.wrapping_sub(self.base));
        let mut found: Vec<(u64, RefKind)> = Vec::new();
        // Address 0 is null, except where a relocation names the symbol
        // that an object file defines there.
        let zero_is_real = seen.patched;
        let mut add = |target: u64, kind: RefKind| {
            if target != 0 || zero_is_real {
                found.push((target, kind));
            }
        };

        // Data: the address of the memory operand.
        let mem = step
            .mem
            .and_then(|(mem, usage)| Some((mem, usage, Self::address_of(state, mem)?)));
        if let Some((_, usage, at)) = mem.filter(|(_, _, at)| at.address) {
            add(
                at.value,
                match usage {
                    MemUse::Load => RefKind::Load,
                    MemUse::Store => RefKind::Store,
                    MemUse::Address => RefKind::Address,
                },
            );
        }

        // The new value of the destination register.
        let value = match step.def {
            Def::None | Def::LoadIndex { .. } | Def::AddReg { .. } | Def::Clamp { .. } => None,
            Def::Const(value) => Some(Value {
                value,
                address: false,
            }),
            Def::Page(value) => Some(Value {
                value,
                address: true,
            }),
            Def::Address(value) => {
                add(value, RefKind::Address);
                Some(Value {
                    value,
                    address: true,
                })
            }
            Def::Add { src, imm } => state.reg(src).map(|v| {
                let value = v.value.wrapping_add(imm);
                if v.address {
                    add(value, RefKind::Address);
                }
                Value { value, ..v }
            }),
            Def::Copy { src } => state.reg(src),
            Def::MovK { imm16, shift } => step.dst.and_then(|dst| state.reg(dst)).map(|v| {
                let mask = 0xffffu64.checked_shl(shift).unwrap_or(0);
                Value {
                    value: (v.value & !mask) | (imm16.checked_shl(shift).unwrap_or(0) & mask),
                    address: false,
                }
            }),
            Def::Lea => mem.map(|(_, _, at)| at),
            Def::Load { size, signed } => mem.and_then(|(_, _, at)| {
                if size == self.memory.pointer_size {
                    // A pointer slot: follow it to what it will point at.
                    self.memory.pointer(at.value).map(|value| Value {
                        value,
                        address: true,
                    })
                } else {
                    let raw = self.memory.read(at.value, size)?;
                    let bits = 8 * size as u32;
                    let value = if signed && bits < 64 && raw >> (bits - 1) != 0 {
                        raw | u64::MAX << bits
                    } else {
                        raw
                    };
                    Some(Value {
                        value,
                        address: false,
                    })
                }
            }),
            Def::Pop => state.pushed_pc.map(|value| Value {
                value,
                address: true,
            }),
        };

        // The other things known about a register.
        let slot = match step.def {
            Def::Copy { src } => state.slot(src),
            Def::LoadIndex {
                base,
                index,
                size,
                signed,
            } => match state.reg(base) {
                Some(base) if base.address => Slot::Entry(Table {
                    base: base.value,
                    anchor: 0,
                    count: match state.slot(index) {
                        Slot::Max(max) if max < u64::from(MAX_TABLE) => max as u32 + 1,
                        _ => 0,
                    },
                    size,
                    signed,
                    shift: 0,
                }),
                _ => Slot::Unknown,
            },
            Def::AddReg { a, b, shift } => match (state.slot(a), state.slot(b)) {
                (Slot::Known(anchor), Slot::Entry(table)) if anchor.address => Slot::Case(Table {
                    anchor: anchor.value,
                    shift,
                    ..table
                }),
                (Slot::Entry(table), Slot::Known(anchor)) if anchor.address && shift == 0 => {
                    Slot::Case(Table {
                        anchor: anchor.value,
                        ..table
                    })
                }
                _ => Slot::Unknown,
            },
            Def::Clamp { src } => match (state.compare, step.cond) {
                (Some((reg, imm)), Some(cond)) if reg == src => {
                    cond.max(imm, true).map_or(Slot::Unknown, Slot::Max)
                }
                _ => Slot::Unknown,
            },
            _ => value.map_or(Slot::Unknown, Slot::Known),
        };

        // Calls and jumps.
        let call = step.flow == Flow::Call;
        let pick = |c: RefKind, j: RefKind| if call { c } else { j };
        // `call next` only reads the program counter.
        let pushes_pc = call && step.target == Target::Address(next) && self.arch == Arch::X86;
        if step.flow != Flow::None && !pushes_pc {
            match step.target {
                Target::None => {}
                Target::Address(target) => add(target, pick(RefKind::Call, RefKind::Jump)),
                Target::Reg(reg) => {
                    if let Some(v) = state.reg(reg) {
                        add(v.value, pick(RefKind::CallReg, RefKind::JumpReg));
                    }
                }
                Target::Mem => {
                    if let Some((mem, _, at)) = mem {
                        if let Some(target) = self.memory.pointer(at.value) {
                            add(
                                target,
                                match mem.base {
                                    None => pick(RefKind::CallRipMem, RefKind::JumpRipMem),
                                    Some(_) => pick(RefKind::CallRegMem, RefKind::JumpRegMem),
                                },
                            );
                        }
                    }
                }
            }
        }
        if let Some(refs) = refs {
            for (target, kind) in found {
                refs.add(
                    target,
                    RefItem {
                        source,
                        kind,
                        ref_raw,
                        ref_vm: address,
                    },
                );
            }
        }

        // The registers after the instruction.
        let mut after = *state;
        after.pushed_pc = pushes_pc.then_some(next);
        let mut lost = step.writes;
        if call && !pushes_pc {
            lost |= self.arch.caller_saved();
        }
        for (reg, slot) in after.regs.iter_mut().enumerate() {
            if lost & bit(reg as Reg) != 0 {
                *slot = Slot::Unknown;
            }
        }
        // The flags still come from the comparison when nothing changed
        // them or the register compared.
        after.compare = step.compare.or(state
            .compare
            .filter(|(reg, _)| !step.flags && !call && lost & bit(*reg) == 0));
        after.same = match (step.def, step.dst) {
            (Def::Copy { src }, Some(dst)) if src != dst => Some((dst, src)),
            _ => state.same.filter(|(a, b)| lost & (bit(*a) | bit(*b)) == 0),
        };
        // The 32-bit form of the destination keeps the low half of the
        // value, zero-extended.
        let slot = match slot {
            Slot::Known(v) if step.narrow => Slot::Known(Value {
                value: v.value & 0xffff_ffff,
                ..v
            }),
            Slot::Entry(table) if step.narrow && table.signed => Slot::Unknown,
            Slot::Case(_) if step.narrow => Slot::Unknown,
            other => other,
        };
        if let (true, Some(dst)) = (
            slot != Slot::Unknown,
            step.dst.and_then(|dst| after.regs.get_mut(dst as usize)),
        ) {
            *dst = slot;
        }
        after
    }
}

/// What the passes over a run keep between them.
struct Pass<'a> {
    labels: &'a mut HashMap<usize, Label>,
    /// The cases of the jump tables found, by the index of the indirect
    /// jump, with the table as it was read.
    cases: &'a mut HashMap<usize, (Table, Vec<u32>)>,
    /// Whether an instruction is reached by falling through and direct
    /// jumps alone; given when such code is to be taken as reached before
    /// a way in has been seen.
    direct: Option<&'a [bool]>,
    /// First instructions of the stretches the pass did not reach: one
    /// per stretch that ends with a return or an unconditional jump.
    unreached: &'a mut Vec<usize>,
    /// Report the references instead of looking for changes.
    report: bool,
}

/// An instruction of a run that a jump or call goes to.
#[derive(Debug, Clone, Copy, Default)]
struct Label {
    /// Jumps of the run to it whose target the instruction bytes give.
    inside: usize,
    /// Also reached from outside the run, or in a way that is not
    /// followed: nothing is known on arrival.
    outside: bool,
    /// What holds after every jump to it seen so far.
    jumped: Option<State>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{MH_MAGIC, MH_MAGIC_64};

    /// A Mach-O with one `__TEXT` segment mapped at 0x1000 holding `code`
    /// in `__text` and one pointer in a non-lazy pointer section right
    /// after it. Returns the bytes and the offset of the pointer.
    fn tiny_macho_bytes(cputype: u32, code: &[u8], pointer: u64) -> (Vec<u8>, u64) {
        let is64 = cputype & 0x0100_0000 != 0;
        let text_off: u64 = if is64 { 264 } else { 28 + 56 + 2 * 68 };
        let ptr_size: u64 = if is64 { 8 } else { 4 };
        let got_off = (text_off + code.len() as u64 + 7) & !7;
        let total = got_off + ptr_size;
        let mut f = Vec::new();
        let u32_ = |f: &mut Vec<u8>, v: u32| f.extend_from_slice(&v.to_le_bytes());
        let word = |f: &mut Vec<u8>, v: u64| {
            if is64 {
                f.extend_from_slice(&v.to_le_bytes())
            } else {
                f.extend_from_slice(&(v as u32).to_le_bytes())
            }
        };
        let name = |f: &mut Vec<u8>, n: &str| {
            let mut b = [0u8; 16];
            b[..n.len()].copy_from_slice(n.as_bytes());
            f.extend_from_slice(&b);
        };
        let cmdsize = (text_off - if is64 { 32 } else { 28 }) as u32;
        let magic = if is64 { MH_MAGIC_64 } else { MH_MAGIC };
        for v in [magic, cputype, 3, 2, 1, cmdsize, 0] {
            u32_(&mut f, v);
        }
        if is64 {
            u32_(&mut f, 0);
        }
        u32_(&mut f, if is64 { 0x19 } else { 0x1 });
        u32_(&mut f, cmdsize);
        name(&mut f, "__TEXT");
        for v in [0x1000, 0x1000, 0, total] {
            word(&mut f, v);
        }
        for v in [5, 5, 2, 0] {
            u32_(&mut f, v);
        }
        for (sect, off, size, flags) in [
            ("__text", text_off, code.len() as u64, 0x8000_0400u32),
            ("__got", got_off, ptr_size, S_NON_LAZY_SYMBOL_POINTERS),
        ] {
            name(&mut f, sect);
            name(&mut f, "__TEXT");
            word(&mut f, 0x1000 + off);
            word(&mut f, size);
            for v in [off as u32, 0, 0, 0, flags, 0, 0] {
                u32_(&mut f, v);
            }
            if is64 {
                u32_(&mut f, 0);
            }
        }
        assert_eq!(f.len() as u64, text_off);
        f.extend_from_slice(code);
        f.resize(got_off as usize, 0);
        word(&mut f, pointer);
        (f, got_off)
    }

    fn tiny_macho(cputype: u32, code: &[u8], pointer: u64) -> (MachHeader, u64) {
        let (f, got_off) = tiny_macho_bytes(cputype, code, pointer);
        let image = std::sync::Arc::new(crate::image::Image::from_vec(f).unwrap());
        (MachHeader::parse(&image, 0).unwrap(), got_off)
    }

    fn summary(x: &Xrefs) -> Vec<(u64, &'static str, u64, u64)> {
        x.targets
            .iter()
            .flat_map(|(t, items)| {
                items
                    .iter()
                    .map(|i| (*t, i.kind.name(), i.ref_raw, i.ref_vm))
            })
            .collect()
    }

    /// References found in the code of a 64-bit image, without file
    /// offsets: `(target, kind, address of the instruction)`.
    fn code_refs(cputype: u32, code: &[u8], pointer: u64) -> Vec<(u64, &'static str, u64)> {
        let (mh, _) = tiny_macho(cputype, code, pointer);
        summary(&collect(&mh))
            .into_iter()
            .filter(|r| r.1 != "pointer")
            .map(|(t, k, _, vm)| (t, k, vm))
            .collect()
    }

    fn arm64(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    // The code of the 64-bit test images starts at 0x1108 and their pointer
    // slot is at the next 8-byte boundary after it.

    /// x86-64 code that switches on `edi` through the table in the
    /// pointer slot of the test image (two 32-bit offsets from the table).
    /// `check`: with the range check; `second`: where the second entry
    /// leads.
    fn x86_64_switch(check: bool, second: u64) -> Vec<(u64, &'static str, u64)> {
        let mut code = vec![
            0x48, 0x8d, 0x15, 0xf1, 0x1e, 0x00,
            0x00, // 1108 lea rdx, [rip + 0x1ef1] -> 0x3000
            0x83, 0xff, 0x01, // 110f cmp edi, 1
            0x77, 0x19, // 1112 ja 0x112d
            0x89, 0xf8, // 1114 mov eax, edi
            0x48, 0x8d, 0x0d, 0x13, 0x00, 0x00, 0x00, // 1116 lea rcx, [rip + 0x13] -> 0x1130
            0x48, 0x63, 0x04, 0x81, // 111d movsxd rax, dword ptr [rcx + rax*4]
            0x48, 0x01, 0xc8, // 1121 add rax, rcx
            0xff, 0xe0, // 1124 jmp rax
            0x8b, 0x02, // 1126 mov eax, [rdx]       case 0
            0xc3, // 1128 ret
            0x89, 0x42, 0x04, // 1129 mov [rdx + 4], eax   case 1
            0xc3, // 112c ret
            0xc3, // 112d ret                  default
        ];
        if !check {
            code[7..12].fill(0x90);
        }
        let entry = |target: u64| target.wrapping_sub(0x1130) & 0xffff_ffff;
        code_refs(CPU_TYPE_X86_64, &code, entry(0x1126) | entry(second) << 32)
    }

    #[test]
    fn jump_tables_x86_64() {
        // The jump goes to both cases, and what `rdx` holds before the
        // switch is known in them.
        assert_eq!(
            x86_64_switch(true, 0x1129),
            [
                (0x1126, "jump-table", 0x1124),
                (0x1129, "jump-table", 0x1124),
                (0x112d, "jump", 0x1112),
                (0x1130, "addr", 0x1116),
                (0x3000, "addr", 0x1108),
                (0x3000, "load", 0x1126),
                (0x3004, "store", 0x1129),
            ]
        );
        // Without the range check the table ends where its section does.
        assert_eq!(
            x86_64_switch(false, 0x1129),
            [
                (0x1126, "jump-table", 0x1124),
                (0x1129, "jump-table", 0x1124),
                (0x1130, "addr", 0x1116),
                (0x3000, "addr", 0x1108),
                (0x3000, "load", 0x1126),
                (0x3004, "store", 0x1129),
            ]
        );
        // An entry that leads into the middle of an instruction, or out
        // of the function: not a jump table, and the code after the jump
        // starts with nothing known.
        for second in [0x112a, 0x2000] {
            for check in [true, false] {
                let refs = x86_64_switch(check, second);
                assert!(refs.iter().all(|r| r.1 != "jump-table"), "{refs:x?}");
                assert!(refs.iter().all(|r| r.1 != "load" && r.1 != "store"));
                assert!(refs.contains(&(0x3000, "addr", 0x1108)));
            }
        }
    }

    /// arm64 code that switches on `w0` through a table of bytes in the
    /// pointer slot of the test image (instructions counted from the
    /// first case).
    fn arm64_switch(check: bool, table: [u8; 8]) -> Vec<(u64, &'static str, u64)> {
        let mut code = [
            0x1000_07cc, // 1108 adr  x12, 0x1200
            0x7100_081f, // 110c cmp  w0, #2
            0x5400_0168, // 1110 b.hi 0x113c
            0x2a00_03e8, // 1114 mov  w8, w0
            0x9000_0009, // 1118 adrp x9, 0x1000
            0x9105_0129, // 111c add  x9, x9, #0x140
            0x1000_008a, // 1120 adr  x10, 0x1130
            0x3868_692b, // 1124 ldrb w11, [x9, x8]
            0x8b0b_094a, // 1128 add  x10, x10, x11, lsl #2
            0xd61f_0140, // 112c br   x10
            0xb940_0180, // 1130 ldr  w0, [x12]        case 0
            0xd65f_03c0, // 1134 ret
            0xb900_0580, // 1138 str  w0, [x12, #4]    cases 1 and 2
            0xd65f_03c0, // 113c ret                   default
        ];
        if !check {
            code[1] = 0xd503_201f;
            code[2] = 0xd503_201f;
        }
        code_refs(CPU_TYPE_ARM64, &arm64(&code), u64::from_le_bytes(table))
    }

    #[test]
    fn jump_tables_arm64() {
        let cases = [
            (0x1130, "addr", 0x1120),
            (0x1130, "jump-table", 0x112c),
            (0x1138, "jump-table", 0x112c),
        ];
        let rest = [
            (0x1140, "addr", 0x111c),
            (0x1200, "addr", 0x1108),
            (0x1200, "load", 0x1130),
            (0x1204, "store", 0x1138),
        ];
        // Three entries are read: what follows them does not matter.
        let mut expected = cases.to_vec();
        expected.push((0x113c, "jump", 0x1110));
        expected.extend(rest);
        assert_eq!(
            arm64_switch(true, [0, 2, 2, 0xff, 0xff, 0xff, 0xff, 0xff]),
            expected
        );
        // No range check: every byte up to the end of the section must be
        // an entry (zero leads to the first case, as padding does).
        let mut expected = cases.to_vec();
        expected.extend(rest);
        assert_eq!(arm64_switch(false, [0, 2, 2, 0, 0, 0, 0, 0]), expected);
        // An entry past the function: not a jump table.
        for (check, table) in [
            (true, [0, 2, 9, 0, 0, 0, 0, 0]),
            (false, [0, 2, 2, 0, 0, 0, 0, 9]),
        ] {
            let refs = arm64_switch(check, table);
            assert!(refs.iter().all(|r| r.1 != "jump-table"), "{refs:x?}");
            assert!(refs.iter().all(|r| r.1 != "load" && r.1 != "store"));
        }
    }

    #[test]
    fn jump_tables_arm64e() {
        // The sequence of the pointer-authentication ABI: the index is
        // forced into range, the entries count from the `adr`.
        for clamp in [
            0x9a9f_9210u32, // csel  x16, x16, xzr, ls
            0xda9f_9610,    // csneg x16, x16, xzr, ls
        ] {
            let code = arm64(&[
                0xf100_061f, // 1108 cmp   x16, #1
                clamp,       // 110c
                0x9000_0011, // 1110 adrp  x17, 0x1000
                0x9104_e231, // 1114 add   x17, x17, #0x138
                0xb8b0_7a30, // 1118 ldrsw x16, [x17, x16, lsl #2]
                0x1000_0011, // 111c adr   x17, 0x111c
                0x8b10_0230, // 1120 add   x16, x17, x16
                0xd61f_0200, // 1124 br    x16
                0xd65f_03c0, // 1128 ret                 case 0
                0xd503_201f, // 112c nop                 case 1
                0xd65f_03c0, // 1130 ret
            ]);
            assert_eq!(
                code_refs(CPU_TYPE_ARM64, &code, 0x10_0000_000c),
                [
                    (0x111c, "addr", 0x111c),
                    (0x1128, "jump-table", 0x1124),
                    (0x112c, "jump-table", 0x1124),
                    (0x1138, "addr", 0x1114),
                ]
            );
        }
    }

    /// The steps of the instructions of `code`.
    fn steps(cputype: u32, code: &[u8]) -> Vec<Step> {
        let arch = Arch::of(cputype).unwrap();
        let disassembler = Disassembler::new(cputype, 0, true).unwrap();
        let region = disasm::Region {
            start: 0,
            end: code.len(),
            kind: disasm::RegionKind::Code { thumb: false },
        };
        let mut out = Vec::new();
        disassembler
            .run(code, 0x1000, &[region], |item| {
                if let Item::Code { cs, insn, .. } = item {
                    out.push(arch.step(cs, insn).unwrap());
                }
            })
            .unwrap();
        out
    }

    #[test]
    fn comparisons_and_flags() {
        // arm64: what sets the flags, and the comparisons with a number.
        let s = steps(
            CPU_TYPE_ARM64,
            &arm64(&[
                0x7100_141f, // cmp   w0, #5
                0xf100_7e1f, // cmp   x16, #0x1f
                0x6b01_001f, // cmp   w0, w1
                0x3100_0400, // adds  w0, w0, #1
                0x6a01_0000, // ands  w0, w0, w1
                0x7200_001f, // tst   w0, #1
                0x7a41_0800, // ccmp  w0, #1, #0, eq
                0x1e21_2000, // fcmp  s0, s1
                0x1100_0400, // add   w0, w0, #1
                0x2a01_03e0, // mov   w0, w1
                0x5400_0048, // b.hi  0x1030
                0x5400_0029, // b.ls  0x1030
                0x5400_0002, // b.hs  0x102c
                0x5400_0003, // b.lo  0x1030
                0x5400_0000, // b.eq  0x1034
                0x3400_0000, // cbz   w0, 0x1038
            ]),
        );
        let compares: Vec<_> = s.iter().map(|s| s.compare).collect();
        assert_eq!(compares[..3], [Some((0, 5)), Some((16, 0x1f)), None]);
        assert!(compares[3..].iter().all(Option::is_none));
        let flags: Vec<_> = s.iter().map(|s| s.flags).collect();
        assert_eq!(flags[..8], [true; 8]);
        assert_eq!(flags[8..], [false; 8]);
        let conds: Vec<_> = s[10..].iter().map(|s| s.cond).collect();
        assert_eq!(
            conds,
            [
                Some(Cond::Above),
                Some(Cond::NotAbove),
                Some(Cond::NotBelow),
                Some(Cond::Below),
                None,
                None
            ]
        );
        // x86-64.
        let s = steps(
            CPU_TYPE_X86_64,
            &[
                0x83, 0xff, 0x05, // cmp  edi, 5
                0x48, 0x83, 0xf8, 0x07, // cmp  rax, 7
                0x39, 0xc7, // cmp  edi, eax
                0x80, 0xfa, 0x09, // cmp  dl, 9
                0x85, 0xc0, // test eax, eax
                0x83, 0xc0, 0x01, // add  eax, 1
                0xff, 0xc0, // inc  eax
                0x31, 0xc0, // xor  eax, eax
                0x83, 0xe1, 0x07, // and  ecx, 7
                0xc1, 0xe8, 0x02, // shr  eax, 2
                0x89, 0xf8, // mov  eax, edi
                0x48, 0x8d, 0x04, 0x88, // lea  rax, [rax + rcx*4]
                0x48, 0x63, 0x04, 0x81, // movsxd rax, dword ptr [rcx + rax*4]
                0x77, 0x00, // ja
                0x76, 0x00, // jbe
                0x73, 0x00, // jae
                0x72, 0x00, // jb
                0x74, 0x00, // je
            ],
        );
        let compares: Vec<_> = s.iter().map(|s| s.compare).collect();
        assert_eq!(compares[..4], [Some((7, 5)), Some((0, 7)), None, None]);
        assert!(compares[4..].iter().all(Option::is_none));
        let flags: Vec<_> = s.iter().map(|s| s.flags).collect();
        assert_eq!(flags[..10], [true; 10]);
        assert_eq!(flags[10..], [false; 8]);
        let conds: Vec<_> = s[13..].iter().map(|s| s.cond).collect();
        assert_eq!(
            conds,
            [
                Some(Cond::Above),
                Some(Cond::NotAbove),
                Some(Cond::NotBelow),
                Some(Cond::Below),
                None
            ]
        );
        assert_eq!(
            s[12].def,
            Def::LoadIndex {
                base: 1,
                index: 0,
                size: 4,
                signed: true
            }
        );
    }

    #[test]
    fn range_checks_bound_the_index() {
        let c = |cond: Cond, holds| cond.max(5, holds);
        assert_eq!(c(Cond::Above, false), Some(5));
        assert_eq!(c(Cond::Above, true), None);
        assert_eq!(c(Cond::NotAbove, true), Some(5));
        assert_eq!(c(Cond::NotBelow, false), Some(4));
        assert_eq!(c(Cond::Below, true), Some(4));
        assert_eq!(c(Cond::Below, false), None);
        assert_eq!(Cond::Below.max(0, true), None);
        // The bound also holds for the register the compared one was
        // copied to or from, and never replaces a known value.
        let mut state = State::UNKNOWN;
        state.same = Some((19, 0));
        state.regs[3] = Slot::Known(Value {
            value: 7,
            address: false,
        });
        state.bound(0, 30);
        state.bound(3, 30);
        assert_eq!(
            (state.slot(0), state.slot(19)),
            (Slot::Max(30), Slot::Max(30))
        );
        assert_eq!(state.reg(3).map(|v| v.value), Some(7));
        state.bound(19, 9);
        assert_eq!(
            (state.slot(0), state.slot(19)),
            (Slot::Max(9), Slot::Max(9))
        );
    }

    #[test]
    fn computed_addresses_are_collected() {
        let code = arm64(&[
            0x9000_0009, // 1108 adrp x9, 0x1000
            0x9105_0129, // 110c add  x9, x9, #0x140
            0xb000_0008, // 1110 adrp x8, 0x2000
            0xf940_0908, // 1114 ldr  x8, [x8, #0x10]
            0x9000_0009, // 1118 adrp x9, 0x1000
            0x9105_0108, // 111c add  x8, x8, #0x140   (another register)
        ]);
        let (mh, _) = tiny_macho(CPU_TYPE_ARM64, &code, 0);
        let region = disasm::Region {
            start: 0,
            end: code.len(),
            kind: disasm::RegionKind::Code { thumb: false },
        };
        assert_eq!(
            computed_addresses(&mh, Arch::Arm64, &code, 0x1108, &[region]),
            [0x1140, 0x2010]
        );
        assert!(computed_addresses(&mh, Arch::X64, &code, 0x1108, &[region]).is_empty());
    }

    #[test]
    fn instruction_halves() {
        // movw r0, #0x1234 / movt r0, #0x1234 in ARM and Thumb.
        assert_eq!(
            arm_imm16(&0xe301_0234u32.to_le_bytes(), 0, false),
            Some(0x1234)
        );
        assert_eq!(
            arm_imm16(&0xe341_0234u32.to_le_bytes(), 0, false),
            Some(0x1234)
        );
        assert_eq!(arm_imm16(&[0x41, 0xf2, 0x34, 0x20], 0, true), Some(0x1234));
        assert_eq!(arm_imm16(&[0xc1, 0xf2, 0x34, 0x20], 0, true), Some(0x1234));
        assert_eq!(arm_imm16(&[0x41, 0xf2, 0x34], 0, true), None);
        // add r0, pc (Thumb); add r0, pc, r0 and ldr r0, [pc, r0] (ARM).
        assert_eq!(arm_pc_ahead(&[0x78, 0x44], 0, true), Some(4));
        assert_eq!(arm_pc_ahead(&[0x08, 0x44], 0, true), None);
        assert_eq!(
            arm_pc_ahead(&0xe08f_0000u32.to_le_bytes(), 0, false),
            Some(8)
        );
        assert_eq!(
            arm_pc_ahead(&0xe79f_0000u32.to_le_bytes(), 0, false),
            Some(8)
        );
        assert_eq!(arm_pc_ahead(&0xe080_0000u32.to_le_bytes(), 0, false), None);
        assert_eq!(arm_pc_ahead(&[0x78, 0x44], 2, true), None);
    }

    #[test]
    fn patches_of_32_bit_code() {
        let apply = |mut step: Step, patch| {
            let changed = Sweep::apply_patch(&mut step, patch);
            (changed, step)
        };
        // A branch to a symbol: the decoded target is the addend.
        let call = Step {
            flow: Flow::Call,
            target: Target::Address(0),
            ..Step::default()
        };
        let to = Patch::Branch { symbol: 0x2000 };
        assert_eq!(
            apply(call, to),
            (
                true,
                Step {
                    target: Target::Address(0x2000),
                    ..call
                }
            )
        );
        let plus_8 = Step {
            target: Target::Address(8),
            ..call
        };
        assert_eq!(apply(plus_8, to).1.target, Target::Address(0x2008));
        // Not a branch: nothing is assumed.
        let other = Step {
            def: Def::Const(1),
            dst: Some(0),
            ..Step::default()
        };
        assert_eq!(apply(other, to).1.def, Def::None);

        // 32-bit x86 absolute operands: `mov eax, [symbol + 4]` and
        // `mov eax, offset symbol`.
        let at = |offset| Mem { base: None, offset };
        let abs = Patch::Absolute { symbol: 0x3000 };
        let load = Step {
            mem: Some((at(4), MemUse::Load)),
            def: Def::Load {
                size: 4,
                signed: false,
            },
            dst: Some(0),
            ..Step::default()
        };
        assert_eq!(apply(load, abs).1.mem, Some((at(0x3004), MemUse::Load)));
        let offset = Step {
            def: Def::Const(0),
            dst: Some(0),
            ..Step::default()
        };
        assert_eq!(apply(offset, abs).1.def, Def::Address(0x3000));
        let indexed = Step {
            mem: Some((
                Mem {
                    base: Some(3),
                    offset: 0,
                },
                MemUse::Load,
            )),
            ..Step::default()
        };
        assert_eq!(apply(indexed, abs).1.mem, None);
        // A section-relative entry: the operand is the address already,
        // and an immediate is one.
        assert_eq!(apply(load, Patch::Immediate), (false, load));
        let local = Step {
            def: Def::Const(0x110),
            dst: Some(0),
            ..Step::default()
        };
        let (changed, step) = apply(local, Patch::Immediate);
        assert!(changed);
        assert_eq!(step.def, Def::Address(0x110));

        // The halves of an address: reported once, at the low half, as an
        // address or as the memory the instruction reads or writes.
        let half = |low| Patch::Half {
            target: 0x4568,
            low,
        };
        let movw = Step::default();
        assert_eq!(apply(movw, half(true)).1.def, Def::Address(0x4568));
        assert_eq!(apply(movw, half(false)), (true, Step::default()));
        let lwz = Step {
            mem: Some((
                Mem {
                    base: Some(3),
                    offset: 0x4568,
                },
                MemUse::Load,
            )),
            ..Step::default()
        };
        let step = apply(lwz, half(true)).1;
        assert_eq!(step.mem, Some((at(0x4568), MemUse::Load)));
        assert_eq!(step.def, Def::None);
    }

    /// A 32-bit object file: `code` in `__text` at address 0 with the
    /// relocation entries `relocs` (pairs of words), a second section of
    /// 16 bytes at 0x100 and the symbols `(name, section, address)`,
    /// section 0 meaning undefined.
    fn object_32(
        cputype: u32,
        big_endian: bool,
        code: &[u8],
        relocs: &[(u32, u32)],
        symbols: &[(&str, u8, u32)],
    ) -> MachHeader {
        let word = |f: &mut Vec<u8>, v: u32| {
            f.extend_from_slice(&if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            })
        };
        let name = |f: &mut Vec<u8>, n: &str| {
            let mut b = [0u8; 16];
            b[..n.len()].copy_from_slice(n.as_bytes());
            f.extend_from_slice(&b);
        };
        let sizeofcmds = 56 + 2 * 68 + 24;
        let text_off = 28 + sizeofcmds;
        let data_off = text_off + 0x100;
        let reloc_off = data_off + 16;
        let symoff = reloc_off + 8 * relocs.len() as u32;
        let stroff = symoff + 12 * symbols.len() as u32;
        let mut strings = vec![0u8];
        let mut f = Vec::new();
        for v in [MH_MAGIC, cputype, 0, MH_OBJECT, 2, sizeofcmds, 0] {
            word(&mut f, v);
        }
        word(&mut f, 1);
        word(&mut f, 56 + 2 * 68);
        name(&mut f, "");
        for v in [0, 0x110, text_off, 0x110, 7, 7, 2, 0] {
            word(&mut f, v);
        }
        for (sect, seg, addr, size, off, reloff, nreloc, flags) in [
            (
                "__text",
                "__TEXT",
                0,
                code.len() as u32,
                text_off,
                reloc_off,
                relocs.len() as u32,
                0x8000_0400u32,
            ),
            ("__data", "__DATA", 0x100, 16, data_off, 0, 0, 0),
        ] {
            name(&mut f, sect);
            name(&mut f, seg);
            for v in [addr, size, off, 0, reloff, nreloc, flags, 0, 0] {
                word(&mut f, v);
            }
        }
        let mut nlists = Vec::new();
        for (symbol, sect, value) in symbols {
            word(&mut nlists, strings.len() as u32);
            nlists.extend_from_slice(&[if *sect == 0 { 0x01 } else { 0x0f }, *sect, 0, 0]);
            word(&mut nlists, *value);
            strings.extend_from_slice(symbol.as_bytes());
            strings.push(0);
        }
        for v in [
            2,
            24,
            symoff,
            symbols.len() as u32,
            stroff,
            strings.len() as u32,
        ] {
            word(&mut f, v);
        }
        assert_eq!(f.len() as u32, text_off);
        f.extend_from_slice(code);
        f.resize(reloc_off as usize, 0);
        for (word0, word1) in relocs {
            word(&mut f, *word0);
            word(&mut f, *word1);
        }
        f.extend_from_slice(&nlists);
        f.extend_from_slice(&strings);
        let image = std::sync::Arc::new(crate::image::Image::from_vec(f).unwrap());
        MachHeader::parse(&image, 0).unwrap()
    }

    /// The second word of a little-endian `relocation_info`.
    fn info(symbolnum: u32, pcrel: bool, length: u32, external: bool, kind: u8) -> u32 {
        symbolnum
            | (pcrel as u32) << 24
            | length << 25
            | (external as u32) << 27
            | (kind as u32) << 28
    }

    /// The first word of a `scattered_relocation_info`.
    fn scattered(address: u32, length: u32, kind: u8) -> u32 {
        0x8000_0000 | length << 28 | (kind as u32) << 24 | address
    }

    fn object_refs(mh: &MachHeader) -> Vec<(u64, &'static str, u64)> {
        summary(&collect(mh))
            .into_iter()
            .map(|(t, k, _, vm)| (t, k, vm))
            .collect()
    }

    #[test]
    fn relocations_of_i386_objects() {
        use reloc::*;
        let code = [
            0xe8, 0xfb, 0xff, 0xff, 0xff, // 00 call _f (the addend 0, less 5)
            0xe8, 0xf6, 0xff, 0xff, 0xff, // 05 call _undefined
            0xa1, 0x04, 0x00, 0x00, 0x00, // 0a mov eax, [_v + 4]
            0xb8, 0x08, 0x01, 0x00, 0x00, // 0f mov eax, 0x108   (section-relative)
            0xe8, 0x00, 0x00, 0x00, 0x00, // 14 call 0x19        (reads the pc)
            0x58, // 19 pop eax
            0x8b, 0x88, 0xeb, 0x00, 0x00, 0x00, // 1a mov ecx, [eax + 0xeb] -> 0x104
            0xc3, // 20 ret
            0xc3, // 21 _f: ret
        ];
        let relocs = [
            (0x01, info(0, true, 2, true, RELOC_UNSIGNED)),
            (0x06, info(2, true, 2, true, RELOC_UNSIGNED)),
            (0x0b, info(1, false, 2, true, RELOC_UNSIGNED)),
            (0x10, info(2, false, 2, false, RELOC_UNSIGNED)),
            (scattered(0x1c, 2, GENERIC_RELOC_LOCAL_SECTDIFF), 0x104),
            (scattered(0, 2, RELOC_PAIR), 0x19),
        ];
        let symbols = [("_f", 1, 0x21), ("_v", 2, 0x100), ("_undefined", 0, 0)];
        let mh = object_32(CPU_TYPE_I386, false, &code, &relocs, &symbols);
        assert_eq!(
            object_refs(&mh),
            [
                (0x21, "call", 0x00),
                (0x104, "load", 0x0a),
                (0x104, "load", 0x1a),
                (0x108, "addr", 0x0f),
            ]
        );
    }

    #[test]
    fn relocations_of_arm_objects() {
        use reloc::*;
        // ARM code: the program counter reads 8 bytes ahead.
        let words: [u32; 9] = [
            0xebff_fffe, // 00 bl   _f           (the addend 0, less 8)
            0xebff_fffe, // 04 bl   _undefined
            0xe300_0004, // 08 movw r0, #4       _v + 4, low half
            0xe340_0000, // 0c movt r0, #0       high half
            0xe300_10e8, // 10 movw r1, #0xe8    0x108 - (0x18 + 8), low half
            0xe340_1000, // 14 movt r1, #0
            0xe08f_1001, // 18 add  r1, pc, r1
            0xe12f_ff1e, // 1c bx   lr
            0xe12f_ff1e, // 20 _f: bx lr
        ];
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let relocs = [
            (0x00, info(0, true, 2, true, ARM_RELOC_BR24)),
            (0x04, info(2, true, 2, true, ARM_RELOC_BR24)),
            (0x08, info(1, false, 0, true, ARM_RELOC_HALF)),
            (0x0000, info(0xff_ffff, false, 0, false, RELOC_PAIR)),
            (0x0c, info(1, false, 1, true, ARM_RELOC_HALF)),
            (0x0004, info(0xff_ffff, false, 1, false, RELOC_PAIR)),
            (scattered(0x10, 0, ARM_RELOC_HALF_SECTDIFF), 0x108),
            (scattered(0x0000, 0, RELOC_PAIR), 0x18),
            (scattered(0x14, 1, ARM_RELOC_HALF_SECTDIFF), 0x108),
            (scattered(0x00e8, 1, RELOC_PAIR), 0x18),
        ];
        let symbols = [("_f", 1, 0x20), ("_v", 2, 0x100), ("_undefined", 0, 0)];
        // CPU_SUBTYPE_ARM_V7 would default to Thumb: v6 decodes as ARM.
        let mh = object_32(CPU_TYPE_ARM, false, &code, &relocs, &symbols);
        assert_eq!(
            object_refs(&mh),
            [
                (0x20, "call", 0x00),
                (0x104, "addr", 0x08),
                (0x108, "addr", 0x10),
            ]
        );
    }

    #[test]
    fn sweep_x86_64() {
        // call 0x2000 ; jmp [rip + got] ; ret
        let mut code = vec![0xe8];
        code.extend_from_slice(&(0x2000u32 - 0x110d).to_le_bytes());
        code.extend_from_slice(&[0xff, 0x25]);
        code.extend_from_slice(&(0x1118u32 - 0x1113).to_le_bytes());
        code.push(0xc3);
        let (mh, got) = tiny_macho(CPU_TYPE_X86_64, &code, 0x1108);
        assert_eq!(got, 280);
        let x = collect(&mh);
        assert_eq!(
            summary(&x),
            [
                (0x1108, "pointer", 280, 0),
                (0x1108, "jump-ripmem", 269, 0x110d),
                (0x1118, "load", 269, 0x110d),
                (0x2000, "call", 264, 0x1108),
            ]
        );
        assert_eq!(x.source_name(&x.targets[&0x1108][0]), "__TEXT/__got");
        assert_eq!(x.source_name(&x.targets[&0x2000][0]), "__TEXT/__text");
    }

    #[test]
    fn x86_64_addresses() {
        let code = [
            0x48, 0x8d, 0x05, 0x11, 0x00, 0x00, 0x00, // 1108 lea rax, [rip + 0x11] -> 0x1120
            0x48, 0x8b, 0x00, // 110f mov rax, [rax]         (the slot: 0x3000)
            0xff, 0xd0, // 1112 call rax
            0x89, 0x05, 0x00, 0x00, 0x00, 0x00, // 1114 mov [rip + 0], eax  -> 0x111a
            0xff, 0xd0, // 111a call rax              (lost by the call)
        ];
        assert_eq!(
            code_refs(CPU_TYPE_X86_64, &code, 0x3000),
            [
                (0x111a, "store", 0x1114),
                (0x1120, "addr", 0x1108),
                (0x1120, "load", 0x110f),
                (0x3000, "call-reg", 0x1112),
            ]
        );
        // The 32-bit register is the same register: `mov eax, eax` keeps
        // (and truncates) what `rax` held; `add` then moves it.
        let code = [
            0x48, 0x8d, 0x05, 0x09, 0x00, 0x00, 0x00, // 1108 lea rax, [rip + 9]
            0x89, 0xc1, // 110f mov ecx, eax
            0x48, 0x83, 0xc1, 0x08, // 1111 add rcx, 8
            0xff, 0xe1, // 1115 jmp rcx
            0xff, 0xe1, // 1117 jmp rcx   (nothing falls through to here)
        ];
        assert_eq!(
            code_refs(CPU_TYPE_X86_64, &code, 0),
            [
                (0x1118, "addr", 0x1108),
                (0x1120, "addr", 0x1111),
                (0x1120, "jump-reg", 0x1115),
            ]
        );
        // `loop` is a jump although Capstone's groups do not say so; a
        // jump table (indexed) names no single target.
        let code = [0xe2, 0xfe, 0xff, 0x24, 0xc5, 0x00, 0x10, 0x00, 0x00];
        assert_eq!(
            code_refs(CPU_TYPE_X86_64, &code, 0),
            [(0x1108, "jump", 0x1108)]
        );
    }

    #[test]
    fn sweep_x86_32() {
        // The 32-bit image: code at 0x10dc, pointer slot at 0x10f0.
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, // 10dc call 0x10e1 (reads the pc)
            0x58, // 10e1 pop eax
            0x8d, 0x48, 0x0f, // 10e2 lea ecx, [eax + 0xf]   -> 0x10f0
            0xff, 0x15, 0xf0, 0x10, 0x00, 0x00, // 10e5 call [0x10f0]
            0xff, 0x11, // 10eb call [ecx]         (ecx lost by the call)
        ];
        let (mh, got) = tiny_macho(CPU_TYPE_I386, &code, 0x2000);
        assert_eq!(got, 0xf0);
        assert_eq!(
            summary(&collect(&mh)),
            [
                (0x10f0, "addr", 0xe2, 0x10e2),
                (0x10f0, "load", 0xe5, 0x10e5),
                (0x2000, "pointer", 0xf0, 0),
                (0x2000, "call-ripmem", 0xe5, 0x10e5),
            ]
        );
    }

    #[test]
    fn sweep_arm64() {
        // ldr x16, got ; br x16 ; bl 0x2000
        let code = arm64(&[0x5800_0090, 0xd61f_0200, 0x9400_03bc]);
        let (mh, _) = tiny_macho(CPU_TYPE_ARM64, &code, 0x1108);
        let x = collect(&mh);
        assert_eq!(
            summary(&x),
            [
                (0x1108, "pointer", 280, 0),
                (0x1108, "jump-reg", 268, 0x110c),
                (0x1118, "load", 264, 0x1108),
                (0x2000, "call", 272, 0x1110),
            ]
        );
    }

    #[test]
    fn arm64_adrp_pairs() {
        let code = arm64(&[
            0x9000_0008, // 1108 adrp x8, 0x1000
            0x9104_c108, // 110c add  x8, x8, #0x130   -> the slot, same register
            0xf940_0109, // 1110 ldr  x9, [x8]         (8 bytes: 0x1_0000_1234)
            0xd63f_0120, // 1114 blr  x9
            0x9000_0008, // 1118 adrp x8, 0x1000
            0xb941_3108, // 111c ldr  w8, [x8, #0x130] (4 bytes: 0x1234)
            0x9000_000a, // 1120 adrp x10, 0x1000
            0x3944_c14b, // 1124 ldrb w11, [x10, #0x130]
            0xf900_994b, // 1128 str  x11, [x10, #0x130]
            0xd61f_0100, // 112c br   x8
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0x1_0000_1234),
            [
                (0x1130, "addr", 0x110c),
                (0x1130, "load", 0x1110),
                (0x1130, "load", 0x111c),
                (0x1130, "load", 0x1124),
                (0x1130, "store", 0x1128),
                (0x1234, "jump-reg", 0x112c),
                (0x1_0000_1234, "call-reg", 0x1114),
            ]
        );
        // A page alone is not a reference, and `w8` names the register
        // `adrp x8` set: writing it ends the pair.
        let code = arm64(&[
            0x9000_0008, // adrp x8, 0x1000
            0x5280_0028, // mov  w8, #1
            0x9104_6108, // add  x8, x8, #0x118
        ]);
        assert_eq!(code_refs(CPU_TYPE_ARM64, &code, 0), []);
    }

    #[test]
    fn arm64_branch_operands() {
        let code = arm64(&[
            0x9000_0003, // 1108 adrp x3, 0x1000
            0x9104_6063, // 110c add  x3, x3, #0x118
            0x3628_0043, // 1110 tbz  w3, #5, 0x1118
            0xb400_0043, // 1114 cbz  x3, 0x111c
            0x5400_0040, // 1118 b.eq 0x1120
            0xd65f_03c0, // 111c ret
        ]);
        // Only the labels: not the bit number, not the tested register.
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1118, "addr", 0x110c),
                (0x1118, "jump", 0x1110),
                (0x111c, "jump", 0x1114),
                (0x1120, "jump", 0x1118),
            ]
        );
    }

    #[test]
    fn arm64_wide_moves() {
        let code = arm64(&[
            0xd2a0_0240, // 1108 movz x0, #0x12, lsl #16
            0xf280_0680, // 110c movk x0, #0x34
            0xd63f_0000, // 1110 blr  x0              -> 0x120034
            0xd280_0020, // 1114 mov  x0, #1
            0xf2c0_0040, // 1118 movk x0, #2, lsl #32
            0xd61f_0000, // 111c br   x0              -> 0x2_0000_0001
            0x1280_0001, // 1120 mov  w1, #-1         (zero-extended)
            0xd61f_0020, // 1124 br   x1
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x12_0034, "call-reg", 0x1110),
                (0xffff_ffff, "jump-reg", 0x1124),
                (0x2_0000_0001, "jump-reg", 0x111c),
            ]
        );
    }

    #[test]
    fn registers_are_forgotten() {
        // A call loses the caller-saved registers, not the others.
        let code = arm64(&[
            0x1000_0008, // 1108 adr x8, 0x1108
            0x1000_0013, // 110c adr x19, 0x110c
            0x9400_03bc, // 1110 bl  0x2000
            0xd63f_0100, // 1114 blr x8
            0xd63f_0260, // 1118 blr x19
            0xd65f_03c0, // 111c ret
            0xd63f_0260, // 1120 blr x19   (after the return)
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x110c, "addr", 0x110c),
                (0x110c, "call-reg", 0x1118),
                (0x2000, "call", 0x1110),
            ]
        );
        // Instructions whose register writes Capstone does not report
        // (flag-setting 32-bit add, LSE atomics) still end what was known.
        for word in [0x3100_0508u32, 0xb829_0048] {
            // adds w8, w8, #1 / ldadd w9, w8, [x2]
            let code = arm64(&[0x1000_0008, word, 0xd61f_0100]);
            assert_eq!(
                code_refs(CPU_TYPE_ARM64, &code, 0),
                [(0x1108, "addr", 0x1108)]
            );
        }
    }

    #[test]
    fn system_register_moves() {
        // Registers the capstone crate has no name for must not be turned
        // into its enum: msr s0_0_c0_c0_1, x0 ; mrs x8, s3_7_c15_c15_7.
        // What `mrs` wrote is unknown afterwards.
        let code = arm64(&[
            0x1000_0008, // 1108 adr x8, 0x1108
            0xd500_0020, // 110c msr s0_0_c0_c0_1, x0
            0xd53f_ffe8, // 1110 mrs x8, s3_7_c15_c15_7
            0xd61f_0100, // 1114 br  x8
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [(0x1108, "addr", 0x1108)]
        );
    }

    #[test]
    fn sweep_continues_past_data() {
        // jmp +0 ; (invalid) ; call 0x2000
        let mut code = vec![0xeb, 0x00, 0xff, 0xff, 0xe8];
        code.extend_from_slice(&(0x2000u32 - 0x1111).to_le_bytes());
        assert_eq!(
            code_refs(CPU_TYPE_X86_64, &code, 0),
            [(0x110a, "jump", 0x1108), (0x2000, "call", 0x110c)]
        );
        // ret ; (invalid) ; bl 0x2000
        let code = arm64(&[0xd65f_03c0, 0xffff_ffff, 0x9400_03bc]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [(0x2000, "call", 0x1110)]
        );
        // CPU types without a disassembler report pointers only.
        let (mh, _) = tiny_macho(0x0100_0012, &code, 0x1234);
        assert_eq!(summary(&collect(&mh)), [(0x1234, "pointer", 280, 0)]);
    }

    #[test]
    fn sweep_arm_32() {
        // Code at 0x10dc. ARM mode (armv6): bl 0x10e4 ; b 0x10e8 ; bx lr.
        let code = arm64(&[0xeb00_0000, 0xea00_0000, 0xe12f_ff1e]);
        let (mh, _) = tiny_macho(CPU_TYPE_ARM, &code, 0);
        assert_eq!(
            summary(&collect(&mh)),
            [
                (0x10e4, "call", 0xdc, 0x10dc),
                (0x10e8, "jump", 0xe0, 0x10e0)
            ]
        );
    }

    #[test]
    fn fat_slices_read_their_own_bytes() {
        // The same image at offset 0x4000 of a larger file: pointer reads
        // must be relative to the Mach-O header.
        let code = arm64(&[0x5800_0050, 0xd61f_0200]);
        let (bytes, got) = tiny_macho_bytes(CPU_TYPE_ARM64, &code, 0x1108);
        let mut file = vec![0xaa; 0x4000];
        file.extend_from_slice(&bytes);
        let image = std::sync::Arc::new(crate::image::Image::from_vec(file).unwrap());
        let mh = MachHeader::parse(&image, 0x4000).unwrap();
        assert_eq!(
            summary(&collect(&mh)),
            [
                (0x1108, "pointer", 0x4000 + got, 0),
                (0x1108, "jump-reg", 0x4000 + 268, 0x110c),
                (0x1110, "load", 0x4000 + 264, 0x1108),
            ]
        );
    }

    #[test]
    fn memory_reads_follow_segments() {
        let (mh, got) = tiny_macho(CPU_TYPE_X86_64, &[0xc3], 0x1122_3344_5566_7788);
        let m = Memory::new(&mh);
        assert_eq!(m.pointer(0x1000 + got), Some(0x1122_3344_5566_7788));
        assert_eq!(m.read(0x1000 + got, 4), Some(0x5566_7788));
        assert_eq!(m.read(0x1000 + got, 2), Some(0x7788));
        assert_eq!(m.read(0x1000 + got + 7, 1), Some(0x11));
        // Last byte of the pointer is past the segment's file contents.
        assert_eq!(m.pointer(0x1000 + got + 1), None);
        assert_eq!(m.read(0x9000, 8), None);
        assert_eq!(m.read(0x1000, 3), None);
    }

    #[test]
    fn chained_pointers() {
        let base = 0x1_0000_0000;
        let t = |format, raw| decode_chained(format, raw, base);
        assert_eq!(t(DYLD_CHAINED_PTR_64, 1 << 63 | 5), Pointer::Bind);
        assert_eq!(
            t(DYLD_CHAINED_PTR_64, 0x0010_0001_0000_4000),
            Pointer::Target(0x1_0000_4000)
        );
        assert_eq!(
            t(DYLD_CHAINED_PTR_64_OFFSET, 0x0010_0000_0000_4000),
            Pointer::Target(0x1_0000_4000)
        );
        // high8 goes back to the top byte.
        assert_eq!(
            t(DYLD_CHAINED_PTR_64, 0x0000_0ff0_0000_4000),
            Pointer::Target(0xff00_0000_0000_4000)
        );
        let userland = DYLD_CHAINED_PTR_ARM64E_USERLAND24;
        assert_eq!(t(userland, 1 << 62 | 7), Pointer::Bind);
        assert_eq!(t(userland, 3 << 62 | 7), Pointer::Bind);
        assert_eq!(
            t(userland, 1 << 63 | 0xabcd << 32 | 0x8000),
            Pointer::Target(0x1_0000_8000)
        );
        assert_eq!(t(userland, 0x8000), Pointer::Target(0x1_0000_8000));
        assert_eq!(
            t(DYLD_CHAINED_PTR_ARM64E, 0x1_0000_8000),
            Pointer::Target(0x1_0000_8000)
        );
        assert_eq!(t(DYLD_CHAINED_PTR_32, 0x8000_0001), Pointer::Bind);
        assert_eq!(t(DYLD_CHAINED_PTR_32, 0x0400_4000), Pointer::Target(0x4000));
        assert_eq!(t(0x7777, 0x1234), Pointer::Target(0x1234));
    }

    fn empty_sweep<'a>(memory: &'a Memory<'a>, arch: Arch) -> Sweep<'a> {
        Sweep {
            memory,
            arch,
            source: 0,
            base: 0,
            end: 0,
            raw_base: 0,
            patches: Vec::new(),
            targets: Vec::new(),
            starts: Vec::new(),
            tables: BTreeSet::new(),
            addresses: Vec::new(),
            table_budget: 0,
            run: Vec::new(),
        }
    }

    #[test]
    fn patches_are_found_by_instruction() {
        let (mh, _) = tiny_macho(CPU_TYPE_ARM64, &[], 0);
        let memory = Memory::new(&mh);
        let mut sweep = empty_sweep(&memory, Arch::Arm64);
        sweep.patches = vec![
            (4, Patch::Keep),
            (0x11, Patch::A64 { kind: 2, target: 9 }),
            (0x20, Patch::Keep),
            (0x22, Patch::Keep),
        ];
        assert_eq!(sweep.patch(0, 4), None);
        assert_eq!(sweep.patch(4, 4), Some(Patch::Keep));
        assert_eq!(sweep.patch(8, 4), None);
        assert_eq!(
            sweep.patch(0x10, 5),
            Some(Patch::A64 { kind: 2, target: 9 })
        );
        assert_eq!(sweep.patch(0x12, 5), None);
        // Two entries in one instruction: not resolved.
        assert_eq!(sweep.patch(0x20, 4), Some(Patch::Drop));
        assert_eq!(sweep.patch(0x24, 4), None);
    }

    #[test]
    fn patches_redirect_operands() {
        let rip = |offset| Mem { base: None, offset };
        let apply = |mut step: Step, patch| {
            let changed = Sweep::apply_patch(&mut step, patch);
            (changed, step)
        };
        // x86-64 `call _f` at 0x100: the displacement field ends at 0x105
        // and holds the addend.
        let call = Step {
            flow: Flow::Call,
            target: Target::Address(0x105),
            ..Step::default()
        };
        let to = |got| Patch::X64 {
            symbol: 0x2000,
            bias: 0x105,
            got,
        };
        assert_eq!(apply(call, to(false)).1.target, Target::Address(0x2000));
        let call_plus_4 = Step {
            target: Target::Address(0x109),
            ..call
        };
        assert_eq!(
            apply(call_plus_4, to(false)).1.target,
            Target::Address(0x2004)
        );
        // `mov eax, [rip + _v]` reads the symbol; with an immediate after
        // the displacement the decoded address is further along.
        let load = Step {
            mem: Some((rip(0x106), MemUse::Load)),
            def: Def::Load {
                size: 4,
                signed: false,
            },
            ..Step::default()
        };
        let (changed, step) = apply(load, to(false));
        assert!(changed);
        assert_eq!(step.mem, Some((rip(0x2001), MemUse::Load)));
        assert_eq!(step.def, load.def);
        // Through the GOT: the load yields the address itself, and a call
        // through the slot calls the symbol.
        let got_load = Step {
            mem: Some((rip(0x105), MemUse::Load)),
            def: Def::Load {
                size: 8,
                signed: false,
            },
            ..Step::default()
        };
        let step = apply(got_load, to(true)).1;
        assert_eq!((step.mem, step.def), (None, Def::Address(0x2000)));
        let got_call = Step {
            flow: Flow::Call,
            target: Target::Mem,
            mem: Some((rip(0x105), MemUse::Load)),
            ..Step::default()
        };
        let step = apply(got_call, to(true)).1;
        assert_eq!((step.target, step.mem), (Target::Address(0x2000), None));
        // A register-relative operand is not what the entry describes.
        let odd = Step {
            mem: Some((
                Mem {
                    base: Some(3),
                    offset: 8,
                },
                MemUse::Load,
            )),
            ..Step::default()
        };
        assert_eq!(apply(odd, to(false)).1.mem, None);

        // arm64: adrp + add, adrp + ldr, bl, and a GOT load.
        let a64 = |kind| Patch::A64 {
            kind,
            target: 0x4567,
        };
        let adrp = Step {
            def: Def::Page(0),
            dst: Some(8),
            ..Step::default()
        };
        assert_eq!(
            apply(adrp, a64(reloc::ARM64_RELOC_PAGE21)).1.def,
            Def::Page(0x4000)
        );
        let add = Step {
            def: Def::Add { src: 8, imm: 0 },
            dst: Some(8),
            ..Step::default()
        };
        assert_eq!(
            apply(add, a64(reloc::ARM64_RELOC_PAGEOFF12)).1.def,
            Def::Add { src: 8, imm: 0x567 }
        );
        let ldr = Step {
            mem: Some((
                Mem {
                    base: Some(8),
                    offset: 0,
                },
                MemUse::Load,
            )),
            def: Def::Load {
                size: 8,
                signed: false,
            },
            dst: Some(0),
            ..Step::default()
        };
        assert_eq!(
            apply(ldr, a64(reloc::ARM64_RELOC_PAGEOFF12)).1.mem,
            Some((
                Mem {
                    base: Some(8),
                    offset: 0x567
                },
                MemUse::Load
            ))
        );
        let step = apply(ldr, a64(reloc::ARM64_RELOC_GOT_LOAD_PAGEOFF12)).1;
        assert_eq!((step.mem, step.def), (None, Def::Address(0x4567)));
        let bl = Step {
            flow: Flow::Call,
            target: Target::Address(0x100),
            ..Step::default()
        };
        assert_eq!(
            apply(bl, a64(reloc::ARM64_RELOC_BRANCH26)).1.target,
            Target::Address(0x4567)
        );
        // An entry that does not fit the instruction, and the two plain
        // kinds.
        let (changed, step) = apply(bl, a64(reloc::ARM64_RELOC_PAGE21));
        assert!(changed);
        assert_eq!(step.target, Target::None);
        assert_eq!(apply(bl, Patch::Keep), (false, bl));
        assert_eq!(apply(bl, Patch::Drop).1.target, Target::None);
    }

    #[test]
    fn labels_join_the_paths_that_reach_them() {
        // Two different values meet at a label: nothing is known there.
        let code = arm64(&[
            0x1000_0008, // 1108 adr x8, 0x1108
            0xb400_0040, // 110c cbz x0, 0x1114
            0x1000_0008, // 1110 adr x8, 0x1110
            0xd61f_0100, // 1114 br  x8
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x1110, "addr", 0x1110),
                (0x1114, "jump", 0x110c),
            ]
        );
        // The same value on both paths is kept.
        let code = arm64(&[
            0x1000_0008, // 1108 adr x8, 0x1108
            0xb400_0040, // 110c cbz x0, 0x1114
            0xd503_201f, // 1110 nop
            0xd61f_0100, // 1114 br  x8
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x1108, "jump-reg", 0x1114),
                (0x1114, "jump", 0x110c),
            ]
        );
        // A label reached only by a jump takes what the jump brings, also
        // when a return precedes it.
        let code = arm64(&[
            0x1000_0008, // 1108 adr x8, 0x1108
            0xb400_0060, // 110c cbz x0, 0x1118
            0xd280_0008, // 1110 mov x8, #0
            0xd65f_03c0, // 1114 ret
            0xd61f_0100, // 1118 br  x8
            0xd61f_0100, // 111c br  x8   (no jump leads here)
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x1108, "jump-reg", 0x1118),
                (0x1118, "jump", 0x110c),
            ]
        );
        // x86-64: lea ; jz ; lea ; jmp rax.
        let code = [
            0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, // 1108 lea rax, [rip]  -> 0x110f
            0x74, 0x07, // 110f jz 0x1118
            0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, // 1111 lea rax, [rip]  -> 0x1118
            0xff, 0xe0, // 1118 jmp rax
        ];
        assert_eq!(
            code_refs(CPU_TYPE_X86_64, &code, 0),
            [
                (0x110f, "addr", 0x1108),
                (0x1118, "jump", 0x110f),
                (0x1118, "addr", 0x1111),
            ]
        );
    }

    #[test]
    fn loops_lose_what_their_body_changes() {
        // x8 is advanced inside the loop, so it is not known at the head
        // (nor after the loop); x9 is set once before it and stays known.
        let code = arm64(&[
            0x1000_0008, // 1108 adr  x8, 0x1108
            0x1000_0009, // 110c adr  x9, 0x110c
            0x9100_1108, // 1110 add  x8, x8, #4      <- loop head
            0xb5ff_ffe0, // 1114 cbnz x0, 0x1110
            0xd63f_0120, // 1118 blr  x9
            0xd61f_0100, // 111c br   x8
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x110c, "addr", 0x110c),
                (0x110c, "call-reg", 0x1118),
                (0x1110, "jump", 0x1114),
            ]
        );
        // A loop that leaves the register alone keeps it.
        let code = arm64(&[
            0x1000_0008, // 1108 adr  x8, 0x1108
            0xd503_201f, // 110c nop                  <- loop head
            0xb5ff_ffe0, // 1110 cbnz x0, 0x110c
            0xd61f_0100, // 1114 br   x8
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x1108, "jump-reg", 0x1114),
                (0x110c, "jump", 0x1110),
            ]
        );
    }

    #[test]
    fn labels_reached_from_elsewhere_start_unknown() {
        // The label is jumped to and also called: whoever calls it brings
        // its own registers.
        let code = arm64(&[
            0x1000_0013, // 1108 adr x19, 0x1108
            0xb400_0040, // 110c cbz x0, 0x1114
            0x9400_0001, // 1110 bl  0x1114
            0xd61f_0260, // 1114 br  x19
        ]);
        assert_eq!(
            code_refs(CPU_TYPE_ARM64, &code, 0),
            [
                (0x1108, "addr", 0x1108),
                (0x1114, "jump", 0x110c),
                (0x1114, "call", 0x1110),
            ]
        );
        // Without the call it is known.
        let code = arm64(&[
            0x1000_0013, // 1108 adr x19, 0x1108
            0xb400_0040, // 110c cbz x0, 0x1114
            0xd503_201f, // 1110 nop
            0xd61f_0260, // 1114 br  x19
        ]);
        assert!(code_refs(CPU_TYPE_ARM64, &code, 0).contains(&(0x1108, "jump-reg", 0x1114)));
    }

    #[test]
    fn branch_targets_are_collected() {
        let code = arm64(&[
            0x1400_0002, // 1108 b    0x1110
            0x9400_0001, // 110c bl   0x1110
            0x5400_0040, // 1110 b.eq 0x1118
            0xb5ff_ffe0, // 1114 cbnz x0, 0x1110
            0x3600_0040, // 1118 tbz  w0, #0, 0x1120
            0xd61f_0100, // 111c br   x8
            0xd65f_03c0, // 1120 ret
        ]);
        let (mh, _) = tiny_macho(CPU_TYPE_ARM64, &code, 0);
        let region = disasm::Region {
            start: 0,
            end: code.len(),
            kind: disasm::RegionKind::Code { thumb: false },
        };
        assert_eq!(
            branch_targets(&mh, Arch::Arm64, &code, 0x1108, &[region], &[]),
            [0x1110, 0x1110, 0x1110, 0x1118, 0x1120]
        );
        // x86-64: call, jz, loop, jmp; indirect ones name no target.
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, // 1108 call 0x110d
            0x74, 0x02, // 110d jz 0x1111
            0xe2, 0xfc, // 110f loop 0x110d
            0xeb, 0x02, // 1111 jmp 0x1115
            0xff, 0xe0, // 1113 jmp rax
            0xc3, // 1115 ret
        ];
        let (mh, _) = tiny_macho(CPU_TYPE_X86_64, &code, 0);
        let region = disasm::Region {
            end: code.len(),
            ..region
        };
        assert_eq!(
            branch_targets(&mh, Arch::X64, &code, 0x1108, &[region], &[]),
            [0x110d, 0x110d, 0x1111, 0x1115]
        );
    }

    #[test]
    fn pointer_sections() {
        use PointerScan::*;
        assert_eq!(pointer_scan(S_NON_LAZY_SYMBOL_POINTERS, "__got"), All);
        assert_eq!(
            pointer_scan(S_MOD_INIT_FUNC_POINTERS, "__mod_init_func"),
            All
        );
        assert_eq!(pointer_scan(0, "__objc_classlist"), Mapped);
        assert_eq!(pointer_scan(0x1000_0000, "__objc_selrefs"), Mapped);
        assert_eq!(pointer_scan(S_CSTRING_LITERALS, "__objc_methname"), No);
        assert_eq!(pointer_scan(0, "__const"), No);
        assert_eq!(pointer_scan(0x8000_0400, "__text"), No);
        // Only the low byte is the section type.
        assert_eq!(pointer_scan(0xff00 | S_LITERAL_POINTERS, "x"), All);

        // 0x1100 is inside the image, 0x9000 is not: in ObjC metadata only
        // the former is a pointer.
        for (pointer, found) in [(0x1100u64, true), (0x9000, false)] {
            let (mut bytes, got) = tiny_macho_bytes(CPU_TYPE_X86_64, &[0xc3], pointer);
            let name = bytes.iter().position(|b| *b == b'g').unwrap() - 2;
            bytes[name..name + 16].copy_from_slice(b"__objc_data\0\0\0\0\0");
            bytes[name + 64] = 0; // a regular section
            let image = std::sync::Arc::new(crate::image::Image::from_vec(bytes).unwrap());
            let mh = MachHeader::parse(&image, 0).unwrap();
            let expected: &[(u64, &str, u64, u64)] = if found {
                &[(pointer, "pointer", got, 0)]
            } else {
                &[]
            };
            assert_eq!(summary(&collect(&mh)), expected);
        }
    }

    #[test]
    fn refs_are_deduplicated_per_target() {
        let mut x = Xrefs::default();
        let s = x.source("__DATA/__got".to_string());
        assert_eq!(x.source("__DATA/__got".to_string()), s);
        let item = RefItem {
            source: s,
            kind: RefKind::Pointer,
            ref_raw: 8,
            ref_vm: 0,
        };
        x.add(0x1000, item.clone());
        x.add(0x1000, item.clone());
        x.add(0x2000, item.clone());
        x.add(
            0x1000,
            RefItem {
                kind: RefKind::Call,
                ..item
            },
        );
        assert_eq!(x.targets[&0x1000].len(), 2);
        assert_eq!(x.targets[&0x2000].len(), 1);
        assert!(RefKind::CallReg.is_branch() && RefKind::Jump.is_branch());
        assert!(!RefKind::Load.is_branch() && RefKind::Load.is_code());
        assert!(!RefKind::Pointer.is_branch() && !RefKind::Pointer.is_code());
    }
}
