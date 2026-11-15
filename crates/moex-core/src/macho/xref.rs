//! Cross references: pointer values stored in pointer-like sections plus
//! what the code of `__TEXT,__text` refers to.
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
//! This is a linear sweep, not a data-flow analysis: what a register holds
//! is forgotten at every region start, after an unconditional jump or a
//! return, across calls (caller-saved registers) and whenever an
//! instruction writes it in a way the sweep does not model. A label that is
//! reached both by falling through and by a jump is treated as if only the
//! fall-through existed.

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
use super::segment::Section;
use crate::consts::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_I386, CPU_TYPE_X86_64,
    LC_DYLD_CHAINED_FIXUPS,
};
use capstone::{Capstone, Insn, InsnGroupType};
use std::collections::{BTreeMap, HashMap, HashSet};

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
}

impl<'a> Memory<'a> {
    fn new(mh: &'a MachHeader) -> Self {
        Memory {
            mh,
            pointer_size: if mh.is64 { 8 } else { 4 },
            image_base: mh.base_address(),
            chained: chained_formats(mh),
        }
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

    /// The little-endian value of `size` (1, 2, 4 or 8) bytes at `vmaddr`.
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

    /// What the raw pointer value `raw`, stored in segment `segment`, will
    /// point at. `None` for null and for pointers bound at load time.
    fn resolve(&self, segment: Option<usize>, raw: u64) -> Option<u64> {
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
        let (segment, _) = self.locate(vmaddr, self.pointer_size as u64)?;
        self.resolve(Some(segment), self.read(vmaddr, self.pointer_size)?)
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

/// Offsets into `sect` that a relocation entry patches, sorted. Only
/// object files have them.
fn relocated_offsets(mh: &MachHeader, sect: &Section) -> Vec<u64> {
    // Scattered entries (high bit of the first word) exist on the 32-bit
    // architectures only; elsewhere the word is the offset itself.
    let scattered = matches!(mh.cputype, CPU_TYPE_I386 | CPU_TYPE_ARM);
    let mut out = Vec::new();
    let Some(table) = mh.offset.checked_add(sect.reloff as u64) else {
        return out;
    };
    for i in 0..sect.nreloc as u64 {
        // Entries are 8 bytes; the table ends where the file does.
        let Some(word) = table.checked_add(i * 8).and_then(|at| mh.image.u32(at)) else {
            break;
        };
        out.push(if scattered && word & 0x8000_0000 != 0 {
            (word & 0x00ff_ffff) as u64
        } else {
            word as u64
        });
    }
    out.sort_unstable();
    out
}

/// Collect every reference of `mh`.
pub fn collect(mh: &MachHeader) -> Xrefs {
    let mut refs = Xrefs::default();
    let mut budget = scan_budget(mh);
    let memory = Memory::new(mh);

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
                    let mut raw = [0u8; 8];
                    for (dst, src) in raw.iter_mut().zip(chunk) {
                        *dst = *src;
                    }
                    let Some(target) = memory
                        .resolve(Some(seg_index), u64::from_le_bytes(raw))
                        .filter(|t| scan == PointerScan::All || memory.is_mapped(*t))
                    else {
                        continue;
                    };
                    let ref_raw = sect.data_offset.wrapping_add((i * width) as u64);
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
                if sect.segname != "__TEXT" || sect.sectname != "__text" {
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
                // that keeps a file with thousands of `__text` sections
                // from repeating it for each.
                budget = (budget - code.len() as u64).saturating_sub(mh.image.len() / 4);
                let mut sweep = Sweep {
                    memory: &memory,
                    arch,
                    source: refs.source("__TEXT/__text".to_string()),
                    base: sect.addr,
                    raw_base: sect.data_offset,
                    relocated: relocated_offsets(mh, sect),
                    regs: [None; 32],
                    pushed_pc: None,
                };
                let regions = disasm::regions(mh, sect, code.len());
                // An engine failure only loses the rest of this section.
                let _ = disassembler.run(code, sect.addr, &regions, |item| match item {
                    Item::Code {
                        cs,
                        insn,
                        region_start,
                    } => {
                        if region_start {
                            sweep.forget();
                        }
                        sweep.instruction(cs, insn, &mut refs);
                    }
                    Item::Data { .. } => sweep.forget(),
                });
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

/// Linear sweep over one `__TEXT,__text` section.
struct Sweep<'a> {
    memory: &'a Memory<'a>,
    arch: Arch,
    /// Source index of the section.
    source: u32,
    /// Address of the first byte.
    base: u64,
    /// File offset of the first byte.
    raw_base: u64,
    /// Section offsets patched by relocations, sorted.
    relocated: Vec<u64>,
    regs: [Option<Value>; 32],
    /// Return address pushed by a call to the next instruction.
    pushed_pc: Option<u64>,
}

impl Sweep<'_> {
    fn forget(&mut self) {
        self.regs = [None; 32];
        self.pushed_pc = None;
    }

    fn reg(&self, reg: Reg) -> Option<Value> {
        self.regs.get(reg as usize).copied().flatten()
    }

    /// The address of a memory operand, when the base register is known.
    fn address_of(&self, mem: Mem) -> Option<Value> {
        match mem.base {
            None => Some(Value {
                value: mem.offset,
                address: true,
            }),
            Some(base) => self.reg(base).map(|v| Value {
                value: v.value.wrapping_add(mem.offset),
                address: v.address,
            }),
        }
    }

    /// True when a relocation patches the instruction: its operands are
    /// placeholders until the object file is linked.
    fn is_relocated(&self, offset: u64, len: u64) -> bool {
        let i = self.relocated.partition_point(|r| *r < offset);
        self.relocated
            .get(i)
            .is_some_and(|r| *r < offset.saturating_add(len))
    }

    fn instruction(&mut self, cs: &Capstone, insn: &Insn<'_>, refs: &mut Xrefs) {
        let address = insn.address();
        let offset = address.wrapping_sub(self.base);
        let next = address.wrapping_add(insn.len() as u64);
        let Some(mut step) = self.arch.step(cs, insn) else {
            self.forget();
            return;
        };
        if self.is_relocated(offset, insn.len() as u64) {
            step.target = Target::None;
            step.mem = None;
            step.def = Def::None;
        }

        let source = self.source;
        let ref_raw = self.raw_base.wrapping_add(offset);
        let mut add = |target: u64, kind: RefKind| {
            if target != 0 {
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
        };

        // Data: the address of the memory operand.
        let mem = step
            .mem
            .and_then(|(mem, usage)| Some((mem, usage, self.address_of(mem)?)));
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
            Def::None => None,
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
            Def::Add { src, imm } => self.reg(src).map(|v| {
                let value = v.value.wrapping_add(imm);
                if v.address {
                    add(value, RefKind::Address);
                }
                Value { value, ..v }
            }),
            Def::Copy { src } => self.reg(src),
            Def::MovK { imm16, shift } => step.dst.and_then(|dst| self.reg(dst)).map(|v| {
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
            Def::Pop => self.pushed_pc.map(|value| Value {
                value,
                address: true,
            }),
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
                    if let Some(v) = self.reg(reg) {
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

        // The registers after the instruction.
        self.pushed_pc = pushes_pc.then_some(next);
        let mut lost = step.writes;
        if call && !pushes_pc {
            lost |= self.arch.caller_saved();
        }
        for (reg, slot) in self.regs.iter_mut().enumerate() {
            if lost & bit(reg as Reg) != 0 {
                *slot = None;
            }
        }
        if let (Some(v), Some(slot)) = (
            value,
            step.dst.and_then(|dst| self.regs.get_mut(dst as usize)),
        ) {
            *slot = Some(Value {
                value: if step.narrow {
                    v.value & 0xffff_ffff
                } else {
                    v.value
                },
                ..v
            });
        }
        // Nothing falls through to what follows.
        if matches!(step.flow, Flow::Return | Flow::Jump { conditional: false }) {
            self.forget();
        }
    }
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
            0x9400_0001, // 1110 bl  0x1114
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
                (0x1114, "call", 0x1110),
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

    #[test]
    fn relocated_instructions_are_not_resolved() {
        let (mh, _) = tiny_macho(CPU_TYPE_ARM64, &[], 0);
        let memory = Memory::new(&mh);
        let sweep = Sweep {
            memory: &memory,
            arch: Arch::Arm64,
            source: 0,
            base: 0,
            raw_base: 0,
            relocated: vec![4, 0x11],
            regs: [None; 32],
            pushed_pc: None,
        };
        assert!(!sweep.is_relocated(0, 4));
        assert!(sweep.is_relocated(4, 4));
        assert!(!sweep.is_relocated(8, 4));
        assert!(sweep.is_relocated(0x10, 5));
        assert!(!sweep.is_relocated(0x12, 5));
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
