//! Cross references: pointer values stored in pointer-like sections plus
//! what the code sections (`__text`, `__stubs`, `__stub_helper`, ...) refer
//! to.
//!
//! The code is decoded by Capstone (see [`super::disasm`]) region by region:
//! decoding restarts at every symbol and function start and steps over
//! data-in-code ranges and undecodable bytes. Per instruction the
//! architecture modules ([`arm64`], [`x86`], [`arm`], [`ppc`]) turn Capstone's
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
//! Indirect jumps (jump tables) are not followed: the code after an
//! unconditional jump or a return starts with nothing known unless a
//! direct jump leads there.
//!
//! In an object file the operands of an instruction a relocation patches
//! are placeholders; the relocation entry supplies the symbol, and with it
//! the address when the symbol is defined in the file.

mod arm;
mod arm64;
mod ppc;
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
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_I386, CPU_TYPE_POWERPC,
    CPU_TYPE_POWERPC64, CPU_TYPE_X86_64, LC_DYLD_CHAINED_FIXUPS, MH_OBJECT,
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
    Ppc,
}

impl Arch {
    fn of(cputype: u32) -> Option<Arch> {
        match cputype {
            CPU_TYPE_I386 => Some(Arch::X86),
            CPU_TYPE_X86_64 => Some(Arch::X64),
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => Some(Arch::Arm64),
            CPU_TYPE_ARM => Some(Arch::Arm),
            CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => Some(Arch::Ppc),
            _ => None,
        }
    }

    fn step(self, cs: &Capstone, insn: &Insn<'_>) -> Option<Step> {
        let detail = cs.insn_detail(insn).ok()?;
        Some(match self {
            Arch::Arm64 => arm64::step(insn, &detail),
            Arch::X64 | Arch::X86 => x86::step(insn, &detail),
            Arch::Arm => arm::step(insn, &detail),
            Arch::Ppc => ppc::step(insn, &detail),
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
            Arch::Arm | Arch::Ppc => 0,
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
    /// For the slots of object-file relocations and threaded binds.
    decoder: PointerDecoder<'a>,
}

impl<'a> Memory<'a> {
    fn new(mh: &'a MachHeader) -> Self {
        Memory {
            mh,
            pointer_size: if mh.is64 { 8 } else { 4 },
            image_base: mh.base_address(),
            chained: chained_formats(mh),
            decoder: PointerDecoder::new(mh),
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
}

/// The patches of a code section, sorted by the section offset they apply
/// to. Charges `budget` 8 bytes per entry read.
fn code_patches(mh: &MachHeader, sect: &Section, budget: &mut u64) -> Vec<(u32, Patch)> {
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
    let mut out: Vec<(u32, Patch)> = Vec::with_capacity(entries.len());
    // `ARM64_RELOC_ADDEND` applies to the entry after it.
    let mut addend: Option<(u32, i64)> = None;
    for r in entries {
        let patch = match mh.cputype {
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
            // 32-bit x86 and ARM: a section-relative entry leaves the
            // address in the instruction; what an external one leaves
            // there depends on the instruction form and is not followed.
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

/// Targets of the direct jumps and calls of a code section, sorted, one
/// entry per instruction. The sweep uses them to know every way a label is
/// reached; calls are included so that a label that is called is never
/// taken for one that is only fallen into.
fn branch_targets(
    mh: &MachHeader,
    arch: Arch,
    code: &[u8],
    base: u64,
    regions: &[disasm::Region],
) -> Vec<u64> {
    let mut out = Vec::new();
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
                    out.push(at.wrapping_add(offset as u64));
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
                        out.push(target);
                    }
                });
            }
        }
        // No registers are followed for 32-bit ARM and PowerPC, so labels
        // do not matter.
        Arch::Arm | Arch::Ppc => {}
    }
    out.sort_unstable();
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
                let mut sweep = Sweep {
                    memory: &memory,
                    arch,
                    source: refs.source(format!("{}/{}", sect.segname, sect.sectname)),
                    base: sect.addr,
                    raw_base: sect.data_offset,
                    patches: code_patches(mh, sect, &mut budget),
                    targets: branch_targets(mh, arch, code, sect.addr, &regions),
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

/// What is known at one point of the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    regs: [Option<Value>; 32],
    /// Return address pushed by a call to the next instruction.
    pushed_pc: Option<u64>,
}

impl State {
    /// Nothing is known.
    const UNKNOWN: State = State {
        regs: [None; 32],
        pushed_pc: None,
    };

    fn reg(&self, reg: Reg) -> Option<Value> {
        self.regs.get(reg as usize).copied().flatten()
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
        out
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
/// knowledge at a label, and there are 32 registers to lose.
const MAX_PASSES: usize = 40;

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
    /// File offset of the first byte.
    raw_base: u64,
    /// What relocations do, by section offset, sorted.
    patches: Vec<(u32, Patch)>,
    /// Every direct jump and call target of the section, sorted.
    targets: Vec<u64>,
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
        let i = self.patches.partition_point(|p| u64::from(p.0) < offset);
        let end = offset.saturating_add(len);
        let mut inside = self
            .patches
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
        let mut settled = false;
        for _ in 0..MAX_PASSES {
            if !self.pass(&run, &mut labels, &jump_to, None) {
                settled = true;
                break;
            }
        }
        if !settled {
            for label in labels.values_mut() {
                label.outside = true;
            }
        }
        self.pass(&run, &mut labels, &jump_to, Some(refs));
    }

    /// One pass over a run in address order. Returns whether a jump back
    /// lowered what is known at its label, so that another pass is needed.
    /// With `refs`, reports the references instead.
    fn pass(
        &self,
        run: &[Seen],
        labels: &mut HashMap<usize, Label>,
        jump_to: &impl Fn(&Seen) -> Option<usize>,
        mut refs: Option<&mut Xrefs>,
    ) -> bool {
        let mut changed = false;
        // The state falling into the next instruction; `None` after a
        // return or an unconditional jump.
        let mut falling: Option<State> = Some(State::UNKNOWN);
        for (index, seen) in run.iter().enumerate() {
            let state = match labels.get(&index) {
                Some(label) if label.outside => State::UNKNOWN,
                Some(label) => match (falling, label.jumped) {
                    (Some(a), Some(b)) => a.meet(&b),
                    (Some(a), None) => a,
                    (None, Some(b)) => b,
                    // Only reached by jumps that come later.
                    (None, None) => State::UNKNOWN,
                },
                // Not a label: reached from above, or (after a return or a
                // jump) by a way the sweep does not see.
                None => falling.unwrap_or(State::UNKNOWN),
            };
            let after = self.transfer(&state, seen, refs.as_deref_mut());
            if let Some(target) = jump_to(seen) {
                if let Some(label) = labels.get_mut(&target) {
                    let merged = label.jumped.map_or(after, |known| known.meet(&after));
                    if label.jumped != Some(merged) {
                        label.jumped = Some(merged);
                        // A label at or before the jump has already been
                        // passed with what was known until now.
                        changed |= target <= index && !label.outside;
                    }
                }
            }
            falling = (!matches!(
                seen.step.flow,
                Flow::Return | Flow::Jump { conditional: false }
            ))
            .then_some(after);
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
                *slot = None;
            }
        }
        if let (Some(v), Some(slot)) = (
            value,
            step.dst.and_then(|dst| after.regs.get_mut(dst as usize)),
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
        after
    }
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
            raw_base: 0,
            patches: Vec::new(),
            targets: Vec::new(),
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
            branch_targets(&mh, Arch::Arm64, &code, 0x1108, &[region]),
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
            branch_targets(&mh, Arch::X64, &code, 0x1108, &[region]),
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
