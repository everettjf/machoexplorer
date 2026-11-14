//! Cross references: pointer values stored in pointer-like sections plus
//! branch and call targets found by a linear sweep of `__TEXT,__text`.
//!
//! The previous implementation used Capstone 5 for the sweep and its output
//! is the reference, so what matters is not what the code means but what
//! Capstone said about it. The sweep needs a few facts per instruction: its
//! length, whether it is in the jump or call group, which general registers
//! it is reported to write, a handful of address-forming patterns, and
//! whether the bytes decode at all (the sweep ends where they do not, which
//! on x86 is usually the first jump table). [`a64`] and [`x86`] are private
//! decoders that produce exactly those facts, including Capstone's
//! operand-access quirks; they are not general-purpose disassemblers.
//!
//! How they were checked against Capstone 5.0.9 (the build behind the golden
//! baselines), fact by fact:
//! - AArch64: every word of the system, exception and branch-register
//!   spaces, of the one/two-source data-processing space and of the
//!   floating-point conversions; tens of millions of random words per
//!   encoding class. Validity of the SIMD/FP, SVE and SME/reserved classes
//!   comes from tables built from an exhaustive scan (`a64_tables`).
//! - x86 (both modes): every opcode x ModRM byte of the one-, two- and
//!   three-byte, VEX and XOP maps under each prefix context, a decode at
//!   every byte offset of several large system binaries, and millions of
//!   random byte strings. Validity of the non-trivial maps comes from scanned
//!   tables (`x86_tables`). Known gaps: a few EVEX encodings whose validity
//!   depends on masking combined with other prefix bits, and 32-bit near
//!   jumps under a 67 prefix.

mod a64;
mod a64_tables;
mod x86;
mod x86_tables;

use super::header::MachHeader;
use crate::consts::{CPU_TYPE_ARM64, CPU_TYPE_I386, CPU_TYPE_X86_64};
use std::collections::{BTreeMap, HashMap, HashSet};

const SECTION_TYPE: u32 = 0x0000_00ff;
const S_LITERAL_POINTERS: u32 = 0x5;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;

/// Register id meaning "not a register the sweep tracks".
pub(crate) const NO_REG: u16 = u16::MAX;

/// One operand of a jump or call, as far as the sweep cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Imm(u64),
    Reg(u16),
    Mem { base: u16, index: u16, disp: i64 },
}

/// The address-forming patterns the sweep follows through registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    None,
    /// `dst = value`
    Set {
        dst: u16,
        value: u64,
    },
    /// `dst = src + imm` when `src` is known.
    Add {
        dst: u16,
        src: u16,
        imm: u64,
    },
    /// `dst = src - imm` when `src` is known.
    Sub {
        dst: u16,
        src: u16,
        imm: u64,
    },
    /// `dst = src` when `src` is known.
    Copy {
        dst: u16,
        src: u16,
    },
    /// Replace 16 bits of `dst` when it is known.
    MovK {
        dst: u16,
        imm16: u64,
        shift: u32,
    },
    /// `dst = *(base + disp)` when `base` is known and the pointer read is
    /// non-zero.
    LoadMem {
        dst: u16,
        base: u16,
        disp: u64,
    },
    /// `dst = *addr` when the pointer read is non-zero.
    LoadAbs {
        dst: u16,
        addr: u64,
    },
}

/// A small fixed-capacity list.
#[derive(Debug, Clone, Copy)]
pub(crate) struct List<T: Copy, const N: usize> {
    items: [T; N],
    len: u8,
}

impl<T: Copy, const N: usize> List<T, N> {
    pub(crate) fn new(fill: T) -> Self {
        List {
            items: [fill; N],
            len: 0,
        }
    }

    /// Append; silently dropped when full.
    pub(crate) fn push(&mut self, v: T) {
        if let Some(slot) = self.items.get_mut(self.len as usize) {
            *slot = v;
            self.len += 1;
        }
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        self.items.get(..self.len as usize).unwrap_or(&[])
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }
}

/// What the sweep needs to know about one decoded instruction.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Insn {
    pub size: u8,
    pub jump: bool,
    pub call: bool,
    /// Tracked registers reported as written.
    pub writes: List<u16, 20>,
    pub action: Action,
    /// Operands, in order. Only filled in for jumps and calls.
    pub ops: List<Op, 4>,
}

impl Insn {
    pub(crate) fn new(size: u8) -> Self {
        Insn {
            size,
            jump: false,
            call: false,
            writes: List::new(NO_REG),
            action: Action::None,
            ops: List::new(Op::Imm(0)),
        }
    }

    /// Record a written register (ignored when untracked or already there).
    pub(crate) fn write(&mut self, reg: u16) {
        if reg != NO_REG && !self.writes.as_slice().contains(&reg) {
            self.writes.push(reg);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86,
    X64,
    Arm64,
}

impl Arch {
    fn decode(self, code: &[u8], addr: u64) -> Option<Insn> {
        match self {
            Arch::Arm64 => a64::decode(code, addr),
            Arch::X64 => x86::decode(code, addr, true),
            Arch::X86 => x86::decode(code, addr, false),
        }
    }
}

/// How a reference was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    Pointer,
    Call,
    Jump,
    CallRipMem,
    JumpRipMem,
    CallRegMem,
    JumpRegMem,
    CallReg,
    JumpReg,
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
        }
    }

    /// True for references found in instructions.
    pub fn is_code(self) -> bool {
        self != RefKind::Pointer
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

fn is_pointer_like(flags: u32, sectname: &str) -> bool {
    matches!(
        flags & SECTION_TYPE,
        S_LITERAL_POINTERS
            | S_NON_LAZY_SYMBOL_POINTERS
            | S_LAZY_SYMBOL_POINTERS
            | S_LAZY_DYLIB_SYMBOL_POINTERS
            | S_MOD_INIT_FUNC_POINTERS
            | S_MOD_TERM_FUNC_POINTERS
    ) || sectname.starts_with("__objc_")
}

/// Pointer-sized value stored at virtual address `vmaddr`.
// QUIRK(parity): the segment's `fileoff` is used as an offset into the whole
// file rather than into this Mach-O, so inside a fat file the value is read
// from the wrong place. 64-bit segments are searched before 32-bit ones and
// the first one whose VM range holds the address decides.
fn read_pointer_at_vm(mh: &MachHeader, vmaddr: u64, wide: bool) -> Option<u64> {
    let size: u64 = if wide { 8 } else { 4 };
    for want64 in [true, false] {
        for seg in mh.segments.iter().filter(|s| s.is64 == want64) {
            if vmaddr < seg.vmaddr || vmaddr >= seg.vmaddr.wrapping_add(seg.vmsize) {
                continue;
            }
            let delta = vmaddr - seg.vmaddr;
            if delta > seg.filesize || size > seg.filesize - delta {
                return None;
            }
            let off = seg.fileoff.checked_add(delta)?;
            return if wide {
                mh.image.u64(off)
            } else {
                mh.image.u32(off).map(u64::from)
            };
        }
    }
    None
}

/// Upper bound on the bytes scanned per Mach-O header. Sections of a
/// well-formed file do not overlap, so it never comes close; it only stops a
/// crafted file whose sections all alias the same bytes.
fn scan_budget(mh: &MachHeader) -> u64 {
    mh.image.len().saturating_mul(4).saturating_add(4096)
}

/// Collect every reference of `mh`.
pub fn collect(mh: &MachHeader) -> Xrefs {
    let mut refs = Xrefs::default();
    let mut budget = scan_budget(mh);

    // 32-bit segments first, then 64-bit ones.
    for want64 in [false, true] {
        for sect in mh
            .segments
            .iter()
            .filter(|s| s.is64 == want64)
            .flat_map(|s| s.sections.iter())
        {
            if !is_pointer_like(sect.flags, &sect.sectname) {
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
                let target = u64::from_le_bytes(raw);
                if target == 0 {
                    continue;
                }
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

    let arch = match mh.cputype {
        CPU_TYPE_I386 => Some(Arch::X86),
        CPU_TYPE_X86_64 => Some(Arch::X64),
        CPU_TYPE_ARM64 => Some(Arch::Arm64),
        // 32-bit ARM code was disassembled too, but nothing was taken from it.
        _ => None,
    };
    if let Some(arch) = arch {
        let mut function_starts = HashSet::new();
        let mut addr = mh.base_address();
        for f in mh.function_starts() {
            addr = addr.wrapping_add(f.data);
            function_starts.insert(addr);
        }
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
                budget -= code.len() as u64;
                let sweep = Sweep {
                    mh,
                    arch,
                    base: sect.addr,
                    raw_base: sect.data_offset,
                    function_starts: &function_starts,
                };
                sweep.run(code, &mut refs);
            }
        }
    }
    // Only needed while collecting.
    refs.seen = HashSet::new();
    refs.source_index = HashMap::new();
    refs
}

/// Linear sweep over one `__TEXT,__text` section.
struct Sweep<'a> {
    mh: &'a MachHeader,
    arch: Arch,
    /// Address of the first byte.
    base: u64,
    /// File offset of the first byte.
    raw_base: u64,
    function_starts: &'a HashSet<u64>,
}

impl Sweep<'_> {
    fn run(&self, code: &[u8], refs: &mut Xrefs) {
        // Pointers are 8 bytes, except in 32-bit x86 code. Arm64 loads are
        // followed as 8-byte reads whatever the register width.
        let wide = self.arch != Arch::X86;
        let source = refs.source("__TEXT/__text".to_string());
        // Register id to the address it is believed to hold.
        let mut regs: HashMap<u16, u64> = HashMap::new();
        let mut pos: usize = 0;
        // The sweep ends at the first byte sequence that does not decode.
        while let Some(rest) = code.get(pos..).filter(|r| !r.is_empty()) {
            let address = self.base.wrapping_add(pos as u64);
            let Some(insn) = self.arch.decode(rest, address) else {
                break;
            };
            if insn.size == 0 {
                break;
            }
            if self.function_starts.contains(&address) {
                regs.clear();
            }
            // QUIRK(parity): registers written by the instruction are
            // forgotten before its own pattern is applied, so `add x8, x8,
            // #off` after `adrp x8` loses x8 instead of completing it.
            for reg in insn.writes.as_slice() {
                regs.remove(reg);
            }
            match insn.action {
                Action::None => {}
                Action::Set { dst, value } => {
                    regs.insert(dst, value);
                }
                Action::Add { dst, src, imm } => {
                    if let Some(v) = regs.get(&src).copied() {
                        regs.insert(dst, v.wrapping_add(imm));
                    }
                }
                Action::Sub { dst, src, imm } => {
                    if let Some(v) = regs.get(&src).copied() {
                        regs.insert(dst, v.wrapping_sub(imm));
                    }
                }
                Action::Copy { dst, src } => {
                    if let Some(v) = regs.get(&src).copied() {
                        regs.insert(dst, v);
                    }
                }
                Action::MovK { dst, imm16, shift } => {
                    if let Some(v) = regs.get(&dst).copied() {
                        let mask = !(0xffffu64.checked_shl(shift).unwrap_or(0));
                        regs.insert(dst, (v & mask) | imm16.checked_shl(shift).unwrap_or(0));
                    }
                }
                Action::LoadMem { dst, base, disp } => {
                    if let Some(v) = regs.get(&base).copied() {
                        if let Some(p) = read_pointer_at_vm(self.mh, v.wrapping_add(disp), wide)
                            .filter(|p| *p != 0)
                        {
                            regs.insert(dst, p);
                        }
                    }
                }
                Action::LoadAbs { dst, addr } => {
                    if let Some(p) = read_pointer_at_vm(self.mh, addr, wide).filter(|p| *p != 0) {
                        regs.insert(dst, p);
                    }
                }
            }

            if insn.jump || insn.call {
                let call = insn.call;
                let ref_raw = self.raw_base.wrapping_add(pos as u64);
                let mut add = |target: u64, kind: RefKind| {
                    refs.add(
                        target,
                        RefItem {
                            source,
                            kind,
                            ref_raw,
                            ref_vm: address,
                        },
                    );
                };
                let pick = |c: RefKind, j: RefKind| if call { c } else { j };
                if self.arch == Arch::Arm64 {
                    // QUIRK(parity): every immediate operand counts as a
                    // target, including the bit number of `tbz`/`tbnz`.
                    for op in insn.ops.as_slice() {
                        if let Op::Imm(v) = op {
                            add(*v, pick(RefKind::Call, RefKind::Jump));
                        }
                    }
                    // QUIRK(parity): any register operand with a known value
                    // counts too, e.g. the tested register of `cbz`.
                    for op in insn.ops.as_slice() {
                        if let Op::Reg(r) = op {
                            if let Some(v) = regs.get(r) {
                                add(*v, pick(RefKind::CallReg, RefKind::JumpReg));
                            }
                        }
                    }
                } else {
                    let next = address.wrapping_add(insn.size as u64);
                    for op in insn.ops.as_slice() {
                        match *op {
                            Op::Imm(v) => add(v, pick(RefKind::Call, RefKind::Jump)),
                            Op::Mem { base, disp, .. } if base == x86::RIP || base == x86::EIP => {
                                let at = next.wrapping_add(disp as u64);
                                if let Some(t) =
                                    read_pointer_at_vm(self.mh, at, wide).filter(|t| *t != 0)
                                {
                                    add(t, pick(RefKind::CallRipMem, RefKind::JumpRipMem));
                                }
                            }
                            Op::Mem { base, index, disp } if index == x86::NONE => {
                                if let Some(v) = regs.get(&base) {
                                    let at = v.wrapping_add(disp as u64);
                                    if let Some(t) =
                                        read_pointer_at_vm(self.mh, at, wide).filter(|t| *t != 0)
                                    {
                                        add(t, pick(RefKind::CallRegMem, RefKind::JumpRegMem));
                                    }
                                }
                            }
                            Op::Mem { .. } => {}
                            Op::Reg(r) => {
                                if let Some(v) = regs.get(&r) {
                                    add(*v, pick(RefKind::CallReg, RefKind::JumpReg));
                                }
                            }
                        }
                    }
                }
            }
            pos = pos.saturating_add(insn.size as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(arch: Arch, r: u16) -> String {
        if r == NO_REG {
            return "~".to_string();
        }
        match arch {
            Arch::Arm64 => a64::reg_name(r),
            _ => x86::reg_name(r).to_string(),
        }
    }

    /// One line per instruction in the format of the Capstone-based oracle
    /// used while developing the decoders (`cs_facts`).
    fn facts(arch: Arch, address: u64, insn: &Insn) -> String {
        let n = |r: u16| name(arch, r);
        let mut w: Vec<String> = insn.writes.as_slice().iter().map(|r| n(*r)).collect();
        w.sort();
        let a = match insn.action {
            Action::None => "-".to_string(),
            Action::Set { dst, value } => format!("set {} {:x}", n(dst), value),
            Action::Add { dst, src, imm } => format!("add {} {} {:x}", n(dst), n(src), imm),
            Action::Sub { dst, src, imm } => format!("sub {} {} {:x}", n(dst), n(src), imm),
            Action::Copy { dst, src } => format!("mov {} {}", n(dst), n(src)),
            Action::MovK { dst, imm16, shift } => format!("movk {} {:x} {}", n(dst), imm16, shift),
            Action::LoadMem { dst, base, disp } => {
                format!("ldrm {} {} {:x}", n(dst), n(base), disp)
            }
            Action::LoadAbs { dst, addr } => format!("ldri {} {:x}", n(dst), addr),
        };
        let mut line = format!(
            "{:x} {} {}{} W={} A={}",
            address,
            insn.size,
            if insn.jump { 'J' } else { '-' },
            if insn.call { 'C' } else { '-' },
            w.join(","),
            a
        );
        if insn.jump || insn.call {
            line.push_str(" B=");
            for op in insn.ops.as_slice() {
                match *op {
                    Op::Imm(v) => line.push_str(&format!("[i {:x}]", v)),
                    Op::Reg(r) => line.push_str(&format!("[r {}]", n(r))),
                    Op::Mem { base, index, disp } => {
                        let m = |r: u16| {
                            if r == x86::NONE {
                                "-".to_string()
                            } else {
                                n(r)
                            }
                        };
                        line.push_str(&format!("[m {} {} {:x}]", m(base), m(index), disp as u64))
                    }
                }
            }
        }
        line
    }

    /// Development aid, not a regression test: dump decoder facts for a raw
    /// code blob so they can be diffed against the Capstone oracle.
    /// `MOEX_XREF_FACTS=arch:infile:base_hex:outfile[:chunk]`; with `chunk`
    /// the input is a sequence of independent `chunk`-byte records and only
    /// the first instruction of each is decoded.
    #[test]
    fn dump_facts_for_oracle_diff() {
        let Ok(spec) = std::env::var("MOEX_XREF_FACTS") else {
            return;
        };
        let parts: Vec<&str> = spec.split(':').collect();
        let arch = match parts[0] {
            "arm64" => Arch::Arm64,
            "x64" => Arch::X64,
            _ => Arch::X86,
        };
        let code = std::fs::read(parts[1]).unwrap();
        let base = u64::from_str_radix(parts[2], 16).unwrap();
        let chunk: usize = parts.get(4).map(|c| c.parse().unwrap()).unwrap_or(0);
        let mut out = String::new();
        if chunk == 1 {
            // Sliding window: one instruction at every byte offset.
            for off in 0..code.len() {
                let address = base.wrapping_add(off as u64);
                let end = (off + 16).min(code.len());
                match arch.decode(&code[off..end], address) {
                    Some(insn) => out.push_str(&facts(arch, address, &insn)),
                    None => out.push_str(&format!("{:x} INVALID", address)),
                }
                out.push('\n');
            }
        } else if chunk > 0 {
            for (i, rec) in code.chunks_exact(chunk).enumerate() {
                let address = base.wrapping_add((i * chunk) as u64);
                match arch.decode(rec, address) {
                    Some(insn) => out.push_str(&facts(arch, address, &insn)),
                    None => out.push_str(&format!("{:x} INVALID", address)),
                }
                out.push('\n');
            }
        } else {
            let mut pos = 0;
            while pos < code.len() {
                let address = base.wrapping_add(pos as u64);
                let Some(insn) = arch.decode(&code[pos..], address) else {
                    break;
                };
                out.push_str(&facts(arch, address, &insn));
                out.push('\n');
                pos += insn.size as usize;
            }
            out.push_str(&format!("STOP {:x}\n", pos));
        }
        std::fs::write(parts[3], out).unwrap();
    }

    /// A 64-bit Mach-O with one `__TEXT` segment mapped at 0x1000 holding
    /// `code` in `__text` (at file offset 264) and one pointer in a
    /// non-lazy pointer section right after it. Returns the header and the
    /// file offset of the pointer.
    fn tiny_macho(cputype: u32, code: &[u8], pointer: u64) -> (MachHeader, u64) {
        const TEXT_OFF: u64 = 264;
        let got_off = (TEXT_OFF + code.len() as u64 + 7) & !7;
        let total = got_off + 8;
        let mut f = Vec::new();
        let u32_ = |f: &mut Vec<u8>, v: u32| f.extend_from_slice(&v.to_le_bytes());
        let u64_ = |f: &mut Vec<u8>, v: u64| f.extend_from_slice(&v.to_le_bytes());
        let name = |f: &mut Vec<u8>, n: &str| {
            let mut b = [0u8; 16];
            b[..n.len()].copy_from_slice(n.as_bytes());
            f.extend_from_slice(&b);
        };
        for v in [0xfeedfacf, cputype, 3, 2, 1, 232, 0, 0] {
            u32_(&mut f, v);
        }
        u32_(&mut f, 0x19);
        u32_(&mut f, 232);
        name(&mut f, "__TEXT");
        for v in [0x1000, 0x1000, 0, total] {
            u64_(&mut f, v);
        }
        for v in [5, 5, 2, 0] {
            u32_(&mut f, v);
        }
        for (sect, off, size, flags) in [
            ("__text", TEXT_OFF, code.len() as u64, 0x8000_0400u32),
            ("__got", got_off, 8, S_NON_LAZY_SYMBOL_POINTERS),
        ] {
            name(&mut f, sect);
            name(&mut f, "__TEXT");
            u64_(&mut f, 0x1000 + off);
            u64_(&mut f, size);
            for v in [off as u32, 0, 0, 0, flags, 0, 0, 0] {
                u32_(&mut f, v);
            }
        }
        assert_eq!(f.len() as u64, TEXT_OFF);
        f.extend_from_slice(code);
        f.resize(got_off as usize, 0);
        u64_(&mut f, pointer);
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
                (0x2000, "call", 264, 0x1108),
            ]
        );
        assert_eq!(x.source_name(&x.targets[&0x1108][0]), "__TEXT/__got");
        assert_eq!(x.source_name(&x.targets[&0x2000][0]), "__TEXT/__text");
    }

    #[test]
    fn sweep_arm64() {
        // ldr x16, got ; br x16 ; bl 0x2000
        let mut code = Vec::new();
        for word in [0x5800_0090u32, 0xd61f_0200, 0x9400_03bc] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let (mh, _) = tiny_macho(CPU_TYPE_ARM64, &code, 0x1108);
        let x = collect(&mh);
        assert_eq!(
            summary(&x),
            [
                (0x1108, "pointer", 280, 0),
                (0x1108, "jump-reg", 268, 0x110c),
                (0x2000, "call", 272, 0x1110),
            ]
        );
    }

    #[test]
    fn sweep_stops_at_undecodable_bytes() {
        // jmp +0 ; (invalid) ; call 0x2000 -- the call is never reached.
        let mut code = vec![0xeb, 0x00, 0xff, 0xff, 0xe8];
        code.extend_from_slice(&(0x2000u32 - 0x1111).to_le_bytes());
        let (mh, _) = tiny_macho(CPU_TYPE_X86_64, &code, 0);
        let x = collect(&mh);
        assert_eq!(summary(&x), [(0x110a, "jump", 264, 0x1108)]);
        // Other CPU types are not swept at all.
        let (mh, _) = tiny_macho(crate::consts::CPU_TYPE_ARM, &code, 0);
        assert!(collect(&mh).targets.is_empty());
    }

    #[test]
    fn pointer_reads_follow_segments() {
        let (mh, got) = tiny_macho(CPU_TYPE_X86_64, &[0xc3], 0x1122_3344_5566_7788);
        assert_eq!(
            read_pointer_at_vm(&mh, 0x1000 + got, true),
            Some(0x1122_3344_5566_7788)
        );
        assert_eq!(
            read_pointer_at_vm(&mh, 0x1000 + got, false),
            Some(0x5566_7788)
        );
        // Last byte of the pointer is past the segment's file contents.
        assert_eq!(read_pointer_at_vm(&mh, 0x1000 + got + 1, true), None);
        assert_eq!(read_pointer_at_vm(&mh, 0x9000, true), None);
    }

    #[test]
    fn pointer_like_sections() {
        assert!(is_pointer_like(S_NON_LAZY_SYMBOL_POINTERS, "__got"));
        assert!(is_pointer_like(S_MOD_INIT_FUNC_POINTERS, "__mod_init_func"));
        assert!(is_pointer_like(0, "__objc_classlist"));
        assert!(is_pointer_like(0x1000_0000, "__objc_methname"));
        assert!(!is_pointer_like(0, "__const"));
        assert!(!is_pointer_like(0x8000_0400, "__text"));
        // Only the low byte is the section type.
        assert!(is_pointer_like(0xff00 | S_LITERAL_POINTERS, "x"));
    }

    #[test]
    fn list_is_bounded() {
        let mut l: List<u16, 2> = List::new(0);
        l.push(1);
        l.push(2);
        l.push(3);
        assert_eq!(l.as_slice(), &[1, 2]);
        l.clear();
        assert!(l.as_slice().is_empty());
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
    }
}
