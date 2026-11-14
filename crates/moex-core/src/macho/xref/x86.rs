//! Minimal x86 / x86-64 decoder for the cross-reference sweep: instruction
//! lengths, jumps and calls with their operands, the general registers an
//! instruction writes, and the few `mov`/`lea`/`xor` patterns the sweep
//! follows.
//!
//! Registers: 64-bit `rax..r15` are 0..=15, 32-bit 16..=31, 16-bit 32..=47,
//! low bytes 48..=63, `ah ch dh bh` 64..=67, then `rip eip ip`, segment,
//! control and debug registers. Different widths of one register are
//! distinct ids, as they were for Capstone register ids.

use super::x86_tables::{self as tables, MapTable};
use super::{Action, Insn, Op, NO_REG};

pub(crate) const R64: u16 = 0;
pub(crate) const R32: u16 = 16;
pub(crate) const R16: u16 = 32;
pub(crate) const R8: u16 = 48;
pub(crate) const R8H: u16 = 64;
pub(crate) const RIP: u16 = 68;
pub(crate) const EIP: u16 = 69;
const SEG: u16 = 72;
const CR: u16 = 80;
const DR: u16 = 96;
/// "No register" in a memory operand.
pub(crate) const NONE: u16 = NO_REG - 1;

const AX: u16 = 0;
const CX: u16 = 1;
const DX: u16 = 2;
const BX: u16 = 3;
const SP: u16 = 4;
const BP: u16 = 5;
const SI: u16 = 6;
const DI: u16 = 7;

#[cfg(test)]
pub(crate) fn reg_name(r: u16) -> &'static str {
    const N64: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    const N32: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    const N16: [&str; 16] = [
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
        "r13w", "r14w", "r15w",
    ];
    const N8: [&str; 16] = [
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
        "r13b", "r14b", "r15b",
    ];
    const NH: [&str; 4] = ["ah", "ch", "dh", "bh"];
    const NS: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];
    const NCR: [&str; 16] = [
        "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11",
        "cr12", "cr13", "cr14", "cr15",
    ];
    const NDR: [&str; 16] = [
        "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11",
        "dr12", "dr13", "dr14", "dr15",
    ];
    let i = r as usize;
    match r {
        0..=15 => N64[i],
        16..=31 => N32[i - 16],
        32..=47 => N16[i - 32],
        48..=63 => N8[i - 48],
        64..=67 => NH[i - 64],
        68 => "rip",
        69 => "eip",
        70 => "ip",
        72..=77 => NS[i - 72],
        80..=95 => NCR[i - 80],
        96..=111 => NDR[i - 96],
        _ => "~",
    }
}

/// Parsed ModRM byte (and SIB / displacement).
#[derive(Debug, Clone, Copy)]
struct ModRm {
    /// `mod` field; 3 means the r/m operand is a register.
    md: u8,
    /// `reg` field without REX.R.
    reg: u8,
    /// `rm` field without REX.B.
    rm: u8,
    base: u16,
    index: u16,
    disp: i64,
}

impl ModRm {
    fn is_reg(&self) -> bool {
        self.md == 3
    }
}

struct Dec<'a> {
    code: &'a [u8],
    pos: usize,
    mode64: bool,
    p66: bool,
    p67: bool,
    /// Last of F2 / F3 seen, or 0.
    rep: u8,
    lock: bool,
    /// REX byte, or 0.
    rex: u8,
    /// VEX/EVEX/XOP state.
    vex: bool,
    vex_w: bool,
    vex_r: bool,
    vex_x: bool,
    vex_b: bool,
    vex_vvvv: u8,
    /// Mandatory prefix of a VEX-like encoding: 0 none, 1 = 66, 2 = F3, 3 = F2.
    vex_pp: u8,
    /// Pending `disp` of a RIP-relative load, resolved once the length is known.
    rip_load: Option<(u16, i64)>,
    rip_lea: Option<(u16, i64)>,
    /// Relative branch displacement, resolved once the length is known.
    rel: Option<(i64, u8)>,
    /// The instruction is one of the few that accept a LOCK prefix.
    lockable: bool,
    rel16_signed: bool,
}

impl<'a> Dec<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.code.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn peek(&self) -> Option<u8> {
        self.code.get(self.pos).copied()
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.code.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    /// Little-endian immediate of `n` bytes, sign-extended.
    fn imm_s(&mut self, n: usize) -> Option<i64> {
        let end = self.pos.checked_add(n)?;
        let b = self.code.get(self.pos..end)?;
        let mut v: u64 = 0;
        for (k, byte) in b.iter().enumerate() {
            v |= (*byte as u64) << (8 * k);
        }
        self.pos = end;
        Some(if n >= 8 || n == 0 {
            v as i64
        } else {
            ((v << (64 - 8 * n)) as i64) >> (64 - 8 * n)
        })
    }

    fn rex_w(&self) -> bool {
        self.rex & 8 != 0 || self.vex_w
    }
    fn rex_r(&self) -> u8 {
        if self.rex & 4 != 0 || self.vex_r {
            8
        } else {
            0
        }
    }
    fn rex_x(&self) -> u8 {
        if self.rex & 2 != 0 || self.vex_x {
            8
        } else {
            0
        }
    }
    fn rex_b(&self) -> u8 {
        if self.rex & 1 != 0 || self.vex_b {
            8
        } else {
            0
        }
    }

    /// Operand size in bits.
    fn osz(&self) -> u32 {
        if self.mode64 && self.rex_w() {
            64
        } else if self.p66 {
            16
        } else {
            32
        }
    }

    /// Operand size of instructions that default to 64 bits in long mode.
    fn osz_d64(&self) -> u32 {
        if self.mode64 {
            if self.p66 && !self.rex_w() {
                16
            } else {
                64
            }
        } else {
            self.osz()
        }
    }

    /// Address size in bits.
    fn asz(&self) -> u32 {
        match (self.mode64, self.p67) {
            (true, false) => 64,
            (true, true) | (false, false) => 32,
            (false, true) => 16,
        }
    }

    /// General register `n` (0..=15) of `size` bits.
    fn gpr(&self, size: u32, n: u8) -> u16 {
        let n = (n & 15) as u16;
        match size {
            64 => R64 + n,
            32 => R32 + n,
            16 => R16 + n,
            _ => {
                if (4..8).contains(&n) && self.rex == 0 && !self.vex {
                    R8H + n - 4
                } else {
                    R8 + n
                }
            }
        }
    }

    /// `rsi`/`rdi`-style implicit register of the string instructions.
    fn string_reg(&self, n: u16) -> u16 {
        if self.mode64 {
            R64 + n
        } else {
            R32 + n
        }
    }

    /// Count register implicitly written under a `rep`/`repne` prefix.
    fn rep_count(&self, i: &mut Insn) {
        if self.rep != 0 {
            i.write(if self.mode64 { R64 + CX } else { R32 + CX });
        }
    }

    /// Stack pointer as named by the implicit operands of stack instructions.
    fn stack_reg(&self) -> u16 {
        if self.mode64 {
            R64 + SP
        } else {
            R32 + SP
        }
    }

    /// Stack pointer for push/pop forms that have a 16-bit variant.
    // QUIRK(parity): the 16-bit forms name `esp`, even in 64-bit mode.
    fn stack_reg_sized(&self) -> u16 {
        if self.mode64 && !self.p66 {
            R64 + SP
        } else {
            R32 + SP
        }
    }

    fn modrm(&mut self) -> Option<ModRm> {
        let b = self.byte()?;
        let md = b >> 6;
        let reg = (b >> 3) & 7;
        let rm = b & 7;
        let mut m = ModRm {
            md,
            reg,
            rm,
            base: NONE,
            index: NONE,
            disp: 0,
        };
        if md == 3 {
            return Some(m);
        }
        let asz = self.asz();
        if asz == 16 {
            let (base, index) = match rm {
                0 => (R16 + BX, R16 + SI),
                1 => (R16 + BX, R16 + DI),
                2 => (R16 + BP, R16 + SI),
                3 => (R16 + BP, R16 + DI),
                4 => (R16 + SI, NONE),
                5 => (R16 + DI, NONE),
                6 => (if md == 0 { NONE } else { R16 + BP }, NONE),
                _ => (R16 + BX, NONE),
            };
            m.base = base;
            m.index = index;
            m.disp = match md {
                0 if rm == 6 => self.imm_s(2)?,
                1 => self.imm_s(1)?,
                2 => self.imm_s(2)?,
                _ => 0,
            };
            return Some(m);
        }
        let areg = |n: u8| {
            if asz == 64 {
                R64 + n as u16
            } else {
                R32 + n as u16
            }
        };
        if rm == 4 {
            let sib = self.byte()?;
            let idx = ((sib >> 3) & 7) | self.rex_x();
            let bs = sib & 7;
            if idx != 4 {
                m.index = areg(idx);
            }
            let no_base = bs == 5 && md == 0;
            if no_base {
                m.disp = self.imm_s(4)?;
            } else {
                m.base = areg(bs | self.rex_b());
            }
            // With 64-bit addressing, a SIB byte that was not needed (no
            // index, and a scale or a base that could have been encoded
            // without SIB) is reported with the pseudo index register riz,
            // which is not a register the sweep knows.
            if asz == 64 && idx == 4 && (sib >> 6 != 0 || (!no_base && bs != 4)) {
                m.index = NO_REG;
            }
        } else if rm == 5 && md == 0 {
            m.disp = self.imm_s(4)?;
            if self.mode64 {
                m.base = if asz == 64 { RIP } else { EIP };
            }
            return Some(m);
        } else {
            m.base = areg(rm | self.rex_b());
        }
        match md {
            1 => m.disp = self.imm_s(1)?,
            2 => m.disp = self.imm_s(4)?,
            _ => {}
        }
        Some(m)
    }

    /// ModRM byte whose `mod` field is ignored: r/m is always a register.
    fn modrm_reg_only(&mut self) -> Option<ModRm> {
        let b = self.byte()?;
        Some(ModRm {
            md: 3,
            reg: (b >> 3) & 7,
            rm: b & 7,
            base: NONE,
            index: NONE,
            disp: 0,
        })
    }

    /// The r/m operand as a general register of `size` bits.
    fn rm_reg(&self, m: &ModRm, size: u32) -> u16 {
        self.gpr(size, m.rm | self.rex_b())
    }

    /// The reg operand as a general register of `size` bits.
    fn reg_reg(&self, m: &ModRm, size: u32) -> u16 {
        self.gpr(size, m.reg | self.rex_r())
    }

    /// Immediate of 2 or 4 bytes by operand size (never 8).
    fn imm_z(&mut self) -> Option<i64> {
        if self.osz() == 16 {
            self.imm_s(2)
        } else {
            self.imm_s(4)
        }
    }

    fn acc(&self, size: u32) -> u16 {
        self.gpr(size, 0)
    }

    /// Prefix context of the legacy opcode maps.
    fn legacy_ctx(&self) -> usize {
        let rep = match self.rep {
            0xf3 => 1,
            0xf2 => 2,
            _ => 0,
        };
        (self.p66 as usize) | rep << 1 | ((self.rex & 8 != 0) as usize) << 3
    }

    /// The byte a ModRM lookup would see (0 past the end of the input).
    fn peek_modrm(&self) -> u8 {
        self.peek().unwrap_or(0)
    }
}

/// Whether `opcode` with ModRM byte `modrm` is accepted under context `ctx`.
fn table_valid(t: &MapTable, ctx: usize, opcode: u8, modrm: u8) -> bool {
    let lookup = || {
        let profile = *t.profile_of.get(opcode as usize)? as usize;
        let shape = *t
            .profiles
            .get(profile.checked_mul(t.contexts)?.checked_add(ctx)?)?;
        let (mem, reg) = *t.shapes.get(shape as usize)?;
        Some(shape_valid(mem, reg, modrm))
    };
    ctx < t.contexts && lookup().unwrap_or(false)
}

fn shape_valid(mem: u8, reg: u64, modrm: u8) -> bool {
    if modrm >> 6 == 3 {
        (reg >> (modrm & 0x3f)) & 1 != 0
    } else {
        (mem >> ((modrm >> 3) & 7)) & 1 != 0
    }
}

/// Zero-extend the low `bits` of `v`.
fn zext(v: i64, bits: u32) -> u64 {
    if bits >= 64 {
        v as u64
    } else {
        (v as u64) & ((1u64 << bits) - 1)
    }
}

/// Decode the instruction at the start of `code`, located at `addr`.
/// `None` when the bytes are not an instruction Capstone 5 accepts.
pub(crate) fn decode(code: &[u8], addr: u64, mode64: bool) -> Option<Insn> {
    let code = code.get(..code.len().min(15)).unwrap_or(code);
    let mut d = Dec {
        code,
        pos: 0,
        mode64,
        p66: false,
        p67: false,
        rep: 0,
        lock: false,
        rex: 0,
        vex: false,
        vex_w: false,
        vex_r: false,
        vex_x: false,
        vex_b: false,
        vex_vvvv: 0,
        vex_pp: 0,
        rip_load: None,
        rip_lea: None,
        rel: None,
        lockable: false,
        rel16_signed: false,
    };
    let mut i = Insn::new(0);
    // Legacy and REX prefixes may come in any order; a REX prefix only
    // counts when it is the last one before the opcode.
    loop {
        let b = d.peek()?;
        match b {
            0x66 => d.p66 = true,
            0x67 => d.p67 = true,
            0xf2 | 0xf3 => {
                d.rep = b;
                // A LOCK that precedes F2/F3 is dropped.
                d.lock = false;
            }
            0xf0 => d.lock = true,
            0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 => {}
            0x40..=0x4f if mode64 => {
                d.rex = b;
                d.pos += 1;
                continue;
            }
            _ => break,
        }
        d.rex = 0;
        d.pos += 1;
    }
    let op = d.byte()?;
    one_byte(&mut d, op, &mut i)?;
    if d.lock && !d.lockable {
        return None;
    }

    let size = d.pos;
    i.size = size as u8;
    let next = addr.wrapping_add(size as u64);
    if let Some((dst, disp)) = d.rip_load {
        i.action = Action::LoadAbs {
            dst,
            addr: next.wrapping_add(disp as u64),
        };
    }
    if let Some((dst, disp)) = d.rip_lea {
        i.action = Action::Set {
            dst,
            value: next.wrapping_add(disp as u64),
        };
    }
    if let Some((rel, bits)) = d.rel {
        let target = next.wrapping_add(rel as u64);
        let target = if mode64 {
            target
        } else {
            zext(target as i64, bits as u32)
        };
        i.ops.push(Op::Imm(target));
    }
    if !(i.jump || i.call) {
        i.ops.clear();
    }
    Some(i)
}

fn mem_op(m: &ModRm) -> Op {
    Op::Mem {
        base: m.base,
        index: m.index,
        disp: m.disp,
    }
}

/// The common `op r/m, r` / `op r, r/m` / `op acc, imm` block of the
/// arithmetic opcodes 00..=3F. `writes` is false for `cmp`.
fn alu(d: &mut Dec, op: u8, writes: bool, i: &mut Insn) -> Option<()> {
    let size = if op & 1 == 0 { 8 } else { d.osz() };
    match op & 7 {
        0 | 1 => {
            let m = d.modrm()?;
            d.lockable = writes && !m.is_reg();
            if writes && m.is_reg() {
                i.write(d.rm_reg(&m, size));
            }
            if op & 0xf8 == 0x30 && m.is_reg() && d.rm_reg(&m, size) == d.reg_reg(&m, size) {
                i.action = Action::Set {
                    dst: d.rm_reg(&m, size),
                    value: 0,
                };
            }
        }
        2 | 3 => {
            let m = d.modrm()?;
            // QUIRK(parity): LOCK is accepted on the register-destination
            // forms too, except for `sbb`.
            d.lockable = writes && !m.is_reg() && op & 0xf8 != 0x18;
            if writes {
                i.write(d.reg_reg(&m, size));
            }
            if op & 0xf8 == 0x30 && m.is_reg() && d.rm_reg(&m, size) == d.reg_reg(&m, size) {
                i.action = Action::Set {
                    dst: d.reg_reg(&m, size),
                    value: 0,
                };
            }
        }
        4 => {
            d.skip(1)?;
            if writes {
                i.write(d.acc(8));
            }
        }
        _ => {
            d.imm_z()?;
            if writes {
                i.write(d.acc(size));
            }
        }
    }
    Some(())
}

fn rel_branch(d: &mut Dec, bytes: usize) -> Option<()> {
    let mut rel = d.imm_s(bytes)?;
    // QUIRK(parity): in 32-bit mode a 16-bit displacement is zero-extended
    // for jumps (and sign-extended for calls).
    if bytes == 2 && !d.mode64 && !d.rel16_signed {
        rel &= 0xffff;
    }
    // QUIRK(parity): in 32-bit mode a 67 prefix makes a near jump use only
    // the low 16 bits of its displacement when bit 15 is set.
    if bytes == 4 && !d.mode64 && d.p67 && !d.rel16_signed && rel & 0x8000 != 0 {
        rel = (rel as i16) as i64;
    }
    let bits = if d.mode64 { 64 } else { 32 };
    d.rel = Some((rel, bits));
    Some(())
}

fn one_byte(d: &mut Dec, op: u8, i: &mut Insn) -> Option<()> {
    let m64 = d.mode64;
    match op {
        0x0f => return two_byte(d, i),
        0x00..=0x3f => {
            match op & 7 {
                6 | 7 => {
                    // push/pop segment, bcd adjust: 32-bit mode only.
                    if m64 {
                        return None;
                    }
                    // Only `pop` reports anything: the segment register.
                    if matches!(op, 0x07 | 0x17 | 0x1f) {
                        i.write(
                            SEG + if op == 0x07 {
                                0
                            } else if op == 0x17 {
                                2
                            } else {
                                3
                            },
                        );
                    }
                }
                _ => alu(d, op, op & 0x38 != 0x38, i)?,
            }
        }
        0x40..=0x4f => {
            // inc / dec (REX was consumed already in 64-bit mode).
            if m64 {
                return None;
            }
            i.write(d.gpr(d.osz(), op & 7));
        }
        0x50..=0x57 => {
            i.write(d.stack_reg_sized());
        }
        0x58..=0x5f => {
            i.write(d.gpr(d.osz_d64(), (op & 7) | d.rex_b()));
            i.write(d.stack_reg_sized());
        }
        0x60 | 0x61 => {
            if m64 {
                return None;
            }
            if op == 0x61 {
                for n in [DI, SI, BP, BX, DX, CX, AX] {
                    i.write(R32 + n);
                }
            }
            i.write(R32 + SP);
        }
        0x62 => {
            let b1 = d.peek()?;
            let b2 = *d.code.get(d.pos + 1)?;
            if (m64 || b1 >= 0xc0) && b1 & 0x0c == 0 && b2 & 4 != 0 {
                return evex(d, i);
            }
            if m64 {
                return None;
            }
            let m = d.modrm()?; // bound
            if m.is_reg() {
                return None;
            }
            // QUIRK(parity): the bounds-checked register is reported as written.
            i.write(d.reg_reg(&m, d.osz()));
        }
        0x63 => {
            // QUIRK(parity): 67-prefixed `movsxd` without 66 or REX.W is
            // rejected.
            if m64 && d.p67 && d.rex & 8 == 0 {
                return None;
            }
            let m = d.modrm()?;
            if m64 {
                i.write(d.reg_reg(&m, d.osz()));
            } else if m.is_reg() {
                i.write(d.rm_reg(&m, 16));
            }
        }
        0x68 => {
            d.imm_z()?;
            i.write(d.stack_reg_sized());
        }
        0x6a => {
            d.skip(1)?;
            i.write(d.stack_reg_sized());
        }
        0x69 | 0x6b => {
            let m = d.modrm()?;
            if op == 0x69 {
                d.imm_z()?;
            } else {
                d.skip(1)?;
            }
            i.write(d.reg_reg(&m, d.osz()));
        }
        0x6c | 0x6d => {
            i.write(R32 + DI);
            d.rep_count(i);
        }
        0x6e | 0x6f => {
            i.write(R32 + SI);
            d.rep_count(i);
        }
        0x70..=0x7f => {
            i.jump = true;
            rel_branch(d, 1)?;
        }
        0x80..=0x83 => {
            if op == 0x82 && m64 {
                return None;
            }
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            if op == 0x81 {
                d.imm_z()?;
            } else {
                d.skip(1)?;
            }
            d.lockable = m.reg != 7 && !m.is_reg();
            if m.reg != 7 && m.is_reg() {
                i.write(d.rm_reg(&m, size));
            }
        }
        0x84 | 0x85 => {
            d.modrm()?;
        }
        0x86 | 0x87 => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            d.lockable = !m.is_reg();
            i.write(d.reg_reg(&m, size));
            if m.is_reg() {
                i.write(d.rm_reg(&m, size));
            }
        }
        0x88 | 0x89 => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            if m.is_reg() {
                let (dst, src) = (d.rm_reg(&m, size), d.reg_reg(&m, size));
                i.write(dst);
                i.action = Action::Copy { dst, src };
            }
        }
        0x8a | 0x8b => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            let dst = d.reg_reg(&m, size);
            i.write(dst);
            if m.is_reg() {
                i.action = Action::Copy {
                    dst,
                    src: d.rm_reg(&m, size),
                };
            } else if m.base == RIP || m.base == EIP {
                d.rip_load = Some((dst, m.disp));
            }
        }
        0x8c => {
            let m = d.modrm()?;
            if m.reg >= 6 {
                return None;
            }
            if m.is_reg() {
                let dst = d.rm_reg(&m, d.osz());
                i.write(dst);
                i.action = Action::Copy {
                    dst,
                    src: SEG + m.reg as u16,
                };
            }
        }
        0x8d => {
            let m = d.modrm()?;
            if m.is_reg() {
                return None;
            }
            let dst = d.reg_reg(&m, d.osz());
            i.write(dst);
            if m.base == RIP || m.base == EIP {
                d.rip_lea = Some((dst, m.disp));
            } else if m.index == NONE && m.base != NONE {
                i.action = Action::Add {
                    dst,
                    src: m.base,
                    imm: m.disp as u64,
                };
            }
        }
        0x8e => {
            let m = d.modrm()?;
            if m.reg >= 6 {
                return None;
            }
            let dst = SEG + m.reg as u16;
            i.write(dst);
            if m.is_reg() {
                i.action = Action::Copy {
                    dst,
                    src: d.rm_reg(&m, d.osz()),
                };
            } else if m.base == RIP || m.base == EIP {
                d.rip_load = Some((dst, m.disp));
            }
        }
        0x8f => {
            if d.peek()? & 0x38 != 0 {
                return xop(d, i);
            }
            let m = d.modrm()?;
            if m.reg != 0 {
                return None;
            }
            if m.is_reg() {
                i.write(d.rm_reg(&m, d.osz_d64()));
            }
            i.write(d.stack_reg_sized());
        }
        0x90 => {
            // QUIRK(parity): `pause` with a 66 prefix is rejected.
            if d.rep == 0xf3 && d.rex == 0 && (d.p66 || (d.p67 && !m64)) {
                return None;
            }
            if d.rex & 1 != 0 {
                let size = d.osz();
                i.write(d.gpr(size, 8));
                i.write(d.acc(size));
            } else if d.rep == 0xf3 && d.rex & 8 != 0 {
                // F3 REX.W 90 is `xchg rax, rax`, not `pause`.
                i.write(R64 + AX);
            }
        }
        0x91..=0x97 => {
            let size = d.osz();
            i.write(d.gpr(size, (op & 7) | d.rex_b()));
            i.write(d.acc(size));
        }
        0x98 => i.write(d.acc(d.osz())),
        0x99 => {
            let size = d.osz();
            i.write(d.acc(size));
            i.write(d.gpr(size, 2));
        }
        0x9a | 0xea => {
            if m64 {
                return None;
            }
            // Far pointer: offset then segment; printed segment first.
            let off = d.imm_z()?;
            let seg = d.imm_s(2)?;
            if op == 0x9a {
                i.call = true;
            } else {
                i.jump = true;
            }
            i.ops.push(Op::Imm(zext(seg, 16)));
            i.ops.push(Op::Imm(zext(off, d.osz())));
        }
        0x9b => {}
        0x9c | 0x9d => i.write(d.stack_reg_sized()),
        0x9e => {}
        0x9f => i.write(R8H),
        0xa0..=0xa3 => {
            let n = (d.asz() / 8) as usize;
            d.skip(n)?;
            if op < 0xa2 {
                i.write(d.acc(if op == 0xa0 { 8 } else { d.osz() }));
            }
        }
        0xa4..=0xa7 => {
            i.write(d.string_reg(DI));
            i.write(d.string_reg(SI));
            // QUIRK(parity): F2 A5 with 32-bit operands is taken for a
            // plain `movsd`, without the count register.
            if !(op == 0xa5 && d.rep == 0xf2 && d.osz() == 32) {
                d.rep_count(i);
            }
        }
        0xa8 => d.skip(1)?,
        0xa9 => {
            d.imm_z()?;
            // QUIRK(parity): `test eax, imm32` reports eax as written.
            if d.osz() == 32 {
                i.write(R32 + AX);
            }
        }
        0xaa | 0xab => {
            i.write(d.string_reg(DI));
            // QUIRK(parity): `stosq` reports rcx even without `rep`.
            if op == 0xab && d.osz() == 64 {
                i.write(R64 + CX);
            }
            d.rep_count(i);
        }
        0xac | 0xad => {
            i.write(d.acc(if op == 0xac { 8 } else { d.osz() }));
            i.write(d.string_reg(SI));
            d.rep_count(i);
        }
        0xae | 0xaf => {
            // QUIRK(parity): `scasd` names edi, the other widths rdi.
            i.write(if op == 0xaf && d.osz() == 32 {
                R32 + DI
            } else {
                d.string_reg(DI)
            });
            d.rep_count(i);
        }
        0xb0..=0xb7 => {
            let v = d.imm_s(1)?;
            let dst = d.gpr(8, (op & 7) | d.rex_b());
            i.write(dst);
            i.action = Action::Set {
                dst,
                value: zext(v, 8),
            };
        }
        0xb8..=0xbf => {
            let size = d.osz();
            let dst = d.gpr(size, (op & 7) | d.rex_b());
            i.write(dst);
            if size == 64 {
                d.skip(8)?; // movabs
            } else {
                let v = d.imm_s((size / 8) as usize)?;
                i.action = Action::Set {
                    dst,
                    value: zext(v, size),
                };
            }
        }
        0xc0 | 0xc1 | 0xd0..=0xd3 => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            if op < 0xd0 {
                d.skip(1)?;
            }
            if m.is_reg() {
                i.write(d.rm_reg(&m, size));
            }
        }
        0xc2 => {
            // QUIRK(parity): with both 66 and REX.W the immediate is 4 bytes.
            d.skip(if d.p66 && d.rex & 8 != 0 { 4 } else { 2 })?;
            i.write(d.stack_reg());
        }
        0xc3 => i.write(d.stack_reg()),
        0xc4 | 0xc5 => {
            if m64 || d.peek()? >= 0xc0 {
                return vex(d, op, i);
            }
            let m = d.modrm()?; // les / lds
            i.write(d.reg_reg(&m, d.osz()));
        }
        0xc6 | 0xc7 => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            if d.peek()? == 0xf8 {
                d.skip(1)?;
                if op == 0xc6 {
                    d.skip(1)?; // xabort
                } else {
                    i.jump = true; // xbegin
                    i.write(R32 + AX);
                    let n = if d.osz() == 16 { 2 } else { 4 };
                    rel_branch(d, n)?;
                }
                return Some(());
            }
            let m = d.modrm()?;
            if m.reg != 0 {
                return None;
            }
            let v = if op == 0xc6 { d.imm_s(1)? } else { d.imm_z()? };
            if m.is_reg() {
                let dst = d.rm_reg(&m, size);
                i.write(dst);
                i.action = Action::Set {
                    dst,
                    value: zext(v, size),
                };
            }
        }
        0xc8 => d.skip(3)?,
        0xc9 => {
            i.write(d.gpr(if m64 { 64 } else { 32 }, 5));
            i.write(d.stack_reg());
        }
        0xca => d.skip(2)?,
        0xcb | 0xcc | 0xcf => {}
        0xcd => d.skip(1)?,
        0xce => {
            if m64 {
                return None;
            }
        }
        0xd4 | 0xd5 => {
            if m64 {
                return None;
            }
            d.skip(1)?;
        }
        0xd6 => {
            if m64 {
                return None;
            }
            i.write(R8 + AX);
        }
        0xd7 => {}
        0xd8..=0xdf => {
            let b = d.peek()?;
            let (mem, reg) = *tables::X87.get((op - 0xd8) as usize)?;
            if !shape_valid(mem, reg, b) {
                return None;
            }
            d.modrm()?;
            if op == 0xdf && b == 0xe0 {
                i.write(R16 + AX);
            }
        }
        0xe0..=0xe2 => {
            // loop / loope / loopne are not in the jump group.
            d.skip(1)?;
            i.write(if m64 { R64 + CX } else { R32 + CX });
        }
        0xe3 => {
            i.jump = true;
            rel_branch(d, 1)?;
        }
        0xe4 | 0xe5 => {
            d.skip(1)?;
            i.write(d.acc(if op == 0xe4 {
                8
            } else if d.p66 {
                16
            } else {
                32
            }));
        }
        0xe6 | 0xe7 => d.skip(1)?,
        0xe8 | 0xe9 => {
            if op == 0xe8 {
                i.call = true;
                d.rel16_signed = true;
                i.write(d.stack_reg());
            } else {
                i.jump = true;
            }
            let n = if !m64 && d.p66 { 2 } else { 4 };
            rel_branch(d, n)?;
        }
        0xeb => {
            i.jump = true;
            rel_branch(d, 1)?;
        }
        0xec | 0xed => i.write(d.acc(if op == 0xec {
            8
        } else if d.p66 {
            16
        } else {
            32
        })),
        0xee | 0xef => {}
        0xf1 | 0xf4 | 0xf5 | 0xf8..=0xfd => {}
        0xf6 | 0xf7 => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            match m.reg {
                0 | 1 => {
                    if op == 0xf6 {
                        d.skip(1)?;
                    } else {
                        d.imm_z()?;
                    }
                }
                2 | 3 => {
                    d.lockable = !m.is_reg();
                    if m.is_reg() {
                        i.write(d.rm_reg(&m, size));
                    }
                }
                _ => {
                    if size == 8 {
                        i.write(R8 + AX);
                        i.write(if m.reg >= 6 { R8H } else { R16 + AX });
                    } else {
                        i.write(d.acc(size));
                        i.write(d.gpr(size, 2));
                    }
                }
            }
        }
        0xfe => {
            let m = d.modrm()?;
            if m.reg > 1 {
                return None;
            }
            d.lockable = !m.is_reg();
            if m.is_reg() {
                i.write(d.rm_reg(&m, 8));
            }
        }
        0xff => {
            let m = d.modrm()?;
            match m.reg {
                0 | 1 => {
                    d.lockable = !m.is_reg();
                    if m.is_reg() {
                        i.write(d.rm_reg(&m, d.osz()));
                    }
                }
                2 | 4 => {
                    if m.reg == 2 {
                        i.call = true;
                        i.write(d.stack_reg());
                    } else {
                        i.jump = true;
                    }
                    if m.is_reg() {
                        let size = if m64 { 64 } else { d.osz() };
                        i.ops.push(Op::Reg(d.rm_reg(&m, size)));
                    } else {
                        i.ops.push(mem_op(&m));
                    }
                }
                3 | 5 => {
                    if m.is_reg() {
                        return None;
                    }
                    if m.reg == 3 {
                        i.call = true;
                    } else {
                        i.jump = true;
                    }
                    i.ops.push(mem_op(&m));
                }
                6 => i.write(d.stack_reg_sized()),
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(())
}

fn two_byte(d: &mut Dec, i: &mut Insn) -> Option<()> {
    let m64 = d.mode64;
    let op = d.byte()?;
    // (3DNow! is validated by its opcode suffix instead.)
    if op != 0x38 && op != 0x3a && op != 0x0f {
        let t = if m64 {
            &tables::MAP_0F_64
        } else {
            &tables::MAP_0F_32
        };
        if !table_valid(t, d.legacy_ctx(), op, d.peek_modrm()) {
            return None;
        }
    }
    match op {
        0x00 => {
            let m = d.modrm()?;
            if m.reg < 2 && m.is_reg() {
                i.write(d.rm_reg(&m, d.osz()));
            }
        }
        0x01 => {
            let b = d.peek()?;
            let m = d.modrm()?;
            if m.is_reg() {
                match b {
                    0xd0 => {
                        i.write(R32 + AX);
                        i.write(R32 + DX);
                    }
                    0xf9 => {
                        let base = if m64 { R64 } else { R32 };
                        i.write(base + AX);
                        i.write(base + CX);
                        i.write(base + DX);
                    }
                    _ => {}
                }
                if m.reg == 4 {
                    i.write(d.rm_reg(&m, d.osz()));
                }
            }
        }
        0x02 | 0x03 => {
            let m = d.modrm()?;
            i.write(d.reg_reg(&m, d.osz()));
        }
        0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0b | 0x0e => {}
        0x0d => {
            d.modrm()?;
        }
        0x0f => {
            // 3DNow!: the opcode proper follows the operands.
            d.modrm()?;
            let suffix = d.byte()?;
            if (tables::NOW3D.get((suffix >> 6) as usize)? >> (suffix & 63)) & 1 == 0 {
                return None;
            }
        }
        0x10..=0x17 | 0x28..=0x2b | 0x2e | 0x2f => {
            d.modrm()?;
        }
        0x18..=0x1f => {
            // MPX bound registers cannot be extended.
            if (op == 0x1a || op == 0x1b) && d.rex & 4 != 0 {
                return None;
            }
            let m = d.modrm()?;
            d.lockable = op == 0x1f && !m.is_reg();
        }
        0x20 | 0x21 => {
            let m = d.modrm_reg_only()?;
            let dst = d.rm_reg(&m, if m64 { 64 } else { 32 });
            i.write(dst);
            let src = (if op == 0x20 { CR } else { DR }) + (m.reg | d.rex_r()) as u16;
            i.action = Action::Copy { dst, src };
        }
        0x22 | 0x23 => {
            let m = d.modrm_reg_only()?;
            let dst = (if op == 0x22 { CR } else { DR }) + (m.reg | d.rex_r()) as u16;
            i.write(dst);
            i.action = Action::Copy {
                dst,
                src: d.rm_reg(&m, if m64 { 64 } else { 32 }),
            };
        }
        0x2c | 0x2d => {
            let m = d.modrm()?;
            if d.rep != 0 {
                i.write(d.reg_reg(&m, if d.rex_w() { 64 } else { 32 }));
            }
        }
        0x30 | 0x34 | 0x35 => {}
        0x37 => {
            for n in [AX, BX, CX] {
                i.write(R64 + n);
            }
        }
        0x31 | 0x33 => {
            // rdtsc names the 32-bit registers in 32-bit mode; rdpmc never.
            let base = if m64 || op == 0x33 { R64 } else { R32 };
            i.write(base + AX);
            i.write(base + DX);
        }
        0x32 => {
            i.write(R32 + AX);
            i.write(R32 + DX);
        }
        0x38 => {
            let op3 = d.byte()?;
            let t = if m64 {
                &tables::MAP_0F38_64
            } else {
                &tables::MAP_0F38_32
            };
            if !table_valid(t, d.legacy_ctx(), op3, d.peek_modrm()) {
                return None;
            }
            let m = d.modrm()?;
            match op3 {
                0xf0 | 0xf1 => {
                    if d.rep == 0xf2 {
                        i.write(d.reg_reg(&m, if d.rex_w() { 64 } else { 32 }));
                    } else if op3 == 0xf0 {
                        i.write(d.reg_reg(&m, d.osz()));
                    }
                }
                // adcx / adox; the unprefixed form is `wrss`.
                0xf6 if d.p66 || d.rep == 0xf3 => {
                    i.write(d.reg_reg(&m, if d.rex_w() { 64 } else { 32 }))
                }
                _ => {}
            }
        }
        0x3a => {
            let op3 = d.byte()?;
            let t = if m64 {
                &tables::MAP_0F3A_64
            } else {
                &tables::MAP_0F3A_32
            };
            if !table_valid(t, d.legacy_ctx(), op3, d.peek_modrm()) {
                return None;
            }
            let m = d.modrm()?;
            d.skip(1)?;
            match op3 {
                0x14 | 0x15 | 0x16 | 0x17 => {
                    if m.is_reg() {
                        i.write(d.rm_reg(&m, if d.rex_w() && op3 == 0x16 { 64 } else { 32 }));
                    }
                }
                0x61 | 0x63 => i.write(R32 + CX),
                _ => {}
            }
        }
        0x40..=0x4f => {
            let m = d.modrm()?;
            i.write(d.reg_reg(&m, d.osz()));
        }
        0x50 | 0xd7 => {
            let m = d.modrm()?;
            i.write(d.reg_reg(&m, 32));
        }
        0x70..=0x73 | 0xc2 | 0xc4 | 0xc6 => {
            d.modrm()?;
            d.skip(1)?;
        }
        0xc5 => {
            let m = d.modrm()?;
            d.skip(1)?;
            i.write(d.reg_reg(&m, 32));
        }
        0x77 => {}
        0x7e => {
            let m = d.modrm()?;
            if d.rep != 0xf3 && m.is_reg() {
                i.write(d.rm_reg(&m, if d.rex_w() { 64 } else { 32 }));
            }
        }
        0x80..=0x8f => {
            i.jump = true;
            // QUIRK(parity): in 64-bit mode only `jo`/`jno` have a 16-bit
            // displacement form under the 66 prefix.
            let rel16 = d.p66
                && if m64 {
                    op <= 0x81 && d.rex & 8 == 0
                } else {
                    true
                };
            rel_branch(d, if rel16 { 2 } else { 4 })?;
        }
        0x90..=0x9f => {
            let m = d.modrm()?;
            if m.is_reg() {
                i.write(d.rm_reg(&m, 8));
            }
        }
        // push fs / gs report nothing; pop reports the segment register.
        0xa0 | 0xa8 => {}
        0xa1 | 0xa9 => i.write(SEG + if op == 0xa1 { 4 } else { 5 }),
        0xa2 => {
            for n in [AX, BX, CX, DX] {
                i.write(R32 + n);
            }
        }
        0xa3 => {
            d.modrm()?;
        }
        0xa4 | 0xac => {
            let m = d.modrm()?;
            d.skip(1)?;
            if m.is_reg() {
                i.write(d.rm_reg(&m, d.osz()));
            }
        }
        0xa5 | 0xad | 0xab | 0xb3 | 0xbb => {
            let m = d.modrm()?;
            d.lockable = op & 7 == 3 && !m.is_reg();
            if m.is_reg() {
                i.write(d.rm_reg(&m, d.osz()));
            }
        }
        0xa6 | 0xa7 => {
            // VIA PadLock.
            let b = d.byte()?;
            match (op, b) {
                (0xa6, 0xc0) => [AX, DX, SI].iter().for_each(|n| i.write(R64 + n)),
                (0xa6, _) => [AX, DI, SI].iter().for_each(|n| i.write(R64 + n)),
                (_, 0xc0) => [AX, DI].iter().for_each(|n| i.write(R64 + n)),
                _ => [DI, SI].iter().for_each(|n| i.write(R64 + n)),
            }
        }
        0x78 | 0x79 => {
            let m = d.modrm()?;
            let size = if m64 { 64 } else { 32 };
            if (d.p66 || d.rep == 0xf2) && (m.is_reg() || d.rex & 8 == 0) {
                if op == 0x78 {
                    d.skip(2)?; // extrq / insertq with two immediates
                }
            } else if op == 0x79 {
                i.write(d.reg_reg(&m, size)); // vmwrite
            } else if m.is_reg() {
                i.write(d.rm_reg(&m, size)); // vmread
            }
        }
        0xaa => {}
        0xae => {
            let m = d.modrm()?;
            if d.rep == 0xf3 && m.is_reg() && m.reg < 2 {
                i.write(d.rm_reg(&m, if d.rex_w() { 64 } else { 32 }));
            }
        }
        0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf | 0xb8 | 0xbc | 0xbd => {
            let m = d.modrm()?;
            i.write(d.reg_reg(&m, d.osz()));
        }
        0xb0 | 0xb1 => {
            let m = d.modrm()?;
            d.lockable = !m.is_reg();
            // QUIRK(parity): the accumulator is never reported, and the
            // destination only when it is a register.
            if m.is_reg() {
                i.write(d.rm_reg(&m, if op == 0xb0 { 8 } else { d.osz() }));
            }
        }
        0xb2 | 0xb4 | 0xb5 => {
            let m = d.modrm()?;
            i.write(d.reg_reg(&m, d.osz()));
        }
        0xb9 => {} // ud1 takes no ModRM here
        0xff => {} // ud0 takes no ModRM here
        0xba => {
            let m = d.modrm()?;
            d.skip(1)?;
            d.lockable = m.reg > 4 && !m.is_reg();
            if m.reg > 4 && m.is_reg() {
                i.write(d.rm_reg(&m, d.osz()));
            }
        }
        0xc0 | 0xc1 => {
            let size = if op & 1 == 0 { 8 } else { d.osz() };
            let m = d.modrm()?;
            d.lockable = !m.is_reg();
            i.write(d.reg_reg(&m, size));
            if m.is_reg() {
                i.write(d.rm_reg(&m, size));
            }
        }
        0xc3 => {
            d.modrm()?;
        }
        0xc7 => {
            let m = d.modrm()?;
            d.lockable = !m.is_reg() && m.reg == 1;
            if m.is_reg() {
                if m.reg >= 6 {
                    // rdrand / rdseed; rdpid always names the full register.
                    let size = if d.rep == 0xf3 && m.reg == 7 {
                        if m64 {
                            64
                        } else {
                            32
                        }
                    } else {
                        d.osz()
                    };
                    i.write(d.rm_reg(&m, size));
                }
            } else if m.reg == 1 {
                if d.rex_w() {
                    i.write(R64 + AX);
                    i.write(R64 + DX);
                } else {
                    i.write(R32 + AX);
                    i.write(R32 + DX);
                }
            }
        }
        0xc8..=0xcf => {
            // No access is reported for the (undefined) 16-bit form.
            if d.osz() != 16 {
                i.write(d.gpr(d.osz(), (op & 7) | d.rex_b()));
            }
        }
        // Everything else the table accepts takes a ModRM byte and writes
        // no general register.
        _ => {
            d.modrm()?;
        }
    }
    Some(())
}

/// VEX-encoded instruction; `first` is C4 or C5 (already consumed).
fn vex(d: &mut Dec, first: u8, i: &mut Insn) -> Option<()> {
    // A REX prefix directly before a VEX prefix is rejected.
    if d.rex != 0 {
        return None;
    }
    let b1 = d.byte()?;
    d.vex = true;
    d.vex_r = b1 & 0x80 == 0;
    let map;
    let b2;
    if first == 0xc5 {
        map = 1;
        b2 = b1;
    } else {
        d.vex_x = b1 & 0x40 == 0;
        d.vex_b = b1 & 0x20 == 0;
        map = b1 & 0x1f;
        b2 = d.byte()?;
        d.vex_w = b2 & 0x80 != 0;
    }
    if !d.mode64 {
        d.vex_r = false;
        d.vex_x = false;
        d.vex_b = false;
    }
    d.vex_vvvv = (!b2 >> 3) & if d.mode64 { 15 } else { 7 };
    d.vex_pp = b2 & 3;
    let ctx = (b2 & 7) as usize | (d.vex_w as usize) << 3 | (((!b2 >> 3) & 15 != 0) as usize) << 4;
    let t = match map {
        1 => &tables::VEX1,
        2 => &tables::VEX2,
        3 => &tables::VEX3,
        _ => return None,
    };
    vex_body(d, map, t, ctx, i)
}

fn evex(d: &mut Dec, i: &mut Insn) -> Option<()> {
    if d.rex != 0 {
        return None;
    }
    let p0 = d.byte()?;
    let p1 = d.byte()?;
    let p2 = d.byte()?;
    d.vex = true;
    if d.mode64 {
        d.vex_r = p0 & 0x80 == 0;
        d.vex_x = p0 & 0x40 == 0;
        d.vex_b = p0 & 0x20 == 0;
    }
    d.vex_w = p1 & 0x80 != 0;
    d.vex_vvvv = (!p1 >> 3) & 15;
    d.vex_pp = p1 & 3;
    let map = p0 & 3;
    let ctx = (p1 & 3) as usize
        | (((p2 >> 5) & 3) as usize) << 2
        | (d.vex_w as usize) << 4
        | ((d.vex_vvvv != 0) as usize) << 5
        | (((p2 >> 4) & 1) as usize) << 6;
    let t = match map {
        1 => &tables::EVEX1,
        2 => &tables::EVEX2,
        3 => &tables::EVEX3,
        _ => return None,
    };
    // Write masks and zeroing are only accepted where the instruction
    // supports them.
    let (zeroing, masked) = (p2 & 0x80 != 0, p2 & 7 != 0);
    if zeroing || masked {
        let op = d.peek()?;
        let key = (map as u16) << 11 | (d.vex_w as u16) << 10 | (d.vex_pp as u16) << 8 | op as u16;
        let class = tables::EVEX_MASKING
            .binary_search_by_key(&key, |e| e.0)
            .ok()
            .and_then(|at| tables::EVEX_MASKING.get(at))
            .map(|e| e.1)
            .unwrap_or(0);
        let memory = *d.code.get(d.pos + 1)? >> 6 != 3;
        let rejected = match class {
            1 => true,
            2 => zeroing && memory,
            3 => zeroing,
            _ => false,
        };
        if rejected {
            return None;
        }
    }
    vex_body(d, map, t, ctx, i)
}

fn vex_body(d: &mut Dec, map: u8, t: &MapTable, ctx: usize, i: &mut Insn) -> Option<()> {
    let op = d.byte()?;
    let modrm = d.peek_modrm();
    if map == 2 && std::ptr::eq(t, &tables::VEX2) && (0x90..=0x93).contains(&op) {
        // Gathers need a SIB byte (for the vector index).
        if d.vex_pp != 1 || modrm >> 6 == 3 || modrm & 7 != 4 {
            return None;
        }
    } else if !table_valid(t, ctx, op, modrm) {
        return None;
    }
    // Mask registers are k0..k7 only: no extension bit may apply to them.
    let is_vex = std::ptr::eq(t, &tables::VEX1) || std::ptr::eq(t, &tables::VEX3);
    if is_vex {
        let k_logic = (map == 1
            && matches!(op, 0x41 | 0x42 | 0x44..=0x47 | 0x4a | 0x4b | 0x98 | 0x99))
            || (map == 3 && (0x30..=0x33).contains(&op));
        let k_in_reg = k_logic || (map == 1 && matches!(op, 0x90..=0x92));
        let k_in_rm = k_logic || (map == 1 && matches!(op, 0x90 | 0x93));
        let k_in_vvvv = map == 1 && matches!(op, 0x41 | 0x42 | 0x45 | 0x46 | 0x47 | 0x4a | 0x4b);
        if (k_in_reg && d.vex_r)
            || (k_in_rm && modrm >> 6 == 3 && d.vex_b)
            || (k_in_vvvv && d.vex_vvvv >= 8)
        {
            return None;
        }
    }
    let wsize = if d.vex_w && d.mode64 { 64 } else { 32 };
    match map {
        1 => {
            if op == 0x77 {
                return Some(());
            }
            let m = d.modrm()?;
            match op {
                0x70..=0x73 | 0xc2 | 0xc4 | 0xc6 => d.skip(1)?,
                0xc5 => {
                    d.skip(1)?;
                    i.write(d.reg_reg(&m, 32));
                }
                0x50 | 0xd7 => i.write(d.reg_reg(&m, 32)),
                0x2c | 0x2d => {
                    if d.vex_pp >= 2 {
                        i.write(d.reg_reg(&m, wsize));
                    }
                }
                // EVEX conversions to unsigned integers.
                0x78 | 0x79 if !std::ptr::eq(t, &tables::VEX1) => {
                    if d.vex_pp >= 2 {
                        i.write(d.reg_reg(&m, wsize));
                    }
                }
                0x7e => {
                    if d.vex_pp == 1 && m.is_reg() {
                        i.write(d.rm_reg(&m, wsize));
                    }
                }
                // kmovq names the 64-bit register even in 32-bit mode.
                0x93 => i.write(d.reg_reg(&m, if d.vex_pp == 3 && d.vex_w { 64 } else { 32 })),
                _ => {}
            }
        }
        2 => {
            let m = d.modrm()?;
            match op {
                0xf2 | 0xf5 | 0xf7 => i.write(d.reg_reg(&m, wsize)),
                0xf3 => i.write(d.gpr(wsize, d.vex_vvvv)),
                0xf6 => {
                    i.write(d.reg_reg(&m, wsize));
                    i.write(d.gpr(wsize, d.vex_vvvv));
                }
                _ => {}
            }
        }
        _ => {
            let m = d.modrm()?;
            d.skip(1)?;
            match op {
                0x14 | 0x15 | 0x16 | 0x17 => {
                    if m.is_reg() {
                        // vpextrq likewise ignores the mode.
                        i.write(d.rm_reg(&m, if op == 0x16 && d.vex_w { 64 } else { 32 }));
                    }
                }
                0x61 | 0x63 => i.write(R32 + CX),
                0xf0 => i.write(d.reg_reg(&m, wsize)),
                _ => {}
            }
        }
    }
    Some(())
}

fn xop(d: &mut Dec, i: &mut Insn) -> Option<()> {
    if d.rex != 0 {
        return None;
    }
    let b1 = d.byte()?;
    let b2 = d.byte()?;
    d.vex = true;
    let map = b1 & 0x1f;
    let vvvv = (!b2 >> 3) & 15;
    let ctx = (b2 & 7) as usize | ((b2 >> 7) as usize) << 3 | ((vvvv != 0) as usize) << 4;
    let t = match map {
        8 => &tables::XOP8,
        9 => &tables::XOP9,
        10 => &tables::XOP10,
        _ => return None,
    };
    let op = d.byte()?;
    if !table_valid(t, ctx, op, d.peek_modrm()) {
        return None;
    }
    d.vex_w = b2 & 0x80 != 0;
    if d.mode64 {
        d.vex_r = b1 & 0x80 == 0;
        d.vex_x = b1 & 0x40 == 0;
        d.vex_b = b1 & 0x20 == 0;
    }
    let wsize = if d.vex_w && d.mode64 { 64 } else { 32 };
    let m = d.modrm()?;
    match map {
        8 => d.skip(1)?,
        9 => {
            // TBM: blcfill, blsic, ... write the vvvv register.
            if op == 0x01 || op == 0x02 {
                i.write(d.gpr(wsize, vvvv));
            }
        }
        _ => {
            d.skip(4)?;
            match op {
                0x10 => i.write(d.reg_reg(&m, wsize)), // bextr
                0x12 => i.write(d.gpr(wsize, vvvv)),   // lwpins / lwpval
                _ => {}
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec64(bytes: &[u8]) -> Option<Insn> {
        decode(bytes, 0x1000, true)
    }

    fn dec32(bytes: &[u8]) -> Option<Insn> {
        decode(bytes, 0x1000, false)
    }

    #[test]
    fn lengths() {
        assert_eq!(dec64(&[0x55]).unwrap().size, 1);
        assert_eq!(dec64(&[0x48, 0x89, 0xe5]).unwrap().size, 3);
        assert_eq!(
            dec64(&[0x48, 0x8d, 0x05, 0x04, 0x4e, 0x00, 0x00])
                .unwrap()
                .size,
            7
        );
        // movabs rax, imm64
        assert_eq!(
            dec64(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap().size,
            10
        );
        // vzeroupper; vmovups xmm0, xmm0 (EVEX)
        assert_eq!(dec64(&[0xc5, 0xf8, 0x77]).unwrap().size, 3);
        assert_eq!(
            dec64(&[0x62, 0xf1, 0x7c, 0x08, 0x10, 0xc0]).unwrap().size,
            6
        );
        // Truncated.
        assert!(dec64(&[0x48, 0x8d, 0x05, 0x04]).is_none());
        assert!(dec64(&[]).is_none());
        assert!(dec64(&[0x66]).is_none());
        // Never longer than 15 bytes.
        assert!(dec64(&[0x66; 32]).is_none());
    }

    #[test]
    fn branches() {
        let i = dec64(&[0xe8, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert!(i.call && !i.jump);
        assert_eq!(i.ops.as_slice(), &[Op::Imm(0x1015)]);
        assert_eq!(i.writes.as_slice(), &[R64 + SP]);
        let i = dec64(&[0xeb, 0xfe]).unwrap();
        assert!(i.jump);
        assert_eq!(i.ops.as_slice(), &[Op::Imm(0x1000)]);
        let i = dec64(&[0xff, 0x25, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(
            i.ops.as_slice(),
            &[Op::Mem {
                base: RIP,
                index: NONE,
                disp: 0x10
            }]
        );
        let i = dec64(&[0xff, 0xd0]).unwrap();
        assert!(i.call);
        assert_eq!(i.ops.as_slice(), &[Op::Reg(R64 + AX)]);
        // call qword ptr [rax + 8]
        let i = dec64(&[0xff, 0x50, 0x08]).unwrap();
        assert_eq!(
            i.ops.as_slice(),
            &[Op::Mem {
                base: R64 + AX,
                index: NONE,
                disp: 8
            }]
        );
        // loop is not a jump; ret is not either.
        let i = dec64(&[0xe2, 0xfe]).unwrap();
        assert!(!i.jump && i.ops.as_slice().is_empty());
        assert_eq!(i.writes.as_slice(), &[R64 + CX]);
        assert!(!dec64(&[0xc3]).unwrap().jump);
        // 32-bit: targets wrap at 4 GiB; far call has two immediates.
        let i = dec32(&[0xe9, 0xfb, 0xef, 0xff, 0xff]).unwrap();
        assert_eq!(i.ops.as_slice(), &[Op::Imm(0)]);
        let i = dec32(&[0x9a, 0x78, 0x56, 0x34, 0x12, 0x08, 0x00]).unwrap();
        assert!(i.call);
        assert_eq!(i.ops.as_slice(), &[Op::Imm(8), Op::Imm(0x1234_5678)]);
    }

    #[test]
    fn patterns() {
        // lea rax, [rip + 0x4e04]
        let i = dec64(&[0x48, 0x8d, 0x05, 0x04, 0x4e, 0x00, 0x00]).unwrap();
        assert_eq!(
            i.action,
            Action::Set {
                dst: R64 + AX,
                value: 0x1000 + 7 + 0x4e04
            }
        );
        // lea rax, [rsi + 0x68]
        let i = dec64(&[0x48, 0x8d, 0x46, 0x68]).unwrap();
        assert_eq!(
            i.action,
            Action::Add {
                dst: R64 + AX,
                src: R64 + SI,
                imm: 0x68
            }
        );
        // lea ebx, [rax + riz]: the redundant SIB byte hides the pattern.
        let i = dec64(&[0x8d, 0x1c, 0x20]).unwrap();
        assert_eq!(i.action, Action::None);
        // mov rax, [rip + 0x10]
        let i = dec64(&[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(
            i.action,
            Action::LoadAbs {
                dst: R64 + AX,
                addr: 0x1000 + 7 + 0x10
            }
        );
        // xor eax, eax
        let i = dec64(&[0x31, 0xc0]).unwrap();
        assert_eq!(
            i.action,
            Action::Set {
                dst: R32 + AX,
                value: 0
            }
        );
        assert_eq!(i.writes.as_slice(), &[R32 + AX]);
        // mov rbp, rsp
        let i = dec64(&[0x48, 0x89, 0xe5]).unwrap();
        assert_eq!(
            i.action,
            Action::Copy {
                dst: R64 + BP,
                src: R64 + SP
            }
        );
        // mov eax, 0xffffffff is not sign-extended; mov rax, -1 is.
        let i = dec64(&[0xb8, 0xff, 0xff, 0xff, 0xff]).unwrap();
        assert_eq!(
            i.action,
            Action::Set {
                dst: R32 + AX,
                value: 0xffff_ffff
            }
        );
        let i = dec64(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]).unwrap();
        assert_eq!(
            i.action,
            Action::Set {
                dst: R64 + AX,
                value: u64::MAX
            }
        );
    }

    #[test]
    fn prefixes() {
        // The last REX wins; a REX followed by a legacy prefix is dropped.
        let i = dec64(&[0x47, 0x4c, 0x00, 0x00]).unwrap();
        assert_eq!(i.size, 4);
        let i = dec64(&[0x48, 0x26, 0x88, 0xe0]).unwrap(); // mov al, ah
        assert_eq!(i.writes.as_slice(), &[R8 + AX]);
        assert_eq!(
            i.action,
            Action::Copy {
                dst: R8 + AX,
                src: R8H
            }
        );
        let i = dec64(&[0x40, 0x88, 0xe0]).unwrap(); // mov al, spl
        assert_eq!(
            i.action,
            Action::Copy {
                dst: R8 + AX,
                src: R8 + SP
            }
        );
        // 16-bit push names esp.
        assert_eq!(dec64(&[0x66, 0x50]).unwrap().writes.as_slice(), &[R32 + SP]);
        assert_eq!(dec64(&[0x50]).unwrap().writes.as_slice(), &[R64 + SP]);
        // LOCK only where it is accepted.
        assert!(dec64(&[0xf0, 0x01, 0x08]).is_some()); // lock add [rax], ecx
        assert!(dec64(&[0xf0, 0x01, 0xc8]).is_none()); // register destination
        assert!(dec64(&[0xf0, 0x90]).is_none());
        assert!(dec64(&[0xf0, 0xf3, 0x90]).is_some()); // lock dropped: pause
                                                       // REX directly before VEX is rejected.
        assert!(dec64(&[0x40, 0xc5, 0xf8, 0x77]).is_none());
    }

    #[test]
    fn validity() {
        assert!(dec64(&[0x0f, 0x0b]).is_some()); // ud2
        assert!(dec64(&[0x0f, 0x04]).is_none());
        assert!(dec64(&[0x06]).is_none()); // push es
        assert!(dec32(&[0x06]).is_some());
        assert!(dec64(&[0xff, 0xff]).is_none());
        assert!(dec64(&[0xda, 0xfb]).is_none()); // x87
        assert!(dec64(&[0xd9, 0xc0]).is_some()); // fld st(0)
                                                 // 3DNow!: validity is in the suffix.
        assert!(dec64(&[0x0f, 0x0f, 0xc0, 0x97]).is_some());
        assert!(dec64(&[0x0f, 0x0f, 0xc0, 0x00]).is_none());
        // inc eax / REX
        assert_eq!(dec32(&[0x40]).unwrap().writes.as_slice(), &[R32 + AX]);
        assert!(dec64(&[0x40]).is_none());
        assert!(shape_valid(0x01, 0, 0x00));
        assert!(!shape_valid(0x01, 0, 0x08));
        assert!(shape_valid(0, 1 << 9, 0xc9));
        assert_eq!(reg_name(R8H + 1), "ch");
        assert_eq!(reg_name(RIP), "rip");
    }
}
