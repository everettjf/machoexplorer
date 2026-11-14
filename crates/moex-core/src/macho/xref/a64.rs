//! Minimal AArch64 decoder for the cross-reference sweep.
//!
//! Registers: `x0..x30` are 0..=30, `sp` 31, `xzr` 32, `w0..w30` 33..=63,
//! `wsp` 64, `wzr` 65. The 32- and 64-bit views of a register are distinct,
//! as they were for Capstone register ids.

use super::a64_tables::{ClassTable, CLASS_0000, CLASS_0010, CLASS_0111, CLASS_1111};
use super::{Action, Insn, Op};

#[cfg(test)]
const SP: u16 = 31;
const XZR: u16 = 32;
const W0: u16 = 33;
const WSP: u16 = 64;
const WZR: u16 = 65;

#[cfg(test)]
pub(crate) fn reg_name(r: u16) -> String {
    match r {
        0..=30 => format!("x{}", r),
        SP => "sp".to_string(),
        XZR => "xzr".to_string(),
        33..=63 => format!("w{}", r - W0),
        WSP => "wsp".to_string(),
        WZR => "wzr".to_string(),
        _ => "~".to_string(),
    }
}

#[inline]
fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

#[inline]
fn bit(w: u32, n: u32) -> bool {
    (w >> n) & 1 != 0
}

/// Sign-extend the low `n` bits of `v`.
#[inline]
fn sext(v: u64, n: u32) -> i64 {
    ((v << (64 - n)) as i64) >> (64 - n)
}

/// `Xn`, where 31 is `xzr`.
#[inline]
fn x(n: u32) -> u16 {
    if n == 31 {
        XZR
    } else {
        n as u16
    }
}

/// `Xn`, where 31 is `sp`.
#[inline]
fn xsp(n: u32) -> u16 {
    n as u16
}

/// `Wn`, where 31 is `wzr`.
#[inline]
fn wr(n: u32) -> u16 {
    if n == 31 {
        WZR
    } else {
        W0 + n as u16
    }
}

/// `Wn`, where 31 is `wsp`.
#[inline]
fn wsp(n: u32) -> u16 {
    if n == 31 {
        WSP
    } else {
        W0 + n as u16
    }
}

#[inline]
fn r(sf: bool, n: u32) -> u16 {
    if sf {
        x(n)
    } else {
        wr(n)
    }
}

#[inline]
fn rsp(sf: bool, n: u32) -> u16 {
    if sf {
        xsp(n)
    } else {
        wsp(n)
    }
}

/// Decode the instruction at the start of `code`, located at `addr`.
/// `None` when the word is not an instruction Capstone 5 accepts.
pub(crate) fn decode(code: &[u8], addr: u64) -> Option<Insn> {
    let b = code.get(..4)?;
    let w = u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]);
    let mut i = Insn::new(4);
    match bits(w, 28, 25) {
        0b1000 | 0b1001 => dp_imm(w, addr, &mut i)?,
        0b1010 | 0b1011 => branch_sys(w, addr, &mut i)?,
        0b0100 | 0b0110 | 0b1100 | 0b1110 => load_store(w, addr, &mut i)?,
        0b0101 | 0b1101 => dp_reg(w, &mut i)?,
        // Scalar floating point and Advanced SIMD.
        0b0111 => {
            table_valid(&CLASS_0111, w).then_some(())?;
            simd_fp_writes(w, &mut i);
        }
        0b1111 => {
            table_valid(&CLASS_1111, w).then_some(())?;
            simd_fp_writes(w, &mut i);
        }
        // SVE, and reserved / SME / `udf`: no register access is reported.
        0b0010 => table_valid(&CLASS_0010, w).then_some(())?,
        0b0000 => table_valid(&CLASS_0000, w).then_some(())?,
        _ => return None,
    }
    Some(i)
}

/// True when `N:immr:imms` is a valid logical-immediate encoding.
fn valid_bitmask(sf: bool, n: u32, imms: u32) -> bool {
    if !sf && n != 0 {
        return false;
    }
    let v = (n << 6) | (!imms & 0x3f);
    if v == 0 {
        return false;
    }
    let len = 31 - v.leading_zeros();
    if len < 1 {
        return false;
    }
    let levels = (1u32 << len) - 1;
    (imms & levels) != levels
}

fn dp_imm(w: u32, addr: u64, i: &mut Insn) -> Option<()> {
    let sf = bit(w, 31);
    let rd = bits(w, 4, 0);
    let rn = bits(w, 9, 5);
    match bits(w, 25, 23) {
        0 | 1 => {
            let imm = sext(((bits(w, 23, 5) << 2) | bits(w, 30, 29)) as u64, 21);
            let value = if sf {
                (addr & !0xfff).wrapping_add((imm << 12) as u64)
            } else {
                addr.wrapping_add(imm as u64)
            };
            let d = x(rd);
            i.write(d);
            i.action = Action::Set { dst: d, value };
        }
        2 => {
            let sub = bit(w, 30);
            let imm12 = bits(w, 21, 10) as u64;
            if !bit(w, 29) {
                let (d, n) = (rsp(sf, rd), rsp(sf, rn));
                i.write(d);
                i.action = if !sub && !bit(w, 22) && imm12 == 0 && (rd == 31 || rn == 31) {
                    // `mov` to or from the stack pointer.
                    Action::Copy { dst: d, src: n }
                } else if sub {
                    Action::Sub {
                        dst: d,
                        src: n,
                        imm: imm12,
                    }
                } else {
                    Action::Add {
                        dst: d,
                        src: n,
                        imm: imm12,
                    }
                };
            } else if !sub && !sf {
                // QUIRK(parity): no register access is reported for the
                // 32-bit `adds` / `cmn` with an immediate.
            } else if rd == 31 {
                // QUIRK(parity): `cmp`/`cmn` drop the destination, and the
                // write access of the dropped operand lands on the first
                // printed one.
                i.write(rsp(sf, rn));
            } else {
                i.write(r(sf, rd));
            }
        }
        3 => {
            // addg / subg
            if !sf || bit(w, 29) || bit(w, 22) || bits(w, 15, 14) != 0 {
                return None;
            }
        }
        4 => {
            let opc = bits(w, 30, 29);
            if !valid_bitmask(sf, bits(w, 22, 22), bits(w, 15, 10)) {
                return None;
            }
            if opc == 3 {
                if rd == 31 {
                    i.write(r(sf, rn)); // tst
                } else {
                    i.write(r(sf, rd));
                }
            } else {
                i.write(rsp(sf, rd));
            }
        }
        5 => {
            let opc = bits(w, 30, 29);
            let hw = bits(w, 22, 21);
            if opc == 1 || (!sf && hw >= 2) {
                return None;
            }
            let d = r(sf, rd);
            let imm16 = bits(w, 20, 5) as u64;
            i.write(d);
            match opc {
                // `movz` never matched the previous implementation's pattern
                // (it is reported as `mov` or without an immediate operand).
                // QUIRK(parity): the shift amount was never applied; the 16
                // bits always replace the low half-word.
                3 => {
                    i.action = Action::MovK {
                        dst: d,
                        imm16,
                        shift: 0,
                    }
                }
                _ => {}
            }
        }
        6 => {
            if bits(w, 30, 29) == 3 || bit(w, 22) != sf {
                return None;
            }
            if !sf && (bit(w, 21) || bit(w, 15)) {
                return None;
            }
            i.write(r(sf, rd));
        }
        _ => {
            if bits(w, 30, 29) != 0 || bit(w, 21) || bit(w, 22) != sf {
                return None;
            }
            if !sf && bit(w, 15) {
                return None;
            }
            i.write(r(sf, rd));
        }
    }
    Some(())
}

fn branch_sys(w: u32, addr: u64, i: &mut Insn) -> Option<()> {
    let rt = bits(w, 4, 0);
    if bits(w, 30, 26) == 0b00101 {
        let target = addr.wrapping_add(sext((bits(w, 25, 0) as u64) << 2, 28) as u64);
        // `bl` is in both the jump and the call group.
        i.jump = true;
        if bit(w, 31) {
            i.call = true;
            i.write(30);
        }
        i.ops.push(Op::Imm(target));
        return Some(());
    }
    match bits(w, 30, 25) {
        0b011010 => {
            i.jump = true;
            i.ops.push(Op::Reg(r(bit(w, 31), rt)));
            i.ops.push(Op::Imm(
                addr.wrapping_add(sext((bits(w, 23, 5) as u64) << 2, 21) as u64),
            ));
            return Some(());
        }
        0b011011 => {
            i.jump = true;
            i.ops.push(Op::Reg(if bit(w, 31) { x(rt) } else { wr(rt) }));
            i.ops
                .push(Op::Imm((bits(w, 31, 31) << 5 | bits(w, 23, 19)) as u64));
            i.ops.push(Op::Imm(
                addr.wrapping_add(sext((bits(w, 18, 5) as u64) << 2, 16) as u64),
            ));
            return Some(());
        }
        _ => {}
    }
    match bits(w, 31, 25) {
        0b0101010 => {
            if bit(w, 24) {
                return None;
            }
            if bit(w, 4) {
                // `bc.cond` is not in the jump group.
                return Some(());
            }
            i.jump = true;
            i.ops.push(Op::Imm(
                addr.wrapping_add(sext((bits(w, 23, 5) as u64) << 2, 21) as u64),
            ));
            Some(())
        }
        0b1101010 => {
            if !bit(w, 24) {
                return exception(w, i);
            }
            if bits(w, 23, 22) != 0 {
                return None;
            }
            system(w, i)
        }
        0b1101011 => branch_reg(w, i),
        _ => None,
    }
}

fn exception(w: u32, i: &mut Insn) -> Option<()> {
    let opc = bits(w, 23, 21);
    let ll = bits(w, 1, 0);
    if bits(w, 4, 2) != 0 {
        return None;
    }
    let ok = match opc {
        0 => ll != 0,
        1 | 2 | 3 => ll == 0,
        5 => ll != 0,
        _ => false,
    };
    if opc == 0 && ll == 1 {
        // QUIRK(parity): `svc` is reported as writing the link register.
        i.write(30);
    }
    ok.then_some(())
}

fn system(w: u32, i: &mut Insn) -> Option<()> {
    let l = bit(w, 21);
    let op0 = bits(w, 20, 19);
    let op1 = bits(w, 18, 16);
    let crn = bits(w, 15, 12);
    let crm = bits(w, 11, 8);
    let op2 = bits(w, 7, 5);
    let rt = bits(w, 4, 0);
    // Nearly everything decodes, as a generic `msr`/`mrs`/`sys`/`sysl` if
    // nothing else. The exceptions are `xaflag`/`axflag`/`sb` with a
    // non-zero CRm.
    if !l && op0 == 0 && rt == 31 && crm != 0 {
        if (op1 == 0 && crn == 4 && (op2 == 1 || op2 == 2)) || (op1 == 3 && crn == 3 && op2 == 7) {
            return None;
        }
    }
    if l {
        // tstart / ttest report no access.
        if !(op0 == 0 && op1 == 3 && crn == 3 && op2 == 3 && crm <= 1) {
            i.write(x(rt));
        }
    } else if op0 == 0 && op1 == 3 && crn == 2 && rt == 31 {
        // Pointer-authentication hints with implicit registers.
        match (crm << 3) | op2 {
            7 | 24..=31 => i.write(30),
            8 | 10 => {
                i.write(16);
                i.write(17);
            }
            12 | 14 => i.write(17),
            _ => {}
        }
    }
    Some(())
}

fn branch_reg(w: u32, i: &mut Insn) -> Option<()> {
    let opc = bits(w, 24, 21);
    let op3 = bits(w, 15, 10);
    let rn = bits(w, 9, 5);
    let op4 = bits(w, 4, 0);
    if bits(w, 20, 16) != 31 {
        return None;
    }
    match (opc, op3) {
        (0, 0) | (1, 0) | (2, 0) => {
            if op4 != 0 {
                return None;
            }
            match opc {
                0 => i.jump = true,
                1 => {
                    i.jump = true;
                    i.call = true;
                    i.write(30);
                }
                _ => {}
            }
            i.ops.push(Op::Reg(x(rn)));
        }
        (0, 2) | (0, 3) | (1, 2) | (1, 3) => {
            if op4 != 31 {
                return None;
            }
            i.jump = true;
            if opc == 1 {
                i.call = true;
                i.write(30);
            }
            i.ops.push(Op::Reg(x(rn)));
        }
        (2, 2) | (2, 3) => {
            if rn != 31 || op4 != 31 {
                return None;
            }
        }
        (4, 0) | (5, 0) => {
            if rn != 31 || op4 != 0 {
                return None;
            }
        }
        (4, 2) | (4, 3) => {
            if rn != 31 || op4 != 31 {
                return None;
            }
        }
        (8, 2) | (8, 3) | (9, 2) | (9, 3) => {
            i.jump = true;
            if opc == 9 {
                i.call = true;
                i.write(30);
            }
            i.ops.push(Op::Reg(x(rn)));
            i.ops.push(Op::Reg(xsp(op4)));
        }
        _ => return None,
    }
    Some(())
}

fn dp_reg(w: u32, i: &mut Insn) -> Option<()> {
    let sf = bit(w, 31);
    let rd = bits(w, 4, 0);
    let rn = bits(w, 9, 5);
    let rm = bits(w, 20, 16);
    let imm6 = bits(w, 15, 10);
    if !bit(w, 28) {
        if !bit(w, 24) {
            // Logical (shifted register).
            let opc = bits(w, 30, 29);
            let n = bit(w, 21);
            if !sf && imm6 >= 32 {
                return None;
            }
            if opc == 1 && !n && rn == 31 && bits(w, 23, 22) == 0 && imm6 == 0 {
                let d = r(sf, rd);
                i.write(d);
                i.action = Action::Copy {
                    dst: d,
                    src: r(sf, rm),
                };
            } else if opc == 3 && !n && rd == 31 {
                i.write(r(sf, rn)); // tst
            } else {
                i.write(r(sf, rd));
            }
        } else if !bit(w, 21) {
            // Add/subtract (shifted register).
            if bits(w, 23, 22) == 3 || (!sf && imm6 >= 32) {
                return None;
            }
            if bit(w, 29) && rd == 31 {
                i.write(r(sf, rn)); // cmp / cmn
            } else {
                i.write(r(sf, rd));
            }
        } else {
            // Add/subtract (extended register).
            if bits(w, 23, 22) != 0 || bits(w, 12, 10) > 4 {
                return None;
            }
            if bit(w, 29) {
                if rd == 31 {
                    i.write(rsp(sf, rn));
                } else {
                    i.write(r(sf, rd));
                }
            } else {
                i.write(rsp(sf, rd));
            }
        }
        return Some(());
    }
    match bits(w, 24, 21) {
        0 => match imm6 {
            0 => i.write(r(sf, rd)),
            // rmif
            _ if imm6 & 0x1f == 1 && sf && !bit(w, 30) && bit(w, 29) && !bit(w, 4) => {}
            // setf8 / setf16
            _ if imm6 & 0xf == 2
                && !sf
                && !bit(w, 30)
                && bit(w, 29)
                && bits(w, 20, 15) == 0
                && rd == 0b01101 => {}
            _ => return None,
        },
        2 => {
            if !bit(w, 29) || bit(w, 10) || bit(w, 4) {
                return None;
            }
        }
        4 => {
            if bit(w, 29) || bit(w, 11) {
                return None;
            }
            i.write(r(sf, rd));
        }
        6 => {
            if bit(w, 30) {
                if bit(w, 29) {
                    return None;
                }
                match (rm, imm6) {
                    (0, 0 | 1 | 4 | 5) => i.write(r(sf, rd)),
                    (0, 2) => i.write(r(sf, rd)),
                    (0, 3) if sf => i.write(x(rd)),
                    (1, 0..=7) if sf => i.write(x(rd)),
                    (1, 8..=17) if sf && rn == 31 => i.write(x(rd)),
                    _ => return None,
                }
            } else if !bit(w, 29) {
                match imm6 {
                    2 | 3 | 8..=11 => i.write(r(sf, rd)),
                    16 | 17 | 18 | 20 | 21 | 22 if !sf => i.write(wr(rd)),
                    19 | 23 if sf => i.write(wr(rd)),
                    12 if sf => i.write(x(rd)),
                    // subp, irg, gmi: no access reported.
                    0 | 4 | 5 if sf => {}
                    _ => return None,
                }
            } else {
                match imm6 {
                    0 if sf => {} // subps
                    _ => return None,
                }
            }
        }
        8..=15 => {
            if bits(w, 30, 29) != 0 {
                return None;
            }
            let o0 = bit(w, 15);
            match bits(w, 23, 21) {
                0 => i.write(r(sf, rd)),
                1 | 5 if sf => i.write(x(rd)),
                2 | 6 if sf && !o0 => i.write(x(rd)),
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(())
}

/// Destination register of an integer load, or `None` for an unallocated
/// `size:opc` combination. `prfm` reports no register.
fn int_load_dst(size: u32, opc: u32, rt: u32, prefetch_ok: bool) -> Option<Option<u16>> {
    Some(match (size, opc) {
        (_, 0) => None,
        (3, 1) => Some(x(rt)),
        (_, 1) => Some(wr(rt)),
        (0 | 1, 2) => Some(x(rt)),
        (0 | 1, 3) => Some(wr(rt)),
        (2, 2) => Some(x(rt)),
        (3, 2) if prefetch_ok => None,
        _ => return None,
    })
}

fn fp_ldst_valid(size: u32, opc: u32) -> bool {
    match size {
        0 => true,
        _ => opc < 2,
    }
}

fn load_store(w: u32, addr: u64, i: &mut Insn) -> Option<()> {
    let size = bits(w, 31, 30);
    let v = bit(w, 26);
    let opc = bits(w, 23, 22);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let rt2 = bits(w, 14, 10);
    let rs = bits(w, 20, 16);
    let base = xsp(rn);
    match bits(w, 29, 28) {
        0 => {
            if v {
                return simd_struct(w, i);
            }
            if bit(w, 24) {
                return None;
            }
            let o2 = bit(w, 23);
            let l = bit(w, 22);
            let o1 = bit(w, 21);
            let rt_reg = if size == 3 { x(rt) } else { wr(rt) };
            match (o2, o1) {
                (false, false) => {
                    if l {
                        // Unused register fields must be all ones.
                        if rs != 31 || rt2 != 31 {
                            return None;
                        }
                        i.write(rt_reg);
                    } else {
                        i.write(wr(rs));
                    }
                }
                (false, true) => {
                    if size >= 2 {
                        if l {
                            if rt == rt2 {
                                return None;
                            }
                            let (a, b) = if size == 3 {
                                (x(rt), x(rt2))
                            } else {
                                (wr(rt), wr(rt2))
                            };
                            i.write(a);
                            i.write(b);
                        } else {
                            i.write(wr(rs));
                        }
                    } else {
                        // casp
                        if rt2 != 31 || rs & 1 != 0 || rt & 1 != 0 {
                            return None;
                        }
                    }
                }
                (true, false) => {
                    if rs != 31 || rt2 != 31 {
                        return None;
                    }
                    // Only `ldar` reports its destination; `ldlar` does not.
                    if l && bit(w, 15) {
                        i.write(rt_reg);
                    }
                }
                (true, true) => {
                    if rt2 != 31 {
                        return None;
                    }
                }
            }
        }
        1 => {
            if !bit(w, 24) {
                // Load register (literal).
                let target = addr.wrapping_add(sext((bits(w, 23, 5) as u64) << 2, 21) as u64);
                if v {
                    if size == 3 {
                        return None;
                    }
                } else {
                    match size {
                        0 => {
                            i.write(wr(rt));
                            i.action = Action::LoadAbs {
                                dst: wr(rt),
                                addr: target,
                            };
                        }
                        1 | 2 => {
                            i.write(x(rt));
                            i.action = Action::LoadAbs {
                                dst: x(rt),
                                addr: target,
                            };
                        }
                        _ => {}
                    }
                }
            } else {
                if !bit(w, 21) && bits(w, 11, 10) == 1 {
                    return mops(w);
                }
                if v {
                    return None;
                }
                if bit(w, 21) {
                    if size != 3 {
                        return None;
                    }
                    return mem_tags(w, i);
                }
                // ldapur / stlur
                if bits(w, 11, 10) != 0 {
                    return None;
                }
                if let Some(d) = int_load_dst(size, opc, rt, false)? {
                    i.write(d);
                }
            }
        }
        2 => {
            let mode = bits(w, 24, 23);
            let l = bit(w, 22);
            // Loading the same register twice is rejected, as is writing
            // back to a base that is also transferred.
            if l && rt == rt2 {
                return None;
            }
            if !v && (mode == 1 || mode == 3) && rn != 31 && (rt == rn || rt2 == rn) {
                return None;
            }
            if v {
                if size == 3 {
                    return None;
                }
            } else {
                match size {
                    0 | 2 => {
                        if l {
                            let (a, b) = if size == 2 {
                                (x(rt), x(rt2))
                            } else {
                                (wr(rt), wr(rt2))
                            };
                            i.write(a);
                            i.write(b);
                        }
                    }
                    1 => {
                        // ldpsw; stgp is not accepted.
                        if mode == 0 || !l {
                            return None;
                        }
                        i.write(x(rt));
                        i.write(x(rt2));
                    }
                    _ => return None,
                }
            }
            if mode == 1 || mode == 3 {
                i.write(base);
            }
        }
        _ => {
            if bit(w, 24) {
                // Unsigned scaled immediate.
                if v {
                    if !fp_ldst_valid(size, opc) {
                        return None;
                    }
                } else if let Some(d) = int_load_dst(size, opc, rt, true)? {
                    i.write(d);
                    if opc == 1 && size >= 2 || (size == 2 && opc == 2) {
                        i.action = Action::LoadMem {
                            dst: d,
                            base,
                            disp: (bits(w, 21, 10) as u64) << size,
                        };
                    }
                }
            } else if !bit(w, 21) {
                let imm9 = sext(bits(w, 20, 12) as u64, 9) as u64;
                let mode = bits(w, 11, 10);
                // An integer load may not write back to (or, for the
                // unprivileged forms, even name) its own base.
                if bit(w, 22) && mode != 0 && !v && rn != 31 && rt == rn {
                    return None;
                }
                if v {
                    if mode == 2 || !fp_ldst_valid(size, opc) {
                        return None;
                    }
                } else if let Some(d) = int_load_dst(size, opc, rt, mode == 0)? {
                    i.write(d);
                    match mode {
                        // ldur (but not ldursw, which has its own id)
                        0 if opc == 1 && size >= 2 => {
                            i.action = Action::LoadMem {
                                dst: d,
                                base,
                                disp: imm9,
                            }
                        }
                        // Post-index: the offset is a separate operand.
                        1 if (opc == 1 && size >= 2) || (size == 2 && opc == 2) => {
                            i.action = Action::LoadMem {
                                dst: d,
                                base,
                                disp: 0,
                            }
                        }
                        3 if (opc == 1 && size >= 2) || (size == 2 && opc == 2) => {
                            i.action = Action::LoadMem {
                                dst: d,
                                base,
                                disp: imm9,
                            }
                        }
                        _ => {}
                    }
                }
                if mode == 1 || mode == 3 {
                    i.write(base);
                }
            } else {
                match bits(w, 11, 10) {
                    2 => {
                        // Register offset.
                        if !bit(w, 14) {
                            return None;
                        }
                        if v {
                            if !fp_ldst_valid(size, opc) {
                                return None;
                            }
                        } else if let Some(d) = int_load_dst(size, opc, rt, true)? {
                            i.write(d);
                            if (opc == 1 && size >= 2) || (size == 2 && opc == 2) {
                                // QUIRK(parity): the index register is
                                // ignored; the load is followed as if it
                                // read `[base]`.
                                i.action = Action::LoadMem {
                                    dst: d,
                                    base,
                                    disp: 0,
                                };
                            }
                        }
                    }
                    0 => {
                        // Atomic memory operations.
                        if v {
                            return None;
                        }
                        let o3 = bit(w, 15);
                        let op = bits(w, 14, 12);
                        // ldadd .. ldumin, swp: no register access is reported.
                        let lse = !o3 || op == 0;
                        let ldapr = o3 && op == 4 && bit(w, 23) && !bit(w, 22) && rs == 31;
                        // st64b / st64bv0 / st64bv / ld64b
                        let ls64 = o3
                            && size == 3
                            && opc == 0
                            && rt & 1 == 0
                            && rt <= 22
                            && (matches!(op, 2 | 3) || (matches!(op, 1 | 5) && rs == 31));
                        if ldapr {
                            i.write(if size == 3 { x(rt) } else { wr(rt) });
                        } else if !lse && !ls64 {
                            return None;
                        }
                    }
                    _ => {
                        // ldraa / ldrab
                        if v || size != 3 {
                            return None;
                        }
                        if bit(w, 11) {
                            if rn != 31 && rt == rn {
                                return None;
                            }
                            i.write(base);
                        }
                    }
                }
            }
        }
    }
    Some(())
}

/// Memory copy / set (`cpy*`, `set*`): no register access is reported.
fn mops(w: u32) -> Option<()> {
    let rd = bits(w, 4, 0);
    let rn = bits(w, 9, 5);
    let rs = bits(w, 20, 16);
    if bits(w, 31, 30) != 0 || rd == 31 || rd == rn || rd == rs || rn == rs {
        return None;
    }
    if bits(w, 23, 22) == 3 {
        (bits(w, 15, 14) != 3).then_some(())
    } else {
        (rs != 31).then_some(())
    }
}

fn mem_tags(w: u32, i: &mut Insn) -> Option<()> {
    let opc = bits(w, 23, 22);
    let op2 = bits(w, 11, 10);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let imm9 = bits(w, 20, 12);
    let _ = rt;
    match op2 {
        0 => match opc {
            // stzgm, stgm, ldgm
            0 | 2 | 3 if imm9 == 0 => {}
            // ldg
            1 => {}
            _ => return None,
        },
        1 | 3 => i.write(xsp(rn)),
        _ => {}
    }
    Some(())
}

/// AdvSIMD load/store of multiple or single structures.
fn simd_struct(w: u32, i: &mut Insn) -> Option<()> {
    if bit(w, 31) {
        return None;
    }
    let post = bit(w, 23);
    let l = bit(w, 22);
    let rn = bits(w, 9, 5);
    if !bit(w, 24) {
        if bit(w, 21) || (!post && bits(w, 20, 16) != 0) {
            return None;
        }
        match bits(w, 15, 12) {
            2 | 6 | 7 | 10 => {}
            // ld2/ld3/ld4 have no 1d arrangement.
            0 | 4 | 8 if bits(w, 11, 10) != 3 || bit(w, 30) => {}
            _ => return None,
        }
    } else {
        if !post && bits(w, 20, 16) != 0 {
            return None;
        }
        let s = bit(w, 12);
        let size = bits(w, 11, 10);
        let ok = match bits(w, 15, 14) {
            0 => true,
            1 => size & 1 == 0,
            2 => size == 0 || (size == 1 && !s),
            _ => l && !s,
        };
        if !ok {
            return None;
        }
    }
    if post {
        i.write(xsp(rn));
        // QUIRK(parity): for `st1` of a single element, the post-index
        // register is reported as written too.
        if bit(w, 24)
            && !l
            && !bit(w, 21)
            && !bit(w, 13)
            && bits(w, 15, 14) != 3
            && bits(w, 20, 16) != 31
        {
            i.write(x(bits(w, 20, 16)));
        }
    }
    Some(())
}

/// Whether `w` is accepted, for the classes whose valid encodings are
/// tabulated rather than decoded.
fn table_valid(t: &ClassTable, w: u32) -> bool {
    let lookup = || {
        let n2 = *t
            .l1
            .get(((bits(w, 31, 29) << 4) | bits(w, 24, 21)) as usize)?;
        let n3 = *t.l2.get(n2 as usize)?.get(bits(w, 15, 13) as usize)?;
        let n4 = *t.l3.get(n3 as usize)?.get(bits(w, 12, 10) as usize)?;
        let p = *t.l4.get(n4 as usize)?.get(bits(w, 20, 16) as usize)?;
        let mask = *t.patterns.get(p as usize)?.get(bits(w, 9, 5) as usize)?;
        Some((mask >> bits(w, 4, 0)) & 1 != 0)
    };
    lookup().unwrap_or(false)
}

/// General registers written by a (valid) floating-point / SIMD instruction.
fn simd_fp_writes(w: u32, i: &mut Insn) {
    let sf = bit(w, 31);
    let rd = bits(w, 4, 0);
    // Conversions between floating point and integer / fixed point.
    if bits(w, 30, 24) == 0b0011110 {
        let ftype = bits(w, 23, 22);
        let rmode = bits(w, 20, 19);
        let opcode = bits(w, 18, 16);
        // No access is reported for the half-precision forms.
        if ftype == 3 {
            return;
        }
        if bit(w, 21) && bits(w, 15, 10) == 0 {
            let to_gpr = match (rmode, opcode) {
                (_, 0 | 1) | (0, 4 | 5) => true,
                (0 | 1, 6) => true,
                // fjcvtzs (3, 6) reports nothing.
                _ => false,
            };
            if to_gpr {
                i.write(r(sf, rd));
            }
        } else if !bit(w, 21) && rmode == 3 && opcode <= 1 {
            i.write(r(sf, rd));
        }
        return;
    }
    // AdvSIMD copy: smov / umov move a vector element to a general register.
    if !bit(w, 31) && bits(w, 29, 21) == 0b001110000 && !bit(w, 15) && bit(w, 10) {
        let q = bit(w, 30);
        let imm5 = bits(w, 20, 16);
        let esize = imm5.trailing_zeros();
        let index = imm5.checked_shr(esize + 1).unwrap_or(0);
        // QUIRK(parity): with element index 0 the destination is not
        // reported as written, except for the byte `umov` and the `mov`
        // spellings (32- and 64-bit `umov`).
        let reported = match bits(w, 14, 11) {
            0b0101 => index != 0,
            0b0111 => esize != 1 || index != 0,
            _ => false,
        };
        if reported {
            i.write(if q { x(rd) } else { wr(rd) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u64 = 0x1_0000_0000;

    fn dec(word: u32) -> Option<Insn> {
        decode(&word.to_le_bytes(), AT)
    }

    #[test]
    fn truncated_input() {
        assert!(decode(&[0x1f, 0x20, 0x03], 0).is_none());
        assert!(decode(&[], 0).is_none());
    }

    #[test]
    fn bitmask_immediates() {
        assert!(valid_bitmask(true, 1, 0));
        assert!(!valid_bitmask(false, 1, 0));
        assert!(!valid_bitmask(true, 1, 0x3f));
        assert!(!valid_bitmask(true, 0, 0x3e));
        assert!(valid_bitmask(false, 0, 0x3c));
    }

    #[test]
    fn sign_extension() {
        assert_eq!(sext(0x1ff, 9), -1);
        assert_eq!(sext(0x0ff, 9), 255);
        assert_eq!(sext(0x100, 9), -256);
    }

    #[test]
    fn branches() {
        // bl +8: in both groups, writes the link register.
        let i = dec(0x9400_0002).unwrap();
        assert!(i.jump && i.call);
        assert_eq!(i.writes.as_slice(), &[30]);
        assert_eq!(i.ops.as_slice(), &[Op::Imm(AT + 8)]);
        // b.eq +0x10
        let i = dec(0x5400_0080).unwrap();
        assert!(i.jump && !i.call);
        assert_eq!(i.ops.as_slice(), &[Op::Imm(AT + 0x10)]);
        // cbz x1, +8
        let i = dec(0xb400_0041).unwrap();
        assert_eq!(i.ops.as_slice(), &[Op::Reg(1), Op::Imm(AT + 8)]);
        // tbz w3, #5, +4: the bit number is an immediate operand too.
        let i = dec(0x3628_0023).unwrap();
        assert_eq!(
            i.ops.as_slice(),
            &[Op::Reg(W0 + 3), Op::Imm(5), Op::Imm(AT + 4)]
        );
        // br x16 / blr x8
        let i = dec(0xd61f_0200).unwrap();
        assert!(i.jump && !i.call);
        assert_eq!(i.ops.as_slice(), &[Op::Reg(16)]);
        let i = dec(0xd63f_0100).unwrap();
        assert!(i.jump && i.call);
        // ret is neither.
        let i = dec(0xd65f_03c0).unwrap();
        assert!(!i.jump && !i.call);
    }

    #[test]
    fn address_patterns() {
        // adrp x8, +1 page
        let i = dec(0xb000_0008).unwrap();
        assert_eq!(
            i.action,
            Action::Set {
                dst: 8,
                value: AT + 0x1000
            }
        );
        // add x0, x8, #0x2c
        let i = dec(0x9100_b100).unwrap();
        assert_eq!(
            i.action,
            Action::Add {
                dst: 0,
                src: 8,
                imm: 0x2c
            }
        );
        assert_eq!(i.writes.as_slice(), &[0]);
        // mov x8, x0
        let i = dec(0xaa00_03e8).unwrap();
        assert_eq!(i.action, Action::Copy { dst: 8, src: 0 });
        // ldr x8, [x1, #0x60]
        let i = dec(0xf940_3028).unwrap();
        assert_eq!(
            i.action,
            Action::LoadMem {
                dst: 8,
                base: 1,
                disp: 0x60
            }
        );
        // movk x30, #0x816e, lsl #48: the shift is dropped.
        let i = dec(0xf2f0_2dde).unwrap();
        assert_eq!(
            i.action,
            Action::MovK {
                dst: 30,
                imm16: 0x816e,
                shift: 0
            }
        );
    }

    #[test]
    fn reported_writes() {
        // cmp x10, x11 reports its first operand.
        assert_eq!(dec(0xeb0b_015f).unwrap().writes.as_slice(), &[10]);
        // pacibsp
        assert_eq!(dec(0xd503_237f).unwrap().writes.as_slice(), &[30]);
        // stp x29, x30, [sp, #-16]!
        assert_eq!(dec(0xa9bf_7bfd).unwrap().writes.as_slice(), &[SP]);
        // ldp x29, x30, [sp], #16
        assert_eq!(dec(0xa8c1_7bfd).unwrap().writes.as_slice(), &[29, 30, SP]);
        // mov w0, #1
        assert_eq!(dec(0x5280_0020).unwrap().writes.as_slice(), &[W0]);
        assert_eq!(reg_name(XZR), "xzr");
        assert_eq!(reg_name(WSP), "wsp");
        assert_eq!(reg_name(WZR), "wzr");
    }

    #[test]
    fn validity() {
        // udf #0 decodes; other reserved words do not.
        assert!(dec(0).is_some());
        assert!(dec(0x0001_0000).is_none());
        assert!(dec(0xffff_ffff).is_none());
        // ldr x1, [x1], #8 writes back to its own destination.
        assert!(dec(0xf840_8421).is_none());
        // ldp x0, x0, [sp]
        assert!(dec(0xa940_03e0).is_none());
        // fmov d0, x0 and an unallocated neighbour.
        assert!(dec(0x9e67_0000).is_some());
        assert!(dec(0x9e69_39fe).is_none());
        // SVE: ptrue p0.b
        assert!(dec(0x2518_e3e0).is_some());
    }
}
