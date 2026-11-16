//! Instructions the bundled Capstone (5.0.6) does not decode.
//!
//! Capstone reports their bytes as data. The ones that current Apple
//! toolchains really emit are decoded here instead, with the same text
//! conventions as Capstone's own output:
//!
//! - AArch64 `FEAT_PAuth_LR` (`pacibsppc`, `retabsppc`, `autibsppc`, ...),
//!   `FEAT_CPA` (`addpt`, `subpt`, `maddpt`, `msubpt`) and `FEAT_CSSC`
//!   (`abs`, `cnt`, `ctz`, `smax`, `smin`, `umax`, `umin`), which the
//!   `arm64e` slices built for recent CPUs are full of;
//! - x86-64 `movsxd` without `REX.W` (`63 /r`).
//!
//! Encodings follow the Arm A-profile A64 instruction set and the Intel
//! SDM; the text was compared with `otool -tV`.

/// An instruction decoded here rather than by Capstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extra {
    /// Length in bytes.
    pub len: usize,
    pub mnemonic: &'static str,
    pub operands: String,
    /// Returns to the caller.
    pub returns: bool,
    /// The general register it writes, in machine encoding order (`x0`-`x30`,
    /// `rax`-`r15`); the stack pointer and the zero register are not listed.
    pub writes: Option<u8>,
}

impl Extra {
    /// `mnemonic operands`, or just the mnemonic.
    pub fn text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.to_string()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

/// An AArch64 general register operand. `sp`: number 31 is the stack
/// pointer rather than the zero register.
fn a64_reg(n: u32, wide: bool, sp: bool) -> String {
    match (n & 31, wide, sp) {
        (31, true, true) => "sp".to_string(),
        (31, false, true) => "wsp".to_string(),
        (31, true, false) => "xzr".to_string(),
        (31, false, false) => "wzr".to_string(),
        (n, true, _) => format!("x{n}"),
        (n, false, _) => format!("w{n}"),
    }
}

/// The register number as the sweep counts it; nothing for 31.
fn a64_written(n: u32) -> Option<u8> {
    let n = n & 31;
    (n < 31).then_some(n as u8)
}

/// An immediate the way Capstone prints it: decimal up to 9, hex above.
fn imm(value: i64) -> String {
    let magnitude = value.unsigned_abs();
    let sign = if value < 0 { "-" } else { "" };
    if magnitude > 9 {
        format!("{sign}0x{magnitude:x}")
    } else {
        format!("{sign}{magnitude}")
    }
}

/// Decodes the AArch64 instruction `word` located at `address`.
pub fn arm64(word: u32, address: u64) -> Option<Extra> {
    let rd = word & 31;
    let rn = (word >> 5) & 31;
    let rm = (word >> 16) & 31;
    let plain = |mnemonic: &'static str, operands: String| Extra {
        len: 4,
        mnemonic,
        operands,
        returns: false,
        writes: None,
    };

    // FEAT_PAuth_LR: sign the link register with sp and the pc as modifiers.
    let mnemonic = match word {
        0xdac1_a3fe => Some("paciasppc"),
        0xdac1_a7fe => Some("pacibsppc"),
        0xdac1_83fe => Some("pacnbiasppc"),
        0xdac1_87fe => Some("pacnbibsppc"),
        _ => None,
    };
    if let Some(mnemonic) = mnemonic {
        return Some(plain(mnemonic, String::new()));
    }
    // Authenticate (and return) naming the signing instruction, which lies
    // `imm16` instructions before this one.
    let label = || {
        let back = ((word >> 5) & 0xffff) as u64 * 4;
        format!("#0x{:x}", address.wrapping_sub(back))
    };
    match word & 0xffe0_001f {
        0xf380_001f => return Some(plain("autiasppc", label())),
        0xf3a0_001f => return Some(plain("autibsppc", label())),
        0x5500_001f | 0x5520_001f => {
            return Some(Extra {
                returns: true,
                ..plain(
                    if word & 0x0020_0000 == 0 {
                        "retaasppc"
                    } else {
                        "retabsppc"
                    },
                    label(),
                )
            })
        }
        _ => {}
    }
    // The same with the signing address in a register.
    match word & 0xffff_fc1f {
        0xdac1_901e => return Some(plain("autiasppcr", a64_reg(rn, true, false))),
        0xdac1_941e => return Some(plain("autibsppcr", a64_reg(rn, true, false))),
        _ => {}
    }
    match word & 0xffff_ffe0 {
        0xd65f_0be0 | 0xd65f_0fe0 => {
            return Some(Extra {
                returns: true,
                ..plain(
                    if word & 0x400 == 0 {
                        "retaasppcr"
                    } else {
                        "retabsppcr"
                    },
                    a64_reg(rd, true, false),
                )
            })
        }
        _ => {}
    }

    // FEAT_CPA: checked pointer arithmetic.
    let pointer_add = word & 0xffe0_e000;
    if matches!(pointer_add, 0x9a00_2000 | 0xda00_2000) {
        let shift = (word >> 10) & 7;
        let mut operands = format!(
            "{}, {}, {}",
            a64_reg(rd, true, true),
            a64_reg(rn, true, true),
            a64_reg(rm, true, false)
        );
        if shift != 0 {
            operands.push_str(&format!(", lsl #{shift}"));
        }
        return Some(Extra {
            writes: a64_written(rd),
            ..plain(
                if pointer_add == 0x9a00_2000 {
                    "addpt"
                } else {
                    "subpt"
                },
                operands,
            )
        });
    }
    let pointer_multiply = word & 0xffe0_8000;
    if matches!(pointer_multiply, 0x9b60_0000 | 0x9b60_8000) {
        let ra = (word >> 10) & 31;
        return Some(Extra {
            writes: a64_written(rd),
            ..plain(
                if pointer_multiply == 0x9b60_0000 {
                    "maddpt"
                } else {
                    "msubpt"
                },
                format!(
                    "{}, {}, {}, {}",
                    a64_reg(rd, true, false),
                    a64_reg(rn, true, false),
                    a64_reg(rm, true, false),
                    a64_reg(ra, true, false)
                ),
            )
        });
    }

    // FEAT_CSSC.
    let wide = word >> 31 != 0;
    let reg = |n: u32| a64_reg(n, wide, false);
    // One source: sf 1 0 11010110 00000 opcode Rn Rd.
    if word & 0x7fff_0000 == 0x5ac0_0000 {
        let mnemonic = match (word >> 10) & 0x3f {
            0b000110 => Some("ctz"),
            0b000111 => Some("cnt"),
            0b001000 => Some("abs"),
            _ => None,
        };
        if let Some(mnemonic) = mnemonic {
            return Some(Extra {
                writes: a64_written(rd),
                ..plain(mnemonic, format!("{}, {}", reg(rd), reg(rn)))
            });
        }
    }
    // Two sources: sf 0 0 11010110 Rm opcode Rn Rd.
    if word & 0x7fe0_0000 == 0x1ac0_0000 {
        let mnemonic = match (word >> 10) & 0x3f {
            0b011000 => Some("smax"),
            0b011001 => Some("umax"),
            0b011010 => Some("smin"),
            0b011011 => Some("umin"),
            _ => None,
        };
        if let Some(mnemonic) = mnemonic {
            return Some(Extra {
                writes: a64_written(rd),
                ..plain(mnemonic, format!("{}, {}, {}", reg(rd), reg(rn), reg(rm)))
            });
        }
    }
    // Immediate: sf 0 0 100011 1 opc(4) imm8 Rn Rd; the immediate is signed
    // for smax/smin.
    if word & 0x7fc0_0000 == 0x11c0_0000 {
        let imm8 = (word >> 10) & 0xff;
        let (mnemonic, value) = match (word >> 18) & 0xf {
            0b0000 => ("smax", imm8 as u8 as i8 as i64),
            0b0001 => ("umax", imm8 as i64),
            0b0010 => ("smin", imm8 as u8 as i8 as i64),
            0b0011 => ("umin", imm8 as i64),
            _ => return None,
        };
        return Some(Extra {
            writes: a64_written(rd),
            ..plain(
                mnemonic,
                format!("{}, {}, #{}", reg(rd), reg(rn), imm(value)),
            )
        });
    }
    None
}

const X86_REG64: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const X86_REG32: [&str; 16] = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d",
];
const X86_REG16: [&str; 16] = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w",
];

/// Decodes the x86-64 instruction at the start of `code`: `movsxd` without
/// `REX.W` (`[66] [REX] 63 /r`), which moves 32 bits (16 with the operand
/// size prefix) without extending them.
pub fn x86_64(code: &[u8]) -> Option<Extra> {
    let mut at = 0;
    let narrow = *code.first()? == 0x66;
    if narrow {
        at += 1;
    }
    let mut rex = 0u8;
    if code.get(at)? & 0xf0 == 0x40 {
        rex = *code.get(at)?;
        at += 1;
    }
    if rex & 8 != 0 || *code.get(at)? != 0x63 {
        return None;
    }
    at += 1;
    let modrm = *code.get(at)?;
    at += 1;
    let mode = modrm >> 6;
    let reg = ((modrm >> 3) & 7) | (rex & 4) << 1;
    let rm = modrm & 7;
    let (names, size) = if narrow {
        (&X86_REG16, "word")
    } else {
        (&X86_REG32, "dword")
    };

    let source = if mode == 3 {
        (*names.get((rm | (rex & 1) << 3) as usize)?).to_string()
    } else {
        let mut base: Option<&str> = None;
        let mut index: Option<(&str, u8)> = None;
        let mut disp_size = match mode {
            1 => 1,
            2 => 4,
            _ => 0,
        };
        if rm == 4 {
            let sib = *code.get(at)?;
            at += 1;
            let scale = 1u8 << (sib >> 6);
            let index_number = ((sib >> 3) & 7) | (rex & 2) << 2;
            let base_number = (sib & 7) | (rex & 1) << 3;
            // rsp cannot be an index.
            if index_number != 4 {
                index = Some((*X86_REG64.get(index_number as usize)?, scale));
            }
            if sib & 7 == 5 && mode == 0 {
                disp_size = 4;
            } else {
                base = Some(*X86_REG64.get(base_number as usize)?);
            }
        } else if rm == 5 && mode == 0 {
            base = Some("rip");
            disp_size = 4;
        } else {
            base = Some(*X86_REG64.get((rm | (rex & 1) << 3) as usize)?);
        }
        let disp: i64 = match disp_size {
            1 => *code.get(at)? as i8 as i64,
            4 => {
                let b = code.get(at..at + 4)?;
                i32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]) as i64
            }
            _ => 0,
        };
        at += disp_size;

        let mut inner = String::new();
        if let Some(base) = base {
            inner.push_str(base);
        }
        if let Some((index, scale)) = index {
            if !inner.is_empty() {
                inner.push_str(" + ");
            }
            inner.push_str(&format!("{index}*{scale}"));
        }
        if inner.is_empty() {
            // An absolute address.
            inner.push_str(&imm(disp & 0xffff_ffff));
        } else if disp != 0 {
            inner.push_str(if disp < 0 { " - " } else { " + " });
            inner.push_str(&imm(disp.abs()));
        }
        format!("{size} ptr [{inner}]")
    };
    Some(Extra {
        len: at,
        mnemonic: "movsxd",
        operands: format!("{}, {}", names.get(reg as usize)?, source),
        returns: false,
        // The stack pointer is not followed.
        writes: (reg != 4).then_some(reg),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a64(word: u32) -> String {
        arm64(word, 0x1000).map_or("-".to_string(), |e| e.text())
    }

    #[test]
    fn pointer_authentication_with_pc() {
        assert_eq!(a64(0xdac1_a7fe), "pacibsppc");
        assert_eq!(a64(0xdac1_a3fe), "paciasppc");
        assert_eq!(a64(0xdac1_83fe), "pacnbiasppc");
        assert_eq!(a64(0xdac1_87fe), "pacnbibsppc");
        // 0x37 instructions back from 0x1000.
        assert_eq!(a64(0x5520_06ff), "retabsppc #0xf24");
        assert_eq!(a64(0x5500_003f), "retaasppc #0xffc");
        assert_eq!(a64(0xf3a0_00df), "autibsppc #0xfe8");
        assert_eq!(a64(0xf380_00df), "autiasppc #0xfe8");
        assert_eq!(a64(0xdac1_921e), "autiasppcr x16");
        assert_eq!(a64(0xdac1_961e), "autibsppcr x16");
        assert_eq!(a64(0xd65f_0bf0), "retaasppcr x16");
        assert_eq!(a64(0xd65f_0ff0), "retabsppcr x16");
        let ret = arm64(0x5520_06ff, 0x1000).unwrap();
        assert!(ret.returns && ret.writes.is_none() && ret.len == 4);
        assert!(!arm64(0xf3a0_00df, 0x1000).unwrap().returns);
    }

    #[test]
    fn checked_pointer_arithmetic() {
        assert_eq!(a64(0x9a08_2d3a), "addpt x26, x9, x8, lsl #3");
        assert_eq!(a64(0x9a08_2133), "addpt x19, x9, x8");
        assert_eq!(a64(0x9a08_23ff), "addpt sp, sp, x8");
        assert_eq!(a64(0xda08_2133), "subpt x19, x9, x8");
        assert_eq!(a64(0x9b68_2d33), "maddpt x19, x9, x8, x11");
        assert_eq!(a64(0x9b68_ad33), "msubpt x19, x9, x8, x11");
        assert_eq!(arm64(0x9a08_2133, 0).unwrap().writes, Some(19));
        assert_eq!(arm64(0x9a08_23ff, 0).unwrap().writes, None);
    }

    #[test]
    fn common_short_sequences() {
        assert_eq!(a64(0x9aca_612a), "smax x10, x9, x10");
        assert_eq!(a64(0x1aca_652a), "umax w10, w9, w10");
        assert_eq!(a64(0x9aca_692a), "smin x10, x9, x10");
        assert_eq!(a64(0x1aca_6d2a), "umin w10, w9, w10");
        assert_eq!(a64(0xdac0_2015), "abs x21, x0");
        assert_eq!(a64(0x5ac0_1c20), "cnt w0, w1");
        assert_eq!(a64(0xdac0_1820), "ctz x0, x1");
        assert_eq!(a64(0x11c0_1420), "smax w0, w1, #5");
        assert_eq!(a64(0x91c3_fc20), "smax x0, x1, #-1");
        assert_eq!(a64(0x11c4_4020), "umax w0, w1, #0x10");
        assert_eq!(a64(0x91cb_fc20), "smin x0, x1, #-1");
        assert_eq!(a64(0x11cf_fc20), "umin w0, w1, #0xff");
    }

    #[test]
    fn everything_else_is_left_alone() {
        for word in [0u32, 0xffff_ffff, 0xd65f_03c0, 0xd4e0_0000, 0x9a08_0133] {
            assert_eq!(a64(word), "-", "{word:#x}");
        }
    }

    fn x86(code: &[u8]) -> String {
        x86_64(code).map_or("-".to_string(), |e| format!("{} {}", e.len, e.text()))
    }

    #[test]
    fn movsxd_without_rex_w() {
        assert_eq!(x86(&[0x63, 0xc1]), "2 movsxd eax, ecx");
        assert_eq!(x86(&[0x45, 0x63, 0xc1]), "3 movsxd r8d, r9d");
        assert_eq!(x86(&[0x66, 0x63, 0xc1]), "3 movsxd ax, cx");
        assert_eq!(x86(&[0x63, 0x07]), "2 movsxd eax, dword ptr [rdi]");
        assert_eq!(
            x86(&[0x63, 0x47, 0x08]),
            "3 movsxd eax, dword ptr [rdi + 8]"
        );
        assert_eq!(
            x86(&[0x63, 0x44, 0x8f, 0xf0]),
            "4 movsxd eax, dword ptr [rdi + rcx*4 - 0x10]"
        );
        assert_eq!(
            x86(&[0x63, 0x05, 0x10, 0, 0, 0]),
            "6 movsxd eax, dword ptr [rip + 0x10]"
        );
        assert_eq!(
            x86(&[0x63, 0x04, 0x25, 0x34, 0x12, 0, 0]),
            "7 movsxd eax, dword ptr [0x1234]"
        );
        assert_eq!(
            x86(&[0x63, 0x04, 0x8d, 0, 0, 0, 0]),
            "7 movsxd eax, dword ptr [rcx*4]"
        );
        assert_eq!(x86(&[0x63, 0x04, 0x24]), "3 movsxd eax, dword ptr [rsp]");
        assert_eq!(x86_64(&[0x63, 0xc1]).unwrap().writes, Some(0));
        assert_eq!(x86_64(&[0x63, 0xe1]).unwrap().writes, None);
        // With REX.W it is Capstone's; truncated encodings are not decoded.
        for code in [
            &[0x48, 0x63, 0xc1][..],
            &[0x63],
            &[0x63, 0x05, 0x10],
            &[],
            &[0x66],
        ] {
            assert_eq!(x86(code), "-", "{code:02x?}");
        }
    }
}
