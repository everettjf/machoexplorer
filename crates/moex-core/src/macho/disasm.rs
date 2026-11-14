//! Machine-code disassembly (Capstone) and address → symbol lookup.

use super::MachHeader;
use crate::consts::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_I386, CPU_TYPE_X86_64};
use crate::hex::{as_short_hex_string, utf8_safe};
use capstone::{Arch, Capstone, Mode, NO_EXTRA_MODE};
use std::collections::HashMap;

/// One decoded instruction, borrowed from the disassembler.
#[derive(Debug, Clone, Copy)]
pub struct Instruction<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
    pub mnemonic: &'a str,
    /// Operand text; empty for instructions without operands.
    pub operands: &'a str,
}

impl Instruction<'_> {
    /// `mnemonic operands`, or just the mnemonic.
    pub fn text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.to_string()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisasmError {
    /// No Capstone mode for this CPU type.
    UnsupportedArch,
    /// The engine could not be created.
    Init,
    /// Nothing was decoded; the payload is Capstone's error text
    /// (`OK (CS_ERR_OK)` when the first bytes are simply not an instruction).
    Failed(String),
}

/// Capstone architecture and mode for a Mach-O CPU type: x86 (32/64),
/// ARM (ARM mode, not Thumb) and ARM64.
pub fn capstone_mode(cputype: u32) -> Option<(Arch, Mode)> {
    match cputype {
        CPU_TYPE_I386 => Some((Arch::X86, Mode::Mode32)),
        CPU_TYPE_X86_64 => Some((Arch::X86, Mode::Mode64)),
        CPU_TYPE_ARM => Some((Arch::ARM, Mode::Arm)),
        CPU_TYPE_ARM64 => Some((Arch::ARM64, Mode::Arm)),
        _ => None,
    }
}

/// Capstone's `cs_strerror` text for an error.
fn strerror(err: &capstone::Error) -> String {
    match err {
        capstone::Error::OutOfMemory => "Out-Of-Memory error (CS_ERR_MEM)".to_string(),
        other => other.to_string(),
    }
}

/// Disassembles `code` as loaded at `address`, calling `sink` for each
/// instruction in order, and returns how many were decoded. Decoding stops
/// at the first byte sequence that is not an instruction (no data skipping),
/// with default syntax and details off.
pub fn disassemble(
    cputype: u32,
    code: &[u8],
    address: u64,
    mut sink: impl FnMut(Instruction<'_>),
) -> Result<usize, DisasmError> {
    let (arch, mode) = capstone_mode(cputype).ok_or(DisasmError::UnsupportedArch)?;
    let mut cs =
        Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None).map_err(|_| DisasmError::Init)?;
    // Same as the default; kept explicit because the output format relies
    // on it.
    let _ = cs.set_detail(false);
    let insns = cs
        .disasm_all(code, address)
        .map_err(|e| DisasmError::Failed(strerror(&e)))?;
    if insns.is_empty() {
        return Err(DisasmError::Failed("OK (CS_ERR_OK)".to_string()));
    }
    for insn in insns.iter() {
        sink(Instruction {
            address: insn.address(),
            bytes: insn.bytes(),
            mnemonic: insn.mnemonic().unwrap_or(""),
            operands: insn.op_str().unwrap_or(""),
        });
    }
    Ok(insns.len())
}

/// Symbol names by address, for annotating code addresses.
#[derive(Debug, Default)]
pub struct SymbolLookup {
    exact: HashMap<u64, String>,
    /// `(address, name)` sorted by address.
    sorted: Vec<(u64, String)>,
}

/// Which symbol names an address when several share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplicates {
    /// Keep every symbol; the last one in table order names the address.
    LastWins,
    /// Keep only the first symbol seen at each address.
    FirstOnly,
}

impl SymbolLookup {
    /// Collects every symbol of `LC_SYMTAB` that has a non-zero value, a
    /// non-zero string index and a non-empty name.
    pub fn from_symtab(mh: &MachHeader, duplicates: Duplicates) -> Self {
        let mut lookup = SymbolLookup::default();
        let Some(symtab) = mh.symtab() else {
            return lookup;
        };
        for sym in symtab.symbols() {
            if sym.n_value == 0 || sym.n_strx == 0 {
                continue;
            }
            let name = symtab.string_bytes(sym.n_strx);
            if name.is_empty() {
                continue;
            }
            lookup.insert(sym.n_value, utf8_safe(name), duplicates);
        }
        lookup.finish();
        lookup
    }

    fn insert(&mut self, address: u64, name: String, duplicates: Duplicates) {
        match duplicates {
            Duplicates::LastWins => {
                self.exact.insert(address, name.clone());
                self.sorted.push((address, name));
            }
            Duplicates::FirstOnly => {
                if let std::collections::hash_map::Entry::Vacant(slot) = self.exact.entry(address) {
                    slot.insert(name.clone());
                    self.sorted.push((address, name));
                }
            }
        }
    }

    fn finish(&mut self) {
        // QUIRK(parity): the original sorts by address with `std::sort`,
        // which is not stable, so which of several symbols at one address
        // sorts last (and names the addresses after it) is an artefact of
        // libc++'s algorithm. The same algorithm is run here.
        let mut order: Vec<(u64, usize)> = self
            .sorted
            .iter()
            .enumerate()
            .map(|(i, (a, _))| (*a, i))
            .collect();
        super::libcxx_sort::sort_by(&mut order, &|a, b| a.0 < b.0);
        let mut names: Vec<Option<String>> = std::mem::take(&mut self.sorted)
            .into_iter()
            .map(|(_, n)| Some(n))
            .collect();
        self.sorted = order
            .into_iter()
            .filter_map(|(address, i)| Some((address, names.get_mut(i)?.take()?)))
            .collect();
    }

    /// Name of the symbol exactly at `address`.
    pub fn exact(&self, address: u64) -> Option<&str> {
        self.exact.get(&address).map(String::as_str)
    }

    /// The closest symbol at or below `address` and the distance to it.
    pub fn preceding(&self, address: u64) -> Option<(&str, u64)> {
        let idx = self.sorted.partition_point(|(a, _)| *a <= address);
        let (base, name) = self.sorted.get(idx.checked_sub(1)?)?;
        Some((name.as_str(), address - base))
    }

    /// `name` for an exact hit, otherwise `name+0x<delta>` relative to the
    /// closest symbol below, provided it is no further than `max_delta`
    /// (`None`: any distance). Empty when nothing qualifies.
    pub fn describe(&self, address: u64, max_delta: Option<u64>) -> String {
        if let Some(name) = self.exact(address) {
            return name.to_string();
        }
        match self.preceding(address) {
            Some((name, delta)) if max_delta.is_none_or(|max| delta <= max) => {
                format!("{name}+0x{}", as_short_hex_string(delta))
            }
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(entries: &[(u64, &str)], duplicates: Duplicates) -> SymbolLookup {
        let mut l = SymbolLookup::default();
        for (a, n) in entries {
            l.insert(*a, n.to_string(), duplicates);
        }
        l.finish();
        l
    }

    #[test]
    fn symbol_lookup() {
        let l = lookup(
            &[(0x2000, "_b"), (0x1000, "_a"), (0x1000, "_a2")],
            Duplicates::LastWins,
        );
        assert_eq!(l.describe(0x1000, None), "_a2");
        assert_eq!(l.describe(0x1004, None), "_a2+0x4");
        assert_eq!(l.describe(0x2abc, Some(0x100000)), "_b+0xABC");
        assert_eq!(l.describe(0x2000 + 0x100001, Some(0x100000)), "");
        assert_eq!(l.describe(0x2000 + 0x100001, None), "_b+0x100001");
        assert_eq!(l.describe(0xfff, None), "");
        let l = lookup(&[(0x1000, "_a"), (0x1000, "_a2")], Duplicates::FirstOnly);
        assert_eq!(l.describe(0x1000, None), "_a");
        assert_eq!(l.describe(0x1001, None), "_a+0x1");
        assert_eq!(SymbolLookup::default().describe(5, None), "");
    }

    #[test]
    fn arm64_and_x86() {
        let mut rows = Vec::new();
        // fmov d1, #2.5 ; ret
        let code = [0x01, 0x90, 0x60, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
        let n = disassemble(CPU_TYPE_ARM64, &code, 0x1000, |i| {
            rows.push((i.address, i.bytes.len(), i.text()))
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(rows[0], (0x1000, 4, "fmov d1, #2.50000000".to_string()));
        assert_eq!(rows[1], (0x1004, 4, "ret".to_string()));

        let mut rows = Vec::new();
        // push rbp ; mov rbp, rsp ; ret
        disassemble(CPU_TYPE_X86_64, &[0x55, 0x48, 0x89, 0xe5, 0xc3], 0, |i| {
            rows.push(i.text())
        })
        .unwrap();
        assert_eq!(rows, ["push rbp", "mov rbp, rsp", "ret"]);
    }

    #[test]
    fn failures() {
        assert_eq!(
            disassemble(0x12, &[0; 4], 0, |_| {}),
            Err(DisasmError::UnsupportedArch)
        );
        assert_eq!(
            disassemble(CPU_TYPE_ARM64, &[], 0, |_| {}),
            Err(DisasmError::Failed("OK (CS_ERR_OK)".into()))
        );
        // Three bytes cannot hold an ARM64 instruction.
        assert_eq!(
            disassemble(CPU_TYPE_ARM64, &[0; 3], 0, |_| {}),
            Err(DisasmError::Failed("OK (CS_ERR_OK)".into()))
        );
        // Decoding stops at the first invalid instruction.
        let mut n = 0;
        let code = [
            0xc0, 0x03, 0x5f, 0xd6, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        assert_eq!(disassemble(CPU_TYPE_ARM64, &code, 0, |_| n += 1), Ok(1));
        assert_eq!(n, 1);
    }
}
