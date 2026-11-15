//! Machine-code disassembly (Capstone), the code/data layout of a code
//! section, and address → symbol lookup.

use super::{MachHeader, Section};
use crate::consts::{
    CPU_SUBTYPE_MASK, CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_I386,
    CPU_TYPE_X86_64,
};
use crate::hex::{as_short_hex_string, utf8_safe};
use capstone::{Arch, Capstone, ExtraMode, Insn, Mode};
use std::collections::HashMap;

const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
/// `n_desc` bit of a symbol that names a Thumb function.
const N_ARM_THUMB_DEF: u16 = 0x0008;

const CPU_SUBTYPE_ARM_V7: u32 = 9;
const CPU_SUBTYPE_ARM_V7K: u32 = 12;
const CPU_SUBTYPE_ARM_V6M: u32 = 14;
const CPU_SUBTYPE_ARM_V7EM: u32 = 16;

const DICE_KIND_JUMP_TABLE8: u16 = 2;
const DICE_KIND_JUMP_TABLE16: u16 = 3;
const DICE_KIND_JUMP_TABLE32: u16 = 4;
const DICE_KIND_ABS_JUMP_TABLE32: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisasmError {
    /// No Capstone mode for this CPU type.
    UnsupportedArch,
    /// The engine could not be created.
    Init,
}

/// What a stretch of a code section holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Instructions; `thumb` only matters for 32-bit ARM.
    Code { thumb: bool },
    /// An `LC_DATA_IN_CODE` range of the given `DICE_KIND_*`.
    Data { kind: u16 },
}

/// A stretch of a code section, as offsets into the section contents.
/// Decoding restarts at the beginning of every region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    pub kind: RegionKind,
}

/// Function entry addresses from `LC_FUNCTION_STARTS`: the running sum of
/// the deltas up to the terminating zero. On 32-bit ARM the low bit marks a
/// Thumb function and is left in place.
pub fn function_start_addresses(mh: &MachHeader) -> Vec<u64> {
    let mut out = Vec::new();
    let mut address = mh.base_address();
    for entry in mh.function_starts() {
        if entry.data == 0 {
            break;
        }
        address = address.wrapping_add(entry.data);
        out.push(address);
    }
    out
}

/// True when code of this 32-bit ARM subtype is Thumb unless a symbol says
/// otherwise: ARMv7 and later (the compilers' default), and the M profile,
/// which has no ARM mode at all.
fn thumb_by_default(cpusubtype: u32) -> bool {
    let subtype = cpusubtype & !CPU_SUBTYPE_MASK;
    (CPU_SUBTYPE_ARM_V7..=CPU_SUBTYPE_ARM_V7K).contains(&subtype) || is_m_profile(cpusubtype)
}

fn is_m_profile(cpusubtype: u32) -> bool {
    let subtype = cpusubtype & !CPU_SUBTYPE_MASK;
    (CPU_SUBTYPE_ARM_V6M..=CPU_SUBTYPE_ARM_V7EM).contains(&subtype)
}

/// Splits the first `len` bytes of `section` into code and data regions.
///
/// Code regions begin at the section start, at every symbol defined in the
/// section, at every function start and after every `LC_DATA_IN_CODE`
/// range, so that decoding gets back in step after bytes that are not
/// instructions. For 32-bit ARM each code region is ARM or Thumb according
/// to the symbol (`N_ARM_THUMB_DEF`) or function start (low bit) that opens
/// it; a region opened by neither keeps the mode before it, and the section
/// starts in the default mode of the CPU subtype.
pub fn regions(mh: &MachHeader, section: &Section, len: usize) -> Vec<Region> {
    let is_arm = mh.cputype == CPU_TYPE_ARM;
    let within = |address: u64| {
        let delta = address.checked_sub(section.addr)?;
        (delta < len as u64).then_some(delta as usize)
    };

    // Symbols first: on equal offsets they decide the mode.
    let mut marks: Vec<(usize, Option<bool>)> = Vec::new();
    let ordinal = mh
        .sections()
        .position(|s| s.header_offset == section.header_offset)
        .map(|i| i + 1);
    if let (Some(ordinal), Some(symtab)) = (ordinal, mh.symtab()) {
        for sym in symtab.symbols() {
            if sym.n_type & N_STAB != 0
                || sym.n_type & N_TYPE != N_SECT
                || sym.n_sect as usize != ordinal
            {
                continue;
            }
            if let Some(offset) = within(sym.n_value) {
                let thumb = is_arm.then_some(sym.n_desc & N_ARM_THUMB_DEF != 0);
                marks.push((offset, thumb));
            }
        }
    }
    for address in function_start_addresses(mh) {
        let (address, thumb) = if is_arm {
            (address & !1, Some(address & 1 != 0))
        } else {
            (address, None)
        };
        if let Some(offset) = within(address) {
            marks.push((offset, thumb));
        }
    }

    let data: Vec<(usize, usize, u16)> = mh
        .data_in_code()
        .iter()
        .filter_map(|d| {
            // Entry offsets are relative to the Mach-O header, like the
            // section's own `offset` field.
            let start = (d.offset as u64).checked_sub(section.offset as u64)?;
            let end = (start + d.length as u64).min(len as u64);
            (start < end).then_some((start as usize, end as usize, d.kind))
        })
        .collect();

    let force_thumb = is_arm && is_m_profile(mh.cpusubtype);
    let default_thumb = is_arm && thumb_by_default(mh.cpusubtype);
    let mut out = layout(len, marks, data, default_thumb);
    if force_thumb {
        for region in &mut out {
            if let RegionKind::Code { thumb } = &mut region.kind {
                *thumb = true;
            }
        }
    }
    out
}

/// Builds the region list from code marks `(offset, mode)` and data ranges
/// `(start, end, kind)` in table order. Where data ranges overlap, the one
/// that starts first (then the one listed first) keeps the shared bytes.
fn layout(
    len: usize,
    mut marks: Vec<(usize, Option<bool>)>,
    mut data: Vec<(usize, usize, u16)>,
    default_thumb: bool,
) -> Vec<Region> {
    // Stable: the first mark listed for an offset is kept.
    marks.sort_by_key(|m| m.0);
    marks.dedup_by_key(|m| m.0);
    if marks.first().is_none_or(|m| m.0 != 0) {
        marks.insert(0, (0, None));
    }
    data.sort_by_key(|d| d.0);
    let mut covered = 0;
    data.retain_mut(|d| {
        d.0 = d.0.max(covered);
        d.1 = d.1.min(len);
        if d.0 >= d.1 {
            return false;
        }
        covered = d.1;
        true
    });

    let mut out = Vec::new();
    let mut thumb = default_thumb;
    let mut next_data = 0;
    let mut covered = 0;
    for (i, (start, mode)) in marks.iter().enumerate() {
        let end = marks.get(i + 1).map_or(len, |m| m.0).min(len);
        thumb = mode.unwrap_or(thumb);
        let mut pos = (*start).max(covered);
        while pos < end {
            while data.get(next_data).is_some_and(|d| d.1 <= pos) {
                next_data += 1;
            }
            match data.get(next_data) {
                Some(&(data_start, data_end, kind)) if data_start < end => {
                    if data_start > pos {
                        out.push(Region {
                            start: pos,
                            end: data_start,
                            kind: RegionKind::Code { thumb },
                        });
                    }
                    out.push(Region {
                        start: data_start.max(pos),
                        end: data_end,
                        kind: RegionKind::Data { kind },
                    });
                    pos = data_end;
                    next_data += 1;
                }
                _ => {
                    out.push(Region {
                        start: pos,
                        end,
                        kind: RegionKind::Code { thumb },
                    });
                    pos = end;
                }
            }
        }
        covered = covered.max(pos);
    }
    out
}

/// One thing found in a code section.
pub enum Item<'a> {
    Code {
        cs: &'a Capstone,
        insn: &'a Insn<'a>,
        /// First item of its region: nothing decoded earlier leads here.
        region_start: bool,
    },
    /// Bytes that are not an instruction: an `LC_DATA_IN_CODE` range
    /// (`kind` is its `DICE_KIND_*`) or, with `kind` `None`, bytes that do
    /// not decode.
    Data {
        address: u64,
        bytes: &'a [u8],
        kind: Option<u16>,
    },
}

/// `mnemonic operands` of an instruction, or just the mnemonic.
pub fn insn_text(insn: &Insn<'_>) -> String {
    let mnemonic = insn.mnemonic().unwrap_or("");
    match insn.op_str() {
        Some(operands) if !operands.is_empty() => format!("{mnemonic} {operands}"),
        _ => mnemonic.to_string(),
    }
}

/// Assembler directive for data bytes: `.long` / `.short` for one
/// little-endian unit of that size, otherwise `.byte` with every byte.
pub fn data_text(bytes: &[u8]) -> String {
    match *bytes {
        [a, b] => format!(".short 0x{:04x}", u16::from_le_bytes([a, b])),
        [a, b, c, d] => format!(".long 0x{:08x}", u32::from_le_bytes([a, b, c, d])),
        _ => {
            let list: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
            format!(".byte {}", list.join(", "))
        }
    }
}

/// Capstone engines for one CPU type.
pub struct Disassembler {
    main: Capstone,
    /// Thumb engine, for 32-bit ARM.
    thumb: Option<Capstone>,
    /// Size of the smallest instruction of the main engine; undecodable
    /// bytes are skipped in steps of this size.
    unit: usize,
    arm: bool,
}

impl Disassembler {
    /// Engines for a Mach-O CPU type: x86 (32/64), ARM (ARM and Thumb) and
    /// ARM64 (also for arm64_32). `detail` turns on operand details.
    pub fn new(cputype: u32, cpusubtype: u32, detail: bool) -> Result<Self, DisasmError> {
        let (arch, mode, unit) = match cputype {
            CPU_TYPE_I386 => (Arch::X86, Mode::Mode32, 1),
            CPU_TYPE_X86_64 => (Arch::X86, Mode::Mode64, 1),
            CPU_TYPE_ARM => (Arch::ARM, Mode::Arm, 4),
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => (Arch::ARM64, Mode::Arm, 4),
            _ => return Err(DisasmError::UnsupportedArch),
        };
        let engine = |mode: Mode| {
            let extra =
                (cputype == CPU_TYPE_ARM && is_m_profile(cpusubtype)).then_some(ExtraMode::MClass);
            let mut cs = Capstone::new_raw(arch, mode, extra.into_iter(), None)
                .map_err(|_| DisasmError::Init)?;
            cs.set_detail(detail).map_err(|_| DisasmError::Init)?;
            // Undecodable bytes come back as data instead of ending the run.
            cs.set_skipdata(true).map_err(|_| DisasmError::Init)?;
            Ok(cs)
        };
        Ok(Disassembler {
            main: engine(mode)?,
            thumb: (cputype == CPU_TYPE_ARM)
                .then(|| engine(Mode::Thumb))
                .transpose()?,
            unit,
            arm: arch != Arch::X86,
        })
    }

    /// Size of one row of an `LC_DATA_IN_CODE` range.
    fn data_unit(&self, kind: u16) -> usize {
        match kind {
            DICE_KIND_JUMP_TABLE8 => 1,
            DICE_KIND_JUMP_TABLE16 => 2,
            DICE_KIND_JUMP_TABLE32 | DICE_KIND_ABS_JUMP_TABLE32 => 4,
            // Plain data: words on the fixed-width architectures.
            _ if self.arm => 4,
            _ => 1,
        }
    }

    /// Walks `regions` of `code` (loaded at `address`), calling `sink` for
    /// every instruction and every piece of data in address order. Every
    /// byte of every region is reported exactly once.
    pub fn run<'c>(
        &self,
        code: &'c [u8],
        address: u64,
        regions: &[Region],
        mut sink: impl FnMut(Item<'_>),
    ) -> Result<(), DisasmError> {
        let empty: &'c [u8] = code.get(..0).unwrap_or(&[]);
        let mut main_iter = self
            .main
            .disasm_iter(empty, address)
            .map_err(|_| DisasmError::Init)?;
        let mut thumb_iter = match &self.thumb {
            Some(cs) => Some(
                cs.disasm_iter(empty, address)
                    .map_err(|_| DisasmError::Init)?,
            ),
            None => None,
        };
        for region in regions {
            let Some(chunk) = code.get(region.start..region.end) else {
                continue;
            };
            let base = address.wrapping_add(region.start as u64);
            let thumb = match region.kind {
                RegionKind::Data { kind } => {
                    let unit = self.data_unit(kind);
                    for (i, bytes) in chunk.chunks(unit).enumerate() {
                        sink(Item::Data {
                            address: base.wrapping_add((i * unit) as u64),
                            bytes,
                            kind: Some(kind),
                        });
                    }
                    continue;
                }
                RegionKind::Code { thumb } => thumb,
            };
            let (cs, iter, unit) = match (thumb, &self.thumb, thumb_iter.as_mut()) {
                (true, Some(cs), Some(iter)) => (cs, iter, 2),
                _ => (&self.main, &mut main_iter, self.unit),
            };
            let mut rest = chunk;
            let mut region_start = true;
            while !rest.is_empty() {
                let at = base.wrapping_add((chunk.len() - rest.len()) as u64);
                iter.reset(rest, at);
                while let Some(insn) = iter.next() {
                    if insn.id().0 == 0 {
                        sink(Item::Data {
                            address: insn.address(),
                            bytes: insn.bytes(),
                            kind: None,
                        });
                    } else {
                        sink(Item::Code {
                            cs,
                            insn: &insn,
                            region_start,
                        });
                    }
                    region_start = false;
                }
                let done = rest.len() - iter.code().len().min(rest.len());
                rest = rest.get(done..).unwrap_or(&[]);
                // What the engine left behind is shorter than an
                // instruction can be (or it gave up): step over one unit.
                let n = unit.min(rest.len());
                if n > 0 {
                    sink(Item::Data {
                        address: base.wrapping_add((chunk.len() - rest.len()) as u64),
                        bytes: rest.get(..n).unwrap_or(&[]),
                        kind: None,
                    });
                    rest = rest.get(n..).unwrap_or(&[]);
                    region_start = false;
                }
            }
        }
        Ok(())
    }
}

/// Symbol names by address, for annotating code addresses.
#[derive(Debug, Default)]
pub struct SymbolLookup {
    exact: HashMap<u64, String>,
    /// `(address, name)` sorted by address; symbols sharing an address keep
    /// their symbol table order.
    sorted: Vec<(u64, String)>,
}

/// Which symbol names an address when several share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplicates {
    /// The last symbol in table order names the address and the addresses
    /// after it.
    LastWins,
    /// Keep only the first symbol seen at each address.
    FirstOnly,
}

impl SymbolLookup {
    /// Collects every symbol of `LC_SYMTAB` that has a non-zero value, a
    /// non-zero string index and a non-empty name.
    pub fn from_symtab(mh: &MachHeader, duplicates: Duplicates) -> Self {
        Self::collect(mh, duplicates, false)
    }

    /// Symbols for annotating code: like [`from_symtab`](Self::from_symtab)
    /// with [`Duplicates::LastWins`], plus symbols defined at address 0
    /// (the first function of an object file).
    pub fn for_code(mh: &MachHeader) -> Self {
        Self::collect(mh, Duplicates::LastWins, true)
    }

    fn collect(mh: &MachHeader, duplicates: Duplicates, defined_at_zero: bool) -> Self {
        let mut lookup = SymbolLookup::default();
        let Some(symtab) = mh.symtab() else {
            return lookup;
        };
        for sym in symtab.symbols() {
            let defined = sym.n_type & N_STAB == 0 && sym.n_type & N_TYPE == N_SECT;
            if (sym.n_value == 0 && !(defined_at_zero && defined)) || sym.n_strx == 0 {
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
        // Stable, so `preceding` finds the same symbol as `exact`.
        self.sorted.sort_by_key(|(address, _)| *address);
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
    fn duplicate_symbols_are_chosen_by_table_order() {
        // Many symbols at one address, surrounded by others: whatever the
        // input order of the other addresses, the last one listed wins for
        // the address and for what follows it.
        let mut entries: Vec<(u64, String)> = (0..40u64)
            .rev()
            .map(|i| (0x1000 + i * 0x10, format!("_f{i}")))
            .collect();
        for i in 0..40 {
            entries.push((0x1100, format!("_dup{i}")));
        }
        let borrowed: Vec<(u64, &str)> = entries.iter().map(|(a, n)| (*a, n.as_str())).collect();
        let l = lookup(&borrowed, Duplicates::LastWins);
        assert_eq!(l.describe(0x1100, None), "_dup39");
        assert_eq!(l.describe(0x1104, None), "_dup39+0x4");
        assert_eq!(l.describe(0x10f8, None), "_f15+0x8");
    }

    /// Runs `code` as one code region and renders every item.
    fn rows(cputype: u32, cpusubtype: u32, code: &[u8], regions: &[Region]) -> Vec<String> {
        let mut out = Vec::new();
        Disassembler::new(cputype, cpusubtype, false)
            .unwrap()
            .run(code, 0x1000, regions, |item| {
                out.push(match item {
                    Item::Code { insn, .. } => {
                        format!("{:x} {}", insn.address(), insn_text(insn))
                    }
                    Item::Data { address, bytes, .. } => {
                        format!("{:x} {}", address, data_text(bytes))
                    }
                })
            })
            .unwrap();
        out
    }

    fn code_region(start: usize, end: usize, thumb: bool) -> Region {
        Region {
            start,
            end,
            kind: RegionKind::Code { thumb },
        }
    }

    #[test]
    fn arm64_and_x86() {
        // fmov d1, #2.5 ; ret
        let code = [0x01, 0x90, 0x60, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
        assert_eq!(
            rows(CPU_TYPE_ARM64, 0, &code, &[code_region(0, 8, false)]),
            ["1000 fmov d1, #2.50000000", "1004 ret"]
        );
        // The same engine serves arm64_32.
        assert_eq!(
            rows(CPU_TYPE_ARM64_32, 1, &code, &[code_region(4, 8, false)]),
            ["1004 ret"]
        );
        // push rbp ; mov rbp, rsp ; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        assert_eq!(
            rows(CPU_TYPE_X86_64, 3, &code, &[code_region(0, 5, false)]),
            ["1000 push rbp", "1001 mov rbp, rsp", "1004 ret"]
        );
        assert!(matches!(
            Disassembler::new(0x12, 0, false),
            Err(DisasmError::UnsupportedArch)
        ));
    }

    #[test]
    fn undecodable_bytes_are_skipped() {
        // ret ; (not an instruction) ; ret ; three stray bytes
        let code = [
            0xc0, 0x03, 0x5f, 0xd6, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x03, 0x5f, 0xd6, 1, 2, 3,
        ];
        assert_eq!(
            rows(CPU_TYPE_ARM64, 0, &code, &[code_region(0, 15, false)]),
            [
                "1000 ret",
                "1004 .long 0xffffffff",
                "1008 ret",
                "100c .byte 0x01, 0x02, 0x03"
            ]
        );
        // x86: ret ; a truncated call ; nothing is lost.
        assert_eq!(
            rows(
                CPU_TYPE_X86_64,
                3,
                &[0xc3, 0xe8, 0x00],
                &[code_region(0, 3, false)]
            ),
            ["1000 ret", "1001 .byte 0xe8", "1002 .byte 0x00"]
        );
        // No regions, no rows; an empty region list is not an error.
        assert!(rows(CPU_TYPE_X86_64, 3, &[0xc3], &[]).is_empty());
    }

    #[test]
    fn arm_and_thumb_regions() {
        // ARM: bx lr. Thumb: bx lr ; nop.
        let code = [0x1e, 0xff, 0x2f, 0xe1, 0x70, 0x47, 0x00, 0xbf];
        assert_eq!(
            rows(
                CPU_TYPE_ARM,
                CPU_SUBTYPE_ARM_V7,
                &code,
                &[code_region(0, 4, false), code_region(4, 8, true)]
            ),
            ["1000 bx lr", "1004 bx lr", "1006 nop"]
        );
    }

    #[test]
    fn data_regions() {
        // ret ; a 16-bit jump table of two entries and a stray byte ; ret
        let code = [0xc3, 0x10, 0x00, 0x20, 0x00, 0x7f, 0xc3];
        let regions = [
            code_region(0, 1, false),
            Region {
                start: 1,
                end: 6,
                kind: RegionKind::Data {
                    kind: DICE_KIND_JUMP_TABLE16,
                },
            },
            code_region(6, 7, false),
        ];
        assert_eq!(
            rows(CPU_TYPE_X86_64, 3, &code, &regions),
            [
                "1000 ret",
                "1001 .short 0x0010",
                "1003 .short 0x0020",
                "1005 .byte 0x7f",
                "1006 ret"
            ]
        );
    }

    #[test]
    fn layout_splits_at_marks_and_data() {
        let code = |start, end, thumb| code_region(start, end, thumb);
        let data = |start, end, kind| Region {
            start,
            end,
            kind: RegionKind::Data { kind },
        };
        // No marks at all: one region in the default mode.
        assert_eq!(layout(8, vec![], vec![], true), [code(0, 8, true)]);
        assert!(layout(0, vec![(0, None)], vec![(0, 4, 1)], false).is_empty());
        // Marks switch the mode; the first one listed for an offset wins and
        // a mark without a mode keeps the current one.
        assert_eq!(
            layout(
                0x40,
                vec![
                    (0x10, Some(true)),
                    (0x30, None),
                    (0x10, Some(false)),
                    (0x20, Some(false))
                ],
                vec![],
                false
            ),
            [
                code(0, 0x10, false),
                code(0x10, 0x20, true),
                code(0x20, 0x30, false),
                code(0x30, 0x40, false)
            ]
        );
        // Data ranges cut code regions, may span marks, are clipped to the
        // section, and overlapping ones do not report a byte twice.
        assert_eq!(
            layout(
                0x40,
                vec![(0x10, None), (0x20, None)],
                vec![
                    (0x1c, 0x24, 4),
                    (0x08, 0x0c, 1),
                    (0x0a, 0x10, 2),
                    (0x3c, 0x80, 3)
                ],
                false
            ),
            [
                code(0, 0x08, false),
                data(0x08, 0x0c, 1),
                data(0x0c, 0x10, 2),
                code(0x10, 0x1c, false),
                data(0x1c, 0x24, 4),
                code(0x24, 0x3c, false),
                data(0x3c, 0x40, 3)
            ]
        );
        // Every byte is covered exactly once.
        let regions = layout(
            100,
            vec![(7, None), (50, None), (51, None)],
            vec![(0, 3, 1), (49, 52, 1), (90, 100, 1)],
            false,
        );
        let mut at = 0;
        for r in &regions {
            assert_eq!(r.start, at);
            assert!(r.end > r.start);
            at = r.end;
        }
        assert_eq!(at, 100);
    }

    #[test]
    fn thumb_defaults() {
        assert!(!thumb_by_default(6)); // armv6
        assert!(thumb_by_default(CPU_SUBTYPE_ARM_V7));
        assert!(thumb_by_default(11)); // armv7s
        assert!(thumb_by_default(CPU_SUBTYPE_ARM_V6M));
        assert!(is_m_profile(15) && !is_m_profile(CPU_SUBTYPE_ARM_V7K));
    }
}
