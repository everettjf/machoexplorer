//! "Disassembly (Capstone)": the instructions of `__TEXT,__text` with the
//! symbol at each address, function starts and data-in-code ranges.

use crate::hex::{as_address, as_hex_data};
use crate::macho::disasm::{disassemble, DisasmError, Duplicates, SymbolLookup};
use crate::macho::{DataInCodeEntry, MachHeader, Section};
use crate::view::Table;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

/// A symbol further than this below an address does not annotate it.
const MAX_SYMBOL_DELTA: u64 = 0x10_0000;

pub(super) fn disassembly(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Address", "Bytes", "Instruction", "Symbol", "Notes"]);
    t.set_widths(&[160, 220, 420, 260, 240]);

    let symbols = SymbolLookup::from_symtab(mh, Duplicates::LastWins);
    let function_starts = function_start_addresses(mh);
    let mut dice = DiceLookup::new(&mh.data_in_code());

    let base = section.addr;
    let result = disassemble(mh.cputype, section.data(&mh.image), base, |insn| {
        let offset = section
            .data_offset
            .wrapping_add(insn.address.wrapping_sub(base));
        let mut notes = String::new();
        if function_starts.contains(&insn.address) {
            notes.push_str("function_start");
        }
        if let Some(kind) = dice.kind_at(offset) {
            if !notes.is_empty() {
                notes.push_str(", ");
            }
            notes.push_str("data_in_code:");
            notes.push_str(kind);
        }
        t.add_data(
            offset,
            insn.bytes.len() as u64,
            [
                as_address(insn.address),
                as_hex_data(insn.bytes),
                insn.text(),
                symbols.describe(insn.address, Some(MAX_SYMBOL_DELTA)),
                notes,
            ],
        );
    });
    let message = match result {
        Ok(_) => return t,
        Err(DisasmError::UnsupportedArch) => {
            "Unsupported architecture for Capstone disassembly.".to_string()
        }
        Err(DisasmError::Init) => "Failed to initialize Capstone.".to_string(),
        Err(DisasmError::Failed(why)) => format!("Disassembly failed: {why}"),
    };
    t.add(["-".to_string(), "-".to_string(), message, "-".to_string()]);
    t
}

/// Function entry addresses from `LC_FUNCTION_STARTS`: running sum of the
/// deltas up to the first zero.
fn function_start_addresses(mh: &MachHeader) -> HashSet<u64> {
    let mut out = HashSet::new();
    let mut address = mh.base_address();
    for entry in mh.function_starts() {
        if entry.data == 0 {
            break;
        }
        address = address.wrapping_add(entry.data);
        out.insert(address);
    }
    out
}

/// Finds, for increasing offsets, the first `LC_DATA_IN_CODE` entry (in
/// table order) whose range contains the offset.
// QUIRK(parity): the entry's `offset` (relative to the Mach-O header) is
// compared with the instruction's offset in the *file*; the two differ
// inside a fat file.
struct DiceLookup {
    /// `(begin, end, table index, kind)` sorted by `begin`.
    ranges: Vec<(u64, u64, usize, &'static str)>,
    next: usize,
    /// Ranges that have begun, smallest table index on top.
    active: BinaryHeap<Reverse<(usize, u64, &'static str)>>,
}

impl DiceLookup {
    fn new(entries: &[DataInCodeEntry]) -> Self {
        let mut ranges: Vec<_> = entries
            .iter()
            .enumerate()
            .map(|(i, d)| {
                (
                    d.offset as u64,
                    d.offset as u64 + d.length as u64,
                    i,
                    d.kind_name(),
                )
            })
            .collect();
        ranges.sort_by_key(|r| r.0);
        DiceLookup {
            ranges,
            next: 0,
            active: BinaryHeap::new(),
        }
    }

    /// `offset` must not decrease between calls.
    fn kind_at(&mut self, offset: u64) -> Option<&'static str> {
        while let Some(&(begin, end, index, kind)) =
            self.ranges.get(self.next).filter(|r| r.0 <= offset)
        {
            debug_assert!(begin <= offset);
            self.active.push(Reverse((index, end, kind)));
            self.next += 1;
        }
        while let Some(&Reverse((_, end, kind))) = self.active.peek() {
            if end > offset {
                return Some(kind);
            }
            self.active.pop();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dice(offset: u32, length: u16, kind: u16) -> DataInCodeEntry {
        DataInCodeEntry {
            file_offset: 0,
            offset,
            length,
            kind,
        }
    }

    #[test]
    fn first_matching_range_in_table_order() {
        // Table order: a wide jump-table range, then a data range inside it,
        // then an earlier one.
        let entries = [dice(0x100, 0x40, 2), dice(0x110, 8, 1), dice(0x80, 4, 4)];
        let mut l = DiceLookup::new(&entries);
        assert_eq!(l.kind_at(0x7f), None);
        assert_eq!(l.kind_at(0x80), Some("DICE_KIND_JUMP_TABLE32"));
        assert_eq!(l.kind_at(0x83), Some("DICE_KIND_JUMP_TABLE32"));
        assert_eq!(l.kind_at(0x84), None);
        assert_eq!(l.kind_at(0x100), Some("DICE_KIND_JUMP_TABLE8"));
        // Inside both: the one listed first wins.
        assert_eq!(l.kind_at(0x114), Some("DICE_KIND_JUMP_TABLE8"));
        assert_eq!(l.kind_at(0x13f), Some("DICE_KIND_JUMP_TABLE8"));
        assert_eq!(l.kind_at(0x140), None);

        // A later-listed range that outlives the first one takes over.
        let entries = [dice(0x10, 4, 1), dice(0x10, 0x10, 3)];
        let mut l = DiceLookup::new(&entries);
        assert_eq!(l.kind_at(0x10), Some("DICE_KIND_DATA"));
        assert_eq!(l.kind_at(0x14), Some("DICE_KIND_JUMP_TABLE16"));
        assert_eq!(l.kind_at(0x20), None);
        assert_eq!(DiceLookup::new(&[]).kind_at(0), None);
    }
}
