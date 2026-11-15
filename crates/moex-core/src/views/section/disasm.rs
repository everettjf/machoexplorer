//! "Disassembly (Capstone)": the instructions of `__TEXT,__text` with the
//! symbol at each address, function starts and data-in-code ranges.

use crate::hex::{as_address, as_hex_data};
use crate::macho::disasm::{
    data_text, function_start_addresses, insn_text, regions, DisasmError, Disassembler, Item,
    SymbolLookup,
};
use crate::macho::{DataInCodeEntry, MachHeader, Section};
use crate::view::Table;
use std::collections::HashSet;

/// A symbol further than this below an address does not annotate it.
const MAX_SYMBOL_DELTA: u64 = 0x10_0000;

pub(super) fn disassembly(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Address", "Bytes", "Instruction", "Symbol", "Notes"]);
    t.set_widths(&[160, 220, 420, 260, 240]);

    let code = section.data(&mh.image);
    if code.is_empty() {
        message(
            &mut t,
            if section.size == 0 {
                "The section is empty."
            } else {
                "The section has no bytes in the file."
            },
        );
        return t;
    }
    let disassembler = match Disassembler::new(mh.cputype, mh.cpusubtype, false) {
        Ok(d) => d,
        Err(e) => {
            message(&mut t, error_text(&e));
            return t;
        }
    };

    let symbols = SymbolLookup::for_code(mh);
    let thumb_bit = u64::from(mh.cputype == crate::consts::CPU_TYPE_ARM);
    let function_starts: HashSet<u64> = function_start_addresses(mh)
        .into_iter()
        .map(|a| a & !thumb_bit)
        .collect();

    let base = section.addr;
    let layout = regions(mh, section, code.len());
    let result = disassembler.run(code, base, &layout, |item| {
        let (address, bytes, text, kind) = match item {
            Item::Code { insn, .. } => (insn.address(), insn.bytes(), insn_text(insn), None),
            Item::Data {
                address,
                bytes,
                kind,
            } => (address, bytes, data_text(bytes), kind),
        };
        let mut notes = String::new();
        if function_starts.contains(&address) {
            notes.push_str("function_start");
        }
        if let Some(kind) = kind {
            if !notes.is_empty() {
                notes.push_str(", ");
            }
            notes.push_str("data_in_code:");
            notes.push_str(dice_kind_name(kind));
        }
        t.add_data(
            section.data_offset.wrapping_add(address.wrapping_sub(base)),
            bytes.len() as u64,
            [
                as_address(address),
                as_hex_data(bytes),
                text,
                symbols.describe(address, Some(MAX_SYMBOL_DELTA)),
                notes,
            ],
        );
    });
    if let Err(e) = result {
        message(&mut t, error_text(&e));
    }
    t
}

fn error_text(e: &DisasmError) -> &'static str {
    match e {
        DisasmError::UnsupportedArch => "Unsupported architecture for Capstone disassembly.",
        DisasmError::Init => "Failed to initialize Capstone.",
    }
}

/// A row that carries a message instead of an instruction.
fn message(t: &mut Table, text: &str) {
    t.add(["-", "-", text, "-", "-"]);
}

fn dice_kind_name(kind: u16) -> &'static str {
    DataInCodeEntry {
        file_offset: 0,
        offset: 0,
        length: 0,
        kind,
    }
    .kind_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_rows_fill_the_table() {
        let mut t = Table::new();
        message(&mut t, error_text(&DisasmError::UnsupportedArch));
        assert_eq!(
            t.rows[0].cells,
            [
                "-",
                "-",
                "Unsupported architecture for Capstone disassembly.",
                "-",
                "-"
            ]
        );
        assert_eq!(dice_kind_name(3), "DICE_KIND_JUMP_TABLE16");
    }
}
