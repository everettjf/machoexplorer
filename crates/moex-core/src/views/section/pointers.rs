//! Pointer sections: literal pointers, module init/term function pointers,
//! lazy / non-lazy symbol pointers and symbol stubs.

use super::{chunks, pointer_entries};
use crate::hex::{as_address, as_hex_data, as_short_hex_string};
use crate::macho::{MachHeader, Section};
use crate::view::Table;

fn pointer_size(section: &Section) -> u64 {
    if section.is64 {
        8
    } else {
        4
    }
}

/// "Literal Pointers" / "Module Init Func Pointers" / "Module Term Func
/// Pointers": `<where>-><value>` for each pointer.
// The original prints the address of the entry inside its own memory
// mapping of the file as `<where>`, which changes on every run. The file
// offset of the entry (that address minus the mapping base) is used
// instead. See "Intentional differences" in docs/rust-port-quirks.md.
pub(super) fn pointers(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    let size = pointer_size(section);
    for (offset, value) in pointer_entries(mh, section) {
        let text = format!(
            "{}->{}",
            as_short_hex_string(offset),
            as_short_hex_string(value)
        );
        t.add_data(
            offset,
            size,
            [as_address(offset), "Pointer".to_string(), text],
        );
    }
    t
}

/// "Lazy Symbol Pointers" / "Non-Lazy Symbol Pointers" / "Lazy Dylib
/// Symbol Pointers": the value of each pointer.
pub(super) fn indirect_pointers(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    let size = pointer_size(section);
    for (offset, value) in pointer_entries(mh, section) {
        t.add_data(
            offset,
            size,
            [
                as_address(offset),
                "Indirect Pointer".to_string(),
                as_short_hex_string(value),
            ],
        );
    }
    t
}

/// "Symbol Stubs": the bytes of each stub; `reserved2` is the stub size.
pub(super) fn symbol_stubs(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    let unit = section.reserved2 as u64;
    for (offset, bytes) in chunks(mh, section, unit) {
        t.add_data(
            offset,
            unit,
            [
                as_address(offset),
                "Indirect Stub".to_string(),
                as_hex_data(bytes),
            ],
        );
    }
    t
}
