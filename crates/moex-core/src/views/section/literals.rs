//! C string literals and 4/8/16-byte literal sections.

use super::chunks;
use crate::hex::{as_address, as_hex_data, as_hex_string, as_string, utf8_safe};
use crate::macho::{MachHeader, Section};
use crate::view::Table;
use crate::views::string_table::string_literals;

/// "C String Literals": every non-empty NUL-terminated string.
pub(super) fn cstrings(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Index", "Offset", "Length", "String"]);
    t.set_widths(&[80, 100, 100, 80, 400]);
    for (index, (at, s)) in string_literals(section.data(&mh.image))
        .into_iter()
        .enumerate()
    {
        let offset = section.data_offset + at;
        // The row covers the characters without the terminator.
        t.add_data(
            offset,
            s.len() as u64,
            [
                as_string(index),
                as_hex_string(offset),
                as_string(s.len()),
                utf8_safe(s),
            ],
        );
    }
    t
}

/// "Floating Point Literals": the raw bytes of each `unit`-byte literal.
// The original aborts on any non-empty literal section (its table has no
// offset resolver and the row helper calls it unconditionally), so there is
// no reference output; the rows are what that code was written to produce.
// See "Intentional differences" in docs/rust-port-quirks.md.
fn literals(mh: &MachHeader, section: &Section, unit: u64) -> Table {
    let mut t = Table::new();
    for (offset, bytes) in chunks(mh, section, unit) {
        t.add_data(
            offset,
            unit,
            [
                as_address(offset),
                "Floating Point Number".to_string(),
                as_hex_data(bytes),
            ],
        );
    }
    t
}

pub(super) fn literals4(mh: &MachHeader, section: &Section) -> Table {
    literals(mh, section, 4)
}

pub(super) fn literals8(mh: &MachHeader, section: &Section) -> Table {
    literals(mh, section, 8)
}

pub(super) fn literals16(mh: &MachHeader, section: &Section) -> Table {
    literals(mh, section, 16)
}
