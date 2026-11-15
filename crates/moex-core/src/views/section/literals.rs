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

/// "Floating Point Literals": each `unit`-byte literal with its value.
///
/// 4- and 8-byte literals are IEEE 754 single and double precision numbers.
/// A 16-byte literal has no single meaning (vector constants, masks, long
/// doubles), so it is shown as the 128-bit little-endian integer it stores
/// together with its reading as two doubles.
fn literals(mh: &MachHeader, section: &Section, unit: u64) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Offset", "Description", "Value", "Bytes"]);
    t.set_widths(&[100, 160, 320, 300]);
    for (offset, bytes) in chunks(mh, section, unit) {
        let (description, value) = describe(bytes);
        t.add_data(
            offset,
            unit,
            [
                as_address(offset),
                description.to_string(),
                value,
                as_hex_data(bytes),
            ],
        );
    }
    t
}

/// `(description, value)` cells for the bytes of one literal.
fn describe(bytes: &[u8]) -> (&'static str, String) {
    if let Ok(b) = <[u8; 4]>::try_from(bytes) {
        ("Float", format!("{:?}", f32::from_le_bytes(b)))
    } else if let Ok(b) = <[u8; 8]>::try_from(bytes) {
        ("Double", format!("{:?}", f64::from_le_bytes(b)))
    } else if let Ok(b) = <[u8; 16]>::try_from(bytes) {
        let (lo, hi) = b.split_at(8);
        let double = |half: &[u8]| {
            <[u8; 8]>::try_from(half)
                .map(f64::from_le_bytes)
                .unwrap_or(f64::NAN)
        };
        (
            "16-byte Literal",
            format!(
                "0x{:032X} (doubles: {:?}, {:?})",
                u128::from_le_bytes(b),
                double(lo),
                double(hi)
            ),
        )
    } else {
        ("Literal", String::new())
    }
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
