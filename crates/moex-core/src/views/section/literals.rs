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
/// doubles), so it is shown as the 128-bit integer it stores (in the byte
/// order of the file)
/// together with its reading as two doubles.
fn literals(mh: &MachHeader, section: &Section, unit: u64) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Offset", "Description", "Value", "Bytes"]);
    t.set_widths(&[100, 160, 320, 300]);
    for (offset, bytes) in chunks(mh, section, unit) {
        let (description, value) = describe(bytes, mh.big_endian);
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

/// `(description, value)` cells for the bytes of one literal, stored in
/// the byte order of the file.
fn describe(bytes: &[u8], big_endian: bool) -> (&'static str, String) {
    let f64_of = |b: [u8; 8]| {
        if big_endian {
            f64::from_be_bytes(b)
        } else {
            f64::from_le_bytes(b)
        }
    };
    if let Ok(b) = <[u8; 4]>::try_from(bytes) {
        let value = if big_endian {
            f32::from_be_bytes(b)
        } else {
            f32::from_le_bytes(b)
        };
        ("Float", format!("{value:?}"))
    } else if let Ok(b) = <[u8; 8]>::try_from(bytes) {
        ("Double", format!("{:?}", f64_of(b)))
    } else if let Ok(b) = <[u8; 16]>::try_from(bytes) {
        let (first, second) = b.split_at(8);
        let double = |half: &[u8]| <[u8; 8]>::try_from(half).map(f64_of).unwrap_or(f64::NAN);
        let integer = if big_endian {
            u128::from_be_bytes(b)
        } else {
            u128::from_le_bytes(b)
        };
        (
            "16-byte Literal",
            format!(
                "0x{:032X} (doubles: {:?}, {:?})",
                integer,
                double(first),
                double(second)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_follow_the_byte_order_of_the_file() {
        let value = |bytes: &[u8], big_endian| describe(bytes, big_endian).1;
        assert_eq!(value(&2.5f32.to_le_bytes(), false), "2.5");
        assert_eq!(value(&2.5f32.to_be_bytes(), true), "2.5");
        assert_eq!(value(&(-0.125f64).to_le_bytes(), false), "-0.125");
        assert_eq!(value(&(-0.125f64).to_be_bytes(), true), "-0.125");
        // 16 bytes: the integer, then the two halves in file order.
        let mut little = 1.0f64.to_le_bytes().to_vec();
        little.extend(2.0f64.to_le_bytes());
        assert_eq!(
            value(&little, false),
            "0x40000000000000003FF0000000000000 (doubles: 1.0, 2.0)"
        );
        let mut big = 1.0f64.to_be_bytes().to_vec();
        big.extend(2.0f64.to_be_bytes());
        assert_eq!(
            value(&big, true),
            "0x3FF00000000000004000000000000000 (doubles: 1.0, 2.0)"
        );
        assert_eq!(describe(&[1, 2, 3], false), ("Literal", String::new()));
    }
}
