//! Hex pane model: row formatting and selection mapping, computed per row on
//! demand so multi-GB ranges never allocate more than what is visible.

use moex_core::BinaryRange;

pub const BYTES_PER_ROW: u64 = 16;
/// Largest selection that may be copied to the clipboard as text.
pub const MAX_COPY_BYTES: u64 = 4 * 1024 * 1024;

/// A byte selection in absolute file offsets, `start..end` (end exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSelection {
    pub start: u64,
    pub end: u64,
}

impl ByteSelection {
    pub fn new(offset: u64, size: u64) -> Option<Self> {
        if size == 0 {
            return None;
        }
        Some(ByteSelection {
            start: offset,
            end: offset.saturating_add(size),
        })
    }

    /// Selection spanning two byte positions (inclusive), in either order.
    pub fn between(a: u64, b: u64) -> Self {
        ByteSelection {
            start: a.min(b),
            end: a.max(b).saturating_add(1),
        }
    }

    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// Restrict `range` to the bytes that exist in a file of `file_len` bytes.
pub fn clip_range(range: BinaryRange, file_len: u64) -> BinaryRange {
    let offset = range.offset.min(file_len);
    let size = range.size.min(file_len - offset);
    BinaryRange {
        offset,
        size,
        start_value: range.start_value,
    }
}

pub fn row_count(range: &BinaryRange) -> u64 {
    range.size.div_ceil(BYTES_PER_ROW)
}

/// Address label of `row`: `0x` followed by 16 hex digits (the Qt widget's
/// `%#018llx`), counted from `start_value`.
pub fn offset_label(range: &BinaryRange, row: u64) -> String {
    format!(
        "{:#018x}",
        range.start_value.wrapping_add(row * BYTES_PER_ROW)
    )
}

/// The (up to 16) bytes shown on `row`. Empty when out of range.
pub fn row_bytes<'a>(data: &'a [u8], range: &BinaryRange, row: u64) -> &'a [u8] {
    let Some(rel) = row.checked_mul(BYTES_PER_ROW) else {
        return &[];
    };
    if rel >= range.size {
        return &[];
    }
    let start = range.offset + rel;
    let end = start + (range.size - rel).min(BYTES_PER_ROW);
    let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
        return &[];
    };
    data.get(start..end.min(data.len())).unwrap_or(&[])
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Two lowercase hex digits.
pub fn hex_byte(b: u8) -> [u8; 2] {
    [
        HEX_DIGITS[(b >> 4) as usize],
        HEX_DIGITS[(b & 0xf) as usize],
    ]
}

/// Printable ASCII or `.`, as in the Qt widget.
pub fn ascii_char(b: u8) -> char {
    if (0x20..=0x7e).contains(&b) {
        b as char
    } else {
        '.'
    }
}

/// `"7f 45 4c"` for a row (no padding for short rows).
pub fn row_hex_text(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let h = hex_byte(*b);
        s.push(h[0] as char);
        s.push(h[1] as char);
    }
    s
}

pub fn row_ascii_text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| ascii_char(*b)).collect()
}

/// Columns `[start, end)` of `row` covered by `sel`, if any.
pub fn row_selection(
    range: &BinaryRange,
    row: u64,
    sel: Option<ByteSelection>,
) -> Option<(usize, usize)> {
    let sel = sel?;
    let row_start = range.offset.checked_add(row.checked_mul(BYTES_PER_ROW)?)?;
    let row_end = row_start
        .saturating_add(BYTES_PER_ROW)
        .min(range.offset.saturating_add(range.size));
    let s = sel.start.max(row_start);
    let e = sel.end.min(row_end);
    if s >= e {
        return None;
    }
    Some(((s - row_start) as usize, (e - row_start) as usize))
}

/// Row containing absolute file offset `offset`, if inside the range.
pub fn row_of_offset(range: &BinaryRange, offset: u64) -> Option<u64> {
    if offset < range.offset || offset - range.offset >= range.size {
        return None;
    }
    Some((offset - range.offset) / BYTES_PER_ROW)
}

/// Absolute file offset of the byte at (`row`, `col`), clamped to the last
/// byte of the row / range. `None` for an empty range.
pub fn offset_at(range: &BinaryRange, row: u64, col: usize) -> Option<u64> {
    if range.size == 0 {
        return None;
    }
    let last = range.size - 1;
    let rel = row
        .saturating_mul(BYTES_PER_ROW)
        .saturating_add(col.min(15) as u64)
        .min(last);
    Some(range.offset + rel)
}

/// Clamp a selection to the displayed range (a table row may describe bytes
/// that are only partly inside the node's range).
pub fn clamp_selection(range: &BinaryRange, sel: ByteSelection) -> Option<ByteSelection> {
    let s = sel.start.max(range.offset);
    let e = sel.end.min(range.offset.saturating_add(range.size));
    (s < e).then_some(ByteSelection { start: s, end: e })
}

fn selected_slice(data: &[u8], sel: ByteSelection) -> Result<&[u8], String> {
    if sel.len() > MAX_COPY_BYTES {
        return Err(format!(
            "Selection too large to copy ({} bytes).",
            sel.len()
        ));
    }
    let start = usize::try_from(sel.start)
        .unwrap_or(usize::MAX)
        .min(data.len());
    let end = usize::try_from(sel.end)
        .unwrap_or(usize::MAX)
        .min(data.len());
    Ok(&data[start..end.max(start)])
}

/// Selected bytes as space-separated lowercase hex.
pub fn selection_as_hex(data: &[u8], sel: ByteSelection) -> Result<String, String> {
    selected_slice(data, sel).map(row_hex_text)
}

/// Selected bytes as ASCII with `.` for non-printable bytes.
pub fn selection_as_ascii(data: &[u8], sel: ByteSelection) -> Result<String, String> {
    selected_slice(data, sel).map(row_ascii_text)
}

/// Header above the hex column: ` 0  1 ...  F` positions as single digits.
pub fn hex_header_digit(col: usize) -> char {
    char::from_digit((col & 0xf) as u32, 16)
        .unwrap()
        .to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(offset: u64, size: u64) -> BinaryRange {
        BinaryRange {
            offset,
            size,
            start_value: offset,
        }
    }

    #[test]
    fn rows_and_labels() {
        let r = range(0x20, 33);
        assert_eq!(row_count(&r), 3);
        assert_eq!(row_count(&range(0, 0)), 0);
        assert_eq!(row_count(&range(0, 16)), 1);
        assert_eq!(offset_label(&r, 0), "0x0000000000000020");
        assert_eq!(offset_label(&r, 2), "0x0000000000000040");
        let labelled = BinaryRange {
            offset: 0x20,
            size: 33,
            start_value: 0x1_0000_0000,
        };
        assert_eq!(offset_label(&labelled, 1), "0x0000000100000010");
    }

    #[test]
    fn row_bytes_and_text() {
        let data: Vec<u8> = (0u8..=255).collect();
        let r = range(0x20, 33);
        assert_eq!(row_bytes(&data, &r, 0), &data[0x20..0x30]);
        assert_eq!(row_bytes(&data, &r, 2), &data[0x40..0x41]);
        assert!(row_bytes(&data, &r, 3).is_empty());
        assert!(row_bytes(&data, &r, u64::MAX).is_empty());
        assert_eq!(row_hex_text(&[0x7f, 0x45, 0x0a]), "7f 45 0a");
        assert_eq!(row_ascii_text(&[0x41, 0x00, 0x7e, 0x7f, 0x20]), "A.~. ");
    }

    #[test]
    fn clip_to_file() {
        assert_eq!(
            clip_range(range(10, 100), 50),
            BinaryRange {
                offset: 10,
                size: 40,
                start_value: 10
            }
        );
        assert_eq!(clip_range(range(80, 100), 50).size, 0);
        assert_eq!(clip_range(range(0, u64::MAX), 50).size, 50);
    }

    #[test]
    fn selection_columns_per_row() {
        let r = range(0x100, 0x40);
        let sel = ByteSelection::new(0x10e, 4);
        assert_eq!(row_selection(&r, 0, sel), Some((14, 16)));
        assert_eq!(row_selection(&r, 1, sel), Some((0, 2)));
        assert_eq!(row_selection(&r, 2, sel), None);
        assert_eq!(row_selection(&r, 0, None), None);
        assert_eq!(ByteSelection::new(5, 0), None);
        // Selection reaching past the range end is cut at the last byte.
        let tail = ByteSelection::new(0x13e, 100);
        assert_eq!(row_selection(&r, 3, tail), Some((14, 16)));
    }

    #[test]
    fn offsets_and_rows() {
        let r = range(0x100, 0x25);
        assert_eq!(row_of_offset(&r, 0x100), Some(0));
        assert_eq!(row_of_offset(&r, 0x124), Some(2));
        assert_eq!(row_of_offset(&r, 0x125), None);
        assert_eq!(row_of_offset(&r, 0xff), None);
        assert_eq!(offset_at(&r, 1, 3), Some(0x113));
        assert_eq!(offset_at(&r, 2, 15), Some(0x124));
        assert_eq!(offset_at(&range(0, 0), 0, 0), None);
        assert_eq!(
            ByteSelection::between(0x113, 0x105),
            ByteSelection {
                start: 0x105,
                end: 0x114
            }
        );
        assert_eq!(
            clamp_selection(
                &r,
                ByteSelection {
                    start: 0,
                    end: 0x102
                }
            ),
            Some(ByteSelection {
                start: 0x100,
                end: 0x102
            })
        );
        assert_eq!(
            clamp_selection(
                &r,
                ByteSelection {
                    start: 0x200,
                    end: 0x202
                }
            ),
            None
        );
    }

    #[test]
    fn copy_text() {
        let data = b"Hello\x00World".to_vec();
        let sel = ByteSelection::new(3, 5).unwrap();
        assert_eq!(selection_as_hex(&data, sel).unwrap(), "6c 6f 00 57 6f");
        assert_eq!(selection_as_ascii(&data, sel).unwrap(), "lo.Wo");
        let huge = ByteSelection {
            start: 0,
            end: MAX_COPY_BYTES + 1,
        };
        assert!(selection_as_hex(&data, huge).is_err());
    }

    #[test]
    fn huge_range_needs_no_allocation_per_row() {
        // 8 GiB range over a tiny buffer: row math must not overflow or
        // allocate; rows beyond the data are simply empty.
        let r = BinaryRange {
            offset: 0,
            size: 8 << 30,
            start_value: 0x7fff_0000_0000,
        };
        assert_eq!(row_count(&r), (8u64 << 30) / 16);
        let data = [0u8; 64];
        assert_eq!(row_bytes(&data, &r, 3).len(), 16);
        assert!(row_bytes(&data, &r, row_count(&r) - 1).is_empty());
        assert_eq!(offset_label(&r, row_count(&r) - 1), "0x00008000fffffff0");
    }
}
