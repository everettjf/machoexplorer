//! Table pane logic: row filtering ("search"), copy/export text, column
//! widths and the row -> byte-range mapping. No UI types.

use crate::hex::ByteSelection;
use moex_core::{Row, Table};
use std::sync::atomic::{AtomicBool, Ordering};

/// Copy-all refuses more rows than this (same limit and wording as Qt).
pub const MAX_COPY_ROWS: usize = 20_000;

pub fn cell(row: &Row, col: usize) -> &str {
    row.cells.get(col).map(String::as_str).unwrap_or("")
}

/// Case-insensitive substring test. `needle_lower` must already be lowercase.
pub fn contains_ci(haystack: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.is_ascii() {
        let n = needle_lower.as_bytes();
        let h = haystack.as_bytes();
        if h.len() < n.len() {
            return false;
        }
        let first = n[0];
        (0..=h.len() - n.len()).any(|i| {
            h[i].to_ascii_lowercase() == first && h[i..i + n.len()].eq_ignore_ascii_case(n)
        })
    } else {
        haystack.to_lowercase().contains(needle_lower)
    }
}

pub fn row_matches(row: &Row, needle_lower: &str) -> bool {
    row.cells.iter().any(|c| contains_ci(c, needle_lower))
}

/// Indices of rows with any cell containing `needle` (case-insensitive).
/// Returns `None` if `cancel` was raised while scanning.
pub fn filter_rows(table: &Table, needle: &str, cancel: &AtomicBool) -> Option<Vec<u32>> {
    let needle = needle.to_lowercase();
    let mut out = Vec::new();
    for (i, row) in table.rows.iter().enumerate() {
        if i % 4096 == 0 && cancel.load(Ordering::Relaxed) {
            return None;
        }
        if row_matches(row, &needle) {
            out.push(i as u32);
        }
    }
    Some(out)
}

/// `"12 rows"` or `"3/12 filtered"`.
pub fn status_text(visible: usize, total: usize, filtered: bool) -> String {
    if filtered {
        format!("{visible}/{total} filtered")
    } else {
        format!("{total} rows")
    }
}

/// Byte range a row describes, when it has one in the file.
pub fn row_byte_range(row: &Row) -> Option<ByteSelection> {
    ByteSelection::new(row.offset?, row.size)
}

pub fn column_count(table: &Table) -> usize {
    table.headers.len()
}

/// Initial column widths: `Table.widths`, padded with a default for columns
/// that have none.
pub fn initial_widths(table: &Table) -> Vec<f32> {
    (0..column_count(table))
        .map(|i| {
            table
                .widths
                .get(i)
                .copied()
                .filter(|w| *w > 0)
                .unwrap_or(160) as f32
        })
        .collect()
}

/// Widths as drawn: the last column stretches to fill the viewport.
pub fn stretched_widths(widths: &[f32], viewport: f32) -> Vec<f32> {
    let mut out = widths.to_vec();
    if let Some((last, rest)) = out.split_last_mut() {
        let used: f32 = rest.iter().sum();
        *last = last.max(viewport - used);
    }
    out
}

pub const MIN_COLUMN_WIDTH: f32 = 40.0;

pub fn row_tsv(row: &Row, cols: usize) -> String {
    (0..cols)
        .map(|c| cell(row, c))
        .collect::<Vec<_>>()
        .join("\t")
}

fn visible_rows<'a>(
    table: &'a Table,
    visible: Option<&'a [u32]>,
) -> Box<dyn Iterator<Item = &'a Row> + 'a> {
    match visible {
        Some(ix) => Box::new(ix.iter().filter_map(|i| table.rows.get(*i as usize))),
        None => Box::new(table.rows.iter()),
    }
}

pub fn visible_count(table: &Table, visible: Option<&[u32]>) -> usize {
    visible.map(|v| v.len()).unwrap_or(table.rows.len())
}

/// Header line plus all visible rows, tab separated.
pub fn all_tsv(table: &Table, visible: Option<&[u32]>) -> Result<String, String> {
    let rows = visible_count(table, visible);
    let cols = column_count(table);
    if rows > MAX_COPY_ROWS {
        return Err(format!(
            "Too many rows to copy at once ({rows}). Please filter first."
        ));
    }
    let mut lines = Vec::with_capacity(rows + 1);
    lines.push(table.headers.join("\t"));
    lines.extend(visible_rows(table, visible).map(|r| row_tsv(r, cols)));
    Ok(lines.join("\n"))
}

fn csv_escape(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// CSV with every field quoted (same shape as the Qt export).
pub fn write_csv(
    table: &Table,
    visible: Option<&[u32]>,
    out: &mut dyn std::io::Write,
) -> std::io::Result<usize> {
    let cols = column_count(table);
    writeln!(
        out,
        "{}",
        table
            .headers
            .iter()
            .map(|h| csv_escape(h))
            .collect::<Vec<_>>()
            .join(",")
    )?;
    let mut n = 0;
    for row in visible_rows(table, visible) {
        writeln!(
            out,
            "{}",
            (0..cols)
                .map(|c| csv_escape(cell(row, c)))
                .collect::<Vec<_>>()
                .join(",")
        )?;
        n += 1;
    }
    Ok(n)
}

/// Text for the Information pane: `Header : value` per column, then the
/// length and (a prefix of) the bytes the row describes.
pub fn row_description(table: &Table, row_index: usize, file: &[u8]) -> String {
    let Some(row) = table.rows.get(row_index) else {
        return String::new();
    };
    let mut out = String::new();
    for (i, h) in table.headers.iter().enumerate() {
        out.push_str(&format!("{h} : {}\n", cell(row, i)));
    }
    if row.size > 0 {
        out.push_str(&format!("Length : {}\n", row.size));
        if let Some(off) = row.offset {
            const MAX: u64 = 256;
            let start = usize::try_from(off).unwrap_or(usize::MAX).min(file.len());
            let end = usize::try_from(off.saturating_add(row.size.min(MAX)))
                .unwrap_or(usize::MAX)
                .min(file.len());
            let mut hex = String::with_capacity((end - start) * 2);
            for b in &file[start..end] {
                hex.push_str(&format!("{b:02X}"));
            }
            if row.size > MAX {
                hex.push('…');
            }
            out.push_str(&format!("Data : {hex}\n"));
        }
    }
    out
}

/// The dyld-cache image list table (`Address | Path Offset | Path`): the
/// image path of `row` when double-clicking it should extract that image.
pub fn cache_image_path_for_row(table: &Table, row_index: usize) -> Option<String> {
    let h = &table.headers;
    if h.len() < 3 || h[0] != "Address" || h[1] != "Path Offset" || h[2] != "Path" {
        return None;
    }
    let path = cell(table.rows.get(row_index)?, 2).trim();
    if path.is_empty() || path.starts_with('(') {
        return None;
    }
    Some(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Table {
        let mut t = Table::new();
        t.set_widths(&[80, 200]);
        t.field(0x10, 4, "Magic Number", "MH_MAGIC_64");
        t.field(0x14, 4, "CPU Type", "X86_64");
        t.add(["", "note", "He said \"hi\""]);
        t.add_sized(8, ["", "decoded", "Ünïcode"]);
        t
    }

    #[test]
    fn filter_is_case_insensitive_over_all_columns() {
        let t = table();
        let none = AtomicBool::new(false);
        assert_eq!(filter_rows(&t, "magic", &none).unwrap(), vec![0]);
        assert_eq!(filter_rows(&t, "X86", &none).unwrap(), vec![1]);
        assert_eq!(filter_rows(&t, "0000001", &none).unwrap(), vec![0, 1]);
        assert_eq!(filter_rows(&t, "ünï", &none).unwrap(), vec![3]);
        assert_eq!(filter_rows(&t, "", &none).unwrap().len(), 4);
        assert!(filter_rows(&t, "zzz", &none).unwrap().is_empty());
        assert_eq!(filter_rows(&t, "a", &AtomicBool::new(true)), None);
    }

    #[test]
    fn status_and_ranges() {
        assert_eq!(status_text(4, 4, false), "4 rows");
        assert_eq!(status_text(1, 4, true), "1/4 filtered");
        let t = table();
        assert_eq!(row_byte_range(&t.rows[0]), ByteSelection::new(0x10, 4));
        assert_eq!(row_byte_range(&t.rows[2]), None);
        assert_eq!(row_byte_range(&t.rows[3]), None);
    }

    #[test]
    fn widths() {
        let t = table();
        assert_eq!(initial_widths(&t), vec![80.0, 200.0, 160.0]);
        assert_eq!(
            stretched_widths(&[80.0, 200.0, 160.0], 1000.0),
            vec![80.0, 200.0, 720.0]
        );
        assert_eq!(
            stretched_widths(&[80.0, 200.0, 160.0], 300.0),
            vec![80.0, 200.0, 160.0]
        );
        assert!(stretched_widths(&[], 300.0).is_empty());
    }

    #[test]
    fn copy_text() {
        let t = table();
        assert_eq!(row_tsv(&t.rows[1], 3), "00000014\tCPU Type\tX86_64");
        let all = all_tsv(&t, None).unwrap();
        assert!(
            all.starts_with("Offset\tDescription\tValue\n00000010\tMagic Number\tMH_MAGIC_64\n")
        );
        assert_eq!(all.lines().count(), 5);
        let some = all_tsv(&t, Some(&[1])).unwrap();
        assert_eq!(
            some,
            "Offset\tDescription\tValue\n00000014\tCPU Type\tX86_64"
        );
        let mut big = Table::new();
        for i in 0..=MAX_COPY_ROWS {
            big.add([i.to_string()]);
        }
        assert_eq!(
            all_tsv(&big, None).unwrap_err(),
            "Too many rows to copy at once (20001). Please filter first."
        );
        assert!(all_tsv(&big, Some(&[0, 1])).is_ok());
    }

    #[test]
    fn csv_quotes_everything() {
        let t = table();
        let mut out = Vec::new();
        assert_eq!(write_csv(&t, Some(&[2]), &mut out).unwrap(), 1);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\"Offset\",\"Description\",\"Value\"\n\"\",\"note\",\"He said \"\"hi\"\"\"\n"
        );
    }

    #[test]
    fn description_lists_columns_and_bytes() {
        let t = table();
        let file: Vec<u8> = (0u8..64).collect();
        assert_eq!(
            row_description(&t, 0, &file),
            "Offset : 00000010\nDescription : Magic Number\nValue : MH_MAGIC_64\nLength : 4\nData : 10111213\n"
        );
        assert_eq!(
            row_description(&t, 2, &file),
            "Offset : \nDescription : note\nValue : He said \"hi\"\n"
        );
        assert!(row_description(&t, 3, &file).ends_with("Length : 8\n"));
        assert_eq!(row_description(&t, 99, &file), "");
    }

    #[test]
    fn cache_image_rows() {
        let mut t = Table::new();
        t.set_headers(&["Address", "Path Offset", "Path"]);
        t.add(["0x1", "0x2", " /usr/lib/libSystem.B.dylib "]);
        t.add(["0x1", "0x2", "(unknown)"]);
        assert_eq!(
            cache_image_path_for_row(&t, 0).as_deref(),
            Some("/usr/lib/libSystem.B.dylib")
        );
        assert_eq!(cache_image_path_for_row(&t, 1), None);
        assert_eq!(cache_image_path_for_row(&table(), 0), None);
    }
}
