//! "String Table" node: the NUL-terminated strings of the `LC_SYMTAB`
//! string table.

use crate::hex::{as_hex_string, as_string, utf8_safe};
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("String Table", move || content(&mh)))
}

/// `(offset within data, bytes)` of every non-empty string that is
/// NUL-terminated inside `data`. An unterminated tail is dropped.
pub fn string_literals(data: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &c) in data.iter().enumerate() {
        if c == 0 {
            if let Some(s) = data.get(start..i).filter(|s| !s.is_empty()) {
                out.push((start as u64, s));
            }
            start = i + 1;
        }
    }
    out
}

fn content(mh: &MachHeader) -> Content {
    let mut t = Table::new();
    t.set_headers(&["Index", "Offset", "Length", "String"]);
    t.set_widths(&[80, 100, 80, 400]);
    let Some(symtab) = mh.symtab() else {
        return Content::table(t);
    };

    let offset = symtab.string_table_offset();
    let size = symtab.string_table_size_in_file();
    let data = mh.image.slice(offset, size).unwrap_or(&[]);
    for (index, (at, s)) in string_literals(data).into_iter().enumerate() {
        t.add([
            as_string(index),
            as_hex_string(offset + at),
            as_string(s.len()),
            utf8_safe(s),
        ]);
    }

    Content::table(t).with_binary(offset, size)
}

#[cfg(test)]
mod tests {
    use super::string_literals;

    #[test]
    fn literals() {
        let got = string_literals(b"\0\0ab\0c\0\0tail");
        assert_eq!(got, [(2, &b"ab"[..]), (5, &b"c"[..])]);
        assert!(string_literals(b"").is_empty());
        assert!(string_literals(b"abc").is_empty());
    }
}
