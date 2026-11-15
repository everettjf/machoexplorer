//! "Symbol Table" node: every `nlist` entry of `LC_SYMTAB`.

use crate::hex::as_short_hex_string;
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Symbol Table", move || content(&mh)))
}

/// True when `name` looks like an Itanium-mangled C++ symbol (`_Z...`,
/// after dropping the extra leading underscore Mach-O symbols carry).
pub fn is_cxx_mangled(name: &[u8]) -> bool {
    let m = if name.len() > 1 && name[0] == b'_' {
        &name[1..]
    } else {
        name
    };
    m.starts_with(b"_Z")
}

/// Demangled C++ name of `name`, or `None` when it is not a mangled C++
/// symbol or cannot be demangled.
fn demangle_cxx(name: &[u8]) -> Option<String> {
    if !is_cxx_mangled(name) {
        return None;
    }
    // Drop the extra leading underscore Mach-O symbols carry.
    crate::demangle::demangle_itanium(&name[1..])
}

fn content(mh: &MachHeader) -> Content {
    let mut t = Table::new();
    let Some(symtab) = mh.symtab() else {
        return Content::table(t);
    };

    for sym in symtab.symbols() {
        let o = sym.offset;
        let name = symtab.string_bytes(sym.n_strx);
        t.field(o, 4, "String Table Index", crate::hex::utf8_safe(name));
        if let Some(demangled) = demangle_cxx(name) {
            t.field(o, 4, "Demangled", demangled);
        }
        t.field(o + 4, 1, "Type", as_short_hex_string(sym.n_type as u64));
        t.field(
            o + 5,
            1,
            "Section Index",
            as_short_hex_string(sym.n_sect as u64),
        );
        t.field(
            o + 6,
            2,
            "Description",
            as_short_hex_string(sym.n_desc as u64),
        );
        t.field(
            o + 8,
            sym.value_size(),
            "Value",
            as_short_hex_string(sym.n_value),
        );
        t.separator();
    }

    Content::table(t).with_binary(
        symtab.symbol_table_offset(),
        symtab.symbol_table_total_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert!(is_cxx_mangled(b"__Z3fooi"));
        // Exactly one leading underscore is dropped, mangled or not.
        assert!(!is_cxx_mangled(b"_Z3fooi"));
        assert!(!is_cxx_mangled(b"_Z"));
        assert!(!is_cxx_mangled(b"_main"));
        assert!(!is_cxx_mangled(b"_"));
        assert!(!is_cxx_mangled(b""));
    }
}
