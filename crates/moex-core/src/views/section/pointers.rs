//! Pointer sections: literal pointers, module init/term function pointers,
//! lazy / non-lazy symbol pointers and symbol stubs.

use super::{chunks, pointer_offsets, pointer_text, SectionContext};
use crate::hex::{as_address, as_hex_data, as_short_hex_string, utf8_safe};
use crate::macho::ptr::{Pointer, PointerDecoder};
use crate::macho::{MachHeader, Section};
use crate::view::Table;

fn pointer_size(section: &Section) -> u64 {
    if section.is64 {
        8
    } else {
        4
    }
}

/// Display text of the pointer at file offset `offset`. A slot the weak
/// bind stream names is followed by `(weak <symbol>)`: dyld points it at
/// the definition of that symbol that wins across all images, which is the
/// address shown unless another image overrides it.
fn target_text(decoder: &PointerDecoder<'_>, offset: u64, pointer: Pointer<'_>) -> String {
    let mut text = pointer_text(pointer);
    if let (Pointer::Address(_), Some(name)) = (pointer, decoder.weak_symbol(offset)) {
        text.push_str(&format!(" (weak {})", utf8_safe(name)));
    }
    text
}

/// "Literal Pointers" / "Module Init Func Pointers" / "Module Term Func
/// Pointers": `<file offset of the entry>-><target>` for each pointer. The
/// target is decoded (chained fixups, authenticated pointers): an address
/// in this image, or the name of an imported symbol.
pub(super) fn pointers(context: &SectionContext, section: &Section) -> Table {
    let mut t = Table::new();
    let size = pointer_size(section);
    let decoder = context.pointers();
    for offset in pointer_offsets(section) {
        let Some(pointer) = decoder.read(offset, section.is64) else {
            break;
        };
        let text = format!(
            "{}->{}",
            as_short_hex_string(offset),
            target_text(&decoder, offset, pointer)
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
/// Symbol Pointers": the decoded target of each pointer (an address, or
/// the imported symbol a bind names).
pub(super) fn indirect_pointers(context: &SectionContext, section: &Section) -> Table {
    let mut t = Table::new();
    let size = pointer_size(section);
    let decoder = context.pointers();
    for offset in pointer_offsets(section) {
        let Some(pointer) = decoder.read(offset, section.is64) else {
            break;
        };
        t.add_data(
            offset,
            size,
            [
                as_address(offset),
                "Indirect Pointer".to_string(),
                target_text(&decoder, offset, pointer),
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
