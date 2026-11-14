//! "Function Starts" node: the ULEB128 address deltas of
//! `LC_FUNCTION_STARTS`.

use crate::consts::LC_FUNCTION_STARTS;
use crate::hex::{as_address, as_short_hex_string};
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Function Starts", move || content(&mh)))
}

fn content(mh: &MachHeader) -> Content {
    let Some(data) = mh.linkedit_data(LC_FUNCTION_STARTS) else {
        return Content::default();
    };
    let mut t = Table::new();
    let mut address = mh.base_address();
    for f in mh.function_starts() {
        // Every value is a delta from the previous one.
        // QUIRK(parity): the list is not cut at its zero terminator, so the
        // padding bytes after it show up as rows repeating the last address.
        address = address.wrapping_add(f.data);
        t.add_data(
            f.offset,
            f.occupy_size as u64,
            [
                as_address(f.offset),
                "uleb128".to_string(),
                as_short_hex_string(address),
            ],
        );
    }
    Content::table(t).with_binary(data.file_offset, data.datasize as u64)
}
