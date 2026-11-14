//! "Data in Code Entries" node: the `data_in_code_entry` list of
//! `LC_DATA_IN_CODE`.

use crate::consts::LC_DATA_IN_CODE;
use crate::hex::as_short_hex_string;
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Data in Code Entries", move || content(&mh)))
}

fn content(mh: &MachHeader) -> Content {
    let Some(data) = mh.linkedit_data(LC_DATA_IN_CODE) else {
        return Content::default();
    };
    let mut t = Table::new();
    for dice in mh.data_in_code() {
        let o = dice.file_offset;
        t.field(o, 4, "Offset", as_short_hex_string(dice.offset as u64));
        t.field(o + 4, 2, "Length", as_short_hex_string(dice.length as u64));
        t.field(o + 6, 2, "Kind", dice.kind_name());
        t.separator();
    }
    // QUIRK(parity): the address label is relative to the Mach-O header
    // (i.e. `dataoff`), not to the start of the file.
    Content::table(t).with_binary_at(data.file_offset, data.datasize as u64, data.dataoff as u64)
}
