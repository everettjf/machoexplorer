//! "Two Level Hints Table" node: the raw hint table of `LC_TWOLEVEL_HINTS`.

use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Two Level Hints Table", move || {
        // The table is created but never filled.
        let content = Content::table(Table::new());
        match mh.twolevel_hints() {
            Some(h) => content.with_binary(h.file_offset, h.nhints as u64 * 4),
            None => content,
        }
    }))
}
