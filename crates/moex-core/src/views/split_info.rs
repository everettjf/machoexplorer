//! Segment split info node: the raw blob of `LC_SEGMENT_SPLIT_INFO`.

use crate::consts::LC_SEGMENT_SPLIT_INFO;
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Segment Split Info", move || {
        // The table is created but never filled.
        let content = Content::table(Table::new());
        match mh.linkedit_data(LC_SEGMENT_SPLIT_INFO) {
            Some(d) => content.with_binary(d.file_offset, d.datasize as u64),
            None => content,
        }
    }))
}
