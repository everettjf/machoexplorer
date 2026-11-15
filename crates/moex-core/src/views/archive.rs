//! "Archive" node: the member list of a `.a` file, with one Mach Header
//! subtree per Mach-O member.

use super::mach_header::mach_header_node;
use crate::hex::{as_short_hex_string, as_string, utf8_safe};
use crate::macho::Archive;
use crate::view::{Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

struct ArchiveNode(Arc<Archive>);

pub fn node(archive: Arc<Archive>) -> ViewNode {
    ViewNode::new(ArchiveNode(archive))
}

impl NodeSource for ArchiveNode {
    fn name(&self) -> String {
        "Archive".into()
    }

    fn content(&self) -> Content {
        let mut t = Table::new();
        t.set_headers(&["Offset", "Name", "Type", "Size"]);
        t.set_widths(&[120, 320, 120, 120]);
        for m in &self.0.members {
            t.add_data(
                m.data_offset,
                m.data_size,
                [
                    as_short_hex_string(m.data_offset),
                    utf8_safe(&m.name),
                    m.type_name().to_string(),
                    as_string(m.data_size),
                ],
            );
        }
        Content::table(t).with_binary(0, self.0.image.len())
    }

    fn children(&self) -> Vec<ViewNode> {
        self.0.headers().into_iter().map(mach_header_node).collect()
    }
}
