//! "Sections" node: one child per section, in load-command order.

use super::section::section_node;
use crate::macho::MachHeader;
use crate::view::{Content, FnNode, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    let (for_content, for_children) = (mh.clone(), mh);
    Some(ViewNode::new(FnNode {
        name: "Sections".to_string(),
        content: move || {
            let mut t = Table::new();
            t.set_headers(&["Information"]);
            t.set_widths(&[300]);
            t.add([format!(
                "Number of sections : {}",
                for_content.sections().count()
            )]);
            Content::table(t)
        },
        children: move || {
            (0..for_children.sections().count())
                .filter_map(|i| section_node(for_children.clone(), i))
                .collect()
        },
    }))
}
