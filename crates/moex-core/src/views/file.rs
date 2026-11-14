use super::{fat::fat_node, mach_header::mach_header_node};
use crate::macho::{Binary, Kind};
use crate::view::{Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

struct FileNode(Arc<Binary>);

pub fn file_node(binary: Arc<Binary>) -> ViewNode {
    ViewNode::new(FileNode(binary))
}

impl NodeSource for FileNode {
    fn name(&self) -> String {
        "File".into()
    }

    fn content(&self) -> Content {
        let mut t = Table::new();
        t.set_headers(&["Information"]);
        t.set_widths(&[300]);
        t.add([match self.0.kind {
            Kind::Archive(_) => "It is an archive file (.a)",
            Kind::DyldSharedCache(_) => "It is a dyld shared cache file",
            Kind::Fat(_) => "It is a fat file",
            Kind::MachO(_) => "It is not a fat file",
        }]);
        Content::table(t)
    }

    fn children(&self) -> Vec<ViewNode> {
        match &self.0.kind {
            Kind::MachO(mh) => vec![mach_header_node(mh.clone())],
            Kind::Fat(fat) => vec![fat_node(fat.clone())],
            Kind::Archive(archive) => vec![super::archive::node(archive.clone())],
            Kind::DyldSharedCache(cache) => vec![super::dyld_cache::node(cache.clone())],
        }
    }
}
