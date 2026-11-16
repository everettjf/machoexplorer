use crate::hex::{as_hex_string, as_string};
use crate::macho::MachHeader;
use crate::names;
use crate::view::{Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

struct MachHeaderNode(Arc<MachHeader>);

pub fn mach_header_node(mh: Arc<MachHeader>) -> ViewNode {
    ViewNode::new(MachHeaderNode(mh))
}

impl NodeSource for MachHeaderNode {
    fn name(&self) -> String {
        format!("Mach Header ({})", self.0.arch())
    }

    fn content(&self) -> Content {
        let d = &self.0;
        let o = d.offset;
        let mut t = Table::new();
        t.field(o, 4, "Magic Number", names::magic(d.magic));
        t.field(o + 4, 4, "CPU Type", names::cpu_type(d.cputype));
        t.field(o + 8, 4, "CPU SubType", "");
        for (value, name) in names::cpu_subtype_array(d.cputype, d.cpusubtype) {
            t.add(["".to_string(), as_hex_string(value as u64), name]);
        }
        t.field(o + 12, 4, "File Type", names::file_type(d.filetype));
        t.field(o + 16, 4, "Number of Load Commands", as_string(d.ncmds));
        t.field(o + 20, 4, "Size of Load Commands", as_string(d.sizeofcmds));
        t.field(o + 24, 4, "Flags", "");
        for (value, name) in names::mach_flags(d.flags) {
            t.add([
                "".to_string(),
                as_hex_string(value as u64),
                name.to_string(),
            ]);
        }
        if d.is64 {
            t.field(o + 28, 4, "Reserved", as_string(d.reserved));
        }
        Content::table(t).with_binary(o, d.header_size())
    }

    fn children(&self) -> Vec<ViewNode> {
        use super::*;
        use crate::consts::*;
        let mh = &self.0;
        // Order is part of the output format.
        let mut nodes = vec![Some(load_commands::load_commands_node(mh.clone()))];
        nodes.push(integrity::node(mh.clone()));
        nodes.push(sections::node(mh.clone()));
        nodes.push(dyld_info::node(mh.clone()));
        nodes.push(symbol_table::node(mh.clone()));
        nodes.push(xref::node(mh.clone()));
        nodes.push(swift_graph::node(mh.clone()));
        nodes.push(dysymtab::node(mh.clone()));
        nodes.push(string_table::node(mh.clone()));
        nodes.push(code_signature::node(mh.clone()));
        if mh.has_load_command(&[LC_FUNCTION_STARTS]) {
            nodes.push(function_starts::node(mh.clone()));
        }
        if mh.has_load_command(&[LC_DATA_IN_CODE]) {
            nodes.push(data_in_code::node(mh.clone()));
        }
        if mh.has_load_command(&[LC_TWOLEVEL_HINTS]) {
            nodes.push(twolevel_hints::node(mh.clone()));
        }
        if mh.has_load_command(&[LC_SEGMENT_SPLIT_INFO]) {
            nodes.push(split_info::node(mh.clone()));
        }
        nodes.into_iter().flatten().collect()
    }
}
