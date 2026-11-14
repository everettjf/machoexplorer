//! "Dyld Shared Cache" node with its "Mappings" and "Images" children.

use crate::hex::{as_address, as_short_hex_string, as_string, utf8_safe};
use crate::macho::dyld_cache::*;
use crate::view::{leaf, Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

/// The Images table stops after this many entries.
const MAX_IMAGE_ROWS: usize = 5000;

struct CacheNode(Arc<DyldSharedCache>);

pub fn node(cache: Arc<DyldSharedCache>) -> ViewNode {
    ViewNode::new(CacheNode(cache))
}

impl NodeSource for CacheNode {
    fn name(&self) -> String {
        "Dyld Shared Cache".into()
    }

    fn content(&self) -> Content {
        let h = &self.0.header;
        let mut t = Table::new();
        // QUIRK(parity): there is no "Magic" row (the C++ `AddRow` call
        // resolved to an empty template overload), and the Offset column of
        // every row is 00000000 because the table had no address resolver.
        // The rows still carry the real field offsets for the hex pane.
        let mut field = |offset: u64, size: u64, desc: &str, value: String| {
            t.add_data(offset, size, [as_address(0), desc.to_string(), value]);
        };
        field(
            OFF_MAPPING_OFFSET,
            4,
            "Mapping Offset",
            as_short_hex_string(h.mapping_offset as u64),
        );
        field(
            OFF_MAPPING_COUNT,
            4,
            "Mapping Count",
            as_string(h.mapping_count),
        );
        field(
            OFF_IMAGES_OFFSET,
            4,
            "Images Offset",
            as_short_hex_string(h.images_offset as u64),
        );
        field(
            OFF_IMAGES_COUNT,
            4,
            "Images Count",
            as_string(h.images_count),
        );
        field(
            OFF_DYLD_BASE_ADDRESS,
            8,
            "Dyld Base Address",
            as_short_hex_string(h.dyld_base_address),
        );
        field(
            OFF_LOCAL_SYMBOLS_OFFSET,
            8,
            "Local Symbols Offset",
            as_short_hex_string(h.local_symbols_offset),
        );
        field(
            OFF_LOCAL_SYMBOLS_SIZE,
            8,
            "Local Symbols Size",
            as_short_hex_string(h.local_symbols_size),
        );
        field(
            OFF_CODE_SIGNATURE_OFFSET,
            8,
            "Code Signature Offset",
            as_short_hex_string(h.code_signature_offset),
        );
        field(
            OFF_CODE_SIGNATURE_SIZE,
            8,
            "Code Signature Size",
            as_short_hex_string(h.code_signature_size),
        );
        Content::table(t).with_binary(0, self.0.image.len())
    }

    fn children(&self) -> Vec<ViewNode> {
        let cache = self.0.clone();
        let mappings = leaf("Mappings", move || {
            let mut t = Table::new();
            t.set_headers(&["Address", "Size", "File Offset", "MaxProt", "InitProt"]);
            t.set_widths(&[180, 180, 180, 120, 120]);
            for m in &cache.mappings {
                t.add([
                    as_address(m.address),
                    as_address(m.size),
                    as_address(m.file_offset),
                    as_short_hex_string(m.max_prot as u64),
                    as_short_hex_string(m.init_prot as u64),
                ]);
            }
            Content::table(t)
        });

        let cache = self.0.clone();
        let images = leaf("Images", move || {
            let mut t = Table::new();
            t.set_headers(&["Address", "Path Offset", "Path"]);
            t.set_widths(&[180, 180, 620]);
            let from_header = cache.header.images_count > 0;
            let rows: Box<dyn Iterator<Item = [String; 3]> + '_> = if from_header {
                Box::new(cache.image_infos().map(|img| {
                    [
                        as_address(img.address),
                        as_address(img.path_file_offset as u64),
                        utf8_safe(cache.read_path_by_offset(img.path_file_offset)),
                    ]
                }))
            } else {
                Box::new(
                    cache
                        .map_images
                        .iter()
                        .map(|img| [as_address(img.address), "-".to_string(), img.path_str()]),
                )
            };
            for (idx, row) in rows.enumerate() {
                t.add(row);
                if idx + 1 >= MAX_IMAGE_ROWS {
                    t.add(["-", "-", "(truncated at 5000 entries)"]);
                    break;
                }
            }
            Content::table(t)
        });
        vec![mappings, images]
    }
}
