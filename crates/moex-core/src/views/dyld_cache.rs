//! "Dyld Shared Cache" node with its "Mappings" and "Images" children.

use crate::hex::{as_address, as_short_hex_string, as_string, format_uuid, utf8_safe};
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
        let mut field = |offset: u64, size: u64, desc: &str, value: String| {
            t.field(offset, size, desc, value);
        };
        field(0, 16, "Magic", h.magic_str());
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
            h.images_field_offset,
            4,
            "Images Offset",
            as_short_hex_string(h.images_offset as u64),
        );
        field(
            h.images_field_offset + 4,
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
        field(OFF_UUID, 16, "UUID", format_uuid(&h.uuid).to_uppercase());
        field(OFF_CACHE_TYPE, 8, "Cache Type", as_string(h.cache_type));
        if h.sub_cache_array_count > 0 {
            field(
                OFF_SUBCACHE_ARRAY_OFFSET,
                4,
                "Sub Cache Array Offset",
                as_short_hex_string(h.sub_cache_array_offset as u64),
            );
            field(
                OFF_SUBCACHE_ARRAY_COUNT,
                4,
                "Sub Cache Array Count",
                as_string(h.sub_cache_array_count),
            );
        }
        Content::table(t).with_binary(0, self.0.image.len())
    }

    fn children(&self) -> Vec<ViewNode> {
        let cache = self.0.clone();
        let mappings = leaf("Mappings", move || {
            let mut t = Table::new();
            t.set_headers(&["Address", "Size", "File Offset", "MaxProt", "InitProt"]);
            t.set_widths(&[180, 180, 180, 120, 120]);
            let table_offset = cache.header.mapping_offset as u64;
            for (i, m) in cache.mappings.iter().enumerate() {
                t.add_data(
                    table_offset + i as u64 * MAPPING_INFO_SIZE,
                    MAPPING_INFO_SIZE,
                    [
                        as_address(m.address),
                        as_address(m.size),
                        as_address(m.file_offset),
                        as_short_hex_string(m.max_prot as u64),
                        as_short_hex_string(m.init_prot as u64),
                    ],
                );
            }
            Content::table(t).with_binary(
                table_offset,
                cache.mappings.len() as u64 * MAPPING_INFO_SIZE,
            )
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
        let mut nodes = vec![mappings, images];
        if !self.0.subcaches.is_empty() {
            let cache = self.0.clone();
            nodes.push(leaf("Sub Caches", move || {
                let mut t = Table::new();
                t.set_headers(&["Offset", "File Suffix", "VM Offset", "UUID", "File"]);
                t.set_widths(&[100, 160, 140, 320, 120]);
                for s in &cache.subcaches {
                    t.add_data(
                        s.entry_offset,
                        s.entry_size,
                        [
                            as_address(s.entry_offset),
                            s.suffix.clone(),
                            as_short_hex_string(s.vm_offset),
                            format_uuid(&s.uuid).to_uppercase(),
                            (if s.file.is_some() {
                                "found"
                            } else {
                                "not found"
                            })
                            .to_string(),
                        ],
                    );
                }
                let size: u64 = cache.subcaches.iter().map(|s| s.entry_size).sum();
                Content::table(t).with_binary(cache.header.sub_cache_array_offset as u64, size)
            }));
        }
        nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::dyld_cache::testutil::{modern_cache, parse};

    fn cells(node: &ViewNode) -> Vec<Vec<String>> {
        let table = node.table().unwrap();
        table.rows.iter().map(|r| r.cells.clone()).collect()
    }

    #[test]
    fn header_rows_have_the_magic_and_real_offsets() {
        let cache = parse(modern_cache(0x1_8000_0000, 7, &[(2, 0x4000, ".01")])).unwrap();
        let root = node(Arc::new(cache));
        let rows = cells(&root);
        assert_eq!(rows[0], ["00000000", "Magic", "dyld_v1  arm64e"]);
        assert_eq!(rows[1], ["00000010", "Mapping Offset", "1D0"]);
        // The image list comes from the modern header fields.
        assert_eq!(rows[3], ["000001C0", "Images Offset", "1F0"]);
        assert_eq!(rows[4], ["000001C4", "Images Count", "1"]);
        assert!(rows.contains(&vec![
            "00000058".to_string(),
            "UUID".to_string(),
            "07070707-0707-0707-0707-070707070707".to_string()
        ]));
        assert_eq!(
            rows.last().unwrap(),
            &["0000018C", "Sub Cache Array Count", "1"]
        );
        let table = root.table().unwrap();
        assert_eq!((table.rows[0].offset, table.rows[0].size), (Some(0), 16));

        let names: Vec<&str> = root.children().iter().map(|c| c.name()).collect();
        assert_eq!(names, ["Mappings", "Images", "Sub Caches"]);
        let subs = cells(&root.children()[2]);
        assert_eq!(
            subs[0],
            [
                "00000229",
                ".01",
                "4000",
                "02020202-0202-0202-0202-020202020202",
                "not found"
            ]
        );
    }
}
