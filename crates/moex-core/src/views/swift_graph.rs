//! "Swift Semantic Graph" node: every `__swift5_*` section decoded into
//! entities (descriptors, records, strings) followed by the reference edges
//! between them.

use crate::hex::{as_address, as_short_hex_string, utf8_safe};
use crate::macho::disasm::{Duplicates, SymbolLookup};
use crate::macho::swift::{
    self, field_descriptor_kind_name, read_printable_cstring, FieldDescriptorHeader, FieldRecord,
};
use crate::macho::vmaddr::{relative_target, SegmentSet, VmReader};
use crate::macho::{MachHeader, Section};
use crate::view::{leaf, Content, Table, ViewNode};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Swift Semantic Graph", move || {
        Content::table(table(&mh))
    }))
}

fn table(mh: &MachHeader) -> Table {
    // First pass: find out which strings need demangling and resolve them
    // together. Demangled text never influences what is read, so the second
    // pass sees the same strings.
    let mut wanted: Vec<Vec<u8>> = Vec::new();
    build(mh, &mut |text| {
        wanted.extend(swift::shell_single_quoted_word(text.as_bytes()));
        String::new()
    });
    swift::prefetch_demangled(&wanted);
    build(mh, &mut |text| {
        swift::demangle_external_shell_quoted(text.as_bytes())
    })
}

// QUIRK(parity): unlike the per-section "Swift Metadata" view, kind 4
// (opaque type) has no name here.
fn context_kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "module",
        1 => "extension",
        2 => "anonymous",
        3 => "protocol",
        16 => "class",
        17 => "struct",
        18 => "enum",
        _ => "unknown",
    }
}

fn section_relation_name(sectname: &str) -> &'static str {
    match sectname {
        "__swift5_types" => "context-ref",
        "__swift5_protos" => "protocol-ref",
        "__swift5_typeref" => "type-string-ref",
        "__swift5_assocty" => "associated-type-ref",
        "__swift5_capture" => "capture-type-ref",
        _ => "rel32-ref",
    }
}

struct Edge {
    from: u64,
    to: u64,
    /// Index into `Graph::labels`.
    label: usize,
    relation: &'static str,
}

#[derive(Default)]
struct Graph {
    /// Display name of the entity at an address; later writes replace
    /// earlier ones.
    entity_names: HashMap<u64, String>,
    labels: Vec<String>,
    edges: Vec<Edge>,
    seen: HashSet<(usize, u64, u64, &'static str)>,
}

impl Graph {
    /// Sections sharing a `segment/section` label share edges.
    fn label_id(&mut self, label: &str) -> usize {
        match self.labels.iter().position(|l| l == label) {
            Some(id) => id,
            None => {
                self.labels.push(label.to_string());
                self.labels.len() - 1
            }
        }
    }

    fn add_edge(&mut self, label: usize, from: u64, to: u64, relation: &'static str) {
        if to != 0 && self.seen.insert((label, from, to, relation)) {
            self.edges.push(Edge {
                from,
                to,
                label,
                relation,
            });
        }
    }
}

/// The `__swift5_*` sections: those of 32-bit segments first, then of
/// 64-bit ones, ordered by segment and section name.
fn swift_sections(mh: &MachHeader) -> Vec<&Section> {
    let of = |is64: bool| {
        mh.sections()
            .filter(move |s| s.is64 == is64 && s.sectname.starts_with("__swift5_"))
    };
    let mut sections: Vec<&Section> = of(false).chain(of(true)).collect();
    sections.sort_by(|a, b| (&a.segname, &a.sectname).cmp(&(&b.segname, &b.sectname)));
    sections
}

fn build(mh: &MachHeader, demangle: &mut dyn FnMut(&str) -> String) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Kind", "Name", "Section", "Address", "Details"]);
    t.set_widths(&[170, 280, 180, 180, 500]);

    let symbols = SymbolLookup::from_symtab(mh, Duplicates::FirstOnly);
    let reader = VmReader::new(mh, SegmentSet::Any);
    let mut g = Graph::default();

    for sec in swift_sections(mh) {
        let label = format!("{}/{}", sec.segname, sec.sectname);
        let label_id = g.label_id(&label);
        t.add([
            "section".to_string(),
            label.clone(),
            label.clone(),
            as_address(sec.addr),
            format!("size={}", sec.data_size),
        ]);
        match sec.sectname.as_str() {
            "__swift5_reflstr" => reflection_strings(&mut t, &mut g, mh, sec, &label),
            "__swift5_fieldmd" => {
                field_metadata(&mut t, &mut g, &reader, sec, &label, label_id, demangle)
            }
            _ => relative_pointers(
                &mut t, &mut g, &reader, &symbols, sec, &label, label_id, demangle,
            ),
        }
    }

    t.separator();
    if g.edges.is_empty() {
        t.add(["-", "No Swift metadata edges found", "-", "-", "-"]);
        return t;
    }
    t.add([
        "edge".to_string(),
        "Swift Metadata Relations".to_string(),
        "-".to_string(),
        "-".to_string(),
        format!("count={}", g.edges.len()),
    ]);
    let name_of = |address: u64| {
        g.entity_names
            .get(&address)
            .cloned()
            .unwrap_or_else(|| as_address(address))
    };
    for (index, e) in g.edges.iter().enumerate() {
        t.add([
            "edge".to_string(),
            format!("#{index}"),
            g.labels.get(e.label).cloned().unwrap_or_default(),
            as_address(e.from),
            format!("[{}] {} -> {}", e.relation, name_of(e.from), name_of(e.to)),
        ]);
    }
    t
}

fn reflection_strings(t: &mut Table, g: &mut Graph, mh: &MachHeader, sec: &Section, label: &str) {
    for (index, (at, s)) in swift::reflection_strings(sec.data(&mh.image))
        .into_iter()
        .enumerate()
    {
        let vmaddr = sec.addr.wrapping_add(at as u64);
        let text = utf8_safe(s);
        g.entity_names.insert(vmaddr, text.clone());
        t.add_data(
            sec.data_offset + at as u64,
            s.len() as u64 + 1,
            [
                "reflstr".to_string(),
                format!("#{index}"),
                label.to_string(),
                as_address(vmaddr),
                text,
            ],
        );
    }
}

fn field_metadata(
    t: &mut Table,
    g: &mut Graph,
    reader: &VmReader<'_>,
    sec: &Section,
    label: &str,
    label_id: usize,
    demangle: &mut dyn FnMut(&str) -> String,
) {
    let image = &reader.mh.image;
    let size = sec.data_size as u64;
    let header = FieldDescriptorHeader::SIZE;
    let mut cursor: u32 = 0;
    let mut descriptor_index = 0usize;
    while cursor as u64 + header <= size {
        let offset = sec.data_offset + cursor as u64;
        let Some(fd) = FieldDescriptorHeader::read(image, offset) else {
            break;
        };
        let vmaddr = sec.addr.wrapping_add(cursor as u64);
        g.entity_names
            .insert(vmaddr, format!("fieldmd#{descriptor_index}"));
        descriptor_index += 1;
        t.add_data(
            offset,
            header,
            [
                "fieldmd".to_string(),
                "descriptor".to_string(),
                label.to_string(),
                as_address(vmaddr),
                format!(
                    "kind={} ({}) fields={} record={}",
                    fd.kind,
                    field_descriptor_kind_name(fd.kind),
                    fd.num_fields,
                    fd.field_record_size
                ),
            ],
        );

        for (field_vmaddr, rel, relation) in [
            (vmaddr, fd.mangled_type_name, "descriptor-type"),
            (
                vmaddr.wrapping_add(4),
                fd.superclass,
                "descriptor-superclass",
            ),
        ] {
            if rel == 0 {
                continue;
            }
            let target = relative_target(field_vmaddr, rel);
            let text = read_printable_cstring(reader, target, 256);
            if !text.is_empty() {
                let demangled = demangle(&text);
                g.entity_names.insert(
                    target,
                    if demangled.is_empty() {
                        text
                    } else {
                        demangled
                    },
                );
            }
            g.add_edge(label_id, vmaddr, target, relation);
        }

        if !fd.is_plausible() {
            break;
        }
        let record_size = fd.field_record_size as u64;
        for fi in 0..fd.num_fields as u64 {
            let record_start = cursor as u64 + header + fi * record_size;
            if record_start + record_size > size {
                break;
            }
            let record_offset = sec.data_offset + record_start;
            let Some(fr) = FieldRecord::read(image, record_offset) else {
                break;
            };
            let record_vmaddr = vmaddr.wrapping_add(header + fi * record_size);
            let type_vmaddr = relative_target(record_vmaddr.wrapping_add(4), fr.mangled_type_name);
            let name_vmaddr = relative_target(record_vmaddr.wrapping_add(8), fr.field_name);
            let field_name = read_printable_cstring(reader, name_vmaddr, 128);
            let mut type_name = read_printable_cstring(reader, type_vmaddr, 256);
            if !type_name.is_empty() {
                let demangled = demangle(&type_name);
                if !demangled.is_empty() {
                    type_name = demangled;
                }
            }
            if !field_name.is_empty() {
                g.entity_names.insert(name_vmaddr, field_name.clone());
            }
            if !type_name.is_empty() {
                g.entity_names.insert(type_vmaddr, type_name.clone());
            }
            t.add_data(
                record_offset,
                FieldRecord::SIZE,
                [
                    "field-record".to_string(),
                    if field_name.is_empty() {
                        format!("#{fi}")
                    } else {
                        field_name
                    },
                    label.to_string(),
                    as_address(record_vmaddr),
                    format!(
                        "flags=0x{} type={}",
                        as_short_hex_string(fr.flags as u64),
                        if type_name.is_empty() {
                            "-"
                        } else {
                            &type_name
                        }
                    ),
                ],
            );
            if fr.field_name != 0 {
                g.add_edge(label_id, vmaddr, name_vmaddr, "field-name");
            }
            if fr.mangled_type_name != 0 {
                g.add_edge(label_id, vmaddr, type_vmaddr, "field-type");
            }
        }
        // QUIRK(parity): the cursor skips the declared record table even
        // when it runs past the section; the product and the cursor are
        // 32-bit like the original's.
        let advance = (fd.field_record_size as u32).wrapping_mul(fd.num_fields);
        let next = (cursor as u64 + header + advance as u64) as u32;
        if next <= cursor {
            // Only reachable with a section of 4 GiB; the original would
            // not terminate.
            break;
        }
        cursor = next;
    }
}

#[allow(clippy::too_many_arguments)]
fn relative_pointers(
    t: &mut Table,
    g: &mut Graph,
    reader: &VmReader<'_>,
    symbols: &SymbolLookup,
    sec: &Section,
    label: &str,
    label_id: usize,
    demangle: &mut dyn FnMut(&str) -> String,
) {
    let image = &reader.mh.image;
    let relation = section_relation_name(&sec.sectname);
    for i in 0..sec.data_size as u64 / 4 {
        let offset = sec.data_offset + i * 4;
        let Some(rel) = image.u32(offset) else { break };
        let from = sec.addr.wrapping_add(i * 4);
        // A zero pointer "refers" to itself here.
        let target = relative_target(from, rel as i32);
        let target_offset = reader.file_offset(target);

        let mut kind = "rel32";
        let mut detail = "-".to_string();
        match sec.sectname.as_str() {
            "__swift5_types" | "__swift5_protos" => {
                kind = if sec.sectname == "__swift5_types" {
                    "type-ref"
                } else {
                    "proto-ref"
                };
                if let Some(desc) = target_offset {
                    // The descriptor is read without checking that it fits;
                    // bytes past the end of the file read as zero.
                    let flags = image.u32(desc).unwrap_or(0);
                    let name_rel =
                        desc.checked_add(8).and_then(|o| image.u32(o)).unwrap_or(0) as i32;
                    let name_vmaddr = relative_target(target.wrapping_add(8), name_rel);
                    let mut name = read_printable_cstring(reader, name_vmaddr, 512);
                    if name.is_empty() {
                        name = "<unnamed>".to_string();
                    }
                    detail = format!(
                        "{} flags=0x{} name={}",
                        context_kind_name(flags & 0x1f),
                        as_short_hex_string(flags as u64),
                        name
                    );
                    g.entity_names.insert(target, name);
                }
            }
            "__swift5_typeref" | "__swift5_assocty" | "__swift5_capture" => {
                let text = read_printable_cstring(reader, target, 256);
                if !text.is_empty() {
                    let demangled = demangle(&text);
                    detail = if demangled.is_empty() {
                        text
                    } else {
                        demangled
                    };
                    g.entity_names.insert(target, detail.clone());
                }
            }
            _ => {}
        }

        g.add_edge(label_id, from, target, relation);
        let symbol = symbols.describe(target, None);
        if !symbol.is_empty() {
            detail.push_str(" symbol=");
            detail.push_str(&symbol);
        }
        t.add_data(
            offset,
            4,
            [
                kind.to_string(),
                format!("#{i}"),
                label.to_string(),
                as_address(target),
                detail,
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edges_are_deduplicated_per_label() {
        let mut g = Graph::default();
        let a = g.label_id("__TEXT/__swift5_types");
        let b = g.label_id("__TEXT/__swift5_proto");
        assert_eq!(g.label_id("__TEXT/__swift5_types"), a);
        g.add_edge(a, 1, 2, "context-ref");
        g.add_edge(a, 1, 2, "context-ref");
        g.add_edge(a, 1, 2, "field-type");
        g.add_edge(b, 1, 2, "context-ref");
        g.add_edge(b, 1, 0, "context-ref");
        assert_eq!(g.edges.len(), 3);
        assert_eq!(
            g.edges.iter().map(|e| e.label).collect::<Vec<_>>(),
            [a, a, b]
        );
    }

    #[test]
    fn names() {
        assert_eq!(context_kind_name(17), "struct");
        assert_eq!(context_kind_name(4), "unknown");
        assert_eq!(section_relation_name("__swift5_types"), "context-ref");
        assert_eq!(section_relation_name("__swift5_proto"), "rel32-ref");
    }
}
