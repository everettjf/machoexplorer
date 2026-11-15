//! "Swift Semantic Graph" node: every `__swift5_*` section decoded into
//! entities (descriptors, records, strings), followed by the reference
//! edges between them and by the Swift symbols of the image.

use crate::hex::{as_address, as_short_hex_string, utf8_safe};
use crate::macho::disasm::{Duplicates, SymbolLookup};
use crate::macho::ptr::{relative_target, Segments, SliceReader};
use crate::macho::swift::{
    self, context_kind_name, field_descriptor_kind_name, read_printable_cstring,
    ContextDescriptorHeader, FieldDescriptorHeader, FieldRecord,
};
use crate::macho::{MachHeader, Section};
use crate::view::{leaf, Content, Table, ViewNode};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Swift Semantic Graph", move || {
        Content::table(table(&mh))
    }))
}

/// The demangled form of a string that may be a mangled type or symbol
/// name, or the string itself.
fn demangled_or_text(text: String) -> String {
    swift::demangle_type_or_symbol(&text).unwrap_or(text)
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

fn table(mh: &MachHeader) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Kind", "Name", "Section", "Address", "Details"]);
    t.set_widths(&[170, 280, 180, 180, 500]);

    let symbols = SymbolLookup::from_symtab(mh, Duplicates::FirstOnly);
    let reader = SliceReader::new(mh, Segments::Any);
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
            "__swift5_fieldmd" => field_metadata(&mut t, &mut g, &reader, sec, &label, label_id),
            _ => relative_pointers(&mut t, &mut g, &reader, &symbols, sec, &label, label_id),
        }
    }

    t.separator();
    if g.edges.is_empty() {
        t.add(["-", "No Swift metadata edges found", "-", "-", "-"]);
    } else {
        t.add([
            "edge".to_string(),
            "Swift Metadata Relations".to_string(),
            "-".to_string(),
            "-".to_string(),
            format!("count={}", g.edges.len()),
        ]);
    }
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
    swift_symbols(&mut t, mh);
    t
}

/// The symbols of the image whose names are Swift manglings, demangled.
fn swift_symbols(t: &mut Table, mh: &MachHeader) {
    let Some(symtab) = mh.symtab() else {
        return;
    };
    let symbols: Vec<(u64, &[u8])> = symtab
        .symbols()
        .filter(|sym| sym.n_strx != 0)
        .map(|sym| (sym.n_value, symtab.string_bytes(sym.n_strx)))
        .filter(|(_, name)| swift::has_swift_prefix(name))
        .collect();
    if symbols.is_empty() {
        return;
    }
    t.separator();
    t.add([
        "symbol".to_string(),
        "Swift Symbols".to_string(),
        "-".to_string(),
        "-".to_string(),
        format!("count={}", symbols.len()),
    ]);
    let names: Vec<&[u8]> = symbols.iter().map(|(_, name)| *name).collect();
    for ((value, name), demangled) in symbols.iter().zip(swift::demangle_all(&names)) {
        let mut decoded = demangled.unwrap_or_else(|| swift::decode_mangled_components(name));
        if decoded.is_empty() {
            decoded = "(raw mangled)".to_string();
        }
        t.add([
            "symbol".to_string(),
            utf8_safe(name),
            "-".to_string(),
            as_address(*value),
            decoded,
        ]);
    }
}

fn reflection_strings(t: &mut Table, g: &mut Graph, mh: &MachHeader, sec: &Section, label: &str) {
    for (index, s) in swift::reflection_strings(sec.data(&mh.image))
        .into_iter()
        .enumerate()
    {
        let vmaddr = sec.addr.wrapping_add(s.offset as u64);
        let text = utf8_safe(s.text);
        g.entity_names.insert(vmaddr, text.clone());
        t.add_data(
            sec.data_offset + s.offset as u64,
            s.size(),
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
    reader: &SliceReader<'_>,
    sec: &Section,
    label: &str,
    label_id: usize,
) {
    let image = reader.image();
    let size = sec.data_size as u64;
    let header = FieldDescriptorHeader::SIZE;
    let mut cursor: u64 = 0;
    let mut descriptor_index = 0usize;
    while cursor + header <= size {
        let offset = sec.data_offset + cursor;
        let Some(fd) = FieldDescriptorHeader::read(image, offset) else {
            break;
        };
        let vmaddr = sec.addr.wrapping_add(cursor);
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
            // A zero relative pointer means "none".
            if rel == 0 {
                continue;
            }
            let target = relative_target(field_vmaddr, rel);
            let text = read_printable_cstring(reader, target, 256);
            if !text.is_empty() {
                g.entity_names.insert(target, demangled_or_text(text));
            }
            g.add_edge(label_id, vmaddr, target, relation);
        }

        if !fd.is_plausible() {
            break;
        }
        // `is_plausible` bounds both factors, so the table size cannot
        // overflow.
        let record_size = fd.field_record_size as u64;
        let records = cursor + header;
        let table_size = record_size * fd.num_fields as u64;
        for fi in 0..fd.num_fields as u64 {
            let record_start = records + fi * record_size;
            if record_start + record_size > size {
                break;
            }
            let record_offset = sec.data_offset + record_start;
            let Some(fr) = FieldRecord::read(image, record_offset) else {
                break;
            };
            let record_vmaddr = sec.addr.wrapping_add(record_start);
            // `(target, text)` of a relative string pointer; none when the
            // pointer is zero.
            let string = |field: u64, rel: i32, max_len: u64| {
                (rel != 0).then(|| {
                    let target = relative_target(record_vmaddr.wrapping_add(field), rel);
                    (target, read_printable_cstring(reader, target, max_len))
                })
            };
            let type_ref = string(4, fr.mangled_type_name, 256)
                .map(|(target, text)| (target, demangled_or_text(text)));
            let name_ref = string(8, fr.field_name, 128);
            for (target, text) in type_ref.iter().chain(&name_ref) {
                if !text.is_empty() {
                    g.entity_names.insert(*target, text.clone());
                }
            }
            let text_of = |r: &Option<(u64, String)>| {
                r.as_ref()
                    .map(|(_, text)| text.clone())
                    .filter(|text| !text.is_empty())
            };
            t.add_data(
                record_offset,
                FieldRecord::SIZE,
                [
                    "field-record".to_string(),
                    text_of(&name_ref).unwrap_or_else(|| format!("#{fi}")),
                    label.to_string(),
                    as_address(record_vmaddr),
                    format!(
                        "flags=0x{} type={}",
                        as_short_hex_string(fr.flags as u64),
                        text_of(&type_ref).unwrap_or_else(|| "-".to_string())
                    ),
                ],
            );
            if let Some((target, _)) = name_ref {
                g.add_edge(label_id, vmaddr, target, "field-name");
            }
            if let Some((target, _)) = type_ref {
                g.add_edge(label_id, vmaddr, target, "field-type");
            }
        }
        if records + table_size > size {
            // The record table is cut off by the end of the section; what
            // follows cannot be another descriptor.
            t.add([
                "fieldmd".to_string(),
                "-".to_string(),
                label.to_string(),
                "-".to_string(),
                "truncated field record table".to_string(),
            ]);
            break;
        }
        cursor = records + table_size;
    }
}

fn relative_pointers(
    t: &mut Table,
    g: &mut Graph,
    reader: &SliceReader<'_>,
    symbols: &SymbolLookup,
    sec: &Section,
    label: &str,
    label_id: usize,
) {
    let image = reader.image();
    let relation = section_relation_name(&sec.sectname);
    for i in 0..sec.data_size as u64 / 4 {
        let offset = sec.data_offset + i * 4;
        let Some(rel) = image.u32(offset) else { break };
        let from = sec.addr.wrapping_add(i * 4);
        let kind = match sec.sectname.as_str() {
            "__swift5_types" => "type-ref",
            "__swift5_protos" => "proto-ref",
            _ => "rel32",
        };
        if rel == 0 {
            // A zero relative pointer refers to nothing.
            t.add_data(
                offset,
                4,
                [
                    kind.to_string(),
                    format!("#{i}"),
                    label.to_string(),
                    "-".to_string(),
                    "none".to_string(),
                ],
            );
            continue;
        }
        let target = relative_target(from, rel as i32);

        let mut detail = "-".to_string();
        match sec.sectname.as_str() {
            "__swift5_types" | "__swift5_protos" => {
                if let Some(desc_offset) = reader.file_offset(target) {
                    match ContextDescriptorHeader::read(image, desc_offset) {
                        Some(desc) => {
                            let name_vmaddr = relative_target(target.wrapping_add(8), desc.name);
                            let mut name = if desc.name == 0 {
                                String::new()
                            } else {
                                read_printable_cstring(reader, name_vmaddr, 512)
                            };
                            if name.is_empty() {
                                name = "<unnamed>".to_string();
                            }
                            detail = format!(
                                "{} flags=0x{} name={}",
                                context_kind_name(desc.kind()),
                                as_short_hex_string(desc.flags as u64),
                                name
                            );
                            g.entity_names.insert(target, name);
                        }
                        None => detail = "truncated context descriptor".to_string(),
                    }
                }
            }
            "__swift5_typeref" | "__swift5_assocty" | "__swift5_capture" => {
                let text = read_printable_cstring(reader, target, 256);
                if !text.is_empty() {
                    detail = demangled_or_text(text);
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
        assert_eq!(context_kind_name(4), "opaque-type");
        assert_eq!(section_relation_name("__swift5_types"), "context-ref");
        assert_eq!(section_relation_name("__swift5_proto"), "rel32-ref");
    }
}
