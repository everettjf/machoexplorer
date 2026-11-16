//! "Swift Semantic Graph" node: every `__swift5_*` section decoded into
//! entities (descriptors, records, strings), followed by the reference
//! edges between them and by the Swift symbols of the image.

use crate::hex::{as_address, as_short_hex_string, utf8_safe};
use crate::image::Image;
use crate::macho::disasm::{Duplicates, SymbolLookup};
use crate::macho::ptr::{relative_target, Segments, SliceReader};
use crate::macho::swift::{
    self, context_kind_name, field_descriptor_kind_name, AssociatedTypeDescriptor,
    AssociatedTypeItem, BuiltinTypeDescriptor, CaptureItem, ContextDescriptorHeader,
    FieldDescriptorHeader, FieldRecord, TypeNames,
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

fn section_relation_name(sectname: &str) -> &'static str {
    match sectname {
        "__swift5_types" => "context-ref",
        "__swift5_protos" => "protocol-ref",
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
    let names = TypeNames::new(reader);
    let sources = swift::metadata_source_addresses(mh);
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
        let image: &Image = &mh.image;
        let mut rows = SectionRows {
            t: &mut t,
            g: &mut g,
            names: &names,
            sec,
            label: &label,
            label_id,
        };
        match sec.sectname.as_str() {
            "__swift5_reflstr" => reflection_strings(&mut t, &mut g, mh, sec, &label),
            "__swift5_fieldmd" => rows.field_metadata(image),
            "__swift5_typeref" => rows.type_references(image, &sources),
            "__swift5_assocty" => rows.associated_types(image),
            "__swift5_capture" => rows.captures(image),
            "__swift5_builtin" => rows.builtin_types(image),
            "__swift5_mpenum" => rows.multi_payload_enums(image),
            _ => relative_pointers(&mut t, &mut g, &names, &symbols, sec, &label, label_id),
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

/// One section being decoded, and where its rows and edges go.
struct SectionRows<'a, 'b> {
    t: &'a mut Table,
    g: &'a mut Graph,
    names: &'a TypeNames<'b>,
    sec: &'a Section,
    label: &'a str,
    label_id: usize,
}

impl SectionRows<'_, '_> {
    /// Row for the `size` bytes at offset `delta` of the section.
    fn row(&mut self, delta: u64, size: u64, kind: &str, name: String, details: String) {
        self.t.add_data(
            self.sec.data_offset + delta,
            size,
            [
                kind.to_string(),
                name,
                self.label.to_string(),
                as_address(self.sec.addr.wrapping_add(delta)),
                details,
            ],
        );
    }

    /// The row that ends a section which is malformed or too long.
    fn error(&mut self, kind: &str, error: Option<&'static str>) {
        if let Some(error) = error {
            self.t.add([kind, "-", self.label, "-", error]);
        }
    }

    /// Display text of the mangled name that the relative pointer `rel`
    /// stored at `field` refers to (`-` for a null pointer), with an edge
    /// to it from the entity at `from`.
    fn type_ref(&mut self, from: u64, field: u64, rel: i32, relation: &'static str) -> String {
        if rel == 0 {
            return "-".to_string();
        }
        let target = relative_target(field, rel);
        self.g.add_edge(self.label_id, from, target, relation);
        match self.names.read(target) {
            Some(name) => {
                let text = name.text().to_string();
                self.g.entity_names.insert(target, text.clone());
                text
            }
            None => "(unreadable)".to_string(),
        }
    }

    /// The C string that the relative pointer `rel` stored at `field`
    /// refers to, with an edge to it from the entity at `from`. `None`
    /// for a null pointer or an unreadable string.
    fn string_ref(
        &mut self,
        from: u64,
        field: u64,
        rel: i32,
        relation: &'static str,
    ) -> Option<String> {
        if rel == 0 {
            return None;
        }
        let target = relative_target(field, rel);
        self.g.add_edge(self.label_id, from, target, relation);
        let text = self.names.cstring(target)?;
        self.g.entity_names.insert(target, text.clone());
        Some(text)
    }

    /// `__swift5_typeref`: the mangled names the other sections refer to.
    fn type_references(&mut self, image: &Image, sources: &HashSet<u64>) {
        let data = self.sec.data(image);
        let pointer_size = if self.sec.is64 { 8 } else { 4 };
        let walk = swift::mangled_names(data, pointer_size);
        for (index, (delta, name)) in walk.items.iter().enumerate() {
            let vmaddr = self.sec.addr.wrapping_add(*delta);
            let decoded = self.names.decode(vmaddr, name.bytes(data));
            let (kind, text) = match &decoded {
                // A metadata source is an encoded path, not a type.
                Some(n) if sources.contains(&vmaddr) => ("metadata-source", n.stored.clone()),
                Some(n) => ("typeref", n.text().to_string()),
                None => ("typeref", "(unreadable)".to_string()),
            };
            if let Some(n) = &decoded {
                self.g.entity_names.insert(vmaddr, text.clone());
                for target in &n.references {
                    self.g
                        .add_edge(self.label_id, vmaddr, *target, "symbolic-ref");
                }
            }
            self.row(*delta, name.size(), kind, format!("#{index}"), text);
        }
        self.error("typeref", walk.error);
    }

    /// `__swift5_assocty`: associated type descriptors and their records.
    fn associated_types(&mut self, image: &Image) {
        let walk = swift::associated_type_records(self.sec.data(image));
        let mut descriptor = 0u64;
        let mut descriptor_index = 0usize;
        for (delta, item) in &walk.items {
            let vmaddr = self.sec.addr.wrapping_add(*delta);
            match item {
                AssociatedTypeItem::Descriptor(desc) => {
                    descriptor = vmaddr;
                    self.g
                        .entity_names
                        .insert(vmaddr, format!("assocty#{descriptor_index}"));
                    descriptor_index += 1;
                    let conforming =
                        self.type_ref(vmaddr, vmaddr, desc.conforming_type_name, "conforming-type");
                    let protocol = self.type_ref(
                        vmaddr,
                        vmaddr.wrapping_add(4),
                        desc.protocol_type_name,
                        "protocol",
                    );
                    self.row(
                        *delta,
                        AssociatedTypeDescriptor::SIZE,
                        "assocty",
                        "descriptor".to_string(),
                        format!(
                            "type={conforming} protocol={protocol} associated_types={} record={}",
                            desc.num_associated_types, desc.associated_type_record_size
                        ),
                    );
                }
                AssociatedTypeItem::Record {
                    index,
                    size,
                    record,
                } => {
                    let name =
                        self.string_ref(descriptor, vmaddr, record.name, "associated-type-name");
                    let substituted = self.type_ref(
                        descriptor,
                        vmaddr.wrapping_add(4),
                        record.substituted_type_name,
                        "associated-type",
                    );
                    self.row(
                        *delta,
                        u64::from(*size),
                        "associated-type",
                        name.unwrap_or_else(|| format!("#{index}")),
                        format!("type={substituted}"),
                    );
                }
            }
        }
        self.error("assocty", walk.error);
    }

    /// `__swift5_capture`: capture descriptors and their records.
    fn captures(&mut self, image: &Image) {
        let walk = swift::capture_records(self.sec.data(image));
        let mut descriptor = 0u64;
        let mut descriptor_index = 0usize;
        for (delta, item) in &walk.items {
            let vmaddr = self.sec.addr.wrapping_add(*delta);
            let (kind, name, details) = match *item {
                CaptureItem::Descriptor(desc) => {
                    descriptor = vmaddr;
                    self.g
                        .entity_names
                        .insert(vmaddr, format!("capture#{descriptor_index}"));
                    descriptor_index += 1;
                    (
                        "capture",
                        "descriptor".to_string(),
                        format!(
                            "capture_types={} metadata_sources={} bindings={}",
                            desc.num_capture_types, desc.num_metadata_sources, desc.num_bindings
                        ),
                    )
                }
                CaptureItem::CaptureType {
                    index,
                    mangled_type_name,
                } => (
                    "capture-type",
                    format!("#{index}"),
                    format!(
                        "type={}",
                        self.type_ref(descriptor, vmaddr, mangled_type_name, "capture-type")
                    ),
                ),
                CaptureItem::MetadataSource {
                    index,
                    mangled_type_name,
                    mangled_metadata_source,
                } => {
                    let ty = self.type_ref(
                        descriptor,
                        vmaddr,
                        mangled_type_name,
                        "metadata-source-type",
                    );
                    let source = self.string_ref(
                        descriptor,
                        vmaddr.wrapping_add(4),
                        mangled_metadata_source,
                        "metadata-source",
                    );
                    (
                        "metadata-source",
                        format!("#{index}"),
                        format!(
                            "type={ty} source={}",
                            source.unwrap_or_else(|| "-".to_string())
                        ),
                    )
                }
            };
            self.row(*delta, item.size(), kind, name, details);
        }
        self.error("capture", walk.error);
    }

    /// `__swift5_builtin`: builtin type descriptors.
    fn builtin_types(&mut self, image: &Image) {
        let walk = swift::builtin_type_records(self.sec.data(image));
        for (index, (delta, desc)) in walk.items.iter().enumerate() {
            let vmaddr = self.sec.addr.wrapping_add(*delta);
            self.g
                .entity_names
                .insert(vmaddr, format!("builtin#{index}"));
            let ty = self.type_ref(vmaddr, vmaddr, desc.type_name, "builtin-type");
            self.row(
                *delta,
                BuiltinTypeDescriptor::SIZE,
                "builtin",
                "descriptor".to_string(),
                format!("type={ty} {}", desc.layout_text()),
            );
        }
        self.error("builtin", walk.error);
    }

    /// `__swift5_mpenum`: multi-payload enum descriptors.
    fn multi_payload_enums(&mut self, image: &Image) {
        let walk = swift::multi_payload_enum_records(self.sec.data(image));
        for (index, (delta, desc)) in walk.items.iter().enumerate() {
            let vmaddr = self.sec.addr.wrapping_add(*delta);
            self.g
                .entity_names
                .insert(vmaddr, format!("mpenum#{index}"));
            let ty = self.type_ref(vmaddr, vmaddr, desc.type_name, "enum-type");
            self.row(
                *delta,
                desc.size(),
                "mpenum",
                "descriptor".to_string(),
                format!("type={ty} {}", desc.layout_text()),
            );
        }
        self.error("mpenum", walk.error);
    }

    /// `__swift5_fieldmd`: field descriptors and their records.
    fn field_metadata(&mut self, image: &Image) {
        let size = self.sec.data_size as u64;
        let header = FieldDescriptorHeader::SIZE;
        let mut cursor: u64 = 0;
        let mut descriptor_index = 0usize;
        while cursor < size {
            let fd = (cursor + header <= size)
                .then(|| FieldDescriptorHeader::read(image, self.sec.data_offset + cursor))
                .flatten();
            let Some(fd) = fd else {
                self.error("fieldmd", Some("truncated field descriptor"));
                break;
            };
            let vmaddr = self.sec.addr.wrapping_add(cursor);
            self.g
                .entity_names
                .insert(vmaddr, format!("fieldmd#{descriptor_index}"));
            descriptor_index += 1;
            let ty = self.type_ref(vmaddr, vmaddr, fd.mangled_type_name, "descriptor-type");
            let superclass = self.type_ref(
                vmaddr,
                vmaddr.wrapping_add(4),
                fd.superclass,
                "descriptor-superclass",
            );
            self.row(
                cursor,
                header,
                "fieldmd",
                "descriptor".to_string(),
                format!(
                    "kind={} ({}) type={ty} super={superclass} fields={} record={}",
                    fd.kind,
                    field_descriptor_kind_name(fd.kind),
                    fd.num_fields,
                    fd.field_record_size
                ),
            );

            if !fd.is_plausible() {
                self.error("fieldmd", Some("invalid field descriptor size/count"));
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
                let Some(fr) = FieldRecord::read(image, self.sec.data_offset + record_start) else {
                    break;
                };
                let record_vmaddr = self.sec.addr.wrapping_add(record_start);
                let name = self.string_ref(
                    vmaddr,
                    record_vmaddr.wrapping_add(8),
                    fr.field_name,
                    "field-name",
                );
                let ty = self.type_ref(
                    vmaddr,
                    record_vmaddr.wrapping_add(4),
                    fr.mangled_type_name,
                    "field-type",
                );
                self.row(
                    record_start,
                    record_size,
                    "field-record",
                    name.unwrap_or_else(|| format!("#{fi}")),
                    format!("flags=0x{} type={ty}", as_short_hex_string(fr.flags as u64)),
                );
            }
            if records + table_size > size {
                // The record table is cut off by the end of the section;
                // what follows cannot be another descriptor.
                self.error("fieldmd", Some("truncated field record table"));
                break;
            }
            cursor = records + table_size;
        }
    }
}

fn relative_pointers(
    t: &mut Table,
    g: &mut Graph,
    names: &TypeNames<'_>,
    symbols: &SymbolLookup,
    sec: &Section,
    label: &str,
    label_id: usize,
) {
    let reader = &names.reader();
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
                                names.cstring(name_vmaddr).unwrap_or_default()
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
    fn reflection_sections_are_decoded_and_end_with_an_error_row() {
        let mh = crate::macho::swift::tests::reflection_image();
        let t = table(&mh);
        let rows: Vec<String> = t.rows.iter().map(|row| row.cells.join("|")).collect();
        let of = |kinds: &[&str]| -> Vec<&str> {
            rows.iter()
                .map(String::as_str)
                .filter(|row| kinds.iter().any(|kind| row.split('|').next() == Some(kind)))
                .collect()
        };
        assert_eq!(
            of(&["assocty", "associated-type"]),
            [
                "assocty|descriptor|__TEXT/__swift5_assocty|00001480|type=Demo.Shape protocol=Swift.Int associated_types=1 record=8",
                "associated-type|Elem|__TEXT/__swift5_assocty|00001490|type=Swift.Int",
                "assocty|-|__TEXT/__swift5_assocty|-|truncated associated type descriptor",
            ]
        );
        assert_eq!(
            of(&["builtin"]),
            [
                "builtin|descriptor|__TEXT/__swift5_builtin|000014C0|type=Demo.Shape size=16 alignment=8 stride=16 extra_inhabitants=0 bitwise_takable=yes flags=0x1",
                "builtin|-|__TEXT/__swift5_builtin|-|truncated builtin type descriptor",
            ]
        );
        assert_eq!(
            of(&["capture", "capture-type"]),
            [
                "capture|descriptor|__TEXT/__swift5_capture|00001440|capture_types=1 metadata_sources=1 bindings=0",
                "capture-type|#0|__TEXT/__swift5_capture|0000144C|type=Swift.Int",
                "capture|-|__TEXT/__swift5_capture|-|truncated capture descriptor",
            ]
        );
        assert_eq!(
            of(&["fieldmd", "field-record"]),
            [
                "fieldmd|descriptor|__TEXT/__swift5_fieldmd|00001540|kind=0 (struct) type=Demo.Shape super=- fields=1 record=12",
                "field-record|na\u{ef}ve|__TEXT/__swift5_fieldmd|00001550|flags=0x2 type=Swift.Int",
                "fieldmd|-|__TEXT/__swift5_fieldmd|-|truncated field descriptor",
            ]
        );
        assert_eq!(
            of(&["mpenum"]),
            [
                "mpenum|descriptor|__TEXT/__swift5_mpenum|00001500|type=Demo.Shape words=1 flags=0x0 payload_spare_bits=no",
                "mpenum|-|__TEXT/__swift5_mpenum|-|truncated multi-payload enum descriptor",
            ]
        );
        assert_eq!(
            of(&["typeref", "metadata-source", "reflstr"]),
            [
                "metadata-source|#0|__TEXT/__swift5_capture|00001450|type=Demo.Shape source=B0",
                "reflstr|#0|__TEXT/__swift5_reflstr|000014F0|Elem",
                "reflstr|#1|__TEXT/__swift5_reflstr|000014F5|na\u{ef}ve",
                "typeref|#0|__TEXT/__swift5_typeref|00001400|Swift.Int",
                "typeref|#1|__TEXT/__swift5_typeref|00001404|Demo.Shape",
                "metadata-source|#2|__TEXT/__swift5_typeref|0000140A|B0",
                "typeref|-|__TEXT/__swift5_typeref|-|truncated mangled name",
            ]
        );
        // Rows with bytes cover the record they describe.
        let ranges: Vec<(u64, u64)> = t
            .rows
            .iter()
            .filter(|row| row.cells.first().is_some_and(|kind| kind == "capture-type"))
            .filter_map(|row| Some((row.offset?, row.size)))
            .collect();
        assert_eq!(ranges, [(0x44c, 4)]);
        let edges = of(&["edge"]);
        for edge in [
            "[capture-type] capture#0 -> Swift.Int",
            "[metadata-source-type] capture#0 -> Demo.Shape",
            "[metadata-source] capture#0 -> B0",
            "[conforming-type] assocty#0 -> Demo.Shape",
            "[associated-type-name] assocty#0 -> Elem",
            "[builtin-type] builtin#0 -> Demo.Shape",
            "[enum-type] mpenum#0 -> Demo.Shape",
            "[field-name] fieldmd#0 -> na\u{ef}ve",
            "[symbolic-ref] Demo.Shape -> 00001810",
        ] {
            assert!(
                edges.iter().any(|row| row.ends_with(edge)),
                "{edge}: {edges:#?}"
            );
        }
    }

    #[test]
    fn names() {
        assert_eq!(context_kind_name(17), "struct");
        assert_eq!(context_kind_name(4), "opaque-type");
        assert_eq!(section_relation_name("__swift5_types"), "context-ref");
        assert_eq!(section_relation_name("__swift5_proto"), "rel32-ref");
    }
}
