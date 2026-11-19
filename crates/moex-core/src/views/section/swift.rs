//! "Swift Metadata": the contents of a `__swift5_*` section. (The Swift
//! symbols of the image are listed once, in the "Swift Semantic Graph".)

use crate::hex::{as_address, as_short_hex_string, as_string, utf8_safe};
use crate::macho::ptr::{relative_target, Segments, SliceReader};
use crate::macho::swift::{
    self, context_kind_name, field_descriptor_kind_name, read_printable_cstring,
    AssociatedTypeDescriptor, AssociatedTypeItem, BuiltinTypeDescriptor, CaptureItem,
    ContextDescriptorHeader, FieldDescriptorHeader, FieldRecord, TypeNames,
};
use crate::macho::{MachHeader, Section};
use crate::view::Table;

/// Size of one relative pointer.
const REL32: u32 = 4;

pub(super) fn metadata(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Index", "Offset", "Kind", "Value", "Decoded"]);
    t.set_widths(&[60, 100, 140, 220, 600]);
    let reader = SliceReader::new(mh, Segments::Only64(section.is64));
    let names = TypeNames::new(reader);
    match section.sectname.as_str() {
        "__swift5_reflstr" => reflection_strings(&mut t, mh, section),
        "__swift5_fieldmd" => field_metadata(&mut t, mh, section, &names),
        "__swift5_typeref" => type_references(&mut t, mh, section, &names),
        "__swift5_assocty" => associated_types(&mut t, mh, section, &names),
        "__swift5_capture" => captures(&mut t, mh, section, &names),
        "__swift5_builtin" => builtin_types(&mut t, mh, section, &names),
        "__swift5_mpenum" => multi_payload_enums(&mut t, mh, section, &names),
        "__swift5_acfuncs" => accessible_functions(&mut t, mh, section, &names),
        _ => relative_section(&mut t, mh, section, &names),
    }
    t
}

/// The row that ends a table whose section is malformed or too long.
fn error_row(t: &mut Table, kind: &str, error: Option<&'static str>) {
    if let Some(error) = error {
        t.add(["-", "-", kind, "-", error]);
    }
}

/// `__swift5_typeref`: the mangled names the other reflection sections
/// refer to, laid end to end.
fn type_references(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let data = section.data(&mh.image);
    let sources = swift::metadata_source_addresses(mh);
    let walk = swift::mangled_names(data, if mh.is64 { 8 } else { 4 });
    for (index, (delta, name)) in walk.items.iter().enumerate() {
        let offset = section.data_offset + delta;
        let vmaddr = section.addr.wrapping_add(*delta);
        let decoded = names.decode(vmaddr, name.bytes(data));
        let (kind, value, text) = match decoded {
            // A metadata source is an encoded path, not a type.
            Some(n) if sources.contains(&vmaddr) => ("metadata-source", n.stored, "-".to_string()),
            Some(n) => {
                let text = n.demangled.unwrap_or_else(|| "-".to_string());
                ("typeref", n.stored, text)
            }
            None => ("typeref", "-".to_string(), "(unreadable)".to_string()),
        };
        t.add_data(
            offset,
            name.size(),
            [
                as_string(index),
                as_address(offset),
                kind.to_string(),
                value,
                text,
            ],
        );
    }
    error_row(t, "typeref", walk.error);
}

/// `__swift5_assocty`: associated type descriptors, each followed by its
/// records.
fn associated_types(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let walk = swift::associated_type_records(section.data(&mh.image));
    let mut descriptor_index = 0u32;
    for (delta, item) in &walk.items {
        let offset = section.data_offset + delta;
        let vmaddr = section.addr.wrapping_add(*delta);
        match item {
            AssociatedTypeItem::Descriptor(desc) => {
                t.add_data(
                    offset,
                    AssociatedTypeDescriptor::SIZE,
                    [
                        as_string(descriptor_index),
                        as_address(offset),
                        "assocty/descriptor".to_string(),
                        as_address(vmaddr),
                        format!(
                            "type={} protocol={} associated_types={} record_size={}",
                            names.relative_text(vmaddr, desc.conforming_type_name),
                            names.relative_text(vmaddr.wrapping_add(4), desc.protocol_type_name),
                            desc.num_associated_types,
                            desc.associated_type_record_size
                        ),
                    ],
                );
                descriptor_index += 1;
            }
            AssociatedTypeItem::Record {
                index,
                size,
                record,
            } => t.add_data(
                offset,
                u64::from(*size),
                [
                    as_string(index),
                    as_address(offset),
                    "associated-type".to_string(),
                    names
                        .relative_cstring(vmaddr, record.name)
                        .unwrap_or_else(|| "-".to_string()),
                    format!(
                        "type={}",
                        names.relative_text(vmaddr.wrapping_add(4), record.substituted_type_name)
                    ),
                ],
            ),
        }
    }
    error_row(t, "assocty", walk.error);
}

/// `__swift5_capture`: capture descriptors, each followed by its capture
/// type and metadata source records.
fn captures(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let walk = swift::capture_records(section.data(&mh.image));
    let mut descriptor_index = 0u32;
    for (delta, item) in &walk.items {
        let offset = section.data_offset + delta;
        let vmaddr = section.addr.wrapping_add(*delta);
        let cells = match *item {
            CaptureItem::Descriptor(desc) => {
                descriptor_index += 1;
                [
                    as_string(descriptor_index - 1),
                    as_address(offset),
                    "capture/descriptor".to_string(),
                    as_address(vmaddr),
                    format!(
                        "capture_types={} metadata_sources={} bindings={}",
                        desc.num_capture_types, desc.num_metadata_sources, desc.num_bindings
                    ),
                ]
            }
            CaptureItem::CaptureType {
                index,
                mangled_type_name,
            } => [
                as_string(index),
                as_address(offset),
                "capture-type".to_string(),
                target_cell(vmaddr, mangled_type_name),
                names.relative_text(vmaddr, mangled_type_name),
            ],
            CaptureItem::MetadataSource {
                index,
                mangled_type_name,
                mangled_metadata_source,
            } => [
                as_string(index),
                as_address(offset),
                "metadata-source".to_string(),
                target_cell(vmaddr, mangled_type_name),
                format!(
                    "type={} source={}",
                    names.relative_text(vmaddr, mangled_type_name),
                    names
                        .relative_cstring(vmaddr.wrapping_add(4), mangled_metadata_source)
                        .unwrap_or_else(|| "-".to_string())
                ),
            ],
        };
        t.add_data(offset, item.size(), cells);
    }
    error_row(t, "capture", walk.error);
}

/// Address a relative pointer stored at `field_vmaddr` refers to; `-` for
/// a null pointer.
fn target_cell(field_vmaddr: u64, rel: i32) -> String {
    if rel == 0 {
        "-".to_string()
    } else {
        as_address(relative_target(field_vmaddr, rel))
    }
}

/// `__swift5_builtin`: builtin type descriptors.
fn builtin_types(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let walk = swift::builtin_type_records(section.data(&mh.image));
    for (index, (delta, desc)) in walk.items.iter().enumerate() {
        let offset = section.data_offset + delta;
        let vmaddr = section.addr.wrapping_add(*delta);
        t.add_data(
            offset,
            BuiltinTypeDescriptor::SIZE,
            [
                as_string(index),
                as_address(offset),
                "builtin/descriptor".to_string(),
                as_address(vmaddr),
                format!(
                    "type={} {}",
                    names.relative_text(vmaddr, desc.type_name),
                    desc.layout_text()
                ),
            ],
        );
    }
    error_row(t, "builtin", walk.error);
}

/// `__swift5_mpenum`: multi-payload enum descriptors.
fn multi_payload_enums(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let data = section.data(&mh.image);
    let walk = swift::multi_payload_enum_records(data);
    for (index, (delta, desc)) in walk.items.iter().enumerate() {
        let offset = section.data_offset + delta;
        let vmaddr = section.addr.wrapping_add(*delta);
        t.add_data(
            offset,
            desc.size(),
            [
                as_string(index),
                as_address(offset),
                "mpenum/descriptor".to_string(),
                as_address(vmaddr),
                format!(
                    "type={} {}{}",
                    names.relative_text(vmaddr, desc.type_name),
                    desc.layout_text(),
                    spare_bits_text(desc, data.get(*delta as usize..).unwrap_or(&[]))
                ),
            ],
        );
    }
    error_row(t, "mpenum", walk.error);
}

/// ` spare_bits_offset=N spare_bits_mask=HEX` for a descriptor that has a
/// spare bit mask (bytes as stored, least significant first); empty
/// otherwise. `record` starts at the descriptor.
fn spare_bits_text(desc: &swift::MultiPayloadEnumDescriptor, record: &[u8]) -> String {
    let (Some(offset), Some(mask)) = (desc.spare_bit_mask_offset(), desc.spare_bit_mask(record))
    else {
        return String::new();
    };
    let mask: String = mask.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(" spare_bits_offset={offset} spare_bits_mask={mask}")
}

/// One 32-bit relative pointer of a section.
struct RelativeEntry {
    index: u32,
    /// File offset of the pointer itself.
    offset: u64,
    /// The stored value is 0: the pointer refers to nothing.
    none: bool,
    /// 0 when there is no target.
    target_vmaddr: u64,
    /// File offset of the target, when it is mapped.
    target_offset: Option<u64>,
}

fn relative_entries<'a>(
    mh: &'a MachHeader,
    section: &'a Section,
) -> impl Iterator<Item = RelativeEntry> + 'a {
    let reader = SliceReader::new(mh, Segments::Only64(section.is64));
    (0..section.data_size / REL32).filter_map(move |index| {
        let delta = (index * REL32) as u64;
        let offset = section.data_offset.checked_add(delta)?;
        let rel = mh.image.u32(offset)? as i32;
        let (target_vmaddr, target_offset) = if rel == 0 {
            (0, None)
        } else {
            let target = relative_target(section.addr.wrapping_add(delta), rel);
            (target, reader.file_offset(target))
        };
        Some(RelativeEntry {
            index,
            offset,
            none: rel == 0,
            target_vmaddr,
            target_offset,
        })
    })
}

/// `(kind, decoded)` cells for the context descriptor at `vmaddr`.
fn decode_context_descriptor(
    reader: &SliceReader<'_>,
    names: &TypeNames<'_>,
    vmaddr: u64,
) -> (String, String) {
    let Some(offset) = reader.file_offset(vmaddr) else {
        return ("swift-context".to_string(), "unmapped".to_string());
    };
    let Some(desc) = ContextDescriptorHeader::read(&reader.mh.image, offset) else {
        return ("swift-context".to_string(), "truncated".to_string());
    };
    let name = names
        .relative_cstring(vmaddr.wrapping_add(8), desc.name)
        .unwrap_or_default();
    let decoded = format!(
        "flags={} parent_rel={} name={}",
        as_short_hex_string(desc.flags as u64),
        desc.parent,
        if name.is_empty() { "-" } else { &name }
    );
    (
        format!("context/{}", context_kind_name(desc.kind())),
        decoded,
    )
}

/// Sections that are arrays of 32-bit relative pointers.
fn relative_section(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let reader = &names.reader();
    let unmapped = || "unmapped".to_string();
    for e in relative_entries(mh, section) {
        let target = e.target_vmaddr;
        let mapped = e.target_offset.is_some();
        let cstring = || read_printable_cstring(reader, target, 512);
        let (kind, decoded) = match section.sectname.as_str() {
            "__swift5_types" | "__swift5_types2" | "__swift5_protos" => {
                if mapped {
                    decode_context_descriptor(reader, names, target)
                } else {
                    ("rel32".to_string(), unmapped())
                }
            }
            // Protocol conformance descriptors.
            "__swift5_proto" => {
                let part = |part: Option<String>| part.unwrap_or_else(|| "?".to_string());
                let decoded = match names.conformance(target) {
                    Some((conforming, protocol)) => {
                        format!("{}: {}", part(conforming), part(protocol))
                    }
                    None => unmapped(),
                };
                ("conformance".to_string(), decoded)
            }
            // The one entry is the program's `main`.
            "__swift5_entry" => (
                "entry".to_string(),
                if mapped { "entry point" } else { "unmapped" }.to_string(),
            ),
            _ => {
                let decoded = mapped.then(cstring).filter(|s| !s.is_empty());
                (
                    "rel32".to_string(),
                    decoded.unwrap_or_else(|| "-".to_string()),
                )
            }
        };
        // A null relative pointer is not an unmapped one.
        let decoded = if e.none { "none".to_string() } else { decoded };
        let cells = [
            as_string(e.index),
            as_address(e.offset),
            kind,
            as_address(target),
            decoded,
        ];
        // The row refers to the target's bytes but has no length.
        match e.target_offset {
            Some(offset) => t.add_data(offset, 0, cells),
            None => t.add(cells),
        }
    }
}

/// `__swift5_acfuncs`: accessible function records (distributed actor
/// methods and the like, found by name at run time), 20 bytes each:
/// relative pointers to the mangled name of the function, to its generic
/// environment, to the mangled name of its type and to the function, then
/// flags.
fn accessible_functions(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    const SIZE: u64 = 20;
    let data = section.data(&mh.image);
    let word = |at: u64| -> Option<u32> {
        let bytes = data.get(at as usize..)?.get(..4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    };
    let count = (data.len() as u64 / SIZE).min(swift::MAX_RECORDS as u64);
    for index in 0..count {
        let delta = index * SIZE;
        let vmaddr = section.addr.wrapping_add(delta);
        let (Some(name), Some(_), Some(function_type), Some(function), Some(flags)) = (
            word(delta),
            word(delta + 4),
            word(delta + 8),
            word(delta + 12),
            word(delta + 16),
        ) else {
            break;
        };
        // The name is a symbol name.
        let symbol = names
            .relative_cstring(vmaddr, name as i32)
            .map(|name| swift::demangle(name.as_bytes()).unwrap_or(name))
            .unwrap_or_else(|| "-".to_string());
        let function = match function as i32 {
            0 => "-".to_string(),
            rel => as_address(relative_target(vmaddr.wrapping_add(12), rel)),
        };
        t.add_data(
            section.data_offset + delta,
            SIZE,
            [
                as_string(index),
                as_address(section.data_offset + delta),
                "acfuncs/record".to_string(),
                as_address(vmaddr),
                format!(
                    "{symbol} type={} function={function} flags=0x{flags:x}",
                    names.relative_text(vmaddr.wrapping_add(8), function_type as i32)
                ),
            ],
        );
    }
    if data.len() as u64 % SIZE != 0 {
        error_row(t, "acfuncs", Some("truncated accessible function record"));
    }
}

/// `__swift5_reflstr`: NUL-terminated strings.
fn reflection_strings(t: &mut Table, mh: &MachHeader, section: &Section) {
    let strings = swift::reflection_strings(section.data(&mh.image));
    for (index, s) in strings.iter().enumerate() {
        let offset = section.data_offset + s.offset as u64;
        t.add_data(
            offset,
            s.size(),
            [
                as_string(index),
                as_address(offset),
                "reflstr".to_string(),
                as_string(s.text.len()),
                utf8_safe(s.text),
            ],
        );
    }
    if strings.is_empty() {
        t.add(["-", "-", "reflstr", "-", "no reflection strings"]);
    }
}

/// `__swift5_fieldmd`: field descriptors, each followed by its records.
fn field_metadata(t: &mut Table, mh: &MachHeader, section: &Section, names: &TypeNames<'_>) {
    let image = &mh.image;
    let size = u64::from(section.data_size);
    let header = FieldDescriptorHeader::SIZE;
    let mut cursor: u64 = 0;
    let mut descriptor_index: u32 = 0;
    while cursor < size {
        let desc_offset = section.data_offset + cursor;
        let desc = (cursor + header <= size)
            .then(|| FieldDescriptorHeader::read(image, desc_offset))
            .flatten();
        let Some(desc) = desc else {
            t.add(["-", "-", "fieldmd", "-", "truncated field descriptor"]);
            return;
        };
        let desc_vmaddr = section.addr.wrapping_add(cursor);
        if !desc.is_plausible() {
            t.add_data(
                desc_offset,
                header,
                [
                    as_string(descriptor_index),
                    as_address(desc_offset),
                    "fieldmd/descriptor?".to_string(),
                    as_address(desc_vmaddr),
                    "invalid field descriptor size/count".to_string(),
                ],
            );
            break;
        }

        t.add_data(
            desc_offset,
            header,
            [
                as_string(descriptor_index),
                as_address(desc_offset),
                format!("fieldmd/{}", field_descriptor_kind_name(desc.kind)),
                as_address(desc_vmaddr),
                format!(
                    "type={} super={} fields={} record_size={}",
                    names.relative_text(desc_vmaddr, desc.mangled_type_name),
                    names.relative_text(desc_vmaddr.wrapping_add(4), desc.superclass),
                    desc.num_fields,
                    desc.field_record_size
                ),
            ],
        );

        // `is_plausible` bounds both factors, so nothing here overflows.
        let record_size = u64::from(desc.field_record_size);
        let mut field_cursor = cursor + header;
        for i in 0..desc.num_fields {
            let record_offset = section.data_offset + field_cursor;
            let record = if field_cursor + record_size > size {
                None
            } else {
                FieldRecord::read(image, record_offset)
            };
            let Some(record) = record else {
                // The rest of the section cannot be told apart from the
                // missing records.
                t.add(["-", "-", "field", "-", "truncated field record table"]);
                return;
            };
            let record_vmaddr = section.addr.wrapping_add(field_cursor);
            t.add_data(
                record_offset,
                record_size,
                [
                    as_string(i),
                    as_address(record_offset),
                    "field".to_string(),
                    names
                        .relative_cstring(record_vmaddr.wrapping_add(8), record.field_name)
                        .unwrap_or_else(|| "-".to_string()),
                    format!(
                        "flags={} type={}",
                        as_short_hex_string(record.flags as u64),
                        names
                            .relative_text(record_vmaddr.wrapping_add(4), record.mangled_type_name)
                    ),
                ],
            );
            field_cursor += record_size;
        }
        cursor = field_cursor;
        descriptor_index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::swift::tests::reflection_image;

    /// The rows of the "Swift Metadata" table of section `name`:
    /// `offset+size cell|cell|…`, or just the cells of a row without bytes.
    fn rows(mh: &MachHeader, name: &str) -> Vec<String> {
        let section = mh.sections().find(|s| s.sectname == name).unwrap();
        metadata(mh, section)
            .rows
            .iter()
            .map(|row| {
                let cells = row.cells.join("|");
                match row.offset {
                    Some(offset) => format!("{offset:x}+{} {cells}", row.size),
                    None => cells,
                }
            })
            .collect()
    }

    #[test]
    fn reflection_sections_are_decoded_and_end_with_an_error_row() {
        let mh = reflection_image();
        assert_eq!(
            rows(&mh, "__swift5_typeref"),
            [
                "400+3 0|00000400|typeref|Si|Swift.Int",
                "404+6 1|00000404|typeref|{Demo.Shape}|Demo.Shape",
                "40a+3 2|0000040A|metadata-source|B0|-",
                "-|-|typeref|-|truncated mangled name",
            ]
        );
        assert_eq!(
            rows(&mh, "__swift5_capture"),
            [
                "440+12 0|00000440|capture/descriptor|00001440|capture_types=1 metadata_sources=1 bindings=0",
                "44c+4 0|0000044C|capture-type|00001400|Swift.Int",
                "450+8 0|00000450|metadata-source|00001404|type=Demo.Shape source=B0",
                "-|-|capture|-|truncated capture descriptor",
            ]
        );
        assert_eq!(
            rows(&mh, "__swift5_assocty"),
            [
                "480+16 0|00000480|assocty/descriptor|00001480|type=Demo.Shape protocol=Swift.Int associated_types=1 record_size=8",
                "490+8 0|00000490|associated-type|Elem|type=Swift.Int",
                "-|-|assocty|-|truncated associated type descriptor",
            ]
        );
        assert_eq!(
            rows(&mh, "__swift5_builtin"),
            [
                "4c0+20 0|000004C0|builtin/descriptor|000014C0|type=Demo.Shape size=16 alignment=8 stride=16 extra_inhabitants=0 bitwise_takable=yes flags=0x1",
                "-|-|builtin|-|truncated builtin type descriptor",
            ]
        );
        assert_eq!(
            rows(&mh, "__swift5_mpenum"),
            [
                "500+8 0|00000500|mpenum/descriptor|00001500|type=Demo.Shape words=1 flags=0x0 payload_spare_bits=no",
                "-|-|mpenum|-|truncated multi-payload enum descriptor",
            ]
        );
        assert_eq!(
            rows(&mh, "__swift5_fieldmd"),
            [
                "540+16 0|00000540|fieldmd/struct|00001540|type=Demo.Shape super=- fields=1 record_size=12",
                "550+12 0|00000550|field|na\u{ef}ve|flags=2 type=Swift.Int",
                "-|-|fieldmd|-|truncated field descriptor",
            ]
        );
        assert_eq!(
            rows(&mh, "__swift5_reflstr"),
            [
                "4f0+5 0|000004F0|reflstr|4|Elem",
                "4f5+7 1|000004F5|reflstr|6|na\u{ef}ve",
            ]
        );
    }
}
