//! "Swift Metadata": the contents of a `__swift5_*` section. (The Swift
//! symbols of the image are listed once, in the "Swift Semantic Graph".)

use crate::hex::{as_address, as_short_hex_string, as_string, utf8_safe};
use crate::macho::ptr::{relative_target, Segments, SliceReader};
use crate::macho::swift::{
    self, context_kind_name, field_descriptor_kind_name, read_identifier_text,
    read_printable_cstring, relative_cstring, ContextDescriptorHeader, FieldDescriptorHeader,
    FieldRecord,
};
use crate::macho::{MachHeader, Section};
use crate::view::Table;

/// Size of one relative pointer.
const REL32: u32 = 4;

pub(super) fn metadata(mh: &MachHeader, section: &Section) -> Table {
    let mut t = Table::new();
    t.set_headers(&["Index", "Offset", "Kind", "Value", "Decoded"]);
    t.set_widths(&[80, 140, 220, 260, 420]);
    let reader = SliceReader::new(mh, Segments::Only64(section.is64));
    match section.sectname.as_str() {
        "__swift5_reflstr" => reflection_strings(&mut t, mh, section),
        "__swift5_fieldmd" => field_metadata(&mut t, mh, section, &reader),
        _ => relative_section(&mut t, mh, section, &reader),
    }
    t
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

/// The text a `__swift5_typeref` entry points at: an identifier-like prefix
/// if there is one, else a whole printable C string.
fn typeref_text(reader: &SliceReader<'_>, vmaddr: u64) -> String {
    let text = read_identifier_text(reader, vmaddr, 256);
    if text.is_empty() {
        read_printable_cstring(reader, vmaddr, 512)
    } else {
        text
    }
}

/// `(kind, decoded)` cells for the context descriptor at `vmaddr`.
fn decode_context_descriptor(reader: &SliceReader<'_>, vmaddr: u64) -> (String, String) {
    let Some(offset) = reader.file_offset(vmaddr) else {
        return ("swift-context".to_string(), "unmapped".to_string());
    };
    let Some(desc) = ContextDescriptorHeader::read(&reader.mh.image, offset) else {
        return ("swift-context".to_string(), "truncated".to_string());
    };
    let name = relative_cstring(reader, vmaddr.wrapping_add(8), desc.name)
        .map(|(_, s)| s)
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
fn relative_section(t: &mut Table, mh: &MachHeader, section: &Section, reader: &SliceReader<'_>) {
    let unmapped = || "unmapped".to_string();
    for e in relative_entries(mh, section) {
        let target = e.target_vmaddr;
        let mapped = e.target_offset.is_some();
        let cstring = || read_printable_cstring(reader, target, 512);
        let (kind, decoded) = match section.sectname.as_str() {
            "__swift5_types" | "__swift5_protos" => {
                if mapped {
                    decode_context_descriptor(reader, target)
                } else {
                    ("rel32".to_string(), unmapped())
                }
            }
            "__swift5_assocty" => {
                if mapped {
                    let (kind, decoded) = decode_context_descriptor(reader, target);
                    (format!("assocty->{kind}"), decoded)
                } else {
                    ("assocty/rel32".to_string(), unmapped())
                }
            }
            "__swift5_capture" => {
                let decoded = if mapped {
                    Some(cstring())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "capture-record".to_string())
                } else {
                    unmapped()
                };
                ("capture/rel32".to_string(), decoded)
            }
            "__swift5_typeref" => {
                let decoded = if mapped {
                    swift::decode_swift_like_text(&typeref_text(reader, target))
                } else {
                    unmapped()
                };
                ("typeref/rel32".to_string(), decoded)
            }
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

/// `__swift5_reflstr`: the printable NUL-terminated strings.
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
        t.add(["-", "-", "reflstr", "-", "no printable reflection strings"]);
    }
}

/// `__swift5_fieldmd`: field descriptors, each followed by its records.
fn field_metadata(t: &mut Table, mh: &MachHeader, section: &Section, reader: &SliceReader<'_>) {
    let image = &mh.image;
    let name_or_dash = |field_vmaddr: u64, rel: i32| {
        relative_cstring(reader, field_vmaddr, rel)
            .map(|(_, s)| s)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "-".to_string())
    };

    let size = u64::from(section.data_size);
    let header = FieldDescriptorHeader::SIZE;
    let mut cursor: u64 = 0;
    let mut descriptor_index: u32 = 0;
    while cursor + header <= size {
        let desc_offset = section.data_offset + cursor;
        let Some(desc) = FieldDescriptorHeader::read(image, desc_offset) else {
            break;
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

        let type_name = name_or_dash(desc_vmaddr, desc.mangled_type_name);
        let super_name = name_or_dash(desc_vmaddr.wrapping_add(4), desc.superclass);
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
                    type_name, super_name, desc.num_fields, desc.field_record_size
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
            let field_name = name_or_dash(record_vmaddr.wrapping_add(8), record.field_name);
            let mangled_name =
                name_or_dash(record_vmaddr.wrapping_add(4), record.mangled_type_name);
            t.add_data(
                record_offset,
                record_size,
                [
                    as_string(i),
                    as_address(record_offset),
                    "field".to_string(),
                    field_name,
                    format!(
                        "flags={} type={}",
                        as_short_hex_string(record.flags as u64),
                        mangled_name
                    ),
                ],
            );
            field_cursor += record_size;
        }
        cursor = field_cursor;
        descriptor_index += 1;
    }
}
