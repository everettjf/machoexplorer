//! "Rebase Info" and the three "... Binding Info" tables: one row per
//! opcode, plus one per operand at the operand's own offset.

use crate::hex::{as_address, as_hex_data, utf8_safe};
use crate::image::Image;
use crate::macho::dyld_info::{
    bind_opcode_name, bind_type_name, rebase_opcode_name, rebase_type_name, special_dylib_name,
    BindKind, BindOp, BindOpcode, DyldInfo, Leb, RebaseOp, RebaseOpcode,
};
use crate::macho::MachHeader;
use crate::view::{Content, Table};

const SEPARATOR: [&str; 4] = ["-", "-", "-", "-"];

fn new_table() -> Table {
    let mut t = Table::new();
    t.set_headers(&["Offset", "Data", "Description", "Value"]);
    t.set_widths(&[100, 160, 380, 320]);
    t
}

/// Row for `size` bytes at file offset `offset`; the Data cell shows at
/// most their first 16 bytes (enough for any LEB128 operand).
fn data_row(image: &Image, t: &mut Table, offset: u64, size: u64, desc: &str, value: String) {
    let shown = image.slice(offset, size.min(16)).unwrap_or(&[]);
    t.add_data(
        offset,
        size,
        [
            as_address(offset),
            as_hex_data(shown),
            desc.to_string(),
            value,
        ],
    );
}

fn uleb_row(image: &Image, t: &mut Table, leb: &Leb<u64>, value: String) {
    data_row(image, t, leb.offset, leb.size as u64, "uleb128", value);
}

/// ` address (0x...)` for the location a `DO_*` opcode applies to.
fn address_text(address: Option<u64>) -> String {
    match address {
        Some(a) => format!("address (0x{a:X})"),
        None => "address (no segment set)".to_string(),
    }
}

pub(super) fn rebase_rows(image: &Image, ops: &[RebaseOpcode], t: &mut Table) {
    for o in ops {
        let value = match o.op {
            RebaseOp::Done => String::new(),
            RebaseOp::SetTypeImm { rebase_type } => {
                format!("type ({}, {})", rebase_type, rebase_type_name(rebase_type))
            }
            RebaseOp::SetSegmentAndOffsetUleb { segment_index, .. } => {
                format!("segment ({segment_index})")
            }
            RebaseOp::AddAddrUleb { .. } => String::new(),
            RebaseOp::AddAddrImmScaled { scale } => format!("scale ({scale})"),
            RebaseOp::DoRebaseImmTimes { count } => {
                format!("count ({}) {}", count, address_text(o.address))
            }
            RebaseOp::DoRebaseUlebTimes { .. }
            | RebaseOp::DoRebaseAddAddrUleb { .. }
            | RebaseOp::DoRebaseUlebTimesSkippingUleb { .. } => address_text(o.address),
            RebaseOp::Unknown => format!("opcode (0x{:02X})", o.byte),
            RebaseOp::Truncated => "malformed operand".to_string(),
        };
        data_row(image, t, o.offset, 1, rebase_opcode_name(o.byte), value);
        match o.op {
            RebaseOp::SetSegmentAndOffsetUleb { offset, .. }
            | RebaseOp::AddAddrUleb { offset }
            | RebaseOp::DoRebaseAddAddrUleb { offset } => {
                uleb_row(image, t, &offset, format!("offset (0x{:X})", offset.value));
            }
            RebaseOp::DoRebaseUlebTimes { count } => {
                uleb_row(image, t, &count, format!("count ({})", count.value));
            }
            RebaseOp::DoRebaseUlebTimesSkippingUleb { count, skip } => {
                uleb_row(image, t, &count, format!("count ({})", count.value));
                uleb_row(image, t, &skip, format!("skip (0x{:X})", skip.value));
            }
            _ => {}
        }
    }
}

pub(super) fn rebase_content(mh: &MachHeader, info: &DyldInfo) -> Content {
    let mut t = new_table();
    rebase_rows(&mh.image, &mh.rebase_opcodes(info), &mut t);
    Content::table(t).with_binary(
        mh.dyld_info_file_offset(info.rebase_off),
        info.rebase_size as u64,
    )
}

/// `dylib (N)`, with the name of a special ordinal appended.
fn dylib_text(ordinal: i64) -> String {
    match special_dylib_name(ordinal).filter(|_| ordinal <= 0) {
        Some(name) => format!("dylib ({ordinal}, {name})"),
        None => format!("dylib ({ordinal})"),
    }
}

pub(super) fn bind_rows(image: &Image, ops: &[BindOpcode], t: &mut Table) {
    for o in ops {
        let value = match &o.op {
            BindOp::Done | BindOp::AddAddrUleb { .. } | BindOp::SetAddendSleb { .. } => {
                String::new()
            }
            BindOp::SetDylibOrdinalImm { ordinal } => format!("dylib ({ordinal})"),
            BindOp::SetDylibOrdinalUleb { .. } => String::new(),
            BindOp::SetDylibSpecialImm { ordinal } => dylib_text(*ordinal as i64),
            BindOp::SetSymbolTrailingFlagsImm { flags, .. } => format!("flags ({flags})"),
            BindOp::SetTypeImm { bind_type } => {
                format!("type ({}, {})", bind_type, bind_type_name(*bind_type))
            }
            BindOp::SetSegmentAndOffsetUleb { segment_index, .. } => {
                format!("segment ({segment_index})")
            }
            BindOp::DoBind
            | BindOp::DoBindAddAddrUleb { .. }
            | BindOp::DoBindUlebTimesSkippingUleb { .. }
            | BindOp::ThreadedApply => address_text(o.address),
            BindOp::DoBindAddAddrImmScaled { scale } => {
                format!("scale ({}) {}", scale, address_text(o.address))
            }
            BindOp::ThreadedSetBindOrdinalTableSizeUleb { .. } => String::new(),
            BindOp::Unknown => format!("opcode (0x{:02X})", o.byte),
            BindOp::Truncated => "malformed operand".to_string(),
        };
        data_row(image, t, o.offset, 1, bind_opcode_name(o.byte), value);
        match &o.op {
            BindOp::SetDylibOrdinalUleb { ordinal } => {
                uleb_row(image, t, ordinal, format!("dylib ({})", ordinal.value));
            }
            BindOp::SetSymbolTrailingFlagsImm {
                name,
                name_offset,
                name_size,
                ..
            } => data_row(
                image,
                t,
                *name_offset,
                *name_size,
                "string",
                format!("name ({})", utf8_safe(name)),
            ),
            BindOp::SetAddendSleb { addend } => data_row(
                image,
                t,
                addend.offset,
                addend.size as u64,
                "sleb128",
                format!("addend ({})", addend.value),
            ),
            BindOp::SetSegmentAndOffsetUleb { offset, .. }
            | BindOp::AddAddrUleb { offset }
            | BindOp::DoBindAddAddrUleb { offset } => {
                uleb_row(image, t, offset, format!("offset (0x{:X})", offset.value));
            }
            BindOp::DoBindUlebTimesSkippingUleb { count, skip } => {
                uleb_row(image, t, count, format!("count ({})", count.value));
                uleb_row(image, t, skip, format!("skip (0x{:X})", skip.value));
            }
            BindOp::ThreadedSetBindOrdinalTableSizeUleb { count } => {
                uleb_row(image, t, count, format!("count ({})", count.value));
            }
            _ => {}
        }
        if matches!(
            o.op,
            BindOp::DoBind
                | BindOp::DoBindAddAddrUleb { .. }
                | BindOp::DoBindAddAddrImmScaled { .. }
                | BindOp::DoBindUlebTimesSkippingUleb { .. }
        ) {
            t.add(SEPARATOR);
        }
    }
}

pub(super) fn bind_content(mh: &MachHeader, info: &DyldInfo, kind: BindKind) -> Content {
    let mut t = new_table();
    bind_rows(&mh.image, &mh.bind_opcodes(info, kind), &mut t);
    let (off, size) = info.bind_range(kind);
    Content::table(t).with_binary(mh.dyld_info_file_offset(off), size as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::dyld_info::{walk_bind_opcodes, walk_rebase_opcodes, WalkContext};

    fn ctx() -> WalkContext {
        WalkContext {
            is64: true,
            segment_vmaddrs: vec![0, 0x1_0000_0000],
        }
    }

    fn cells(t: &Table) -> Vec<Vec<&str>> {
        t.rows
            .iter()
            .map(|r| r.cells.iter().map(String::as_str).collect())
            .collect()
    }

    #[test]
    fn rebase_table() {
        // 16 bytes of padding, then the stream.
        let mut file = vec![0xEE; 16];
        file.extend([0x11, 0x21, 0x90, 0x01, 0x52, 0x80, 0x03, 0x08, 0xF0]);
        let image = Image::from_vec(file).unwrap();
        let ops = walk_rebase_opcodes(&image.bytes()[16..], 16, &ctx());
        let mut t = new_table();
        rebase_rows(&image, &ops, &mut t);
        assert_eq!(
            cells(&t),
            [
                [
                    "00000010",
                    "11",
                    "REBASE_OPCODE_SET_TYPE_IMM",
                    "type (1, REBASE_TYPE_POINTER)"
                ],
                [
                    "00000011",
                    "21",
                    "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
                    "segment (1)"
                ],
                // The operand has its own offset and bytes.
                ["00000012", "9001", "uleb128", "offset (0x90)"],
                [
                    "00000014",
                    "52",
                    "REBASE_OPCODE_DO_REBASE_IMM_TIMES",
                    "count (2) address (0x100000090)"
                ],
                [
                    "00000015",
                    "80",
                    "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB",
                    "address (0x1000000A0)"
                ],
                ["00000016", "03", "uleb128", "count (3)"],
                ["00000017", "08", "uleb128", "skip (0x8)"],
                ["00000018", "F0", "REBASE_OPCODE_UNKNOWN", "opcode (0xF0)"],
            ]
        );
        assert!(t.rows.iter().all(|r| r.cells.len() == t.headers.len()));
        assert_eq!((t.rows[2].offset, t.rows[2].size), (Some(0x12), 2));
    }

    #[test]
    fn bind_table() {
        let mut file = vec![0x3e, 0x41];
        file.extend(b"_a_long_symbol\0");
        file.extend([
            0x51, 0x71, 0x10, 0x90, 0xC0, 0x02, 0x08, 0xD0, 0x05, 0x60, 0x80,
        ]);
        let image = Image::from_vec(file).unwrap();
        let ops = walk_bind_opcodes(image.bytes(), 0, BindKind::Bind, &ctx());
        let mut t = new_table();
        bind_rows(&image, &ops, &mut t);
        assert_eq!(
            cells(&t),
            [
                [
                    "00000000",
                    "3E",
                    "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM",
                    "dylib (-2, BIND_SPECIAL_DYLIB_FLAT_LOOKUP)"
                ],
                [
                    "00000001",
                    "41",
                    "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM",
                    "flags (1)"
                ],
                [
                    "00000002",
                    "5F615F6C6F6E675F73796D626F6C00",
                    "string",
                    "name (_a_long_symbol)"
                ],
                [
                    "00000011",
                    "51",
                    "BIND_OPCODE_SET_TYPE_IMM",
                    "type (1, BIND_TYPE_POINTER)"
                ],
                [
                    "00000012",
                    "71",
                    "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
                    "segment (1)"
                ],
                ["00000013", "10", "uleb128", "offset (0x10)"],
                [
                    "00000014",
                    "90",
                    "BIND_OPCODE_DO_BIND",
                    "address (0x100000010)"
                ],
                ["-", "-", "-", "-"],
                [
                    "00000015",
                    "C0",
                    "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB",
                    "address (0x100000018)"
                ],
                ["00000016", "02", "uleb128", "count (2)"],
                ["00000017", "08", "uleb128", "skip (0x8)"],
                ["-", "-", "-", "-"],
                [
                    "00000018",
                    "D0",
                    "BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB",
                    ""
                ],
                ["00000019", "05", "uleb128", "count (5)"],
                [
                    "0000001A",
                    "60",
                    "BIND_OPCODE_SET_ADDEND_SLEB",
                    "malformed operand"
                ],
            ]
        );
        assert!(t.rows.iter().all(|r| r.cells.len() == t.headers.len()));
        // The name row covers the whole string and its terminator.
        assert_eq!((t.rows[2].offset, t.rows[2].size), (Some(2), 15));
    }
}
