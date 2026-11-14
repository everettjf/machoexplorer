//! "Rebase Info" and the three "... Binding Info" tables: one row per
//! opcode, plus one per operand.

use super::to_hex_string;
use crate::hex::{as_hex_data, as_hex_string, utf8_safe};
use crate::image::Image;
use crate::macho::dyld_info::{
    bind_type_name, rebase_type_name, BindKind, BindOp, BindOpcode, DyldInfo, Leb, RebaseOp,
    RebaseOpcode,
};
use crate::macho::MachHeader;
use crate::view::{Content, Table};

/// Hex of the bytes an operand occupies (empty for a malformed operand).
fn operand_hex<T>(image: &Image, leb: &Leb<T>) -> String {
    as_hex_data(image.slice(leb.offset, leb.size as u64).unwrap_or(&[]))
}

const SEPARATOR: [&str; 4] = ["-", "-", "-", "-"];

pub(super) fn rebase_rows(image: &Image, ops: &[RebaseOpcode], t: &mut Table) {
    for o in ops {
        let at = to_hex_string(o.offset);
        let byte = to_hex_string(o.byte as u64);
        let mut opcode_row =
            |name: &str, value: String| t.add([at.clone(), byte.clone(), name.to_string(), value]);
        // QUIRK(parity): operand rows repeat the opcode's offset instead of
        // the operand's own, and ULEB128 values are cut to a signed 32-bit
        // integer where the original casts to `int`.
        let operand = |desc: String, leb: &Leb<u64>| {
            [
                at.clone(),
                format!("0x{}", operand_hex(image, leb)),
                "uleb128".to_string(),
                desc,
            ]
        };
        match o.op {
            RebaseOp::Done => opcode_row("REBASE_OPCODE_DONE", String::new()),
            RebaseOp::SetTypeImm => opcode_row(
                "REBASE_OPCODE_SET_TYPE_IMM",
                format!(
                    "type ({}, {})",
                    o.rebase_type,
                    rebase_type_name(o.rebase_type)
                ),
            ),
            RebaseOp::SetSegmentAndOffsetUleb {
                segment_index,
                offset,
            } => {
                opcode_row(
                    "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
                    format!("segment ({})", segment_index),
                );
                t.add(operand(
                    format!("offset ({})", as_hex_string(offset.value)),
                    &offset,
                ));
            }
            RebaseOp::AddAddrUleb { offset } => {
                opcode_row("REBASE_OPCODE_ADD_ADDR_ULEB", String::new());
                t.add(operand(
                    format!("offset ({})", as_hex_string(offset.value)),
                    &offset,
                ));
            }
            RebaseOp::AddAddrImmScaled { scale } => opcode_row(
                "REBASE_OPCODE_ADD_ADDR_IMM_SCALED",
                format!("scale ({})", scale),
            ),
            RebaseOp::DoRebaseImmTimes { count } => opcode_row(
                "REBASE_OPCODE_DO_REBASE_IMM_TIMES",
                format!("count ({})", count),
            ),
            RebaseOp::DoRebaseUlebTimes { count } => {
                opcode_row("REBASE_OPCODE_DO_REBASE_ULEB_TIMES", String::new());
                t.add(operand(format!("count ({})", count.value as i32), &count));
            }
            RebaseOp::DoRebaseAddAddrUleb { offset } => {
                opcode_row("REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB", String::new());
                t.add(operand(
                    format!("offset ({})", as_hex_string(offset.value)),
                    &offset,
                ));
            }
            RebaseOp::DoRebaseUlebTimesSkippingUleb { count, skip } => {
                opcode_row(
                    "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB",
                    String::new(),
                );
                t.add(operand(format!("count ({})", count.value as i32), &count));
                t.add(operand(format!("skip ({})", skip.value as i32), &skip));
            }
        }
    }
}

pub(super) fn rebase_content(mh: &MachHeader, info: &DyldInfo) -> Content {
    let mut t = Table::new();
    rebase_rows(&mh.image, &mh.rebase_opcodes(info), &mut t);
    Content::table(t).with_binary(
        mh.dyld_info_file_offset(info.rebase_off),
        info.rebase_size as u64,
    )
}

pub(super) fn bind_rows(image: &Image, ops: &[BindOpcode], t: &mut Table) {
    for o in ops {
        let at = to_hex_string(o.offset);
        let byte = to_hex_string(o.byte as u64);
        let mut opcode_row =
            |name: &str, value: String| t.add([at.clone(), byte.clone(), name.to_string(), value]);
        let operand = |kind: &str, hex: String, offset: u64, desc: String| {
            [to_hex_string(offset), hex, kind.to_string(), desc]
        };
        let uleb = |desc: String, leb: &Leb<u64>| {
            operand("uleb128", operand_hex(image, leb), leb.offset, desc)
        };
        match &o.op {
            BindOp::Done => opcode_row("BIND_OPCODE_DONE", String::new()),
            BindOp::SetDylibOrdinalImm { ordinal } => opcode_row(
                "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM",
                format!("dylib ({})", ordinal),
            ),
            BindOp::SetDylibOrdinalUleb { ordinal } => {
                opcode_row("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB", String::new());
                t.add(uleb(format!("dylib ({})", ordinal.value), ordinal));
            }
            // QUIRK(parity): special ordinals are negative but printed as
            // unsigned 64-bit numbers (-1 shows as 18446744073709551615).
            BindOp::SetDylibSpecialImm { ordinal } => opcode_row(
                "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM",
                format!("dylib ({})", ordinal),
            ),
            BindOp::SetSymbolTrailingFlagsImm {
                flags,
                name,
                name_offset,
                name_size,
            } => {
                opcode_row(
                    "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM",
                    format!("flags ({})", flags),
                );
                // At most the first 8 bytes of the name and its terminator.
                let shown = image
                    .slice(*name_offset, (*name_size as u64).min(8))
                    .unwrap_or(&[]);
                t.add(operand(
                    "string",
                    as_hex_data(shown),
                    *name_offset,
                    format!("name ({})", utf8_safe(name)),
                ));
            }
            BindOp::SetTypeImm => opcode_row(
                "BIND_OPCODE_SET_TYPE_IMM",
                format!("type ({})", bind_type_name(o.bind_type)),
            ),
            BindOp::SetAddendSleb { addend } => {
                opcode_row("BIND_OPCODE_SET_ADDEND_SLEB", String::new());
                t.add(operand(
                    "sleb128",
                    operand_hex(image, addend),
                    addend.offset,
                    format!("addend ({})", addend.value),
                ));
            }
            BindOp::SetSegmentAndOffsetUleb {
                segment_index,
                offset,
            } => {
                opcode_row(
                    "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
                    format!("segment ({})", segment_index),
                );
                t.add(uleb(format!("offset ({})", offset.value), offset));
            }
            BindOp::AddAddrUleb { offset } => {
                opcode_row("BIND_OPCODE_ADD_ADDR_ULEB", String::new());
                t.add(uleb(format!("offset ({})", offset.value), offset));
            }
            BindOp::DoBind => {
                opcode_row("BIND_OPCODE_DO_BIND", String::new());
                t.add(SEPARATOR);
            }
            BindOp::DoBindAddAddrUleb { offset } => {
                opcode_row("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB", String::new());
                t.add(uleb(format!("offset ({})", offset.value), offset));
                t.add(SEPARATOR);
            }
            BindOp::DoBindAddAddrImmScaled { scale } => {
                opcode_row(
                    "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED",
                    format!("scaled ({})", scale),
                );
                t.add(SEPARATOR);
            }
            BindOp::DoBindUlebTimesSkippingUleb { count, skip } => {
                // QUIRK(parity): this bind opcode is labelled with the
                // rebase opcode's name, its operand rows repeat the opcode's
                // offset with a `0x`-prefixed hex dump (unlike every other
                // bind operand), and the values are cut to a signed 32-bit
                // integer.
                opcode_row(
                    "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB",
                    String::new(),
                );
                let prefixed = |desc: String, leb: &Leb<u64>| {
                    operand(
                        "uleb128",
                        format!("0x{}", operand_hex(image, leb)),
                        o.offset,
                        desc,
                    )
                };
                t.add(prefixed(format!("count ({})", count.value as i32), count));
                t.add(prefixed(format!("skip ({})", skip.value as i32), skip));
                t.add(SEPARATOR);
            }
        }
    }
}

pub(super) fn bind_content(mh: &MachHeader, info: &DyldInfo, kind: BindKind) -> Content {
    let mut t = Table::new();
    bind_rows(&mh.image, &mh.bind_opcodes(info, kind), &mut t);
    // The original never fills in a byte range for the bind streams.
    Content::table(t)
}
