//! "Chained Fixups (LC_DYLD_CHAINED_FIXUPS)" table: header, per-segment
//! starts, every fixup of every chain, and the imports table.
//!
//! The original walk has several defects that are reproduced here because
//! its output is the reference; see the `QUIRK(parity)` notes.

use crate::hex::{as_address, as_short_hex_string, as_string, utf8_safe};
use crate::image::Image;
use crate::macho::chained_fixups::{
    decode_next, decode_pointer, import_format_name, is_64bit_pointer_format, pointer_format_name,
    ChainedFixupsHeader, ChainedImport, ChainedStartsInSegment, ImportAddend,
    CHAINED_STARTS_IN_SEGMENT_SIZE, DYLD_CHAINED_PTR_START_LAST, DYLD_CHAINED_PTR_START_MULTI,
    DYLD_CHAINED_PTR_START_NONE,
};
use crate::macho::{LinkeditData, MachHeader};
use crate::view::{Content, Table};

/// Longest chain followed from one start, and most overflow starts read
/// for one page (same limits as the original).
const MAX_CHAIN_LENGTH: u32 = 1024;
const MAX_OVERFLOW_STARTS: u32 = 1024;
/// Most import entries listed (same limit as the original).
const MAX_IMPORTS: u32 = 4096;
/// Bounds on the whole starts walk. The original has none, so a crafted
/// blob (65535 pages x 1024 overflow starts x 1024 fixups, per segment)
/// could make it run practically forever; no real binary gets near these.
const MAX_FIXUP_ROWS: usize = 1_000_000;
const MAX_WALK_STEPS: u64 = 8_000_000;

struct Walk<'a> {
    image: &'a Image,
    t: Table,
    /// `dataoff` of the blob (relative to the Mach-O header).
    dataoff: u32,
    /// File offset of the blob.
    blob: u64,
    steps: u64,
}

impl Walk<'_> {
    /// Charges one unit of work; false once the walk must stop.
    fn step(&mut self) -> bool {
        self.steps = self.steps.saturating_add(1);
        self.steps <= MAX_WALK_STEPS && self.t.rows.len() < MAX_FIXUP_ROWS
    }

    fn row(&mut self, offset: String, kind: &str, field: String, value: String) {
        self.t.add([offset, kind.to_string(), field, value]);
    }

    /// Offset column for a position inside the blob: `dataoff` plus the
    /// distance from the blob start, in 64 bits.
    fn blob_address(&self, file_pos: u64) -> String {
        as_address((self.dataoff as u64).wrapping_add(file_pos.wrapping_sub(self.blob)))
    }

    /// Offset column for `dataoff + delta` computed in 32 bits, as the
    /// original does for struct fields.
    fn field_address(&self, delta: u32) -> String {
        as_address(self.dataoff.wrapping_add(delta) as u64)
    }

    /// Follow one chain. Returns false when the walk budget ran out.
    fn chain(
        &mut self,
        seg: &ChainedStartsInSegment,
        seg_index: u32,
        start: u16,
        page_index: u16,
        multi_index: u32,
    ) -> bool {
        // QUIRK(parity): the fixup location is used as a plain file offset:
        // the slice offset inside a fat file is not added, and
        // `segment_offset` (a VM offset) is not translated.
        let mut fixup_off = seg.segment_offset.wrapping_add(
            (page_index as u64)
                .wrapping_mul(seg.page_size as u64)
                .wrapping_add(start as u64),
        );
        let wide = is_64bit_pointer_format(seg.pointer_format);
        for chain_index in 0..MAX_CHAIN_LENGTH {
            let raw = if wide {
                self.image.u64(fixup_off)
            } else {
                self.image.u32(fixup_off).map(u64::from)
            };
            let Some(raw) = raw else { break };
            if !self.step() {
                return false;
            }
            let next = decode_next(seg.pointer_format, raw);
            let field = format!(
                "seg[{}] page[{}] chain[{}:{}]",
                seg_index, page_index, multi_index, chain_index
            );
            if wide {
                let detail = decode_pointer(seg.pointer_format, raw);
                let value = format!(
                    "raw=0x{} next={} {}",
                    as_short_hex_string(raw),
                    next,
                    detail
                );
                self.row(as_address(fixup_off), "fixup", field, value);
            } else {
                let value = format!("raw=0x{} next={}", as_short_hex_string(raw), next);
                self.row(as_address(fixup_off), "fixup32", field, value);
            }
            if next == 0 {
                break;
            }
            // QUIRK(parity): the stride is always 4 bytes.
            fixup_off = fixup_off.wrapping_add(next.wrapping_mul(4));
        }
        true
    }

    /// One `dyld_chained_starts_in_segment`. Returns false when the walk
    /// budget ran out.
    fn segment(&mut self, seg_index: u32, seg_info_off: u32) -> bool {
        // QUIRK(parity): the info offset is taken relative to the start of
        // the blob; it is really relative to `dyld_chained_starts_in_image`,
        // so what gets decoded here is usually unrelated bytes.
        let seg_at = self.blob.wrapping_add(seg_info_off as u64);
        let Some(seg) = ChainedStartsInSegment::read(self.image, seg_at) else {
            return true;
        };
        let name = |field: &str| format!("seg[{}].{}", seg_index, field);
        self.row(
            self.field_address(seg_info_off),
            "segment",
            name("page_size"),
            as_string(seg.page_size),
        );
        self.row(
            self.field_address(seg_info_off.wrapping_add(6)),
            "segment",
            name("pointer_format"),
            pointer_format_name(seg.pointer_format).to_string(),
        );
        self.row(
            self.field_address(seg_info_off.wrapping_add(8)),
            "segment",
            name("segment_offset"),
            as_short_hex_string(seg.segment_offset),
        );
        self.row(
            self.field_address(seg_info_off.wrapping_add(20)),
            "segment",
            name("page_count"),
            as_string(seg.page_count),
        );

        // QUIRK(parity): `page_start[]` is read from the end of the padded
        // struct (offset 24), not from its real offset 22.
        let page_starts = seg_at.wrapping_add(CHAINED_STARTS_IN_SEGMENT_SIZE);
        let overflow_starts = page_starts.wrapping_add(seg.page_count as u64 * 2);
        for page_index in 0..seg.page_count {
            if !self.step() {
                return false;
            }
            let ps = page_starts.wrapping_add(page_index as u64 * 2);
            let Some(start) = self.image.u16(ps) else {
                break;
            };
            if start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            self.row(
                self.blob_address(ps),
                "page_start",
                format!("seg[{}] page[{}]", seg_index, page_index),
                as_short_hex_string(start as u64),
            );
            if start & DYLD_CHAINED_PTR_START_MULTI == 0 {
                if !self.chain(&seg, seg_index, start, page_index, 0) {
                    return false;
                }
                continue;
            }

            let overflow_index = start & !DYLD_CHAINED_PTR_START_LAST;
            self.row(
                self.blob_address(ps),
                "page_start_multi",
                format!("seg[{}] page[{}].overflow_index", seg_index, page_index),
                as_string(overflow_index),
            );
            for overflow_iter in 0..MAX_OVERFLOW_STARTS {
                if !self.step() {
                    return false;
                }
                let ov = overflow_starts
                    .wrapping_add((overflow_index as u64 + overflow_iter as u64) * 2);
                let Some(ov_start) = self.image.u16(ov) else {
                    break;
                };
                let is_last = ov_start & DYLD_CHAINED_PTR_START_LAST != 0;
                let start_off = ov_start & !DYLD_CHAINED_PTR_START_LAST;
                self.row(
                    self.blob_address(ov),
                    "page_start_multi.item",
                    format!(
                        "seg[{}] page[{}] overflow[{}]",
                        seg_index, page_index, overflow_iter
                    ),
                    format!(
                        "start=0x{} last={}",
                        as_short_hex_string(start_off as u64),
                        is_last
                    ),
                );
                if !self.chain(&seg, seg_index, start_off, page_index, overflow_iter) {
                    return false;
                }
                if is_last {
                    break;
                }
            }
        }
        true
    }

    fn starts(&mut self, header: &ChainedFixupsHeader, datasize: u32) {
        let starts_at = self.blob.wrapping_add(header.starts_offset as u64);
        let Some(seg_count) = self.image.u32(starts_at) else {
            self.row(
                "-".to_string(),
                "error",
                "starts_in_image".to_string(),
                "truncated".to_string(),
            );
            return;
        };
        self.row(
            self.field_address(header.starts_offset),
            "starts_in_image",
            "seg_count".to_string(),
            as_string(seg_count),
        );
        let entries = starts_at.wrapping_add(4);
        for seg_index in 0..seg_count {
            if !self.step() {
                return;
            }
            let entry = entries.wrapping_add(seg_index as u64 * 4);
            let Some(seg_info_off) = self.image.u32(entry) else {
                break;
            };
            self.row(
                self.blob_address(entry),
                "segment",
                format!("seg[{}].info_offset", seg_index),
                as_short_hex_string(seg_info_off as u64),
            );
            if seg_info_off == 0 || seg_info_off >= datasize {
                continue;
            }
            if !self.segment(seg_index, seg_info_off) {
                return;
            }
        }
    }

    fn imports(&mut self, header: &ChainedFixupsHeader, datasize: u32) {
        if header.imports_offset >= datasize || header.imports_count == 0 {
            return;
        }
        self.row("-".to_string(), "-", "-".to_string(), "-".to_string());
        self.row(
            self.field_address(header.imports_offset),
            "imports",
            "format".to_string(),
            import_format_name(header.imports_format).to_string(),
        );
        let Some(entry_size) = ChainedImport::entry_size(header.imports_format) else {
            return;
        };
        let datasize = datasize as u64;
        let blob_end = self.blob.saturating_add(datasize);
        for i in 0..header.imports_count.min(MAX_IMPORTS) {
            let entry_off = header.imports_offset as u64 + i as u64 * entry_size;
            if entry_off + entry_size > datasize {
                break;
            }
            let Some(import) = ChainedImport::read(
                self.image,
                self.blob.saturating_add(entry_off),
                header.imports_format,
            ) else {
                break;
            };
            let addend = match import.addend {
                ImportAddend::None => "-".to_string(),
                ImportAddend::Signed32(v) => as_string(v),
                ImportAddend::Unsigned64(v) => as_short_hex_string(v),
            };
            // The name runs to its terminator, searched up to the blob end.
            let name_rel = (header.symbols_offset as u64).wrapping_add(import.name_offset);
            let name = (name_rel < datasize)
                .then(|| self.blob.saturating_add(name_rel))
                .and_then(|at| self.image.slice(at, blob_end.saturating_sub(at)))
                .and_then(|bytes| {
                    bytes
                        .iter()
                        .position(|&c| c == 0)
                        .and_then(|len| bytes.get(..len))
                });
            let symbol = name
                .map(utf8_safe)
                .unwrap_or_else(|| "<invalid>".to_string());
            self.row(
                as_address((self.dataoff as u64).wrapping_add(entry_off)),
                "import",
                format!("#{}", i),
                format!(
                    "lib={} weak={} addend={} symbol={}",
                    import.lib_ordinal, import.weak_import, addend, symbol
                ),
            );
        }
    }
}

pub(super) fn content(mh: &MachHeader, data: &LinkeditData) -> Content {
    let mut t = Table::new();
    t.set_headers(&["Offset", "Type", "Field", "Value"]);
    t.set_widths(&[120, 240, 240, 420]);
    let image = &*mh.image;
    if !image.in_file(data.file_offset, data.datasize as u64) {
        t.add(["-", "error", "chained fixups", "blob out of range"]);
        return Content::table(t);
    }
    let Some(header) = ChainedFixupsHeader::read(image, data.file_offset) else {
        t.add(["-", "error", "header", "truncated"]);
        return Content::table(t);
    };

    let mut w = Walk {
        image,
        t,
        dataoff: data.dataoff,
        blob: data.file_offset,
        steps: 0,
    };
    let fields = [
        ("fixups_version", as_string(header.fixups_version)),
        (
            "starts_offset",
            as_short_hex_string(header.starts_offset as u64),
        ),
        (
            "imports_offset",
            as_short_hex_string(header.imports_offset as u64),
        ),
        (
            "symbols_offset",
            as_short_hex_string(header.symbols_offset as u64),
        ),
        ("imports_count", as_string(header.imports_count)),
        (
            "imports_format",
            import_format_name(header.imports_format).to_string(),
        ),
        ("symbols_format", as_string(header.symbols_format)),
    ];
    let mut delta = 0u32;
    for (name, value) in fields {
        w.row(w.field_address(delta), "header", name.to_string(), value);
        delta += 4;
    }
    w.starts(&header, data.datasize);
    w.imports(&header, data.datasize);

    // The address label is the header-relative `dataoff`.
    Content::table(w.t).with_binary_at(data.file_offset, data.datasize as u64, data.dataoff as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::LC_DYLD_CHAINED_FIXUPS;
    use std::sync::Arc;

    /// A 64-bit Mach-O whose only load command is `LC_DYLD_CHAINED_FIXUPS`
    /// with `blob` stored at file offset 0x100.
    fn macho_with_fixups(blob: &[u8]) -> Arc<MachHeader> {
        let mut f = Vec::new();
        for v in [
            0xfeed_facfu32,
            0x0100_000c,
            0,
            6,
            1,
            16,
            0,
            0,
            LC_DYLD_CHAINED_FIXUPS,
            16,
            0x100,
            blob.len() as u32,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.resize(0x100, 0);
        f.extend_from_slice(blob);
        let image = Arc::new(Image::from_vec(f).unwrap());
        Arc::new(MachHeader::parse(&image, 0).unwrap())
    }

    fn table_of(mh: &MachHeader) -> Table {
        let data = mh.linkedit_data(LC_DYLD_CHAINED_FIXUPS).unwrap();
        content(mh, &data).table.unwrap()
    }

    fn header(starts: u32, imports: u32, symbols: u32, count: u32, format: u32) -> Vec<u8> {
        [0, starts, imports, symbols, count, format, 0]
            .iter()
            .flat_map(|v: &u32| v.to_le_bytes())
            .collect()
    }

    #[test]
    fn segment_info_is_read_relative_to_the_blob() {
        // starts_in_image at 0x1c: one segment whose info offset is 0x28.
        let mut blob = header(0x1c, 0x48, 0x4c, 1, 1);
        blob.extend(1u32.to_le_bytes());
        blob.extend(0x28u32.to_le_bytes());
        blob.resize(0x28, 0);
        // dyld_chained_starts_in_segment: page_size 0x10, format 2 (64),
        // segment_offset 0x180, page_count 1; page start read at +24.
        blob.extend(0u32.to_le_bytes());
        blob.extend(0x10u16.to_le_bytes());
        blob.extend(2u16.to_le_bytes());
        blob.extend(0x180u64.to_le_bytes());
        blob.extend(0u32.to_le_bytes());
        blob.extend(1u16.to_le_bytes());
        blob.extend(0xAAAAu16.to_le_bytes());
        blob.extend(0x8u16.to_le_bytes());
        blob.resize(0x48, 0);
        blob.extend((1u32 | (1 << 9)).to_le_bytes()); // import: lib 1, name offset 1
        blob.extend(b"\0_puts\0");
        blob.resize(0x90, 0);
        // Two fixups at file offset 0x188: a rebase (next = 2) and a bind.
        blob[0x88..0x90].copy_from_slice(&0x0010_0000_0000_4000u64.to_le_bytes());
        blob.extend(0x8000_0000_0000_0000u64.to_le_bytes());

        let t = table_of(&macho_with_fixups(&blob));
        let cells: Vec<Vec<&str>> = t
            .rows
            .iter()
            .map(|r| r.cells.iter().map(String::as_str).collect())
            .collect();
        assert_eq!(cells[7], ["0000011C", "starts_in_image", "seg_count", "1"]);
        assert_eq!(
            cells[8],
            ["00000120", "segment", "seg[0].info_offset", "28"]
        );
        assert_eq!(cells[9], ["00000128", "segment", "seg[0].page_size", "16"]);
        assert_eq!(
            cells[10],
            ["0000012E", "segment", "seg[0].pointer_format", "64"]
        );
        assert_eq!(cells[13], ["00000140", "page_start", "seg[0] page[0]", "8"]);
        assert_eq!(
            cells[14],
            [
                "00000188",
                "fixup",
                "seg[0] page[0] chain[0:0]",
                "raw=0x10000000004000 next=2 rebase target-vm=0x4000 high8=0x0"
            ]
        );
        assert_eq!(
            cells[15],
            [
                "00000190",
                "fixup",
                "seg[0] page[0] chain[0:1]",
                "raw=0x8000000000000000 next=0 bind ordinal=0 addend=0"
            ]
        );
        assert_eq!(cells[16], ["-", "-", "-", "-"]);
        assert_eq!(
            cells[17],
            ["00000148", "imports", "format", "DYLD_CHAINED_IMPORT"]
        );
        assert_eq!(
            cells[18],
            [
                "00000148",
                "import",
                "#0",
                "lib=1 weak=0 addend=- symbol=_puts"
            ]
        );
        assert_eq!(cells.len(), 19);
    }

    #[test]
    fn truncated_blobs() {
        let t = table_of(&macho_with_fixups(&[0; 8]));
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.rows[0].cells, ["-", "error", "header", "truncated"]);
        // starts_offset past the end of the file.
        let t = table_of(&macho_with_fixups(&header(0x1000, 0, 0, 0, 1)));
        assert_eq!(t.rows.len(), 8);
        assert_eq!(
            t.rows[7].cells,
            ["-", "error", "starts_in_image", "truncated"]
        );
    }

    #[test]
    fn hostile_page_tables_are_bounded() {
        // 65535 pages, each a multi-start whose overflow list never ends:
        // unbounded, this is tens of millions of rows.
        let mut blob = header(0x1c, 0, 0, 0, 1);
        blob.extend(u32::MAX.to_le_bytes());
        blob.extend(0x40u32.to_le_bytes());
        blob.resize(0x40, 0);
        blob.extend(0u32.to_le_bytes());
        blob.extend(0x10u16.to_le_bytes());
        blob.extend(3u16.to_le_bytes());
        blob.extend(0u64.to_le_bytes());
        blob.extend(0u32.to_le_bytes());
        blob.extend(0xFFFFu16.to_le_bytes());
        blob.extend(0u16.to_le_bytes());
        for _ in 0..0xFFFF {
            blob.extend(0x8000u16.to_le_bytes());
        }
        blob.resize(blob.len() + 0x4000, 0);
        let t = table_of(&macho_with_fixups(&blob));
        assert!(
            t.rows.len() >= MAX_FIXUP_ROWS && t.rows.len() <= MAX_FIXUP_ROWS + 8,
            "{}",
            t.rows.len()
        );
    }
}
