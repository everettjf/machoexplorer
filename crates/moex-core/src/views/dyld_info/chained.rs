//! "Chained Fixups (LC_DYLD_CHAINED_FIXUPS)" table: header, per-segment
//! starts, every fixup of every chain, and the imports table, decoded per
//! `<mach-o/fixup-chains.h>`.
//!
//! The Offset column and the row byte ranges are file offsets. A fixup row
//! also gives the fixup's (unslid) virtual address, the value dyld would
//! store there for a rebase, and the imported symbol for a bind.

use crate::hex::{as_address, as_short_hex_string, as_string, utf8_safe};
use crate::macho::chained_fixups::{
    decode_next, decode_pointer, import_format_name, pointer_format_name, pointer_layout,
    ChainedFixupsHeader, ChainedImport, ChainedPointer, ChainedStartsInSegment, ImportAddend,
    PointerLayout, CHAINED_STARTS_PAGE_START_OFFSET, DYLD_CHAINED_PTR_32,
    DYLD_CHAINED_PTR_START_LAST, DYLD_CHAINED_PTR_START_MULTI, DYLD_CHAINED_PTR_START_NONE,
};
use crate::macho::{LinkeditData, MachHeader};
use crate::view::{Content, Table};

/// Most fixups followed from one start. A chain cannot leave its page and
/// a page holds at most 65535 bytes, so no well-formed chain is longer.
const MAX_CHAIN_LENGTH: u32 = 65536;
/// Most overflow starts read for one page.
const MAX_OVERFLOW_STARTS: u32 = 1024;
/// Most import entries listed.
const MAX_IMPORTS: u32 = 1_000_000;
/// Bounds on the whole starts walk, so that a crafted blob (65535 pages x
/// 1024 overflow starts x a page of fixups, per segment) cannot make it run
/// practically forever; no real binary gets near these.
const MAX_FIXUP_ROWS: usize = 1_000_000;
const MAX_WALK_STEPS: u64 = 8_000_000;

struct Walk<'a> {
    mh: &'a MachHeader,
    t: Table,
    /// File offset and size of the blob.
    blob: u64,
    datasize: u64,
    header: ChainedFixupsHeader,
    /// The image's preferred load address.
    base: u64,
    steps: u64,
    /// The symbols pool inflated, when it is stored as a zlib stream
    /// (`symbols_format` 1) that could be read.
    inflated: Option<Vec<u8>>,
}

impl Walk<'_> {
    /// Charges one unit of work; false once the walk must stop.
    fn step(&mut self) -> bool {
        self.steps = self.steps.saturating_add(1);
        self.steps <= MAX_WALK_STEPS && self.t.rows.len() < MAX_FIXUP_ROWS
    }

    /// Row describing `size` bytes at offset `rel` of the blob.
    fn row(&mut self, rel: u64, size: u64, kind: &str, field: String, value: String) {
        let at = self.blob.saturating_add(rel);
        self.t
            .add_data(at, size, [as_address(at), kind.to_string(), field, value]);
    }

    fn note(&mut self, kind: &str, field: String, value: &str) {
        self.t
            .add(["-".to_string(), kind.to_string(), field, value.to_string()]);
    }

    /// File offset of `size` bytes at offset `rel` of the blob; `None` when
    /// they are not wholly inside it.
    fn blob_at(&self, rel: u64, size: u64) -> Option<u64> {
        (rel.checked_add(size)? <= self.datasize).then(|| self.blob + rel)
    }

    fn blob_u16(&self, rel: u64) -> Option<u16> {
        self.mh.image.u16(self.blob_at(rel, 2)?)
    }

    fn blob_u32(&self, rel: u64) -> Option<u32> {
        self.mh.image.u32(self.blob_at(rel, 4)?)
    }

    /// Entry `ordinal` of the imports table.
    fn import(&self, ordinal: u32) -> Option<ChainedImport> {
        if ordinal >= self.header.imports_count {
            return None;
        }
        let entry_size = ChainedImport::entry_size(self.header.imports_format)?;
        let rel = (self.header.imports_offset as u64).checked_add(ordinal as u64 * entry_size)?;
        ChainedImport::read(
            &self.mh.image,
            self.blob_at(rel, entry_size)?,
            self.header.imports_format,
        )
    }

    /// Name of `import` from the symbols pool: the bytes up to the
    /// terminator, searched no further than the end of the blob (of the
    /// inflated pool when it is compressed). `None` when the pool's format
    /// is not known or it cannot be inflated, the offset is outside the
    /// pool or the name is unterminated.
    fn import_name(&self, import: &ChainedImport) -> Option<String> {
        if self.header.symbols_format == 1 {
            let pool = self.inflated.as_deref()?;
            let bytes = pool.get(usize::try_from(import.name_offset).ok()?..)?;
            let len = bytes.iter().position(|&c| c == 0)?;
            return Some(utf8_safe(bytes.get(..len)?));
        }
        if self.header.symbols_format != 0 {
            return None;
        }
        let rel = (self.header.symbols_offset as u64).checked_add(import.name_offset)?;
        let at = self.blob_at(rel, 1)?;
        let bytes = self.mh.image.slice(at, self.datasize - rel)?;
        let len = bytes.iter().position(|&c| c == 0)?;
        Some(utf8_safe(bytes.get(..len)?))
    }

    /// Follow one chain that starts `start` bytes into page `page_index` of
    /// the segment. Returns false when the walk budget ran out.
    #[allow(clippy::too_many_arguments)]
    fn chain(
        &mut self,
        seg: &ChainedStartsInSegment,
        layout: PointerLayout,
        seg_index: u32,
        start: u16,
        page_index: u16,
        multi_index: u32,
    ) -> bool {
        // `segment_offset` is the segment's distance from the load address;
        // the page is found in the file through the segment that maps it.
        let page_vm = self
            .base
            .wrapping_add(seg.segment_offset)
            .wrapping_add(page_index as u64 * seg.page_size as u64);
        let Some(page_file) = self.mh.vm_to_file_offset_any(page_vm) else {
            self.note(
                "error",
                format!("seg[{}] page[{}]", seg_index, page_index),
                "page is not mapped to the file",
            );
            return true;
        };
        let mut in_page = start as u64;
        for chain_index in 0..MAX_CHAIN_LENGTH {
            // A fixup lies wholly inside its page.
            if in_page + layout.width > seg.page_size as u64 {
                break;
            }
            let at = page_file + in_page;
            let raw = if layout.width == 8 {
                self.mh.image.u64(at)
            } else {
                self.mh.image.u32(at).map(u64::from)
            };
            let Some(raw) = raw else { break };
            if !self.step() {
                return false;
            }
            let next = decode_next(seg.pointer_format, raw);
            let pointer = decode_pointer(seg.pointer_format, raw);
            let detail = match pointer {
                // DYLD_CHAINED_PTR_32 chains may run through values that are
                // not pointers: anything above `max_valid_pointer`, stored
                // with a bias.
                ChainedPointer::Rebase { target, .. }
                    if seg.pointer_format == DYLD_CHAINED_PTR_32
                        && seg.max_valid_pointer != 0
                        && target > seg.max_valid_pointer as u64 =>
                {
                    let bias = (0x0400_0000 + seg.max_valid_pointer as u64) / 2;
                    format!("non-pointer value=0x{:X}", target.wrapping_sub(bias))
                }
                ChainedPointer::Bind { ordinal, .. } => {
                    let symbol = self.import(ordinal).and_then(|i| self.import_name(&i));
                    pointer.describe(self.base, symbol.as_deref())
                }
                _ => pointer.describe(self.base, None),
            };
            self.t.add_data(
                at,
                layout.width,
                [
                    as_address(at),
                    "fixup".to_string(),
                    format!(
                        "seg[{}] page[{}] chain[{}:{}]",
                        seg_index, page_index, multi_index, chain_index
                    ),
                    format!(
                        "addr=0x{:X} raw=0x{:X} next={} {}",
                        page_vm.wrapping_add(in_page),
                        raw,
                        next,
                        detail
                    ),
                ],
            );
            if next == 0 {
                break;
            }
            in_page += next * layout.stride;
        }
        true
    }

    /// One `dyld_chained_starts_in_segment` at offset `seg_rel` of the
    /// blob. Returns false when the walk budget ran out.
    fn segment(&mut self, seg_index: u32, seg_rel: u64) -> bool {
        let name = |field: &str| format!("seg[{}].{}", seg_index, field);
        let seg = self
            .blob_at(seg_rel, CHAINED_STARTS_PAGE_START_OFFSET)
            .and_then(|at| ChainedStartsInSegment::read(&self.mh.image, at));
        let Some(seg) = seg else {
            self.note("error", name("starts_in_segment"), "truncated");
            return true;
        };
        self.row(seg_rel, 4, "segment", name("size"), as_string(seg.size));
        self.row(
            seg_rel + 4,
            2,
            "segment",
            name("page_size"),
            as_short_hex_string(seg.page_size as u64),
        );
        self.row(
            seg_rel + 6,
            2,
            "segment",
            name("pointer_format"),
            format!(
                "{} ({})",
                seg.pointer_format,
                pointer_format_name(seg.pointer_format)
            ),
        );
        self.row(
            seg_rel + 8,
            8,
            "segment",
            name("segment_offset"),
            as_short_hex_string(seg.segment_offset),
        );
        self.row(
            seg_rel + 16,
            4,
            "segment",
            name("max_valid_pointer"),
            as_short_hex_string(seg.max_valid_pointer as u64),
        );
        self.row(
            seg_rel + 20,
            2,
            "segment",
            name("page_count"),
            as_string(seg.page_count),
        );
        let layout = pointer_layout(seg.pointer_format);
        if layout.is_none() {
            self.note(
                "error",
                name("pointer_format"),
                "unknown pointer format: chains not decoded",
            );
        }

        // `page_start[]` follows the fixed fields; the overflow starts of
        // multi-start pages are further entries of the same array.
        let page_starts = seg_rel + CHAINED_STARTS_PAGE_START_OFFSET;
        for page_index in 0..seg.page_count {
            if !self.step() {
                return false;
            }
            let ps = page_starts + page_index as u64 * 2;
            let Some(start) = self.blob_u16(ps) else {
                break;
            };
            if start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            let page = format!("seg[{}] page[{}]", seg_index, page_index);
            if start & DYLD_CHAINED_PTR_START_MULTI == 0 {
                self.row(ps, 2, "page_start", page, as_short_hex_string(start as u64));
                if let Some(layout) = layout {
                    if !self.chain(&seg, layout, seg_index, start, page_index, 0) {
                        return false;
                    }
                }
                continue;
            }

            let overflow_index = start & !DYLD_CHAINED_PTR_START_MULTI;
            self.row(
                ps,
                2,
                "page_start_multi",
                format!("{page}.overflow_index"),
                as_string(overflow_index),
            );
            for overflow_iter in 0..MAX_OVERFLOW_STARTS {
                if !self.step() {
                    return false;
                }
                let ov = page_starts + (overflow_index as u64 + overflow_iter as u64) * 2;
                let Some(ov_start) = self.blob_u16(ov) else {
                    break;
                };
                let is_last = ov_start & DYLD_CHAINED_PTR_START_LAST != 0;
                let start_off = ov_start & !DYLD_CHAINED_PTR_START_LAST;
                self.row(
                    ov,
                    2,
                    "page_start_multi.item",
                    format!("{page} overflow[{overflow_iter}]"),
                    format!(
                        "start=0x{} last={}",
                        as_short_hex_string(start_off as u64),
                        is_last
                    ),
                );
                if let Some(layout) = layout {
                    if !self.chain(
                        &seg,
                        layout,
                        seg_index,
                        start_off,
                        page_index,
                        overflow_iter,
                    ) {
                        return false;
                    }
                }
                if is_last {
                    break;
                }
            }
        }
        true
    }

    fn starts(&mut self) {
        let starts_rel = self.header.starts_offset as u64;
        let Some(seg_count) = self.blob_u32(starts_rel) else {
            self.note("error", "starts_in_image".to_string(), "truncated");
            return;
        };
        self.row(
            starts_rel,
            4,
            "starts_in_image",
            "seg_count".to_string(),
            as_string(seg_count),
        );
        for seg_index in 0..seg_count {
            if !self.step() {
                return;
            }
            let entry = starts_rel + 4 + seg_index as u64 * 4;
            let Some(seg_info_off) = self.blob_u32(entry) else {
                break;
            };
            self.row(
                entry,
                4,
                "segment",
                format!("seg[{}].info_offset", seg_index),
                as_short_hex_string(seg_info_off as u64),
            );
            // 0: the segment has no fixups. Otherwise the offset is relative
            // to `dyld_chained_starts_in_image`.
            if seg_info_off == 0 {
                continue;
            }
            if !self.segment(seg_index, starts_rel + seg_info_off as u64) {
                return;
            }
        }
    }

    fn imports(&mut self) {
        let header = self.header;
        if header.imports_count == 0 {
            return;
        }
        self.t.add(["-", "-", "-", "-"]);
        self.row(
            20,
            4,
            "imports",
            "format".to_string(),
            import_format_name(header.imports_format).to_string(),
        );
        let Some(entry_size) = ChainedImport::entry_size(header.imports_format) else {
            return;
        };
        match (header.symbols_format, &self.inflated) {
            (0, _) => {}
            (1, Some(pool)) => {
                let size = format!("zlib, {} bytes inflated", pool.len());
                self.note("imports", "symbols".to_string(), &size);
            }
            (1, None) => self.note(
                "imports",
                "symbols".to_string(),
                "the zlib stream of symbol names cannot be read",
            ),
            _ => self.note(
                "imports",
                "symbols".to_string(),
                "symbol names are in a format that is not known",
            ),
        }
        for i in 0..header.imports_count {
            if i >= MAX_IMPORTS {
                self.note("imports", "...".to_string(), "row limit reached");
                break;
            }
            let Some(import) = self.import(i) else {
                break;
            };
            let addend = match import.addend {
                ImportAddend::None => "-".to_string(),
                ImportAddend::Signed32(v) => as_string(v),
                ImportAddend::Unsigned64(v) => format!("0x{v:X}"),
            };
            let symbol = self
                .import_name(&import)
                .unwrap_or_else(|| "<invalid>".to_string());
            self.row(
                header.imports_offset as u64 + i as u64 * entry_size,
                entry_size,
                "import",
                format!("#{}", i),
                format!(
                    "lib={} weak={} addend={} symbol={}",
                    import.lib_ordinal, import.weak_import as u8, addend, symbol
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
    let header = ChainedFixupsHeader::read(image, data.file_offset).filter(|_| {
        data.datasize as u64 >= crate::macho::chained_fixups::CHAINED_FIXUPS_HEADER_SIZE
    });
    let Some(header) = header else {
        t.add(["-", "error", "header", "truncated"]);
        return Content::table(t);
    };

    let mut w = Walk {
        mh,
        t,
        blob: data.file_offset,
        datasize: data.datasize as u64,
        header,
        base: mh.base_address(),
        steps: 0,
        inflated: None,
    };
    if header.symbols_format == 1 {
        // The stream runs from the start of the pool to the end of the blob.
        let pool = u64::from(header.symbols_offset);
        w.inflated = w
            .blob_at(pool, 0)
            .and_then(|at| mh.image.slice(at, w.datasize - pool))
            .and_then(crate::macho::ptr::inflate);
    }
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
    for (i, (name, value)) in fields.into_iter().enumerate() {
        w.row(i as u64 * 4, 4, "header", name.to_string(), value);
    }
    w.starts();
    w.imports();

    Content::table(w.t).with_binary(data.file_offset, data.datasize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{LC_DYLD_CHAINED_FIXUPS, LC_SEGMENT_64};
    use crate::image::Image;
    use std::sync::Arc;

    /// A 64-bit Mach-O placed `at` bytes into the file with two load
    /// commands: a `__DATA` segment (vm 0x1_0000_0000, 0x400 bytes at slice
    /// offset 0) and `LC_DYLD_CHAINED_FIXUPS` with `blob` at slice offset
    /// 0x400. `data` is written at slice offset 0x200.
    fn macho_with_fixups_at(at: usize, blob: &[u8], data: &[u8]) -> Arc<MachHeader> {
        let mut f = vec![0u8; at];
        for v in [0xfeed_facfu32, 0x0100_000c, 0, 6, 2, 72 + 16, 0, 0] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        for v in [LC_SEGMENT_64, 72] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(b"__DATA\0\0\0\0\0\0\0\0\0\0");
        for v in [0x1_0000_0000u64, 0x400, 0, 0x400] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(&[0u8; 16]);
        for v in [LC_DYLD_CHAINED_FIXUPS, 16, 0x400, blob.len() as u32] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.resize(at + 0x200, 0);
        f.extend_from_slice(data);
        f.resize(at + 0x400, 0);
        f.extend_from_slice(blob);
        let image = Arc::new(Image::from_vec(f).unwrap());
        Arc::new(MachHeader::parse(&image, at as u64).unwrap())
    }

    fn table_of(mh: &MachHeader) -> Table {
        let data = mh.linkedit_data(LC_DYLD_CHAINED_FIXUPS).unwrap();
        content(mh, &data).table.unwrap()
    }

    fn cells(t: &Table) -> Vec<Vec<&str>> {
        t.rows
            .iter()
            .map(|r| r.cells.iter().map(String::as_str).collect())
            .collect()
    }

    fn header(starts: u32, imports: u32, symbols: u32, count: u32, format: u32) -> Vec<u8> {
        [0, starts, imports, symbols, count, format, 0]
            .iter()
            .flat_map(|v: &u32| v.to_le_bytes())
            .collect()
    }

    /// `dyld_chained_starts_in_segment` fixed fields plus `page_start[]`.
    fn starts_in_segment(format: u16, segment_offset: u64, page_starts: &[u16]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend((22 + 2 * page_starts.len() as u32).to_le_bytes());
        s.extend(0x100u16.to_le_bytes());
        s.extend(format.to_le_bytes());
        s.extend(segment_offset.to_le_bytes());
        s.extend(0u32.to_le_bytes());
        s.extend((page_starts.len() as u16).to_le_bytes());
        for p in page_starts {
            s.extend(p.to_le_bytes());
        }
        s
    }

    /// Blob: header, starts_in_image at 0x1c with two segments (the first
    /// without fixups, the second's info 0x10 bytes into starts_in_image),
    /// one import `_puts` from lib 1.
    fn sample_blob(format: u16, page_starts: &[u16]) -> Vec<u8> {
        let mut blob = header(0x1c, 0x60, 0x64, 1, 1);
        blob.extend(2u32.to_le_bytes());
        blob.extend(0u32.to_le_bytes());
        blob.extend(0x10u32.to_le_bytes());
        blob.resize(0x1c + 0x10, 0);
        blob.extend(starts_in_segment(format, 0x200, page_starts));
        assert!(blob.len() <= 0x60);
        blob.resize(0x60, 0);
        blob.extend((1u32 | (1 << 9)).to_le_bytes()); // lib 1, name offset 1
        blob.extend(b"\0_puts\0");
        blob
    }

    #[test]
    fn decodes_starts_relative_to_starts_in_image() {
        // Page 0 has no fixups; page 1 (at slice offset 0x300) has a chain
        // starting at 8: a rebase to vm offset 0x4000 (next = 2, stride 4)
        // and a bind of import 0.
        let mut data = vec![0u8; 0x200];
        data[0x108..0x110].copy_from_slice(&0x0010_0000_0000_4000u64.to_le_bytes());
        data[0x110..0x118].copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
        for at in [0usize, 0x4000] {
            let mh = macho_with_fixups_at(at, &sample_blob(6, &[0xFFFF, 8]), &data);
            let t = table_of(&mh);
            let row = |rel: u64, kind: &str, field: &str, value: &str| {
                vec![
                    as_address(at as u64 + rel),
                    kind.to_string(),
                    field.to_string(),
                    value.to_string(),
                ]
            };
            let c = |i: usize| t.rows[i].cells.clone();
            assert_eq!(c(0), row(0x400, "header", "fixups_version", "0"));
            assert_eq!(c(7), row(0x41c, "starts_in_image", "seg_count", "2"));
            assert_eq!(c(8), row(0x420, "segment", "seg[0].info_offset", "0"));
            assert_eq!(c(9), row(0x424, "segment", "seg[1].info_offset", "10"));
            // starts_in_segment at starts_in_image + 0x10 = blob + 0x2c.
            assert_eq!(c(10), row(0x42c, "segment", "seg[1].size", "26"));
            assert_eq!(c(11), row(0x430, "segment", "seg[1].page_size", "100"));
            assert_eq!(
                c(12),
                row(0x432, "segment", "seg[1].pointer_format", "6 (64_OFFSET)")
            );
            assert_eq!(c(13), row(0x434, "segment", "seg[1].segment_offset", "200"));
            assert_eq!(c(15), row(0x440, "segment", "seg[1].page_count", "2"));
            // page_start[] at +22; entry 1 at +24.
            assert_eq!(c(16), row(0x444, "page_start", "seg[1] page[1]", "8"));
            assert_eq!(
                c(17),
                row(
                    0x308,
                    "fixup",
                    "seg[1] page[1] chain[0:0]",
                    "addr=0x100000308 raw=0x10000000004000 next=2 rebase target=0x100004000"
                )
            );
            assert_eq!(
                c(18),
                row(
                    0x310,
                    "fixup",
                    "seg[1] page[1] chain[0:1]",
                    "addr=0x100000310 raw=0x8000000000000000 next=0 bind ordinal=0 symbol=_puts"
                )
            );
            assert_eq!(c(19), ["-", "-", "-", "-"]);
            assert_eq!(
                c(20),
                row(0x414, "imports", "format", "DYLD_CHAINED_IMPORT")
            );
            assert_eq!(
                c(21),
                row(0x460, "import", "#0", "lib=1 weak=0 addend=- symbol=_puts")
            );
            assert_eq!(t.rows.len(), 22);
            assert_eq!(
                (t.rows[17].offset, t.rows[17].size),
                (Some(at as u64 + 0x308), 8)
            );
        }
    }

    #[test]
    fn arm64e_chains_use_an_8_byte_stride() {
        // DYLD_CHAINED_PTR_ARM64E_USERLAND24: rebase (next 1), auth-bind
        // (next 2), auth-rebase (end).
        let mut data = vec![0u8; 0x200];
        data[0x10..0x18].copy_from_slice(&0x0008_0000_0000_067Bu64.to_le_bytes());
        data[0x18..0x20].copy_from_slice(&0xC011_0000_0000_0000u64.to_le_bytes());
        data[0x28..0x30].copy_from_slice(&0x8000_0000_0000_0700u64.to_le_bytes());
        let mh = macho_with_fixups_at(0, &sample_blob(12, &[0x10]), &data);
        let t = table_of(&mh);
        let fixups: Vec<(&str, &str)> = cells(&t)
            .into_iter()
            .filter(|c| c[1] == "fixup")
            .map(|c| (c[0], c[3]))
            .collect();
        assert_eq!(
            fixups,
            [
                (
                    "00000210",
                    "addr=0x100000210 raw=0x800000000067B next=1 rebase target=0x10000067B"
                ),
                (
                    "00000218",
                    "addr=0x100000218 raw=0xC011000000000000 next=2 auth-bind ordinal=0 \
                     symbol=_puts key=IA addrDiv=1 diversity=0x0000"
                ),
                (
                    "00000228",
                    "addr=0x100000228 raw=0x8000000000000700 next=0 auth-rebase \
                     target=0x100000700 key=IA addrDiv=0 diversity=0x0000"
                ),
            ]
        );
    }

    #[test]
    fn multi_start_pages_and_32_bit_pointers() {
        // DYLD_CHAINED_PTR_32: the only page has two starts, listed after the
        // page table from page_start[1]: 0x4 and 0x20 (last).
        let mut data = vec![0u8; 0x200];
        data[0x4..0x8].copy_from_slice(&0x0400_1000u32.to_le_bytes()); // next 1
        data[0x8..0xc].copy_from_slice(&0x8010_0000u32.to_le_bytes()); // bind, addend 1
        data[0x20..0x24].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        let mut blob = sample_blob(3, &[0x8001, 0x0004, 0x8020]);
        blob[0x2c + 20..0x2c + 22].copy_from_slice(&1u16.to_le_bytes()); // page_count
        let mh = macho_with_fixups_at(0, &blob, &data);
        let t = table_of(&mh);
        let c = cells(&t);
        let rows: Vec<(&str, &str, &str)> = c
            .iter()
            .filter(|c| c[1].starts_with("page_start") || c[1] == "fixup")
            .map(|c| (c[1], c[2], c[3]))
            .collect();
        assert_eq!(
            rows,
            [
                ("page_start_multi", "seg[1] page[0].overflow_index", "1"),
                (
                    "page_start_multi.item",
                    "seg[1] page[0] overflow[0]",
                    "start=0x4 last=false"
                ),
                (
                    "fixup",
                    "seg[1] page[0] chain[0:0]",
                    "addr=0x100000204 raw=0x4001000 next=1 rebase target=0x1000"
                ),
                (
                    "fixup",
                    "seg[1] page[0] chain[0:1]",
                    "addr=0x100000208 raw=0x80100000 next=0 bind ordinal=0 symbol=_puts addend=1"
                ),
                (
                    "page_start_multi.item",
                    "seg[1] page[0] overflow[1]",
                    "start=0x20 last=true"
                ),
                (
                    "fixup",
                    "seg[1] page[0] chain[1:0]",
                    "addr=0x100000220 raw=0x2000 next=0 rebase target=0x2000"
                ),
            ]
        );
    }

    #[test]
    fn unknown_format_and_unmapped_page() {
        let mh = macho_with_fixups_at(0, &sample_blob(99, &[0x10]), &[]);
        let t = table_of(&mh);
        let c = cells(&t);
        assert!(c.contains(&vec![
            "-",
            "error",
            "seg[1].pointer_format",
            "unknown pointer format: chains not decoded"
        ]));
        assert!(!c.iter().any(|r| r[1] == "fixup"));
        // segment_offset 0x200 + page 4 * 0x100 is past the segment.
        let mh = macho_with_fixups_at(
            0,
            &sample_blob(6, &[0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0]),
            &[],
        );
        let t = table_of(&mh);
        let c = cells(&t);
        assert!(c.contains(&vec![
            "-",
            "error",
            "seg[1] page[4]",
            "page is not mapped to the file"
        ]));
    }

    #[test]
    fn truncated_blobs() {
        let t = table_of(&macho_with_fixups_at(0, &[0; 8], &[]));
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.rows[0].cells, ["-", "error", "header", "truncated"]);
        // starts_offset past the end of the blob.
        let t = table_of(&macho_with_fixups_at(0, &header(0x1000, 0, 0, 0, 1), &[]));
        assert_eq!(t.rows.len(), 8);
        assert_eq!(
            t.rows[7].cells,
            ["-", "error", "starts_in_image", "truncated"]
        );
        // Segment info offset outside the blob.
        let mut blob = header(0x1c, 0, 0, 0, 1);
        blob.extend(1u32.to_le_bytes());
        blob.extend(0x4000u32.to_le_bytes());
        let t = table_of(&macho_with_fixups_at(0, &blob, &[]));
        assert_eq!(
            t.rows.last().unwrap().cells,
            ["-", "error", "seg[0].starts_in_segment", "truncated"]
        );
    }

    #[test]
    fn hostile_page_tables_are_bounded() {
        // Thousands of pages, each a multi-start whose overflow list never
        // ends: unbounded, this is tens of millions of rows.
        let mut blob = header(0x1c, 0, 0, 0, 1);
        blob.extend(u32::MAX.to_le_bytes());
        blob.extend(0x24u32.to_le_bytes());
        blob.resize(0x40, 0);
        blob.extend(0u32.to_le_bytes());
        blob.extend(0x10u16.to_le_bytes());
        blob.extend(3u16.to_le_bytes());
        blob.extend(0u64.to_le_bytes());
        blob.extend(0u32.to_le_bytes());
        // 0x7000 pages, each multi-start with its overflow list in the
        // zeros after the page table (start 0, never "last").
        blob.extend(0x7000u16.to_le_bytes());
        for _ in 0..0x7000 {
            blob.extend(0xF000u16.to_le_bytes());
        }
        blob.resize(blob.len() + 0x4000, 0);
        let t = table_of(&macho_with_fixups_at(0, &blob, &[]));
        assert!(
            t.rows.len() >= MAX_FIXUP_ROWS && t.rows.len() <= MAX_FIXUP_ROWS + 8,
            "{}",
            t.rows.len()
        );
    }
}
