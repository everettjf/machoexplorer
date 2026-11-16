//! dyld shared cache tools: list the images of a cache and extract an image
//! to a standalone Mach-O file. Shared by `moex cache-list`,
//! `moex cache-extract` and the GUI.
//!
//! Image paths are raw bytes (`Vec<u8>`): they come straight from the cache
//! and are not guaranteed to be UTF-8. Use [`CacheImage::path_str`] for
//! display.

use crate::consts::*;
use crate::hex::utf8_safe;
use crate::image::Image;
use crate::macho::dyld_cache::DyldSharedCache;
use crate::macho::{Binary, Kind};
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub use crate::macho::dyld_cache::CacheImage;

/// Bytes copied between cancellation checks / progress reports.
const COPY_CHUNK: u64 = 1024 * 1024;
const MAX_NCMDS: u32 = 65535;
const MAX_SIZEOFCMDS: u32 = 64 * 1024 * 1024;

pub const NOT_A_CACHE: &str = "input is not a dyld shared cache file";

/// Open `path` as a dyld shared cache. Fails with the parser's message when
/// the file cannot be parsed and with [`NOT_A_CACHE`] when it is some other
/// kind of binary.
pub fn open_cache(path: &Path) -> crate::Result<Arc<DyldSharedCache>> {
    match Binary::open(path)?.kind {
        Kind::DyldSharedCache(cache) => Ok(cache),
        _ => Err(crate::Error::new(NOT_A_CACHE)),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

/// Listing filter: an empty filter matches everything, otherwise the path
/// must equal (`exact`) or contain the filter.
pub fn filter_matches(path: &[u8], filter: &[u8], exact: bool) -> bool {
    if filter.is_empty() {
        true
    } else if exact {
        path == filter
    } else {
        contains(path, filter)
    }
}

/// Extraction selector: the path must equal the selector, or contain it
/// unless `exact`. Unlike [`filter_matches`], an empty selector with `exact`
/// only matches an empty path.
pub fn selector_matches(path: &[u8], selector: &[u8], exact: bool) -> bool {
    path == selector || (!exact && contains(path, selector))
}

/// Images matching a listing filter, sorted by path, then address.
pub fn list_images(cache: &DyldSharedCache, filter: &[u8], exact: bool) -> Vec<CacheImage> {
    let mut out: Vec<CacheImage> = cache
        .images()
        .filter(|i| filter_matches(&i.path, filter, exact))
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.address.cmp(&b.address)));
    out
}

/// Sorted, displayable paths of every image in the cache.
pub fn image_paths(cache: &DyldSharedCache) -> Vec<String> {
    list_images(cache, b"", false)
        .iter()
        .map(CacheImage::path_str)
        .collect()
}

/// Images matching an extraction selector, in cache order.
pub fn select_images(cache: &DyldSharedCache, selector: &[u8], exact: bool) -> Vec<CacheImage> {
    cache
        .images()
        .filter(|i| selector_matches(&i.path, selector, exact))
        .collect()
}

/// Minimal JSON string escaping used by the tools' hand-written JSON:
/// only `\`, `"`, newline, carriage return and tab are escaped.
pub fn json_escape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 16);
    for &c in s {
        match c {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Byte string to a filesystem path (lossless on Unix).
pub fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(utf8_safe(bytes))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtractOptions {
    /// Pack segments back to back (4 KiB aligned, the header's segment at
    /// offset 0, `__LINKEDIT` last). Without it each segment keeps the file
    /// offset its load command records, which is only possible when the
    /// whole image is in one cache file and those offsets overlap neither
    /// each other nor the header. Otherwise (every image of a split cache:
    /// its offsets are relative to different files) the compact layout is
    /// used anyway and [`ExtractPlan::compact`] / [`ExtractOutcome::compact`]
    /// say so.
    pub compact: bool,
    /// Compute the plan but do not write anything.
    pub dry_run: bool,
}

impl ExtractOptions {
    pub fn mode_name(&self) -> &'static str {
        if self.compact {
            "compact"
        } else {
            "raw-fileoff"
        }
    }
}

/// Why an extraction failed. `message` is the user-facing line (raw bytes,
/// because it can embed an image path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractError {
    pub message: Vec<u8>,
    /// True when the cancellation flag stopped the extraction.
    pub cancelled: bool,
}

impl ExtractError {
    fn new(prefix: &str, detail: &[u8]) -> Self {
        let mut message = prefix.as_bytes().to_vec();
        message.extend_from_slice(detail);
        ExtractError {
            message,
            cancelled: false,
        }
    }
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&utf8_safe(&self.message))
    }
}

impl std::error::Error for ExtractError {}

/// One segment to copy out of the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentCopyPlan {
    pub name: Vec<u8>,
    pub vmaddr: u64,
    /// The segment's `fileoff` as recorded in the image's load command.
    pub image_fileoff: u64,
    /// Which cache file holds the segment's bytes: 0 is the main file, `n`
    /// the n-th sub-cache (see [`DyldSharedCache::file_image`]).
    pub source_file: usize,
    /// Where the segment's bytes are in that file.
    pub source_fileoff: u64,
    /// Where they go in the output file.
    pub target_fileoff: u64,
    /// Bytes written to the output file. For the rebuilt `__LINKEDIT` this
    /// is the size of [`RebuiltLinkedit::data`], not the size in the cache.
    pub size: u64,
}

/// Everything needed to write one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPlan {
    /// Cache file (see [`SegmentCopyPlan::source_file`]) and offset of the
    /// image's Mach-O header.
    pub header_file: usize,
    pub header_fileoff: u64,
    pub is64: bool,
    pub mh_size: u64,
    pub sizeofcmds: u32,
    /// The segments with file content, in load command order.
    pub segments: Vec<SegmentCopyPlan>,
    pub out_size: u64,
    /// The layout used; true without [`ExtractOptions::compact`] when the
    /// recorded file offsets cannot be kept.
    pub compact: bool,
    /// Index in `segments` of the segment that starts with the Mach-O
    /// header, if there is one.
    pub header_segment: Option<usize>,
    /// Mach-O header and load commands of the output file.
    pub header: Vec<u8>,
    /// The output's `__LINKEDIT`.
    pub linkedit: RebuiltLinkedit,
}

/// Result of a successful (or dry-run) extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractOutcome {
    pub image_path: Vec<u8>,
    pub output: PathBuf,
    /// The layout used (see [`ExtractOptions::compact`]).
    pub compact: bool,
    pub dry_run: bool,
    /// Size in bytes of the output file.
    pub size: u64,
    pub segments: usize,
}

impl ExtractOutcome {
    fn output_bytes(&self) -> Vec<u8> {
        self.output.as_os_str().as_encoded_bytes().to_vec()
    }

    fn mode_name(&self) -> &'static str {
        if self.compact {
            "compact"
        } else {
            "raw-fileoff"
        }
    }

    /// Human-readable report: one `plan:` line for a dry run, otherwise the
    /// `extracted:` / `mode:` / `output:` lines. Newline terminated.
    pub fn text(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.dry_run {
            out.extend_from_slice(b"plan: ");
            out.extend_from_slice(&self.image_path);
            out.extend_from_slice(b" -> ");
            out.extend_from_slice(&self.output_bytes());
            out.extend_from_slice(
                format!(
                    " mode={} size={} bytes segments={}\n",
                    self.mode_name(),
                    self.size,
                    self.segments
                )
                .as_bytes(),
            );
        } else {
            out.extend_from_slice(b"extracted: ");
            out.extend_from_slice(&self.image_path);
            out.extend_from_slice(format!("\nmode: {}\noutput: ", self.mode_name()).as_bytes());
            out.extend_from_slice(&self.output_bytes());
            out.extend_from_slice(
                format!(" size={} bytes segments={}\n", self.size, self.segments).as_bytes(),
            );
        }
        out
    }

    /// The same report as one JSON line.
    pub fn json(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(if self.dry_run {
            b"{\"event\":\"plan\""
        } else {
            b"{\"event\":\"extracted\""
        });
        out.extend_from_slice(b",\"image\":\"");
        out.extend_from_slice(&json_escape(&self.image_path));
        out.extend_from_slice(b"\",\"output\":\"");
        out.extend_from_slice(&json_escape(&self.output_bytes()));
        out.extend_from_slice(
            format!(
                "\",\"mode\":\"{}\",\"size\":{},\"segments\":{}}}\n",
                self.mode_name(),
                self.size,
                self.segments
            )
            .as_bytes(),
        );
        out
    }
}

/// Progress of the copy phase of an extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractProgress<'a> {
    /// Segment being copied.
    pub segment: &'a [u8],
    pub bytes_done: u64,
    pub bytes_total: u64,
}

/// `value` rounded up to a multiple of `alignment` (a power of two);
/// `None` on overflow.
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    Some(value.checked_add(mask)? & !mask)
}

fn get_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn get_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    if let Some(dst) = off
        .checked_add(bytes.len())
        .and_then(|end| buf.get_mut(off..end))
    {
        dst.copy_from_slice(bytes);
    }
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    put(buf, off, &value.to_le_bytes());
}

const SEGMENT_COMMAND_SIZE: u64 = crate::macho::segment::SEGMENT_COMMAND_SIZE;
const SEGMENT_COMMAND_64_SIZE: u64 = crate::macho::segment::SEGMENT_COMMAND_64_SIZE;
const SYMTAB_COMMAND_SIZE: usize = 24;
const DYSYMTAB_COMMAND_SIZE: usize = 80;
const DYLD_INFO_COMMAND_SIZE: usize = 48;
const LINKEDIT_DATA_COMMAND_SIZE: usize = 16;

// `linkedit_data_command`s that `consts` does not name.
const LC_ATOM_INFO: u32 = 0x36;
const LC_FUNCTION_VARIANTS: u32 = 0x37;
const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
const LC_LAZY_LOAD_DYLIB_INFO: u32 = 0x3a;

/// Header flag of an image that the cache builder placed in a cache.
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

const CPU_TYPE_ARM: u32 = 12;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_INDR: u8 = 0x0a;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

/// Alignment of segments in the compact layout.
const SEGMENT_ALIGNMENT: u64 = 0x1000;

/// One load command: (cmd, offset in the load commands, cmdsize).
type LoadCommand = (u32, usize, usize);

/// The well-formed load commands at the start of `cmds`, at most `ncmds`.
fn load_commands(cmds: &[u8], ncmds: u32) -> Vec<LoadCommand> {
    let mut out = Vec::new();
    let mut parsed = 0usize;
    for _ in 0..ncmds {
        let (Some(cmd), Some(cmdsize)) = (get_u32(cmds, parsed), get_u32(cmds, parsed + 4)) else {
            break;
        };
        let cmdsize = cmdsize as usize;
        if cmdsize < LOAD_COMMAND_SIZE as usize || cmdsize > cmds.len() - parsed {
            break;
        }
        out.push((cmd, parsed, cmdsize));
        parsed += cmdsize;
    }
    out
}

fn is_linkedit_data_command(cmd: u32) -> bool {
    matches!(
        cmd,
        LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_SEGMENT_SPLIT_INFO
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_ATOM_INFO
            | LC_FUNCTION_VARIANTS
            | LC_FUNCTION_VARIANT_FIXUPS
            | LC_LAZY_LOAD_DYLIB_INFO
    )
}

/// A `__LINKEDIT` segment holding only what one image's load commands
/// reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuiltLinkedit {
    /// Index in [`ExtractPlan::segments`] of the segment these bytes
    /// replace; `None` when the image has no `__LINKEDIT` with file content
    /// (`data` is then empty).
    pub segment: Option<usize>,
    pub data: Vec<u8>,
    /// For each file-offset field of a load command that points into the
    /// segment: (offset of the `u32` field in the load commands, position
    /// in `data` it must point at).
    fixups: Vec<(usize, u32)>,
}

struct LinkeditBuilder<'a> {
    /// The image's `__LINKEDIT` as it is in the cache, and the file offset
    /// its load command gives it.
    src: &'a [u8],
    src_fileoff: u64,
    data: Vec<u8>,
    /// Upper bound for `data`: a rebuilt segment only holds parts of the
    /// original one, so anything larger means the commands overlap.
    limit: usize,
    fixups: Vec<(usize, u32)>,
}

const TOO_LARGE: &str = "load commands reference more data than the segment holds";

impl<'a> LinkeditBuilder<'a> {
    /// `size` bytes at file offset `off`, which must lie in the segment.
    fn source(&self, off: u32, size: u64) -> Option<&'a [u8]> {
        let start = (off as u64).checked_sub(self.src_fileoff)?;
        let end = start.checked_add(size)?;
        self.src
            .get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() > self.limit.saturating_sub(self.data.len()) {
            return Err(TOO_LARGE);
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    /// Start a new table at the next 8-byte boundary and make the file
    /// offset field at `field` point at it.
    fn begin(&mut self, field: usize) -> Result<(), &'static str> {
        let padding = self.data.len().wrapping_neg() % 8;
        self.push(&[0u8; 8][..padding])?;
        let pos = u32::try_from(self.data.len()).map_err(|_| TOO_LARGE)?;
        self.fixups.push((field, pos));
        Ok(())
    }

    /// Copy the table a load command describes with a file offset at
    /// `off_field` and a byte size at `off_field + 4`. An absent table
    /// (offset and size 0) stays absent.
    fn copy_blob(
        &mut self,
        cmds: &[u8],
        off_field: usize,
        what: &'static str,
    ) -> Result<(), &'static str> {
        let (Some(off), Some(size)) = (get_u32(cmds, off_field), get_u32(cmds, off_field + 4))
        else {
            return Ok(());
        };
        if size == 0 {
            if off != 0 {
                self.begin(off_field)?;
            }
            return Ok(());
        }
        let bytes = self.source(off, size as u64).ok_or(what)?;
        self.begin(off_field)?;
        self.push(bytes)
    }
}

/// Build the `__LINKEDIT` of one image from `src`, the shared segment of the
/// cache (`src_fileoff` is the file offset the image's segment command gives
/// it), and update the counts and symbol indices in `cmds`. The file offsets
/// in `cmds` are left for [`RebuiltLinkedit::fixups`], because they depend
/// on where the segment ends up.
///
/// The new segment holds, in this order: the `LC_DYLD_INFO` tables, the
/// data of every `linkedit_data_command` except the code signature, the
/// symbols in the three `LC_DYSYMTAB` ranges (all symbols without an
/// `LC_DYSYMTAB`), the indirect symbol table and the strings those symbols
/// name. The code signature, the two-level hints and the other
/// `LC_DYSYMTAB` tables are dropped: their offsets and counts become 0.
///
/// The error says what is wrong with the image's linkedit data.
fn rebuild_linkedit(
    cmds: &mut [u8],
    commands: &[LoadCommand],
    is64: bool,
    src: &[u8],
    src_fileoff: u64,
) -> Result<RebuiltLinkedit, &'static str> {
    let mut b = LinkeditBuilder {
        src,
        src_fileoff,
        data: Vec::new(),
        limit: src
            .len()
            .saturating_add(8 * commands.len())
            .saturating_add(64),
        fixups: Vec::new(),
    };

    for &(cmd, lc, cmdsize) in commands {
        if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) && cmdsize >= DYLD_INFO_COMMAND_SIZE {
            for (field, what) in [
                (8, "rebase info outside the segment"),
                (16, "bind info outside the segment"),
                (24, "weak bind info outside the segment"),
                (32, "lazy bind info outside the segment"),
                (40, "export info outside the segment"),
            ] {
                b.copy_blob(cmds, lc + field, what)?;
            }
        }
    }
    for &(cmd, lc, cmdsize) in commands {
        if cmdsize < LINKEDIT_DATA_COMMAND_SIZE {
            continue;
        }
        if is_linkedit_data_command(cmd) {
            b.copy_blob(cmds, lc + 8, "linkedit data outside the segment")?;
        } else if cmd == LC_CODE_SIGNATURE || cmd == LC_TWOLEVEL_HINTS {
            // Dropped: a signature of the cache's bytes cannot be right for
            // the extracted file, and the hints are obsolete.
            put(cmds, lc + 8, &[0u8; 8]);
        }
    }

    let find = |wanted: u32, min_size: usize| {
        commands
            .iter()
            .find(|&&(cmd, _, cmdsize)| cmd == wanted && cmdsize >= min_size)
            .map(|&(_, lc, _)| lc)
    };
    let symtab = find(LC_SYMTAB, SYMTAB_COMMAND_SIZE);
    let dysymtab = find(LC_DYSYMTAB, DYSYMTAB_COMMAND_SIZE);
    let field = |cmds: &[u8], off: usize| get_u32(cmds, off).unwrap_or(0);

    // (first symbol, count) of the symbols to keep, in output order.
    let mut ranges = [(0u32, 0u32); 3];
    // The new string table; offset 0 is the empty name, as usual.
    let mut pool: Vec<u8> = vec![0];
    if let Some(st) = symtab {
        let symoff = field(cmds, st + 8);
        let nsyms = field(cmds, st + 12);
        let strsize = field(cmds, st + 20);
        let nlist_size: usize = if is64 { 16 } else { 12 };
        let table = match nsyms {
            0 => &[][..],
            _ => b
                .source(symoff, nsyms as u64 * nlist_size as u64)
                .ok_or("symbol table outside the segment")?,
        };
        let strings = match strsize {
            0 => &[][..],
            _ => b
                .source(field(cmds, st + 16), strsize as u64)
                .ok_or("string table outside the segment")?,
        };
        match dysymtab {
            Some(d) => {
                for (range, off) in ranges.iter_mut().zip([8, 16, 24]) {
                    *range = (field(cmds, d + off), field(cmds, d + off + 4));
                }
            }
            None => ranges[0] = (0, nsyms),
        }
        let mut kept: u64 = 0;
        for range in &mut ranges {
            if range.1 == 0 {
                range.0 = 0;
            } else if range.0 as u64 + range.1 as u64 > nsyms as u64 {
                return Err("LC_DYSYMTAB symbol range outside the symbol table");
            }
            kept += range.1 as u64;
        }
        if kept.saturating_mul(nlist_size as u64) > b.limit as u64 {
            return Err(TOO_LARGE);
        }
        let Ok(kept) = u32::try_from(kept) else {
            return Err(TOO_LARGE);
        };

        let mut pooled: HashMap<&[u8], u32> = HashMap::new();
        pooled.insert(&[], 0);
        let limit = b.limit;
        let mut intern = |strx: u64| -> Result<u32, &'static str> {
            if strx == 0 {
                return Ok(0);
            }
            let rest = usize::try_from(strx)
                .ok()
                .and_then(|strx| strings.get(strx..))
                .filter(|rest| !rest.is_empty())
                .ok_or("symbol name outside the string table")?;
            let len = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            let name = &rest[..len];
            if let Some(&at) = pooled.get(name) {
                return Ok(at);
            }
            if name.len() >= limit.saturating_sub(pool.len()) {
                return Err(TOO_LARGE);
            }
            let at = u32::try_from(pool.len()).map_err(|_| TOO_LARGE)?;
            pool.extend_from_slice(name);
            pool.push(0);
            pooled.insert(name, at);
            Ok(at)
        };

        if kept != 0 || symoff != 0 {
            b.begin(st + 8)?;
        }
        for &(first, count) in &ranges {
            // In range: `first + count <= nsyms`, and the table holds
            // `nsyms` entries.
            let start = first as usize * nlist_size;
            let entries = &table[start..start + count as usize * nlist_size];
            for old in entries.chunks_exact(nlist_size) {
                let mut entry = [0u8; 16];
                entry[..nlist_size].copy_from_slice(old);
                let strx = get_u32(&entry, 0).unwrap_or(0);
                put_u32(&mut entry, 0, intern(strx as u64)?);
                let n_type = entry[4];
                if n_type & N_STAB == 0 && n_type & N_TYPE == N_INDR {
                    // The value of an indirect symbol is the string table
                    // offset of the name it stands for.
                    if is64 {
                        let value = intern(get_u64(&entry, 8).unwrap_or(0))?;
                        put(&mut entry, 8, &(value as u64).to_le_bytes());
                    } else {
                        let value = intern(get_u32(&entry, 8).unwrap_or(0) as u64)?;
                        put_u32(&mut entry, 8, value);
                    }
                }
                b.push(&entry[..nlist_size])?;
            }
        }
        put_u32(cmds, st + 12, kept);
    }

    if let Some(d) = dysymtab {
        let indirect_off = field(cmds, d + 56);
        let count = field(cmds, d + 60);
        let table = match count {
            0 => &[][..],
            _ => b
                .source(indirect_off, count as u64 * 4)
                .ok_or("indirect symbol table outside the segment")?,
        };
        if count != 0 || indirect_off != 0 {
            b.begin(d + 56)?;
        }
        for entry in table.chunks_exact(4) {
            let index = get_u32(entry, 0).unwrap_or(0);
            let mut new_index = None;
            if index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                new_index = Some(index);
            } else {
                let mut base = 0u32;
                for &(first, count) in &ranges {
                    if index >= first && index - first < count {
                        new_index = Some(base + (index - first));
                        break;
                    }
                    // No overflow: the counts add up to a u32 (`kept`).
                    base += count;
                }
            }
            let Some(new_index) = new_index else {
                return Err("indirect symbol table names a symbol outside the image's ranges");
            };
            b.push(&new_index.to_le_bytes())?;
        }

        let (nlocal, nextdef) = (ranges[0].1, ranges[1].1);
        put_u32(cmds, d + 8, 0);
        put_u32(cmds, d + 16, nlocal);
        put_u32(cmds, d + 24, nlocal + nextdef);
        // Table of contents, module table, external references, external
        // and local relocations: dropped.
        for off in [32, 40, 48, 64, 72] {
            put(cmds, d + off, &[0u8; 8]);
        }
    }

    if let Some(st) = symtab {
        let kept = field(cmds, st + 12);
        if kept != 0 || field(cmds, st + 16) != 0 || field(cmds, st + 20) != 0 {
            b.begin(st + 16)?;
            let padding = pool.len().wrapping_neg() % 8;
            pool.extend_from_slice(&[0u8; 8][..padding]);
            b.push(&pool)?;
            put_u32(
                cmds,
                st + 20,
                u32::try_from(pool.len()).map_err(|_| TOO_LARGE)?,
            );
        }
    }

    let padding = b.data.len().wrapping_neg() % 8;
    b.push(&[0u8; 8][..padding])?;
    Ok(RebuiltLinkedit {
        segment: None,
        data: b.data,
        fixups: b.fixups,
    })
}

/// Set the file offset of the segment command at `lc` to `target` and move
/// the file offsets of its sections along. `vmaddr` and `image_fileoff` are
/// what the command records in the cache. False when an offset does not fit
/// in its field.
fn patch_segment_command(
    cmds: &mut [u8],
    lc: usize,
    is64: bool,
    vmaddr: u64,
    image_fileoff: u64,
    target: u64,
) -> bool {
    // `old_size` is the size the segment has in the cache, which is what
    // the section offsets were laid out in.
    let (old_size, sections, section_size, offset_field) = if is64 {
        let old_size = get_u64(cmds, lc + 48).unwrap_or(0);
        put(cmds, lc + 40, &target.to_le_bytes());
        (old_size, lc + 72, 80, 48)
    } else {
        let old_size = get_u32(cmds, lc + 36).unwrap_or(0) as u64;
        let Ok(target) = u32::try_from(target) else {
            return false;
        };
        put_u32(cmds, lc + 32, target);
        (old_size, lc + 56, 68, 40)
    };
    let nsects = get_u32(cmds, sections - 8).unwrap_or(0) as usize;
    let cmdsize = get_u32(cmds, lc + 4).unwrap_or(0) as usize;
    // `cmdsize` bounds the number of sections looked at.
    for n in 0..nsects.min(cmdsize / section_size) {
        let section = sections + n * section_size;
        if section + section_size > lc + cmdsize {
            break;
        }
        // Zero-fill sections have no file offset. The cache builder also
        // leaves offset 0 in sections it emptied (stubs, ObjC strings),
        // which Apple's tools reject in a file: those get the offset their
        // address has in the segment, as does a section whose offset is
        // not in the segment. A section that is outside the segment both
        // ways is left as it is.
        let old = get_u32(cmds, section + offset_field).unwrap_or(0) as u64;
        let section_type = get_u32(cmds, section + offset_field + 16).unwrap_or(0) & 0xff;
        let zero_fill = matches!(
            section_type,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        );
        let by_offset = old
            .checked_sub(image_fileoff)
            .filter(|&d| old != 0 && d <= old_size);
        let addr = if is64 {
            get_u64(cmds, section + 32)
        } else {
            get_u32(cmds, section + 32).map(u64::from)
        };
        let by_address = addr
            .and_then(|addr| addr.checked_sub(vmaddr))
            .filter(|&d| !zero_fill && d <= old_size);
        if let Some(delta) = by_offset.or(by_address) {
            let Ok(new) = u32::try_from(target.saturating_add(delta)) else {
                return false;
            };
            put_u32(cmds, section + offset_field, new);
        }
        // reloff, nreloc: relocation entries are not copied.
        put(cmds, section + offset_field + 8, &[0u8; 8]);
    }
    true
}

/// True when every segment can stay at the file offset its load command
/// records: the ranges overlap neither each other nor the Mach-O header at
/// the start of the file. `header_segment` is the segment that starts with
/// the header, if any.
fn raw_layout_fits(
    segments: &[SegmentCopyPlan],
    header_segment: Option<usize>,
    header_len: u64,
) -> bool {
    let mut ranges = vec![(0u64, header_len)];
    for (i, p) in segments.iter().enumerate() {
        let Some(end) = p.image_fileoff.checked_add(p.size) else {
            return false;
        };
        if Some(i) == header_segment && p.image_fileoff == 0 {
            ranges[0].1 = header_len.max(end);
        } else if p.size != 0 {
            ranges.push((p.image_fileoff, end));
        }
    }
    ranges.sort_unstable();
    ranges.windows(2).all(|w| w[0].1 <= w[1].0)
}

/// Work out which byte ranges of the cache make up `image`, where they go
/// in the output file, and the load commands and `__LINKEDIT` of that file.
pub fn plan_extraction(
    cache: &DyldSharedCache,
    image: &CacheImage,
    options: &ExtractOptions,
) -> Result<ExtractPlan, ExtractError> {
    let fail = |prefix: &str| Err(ExtractError::new(prefix, &image.path));

    // The header and each segment may live in different files of a split
    // cache.
    let located = cache
        .resolve(image.address)
        .and_then(|(file, off)| Some((file, off, cache.file_image(file)?)));
    let Some((header_file, header_fileoff, data)) = located else {
        return fail("cannot map image vmaddr to cache file offset: ");
    };
    if !data.in_file(header_fileoff, MACH_HEADER_64_SIZE) {
        return fail("header out of range: ");
    }
    let rd32 = |off: u64| data.u32(off).unwrap_or(0);

    let magic = rd32(header_fileoff);
    let is64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
    let is32 = magic == MH_MAGIC || magic == MH_CIGAM;
    if !is64 && !is32 {
        return fail("target image is not Mach-O: ");
    }
    let ncmds = rd32(header_fileoff + 16);
    let sizeofcmds = rd32(header_fileoff + 20);
    let mh_size = if is64 {
        MACH_HEADER_64_SIZE
    } else {
        MACH_HEADER_SIZE
    };
    if ncmds > MAX_NCMDS || sizeofcmds > MAX_SIZEOFCMDS {
        return fail("invalid load commands metadata: ");
    }
    // `header_fileoff + 32 <= cache_size` was checked above. The caps also
    // bound this copy (at most 64 MiB + 32 bytes).
    let header_len = mh_size + sizeofcmds as u64;
    let Some(header) = data.slice(header_fileoff, header_len) else {
        return fail("load commands out of range: ");
    };
    let mut header = header.to_vec();
    let (mach_header, cmds) = header.split_at_mut(mh_size as usize);
    // `ncmds` is capped at 65535, which bounds these lists.
    let commands = load_commands(cmds, ncmds);

    let segment_error = |prefix: &str, name: &[u8]| {
        let mut detail = name.to_vec();
        detail.extend_from_slice(b" image=");
        detail.extend_from_slice(&image.path);
        ExtractError::new(prefix, &detail)
    };

    let mut segments = Vec::new();
    // Offset in `cmds` of the load command of each entry of `segments`.
    let mut segment_commands = Vec::new();
    // Segments without file content: (offset in `cmds` of the load command,
    // vmaddr, recorded fileoff, number of `segments` entries before it).
    let mut empty_segments = Vec::new();
    for &(cmd, lc, cmdsize) in &commands {
        // (vmaddr, fileoff, filesize)
        let seg = if cmd == LC_SEGMENT_64 && cmdsize as u64 >= SEGMENT_COMMAND_64_SIZE && is64 {
            Some((
                get_u64(cmds, lc + 24).unwrap_or(0),
                get_u64(cmds, lc + 40).unwrap_or(0),
                get_u64(cmds, lc + 48).unwrap_or(0),
            ))
        } else if cmd == LC_SEGMENT && cmdsize as u64 >= SEGMENT_COMMAND_SIZE && !is64 {
            Some((
                get_u32(cmds, lc + 24).unwrap_or(0) as u64,
                get_u32(cmds, lc + 32).unwrap_or(0) as u64,
                get_u32(cmds, lc + 36).unwrap_or(0) as u64,
            ))
        } else {
            None
        };
        let Some((vmaddr, fileoff, filesize)) = seg else {
            continue;
        };
        if filesize == 0 {
            empty_segments.push((lc, vmaddr, fileoff, segments.len()));
            continue;
        }
        let name = cmds.get(lc + 8..lc + 24).unwrap_or(&[]);
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        // The load command says the segment has bytes in the file; an
        // output without them would not match its own load commands.
        let Some((source_file, source_fileoff)) = cache.resolve(vmaddr) else {
            return Err(segment_error("segment not in any cache file: ", name));
        };
        let in_source = cache
            .file_image(source_file)
            .is_some_and(|f| f.in_file(source_fileoff, filesize));
        if !in_source {
            return Err(segment_error("segment source out of range: ", name));
        }
        segments.push(SegmentCopyPlan {
            name: name.to_vec(),
            vmaddr,
            image_fileoff: fileoff,
            source_file,
            source_fileoff,
            target_fileoff: fileoff,
            size: filesize,
        });
        segment_commands.push(lc);
    }
    if segments.is_empty() {
        return fail("no loadable segments found: ");
    }

    // Replace the shared __LINKEDIT with one that holds this image's data
    // only.
    let linkedit_segment = segments.iter().rposition(|p| p.name == b"__LINKEDIT");
    let (linkedit_src, linkedit_fileoff): (&[u8], u64) = match linkedit_segment {
        Some(i) => {
            let p = &segments[i];
            let src = cache
                .file_image(p.source_file)
                .and_then(|f| f.slice(p.source_fileoff, p.size));
            // In range: checked just above.
            (src.unwrap_or(&[]), p.image_fileoff)
        }
        None => (&[], 0),
    };
    let mut linkedit = match rebuild_linkedit(cmds, &commands, is64, linkedit_src, linkedit_fileoff)
    {
        Ok(linkedit) => linkedit,
        Err(why) => return fail(&format!("cannot rebuild __LINKEDIT ({why}): ")),
    };
    linkedit.segment = linkedit_segment;
    if let Some(i) = linkedit_segment {
        segments[i].size = linkedit.data.len() as u64;
    }

    // The segment that starts with the Mach-O header (`__TEXT`).
    let header_segment = segments.iter().position(|p| p.vmaddr == image.address);
    // File offsets recorded in the cache are only comparable when they are
    // offsets in the same file.
    let one_file = segments.iter().all(|p| p.source_file == header_file);
    let compact =
        options.compact || !one_file || !raw_layout_fits(&segments, header_segment, header_len);
    if compact {
        // The header's segment first, so that the file starts with the
        // header, then the others in load command order, __LINKEDIT last.
        let mut order: Vec<usize> = (0..segments.len()).collect();
        order.sort_by_key(|&i| {
            if Some(i) == header_segment {
                0
            } else if Some(i) == linkedit_segment {
                2
            } else {
                1
            }
        });
        let mut next_off = header_len;
        for i in order {
            let p = &mut segments[i];
            let target = if Some(i) == header_segment {
                Some(0)
            } else {
                align_up(next_off, SEGMENT_ALIGNMENT)
            };
            let end = target.and_then(|t| t.checked_add(p.size));
            let (Some(target), Some(end)) = (target, end) else {
                return Err(segment_error("segment target out of range: ", &p.name));
            };
            p.target_fileoff = target;
            next_off = next_off.max(end);
        }
    }

    let mut out_size = header_len;
    for p in &segments {
        // No overflow: checked by `raw_layout_fits` or just above.
        out_size = out_size.max(p.target_fileoff + p.size);
    }

    // Make the load commands describe the output file.
    let too_far = || fail("file offsets do not fit in 32 bits: ");
    for (p, &lc) in segments.iter().zip(&segment_commands) {
        if !patch_segment_command(cmds, lc, is64, p.vmaddr, p.image_fileoff, p.target_fileoff) {
            return too_far();
        }
    }
    for &(lc, vmaddr, fileoff, preceding) in &empty_segments {
        // There are no bytes to point at, but the offset must be in the
        // file for Apple's tools to accept it: a recorded offset that is
        // not (always, in the compact layout) becomes the end of the
        // segment before it.
        let target = if !compact && fileoff <= out_size {
            fileoff
        } else {
            match preceding.checked_sub(1) {
                Some(i) => segments[i].target_fileoff + segments[i].size,
                None => 0,
            }
        };
        if !patch_segment_command(cmds, lc, is64, vmaddr, fileoff, target) {
            return too_far();
        }
    }
    let linkedit_target = match linkedit_segment {
        Some(i) => segments[i].target_fileoff,
        None => out_size,
    };
    if let Some(i) = linkedit_segment {
        // filesize, and vmsize rounded up to the page size of the
        // architecture (16 KiB on arm64, 4 KiB elsewhere).
        let lc = segment_commands[i];
        let size = linkedit.data.len() as u64;
        let cputype = get_u32(mach_header, 4).unwrap_or(0);
        let is_arm64 = cputype & (CPU_ARCH_ABI64 | CPU_ARCH_ABI64_32) != 0
            && cputype & !(CPU_ARCH_ABI64 | CPU_ARCH_ABI64_32) == CPU_TYPE_ARM;
        let page: u64 = if is_arm64 { 0x4000 } else { 0x1000 };
        // `size` is at most a little more than the size in the cache.
        let vmsize = align_up(size, page).unwrap_or(size);
        if is64 {
            put(cmds, lc + 32, &vmsize.to_le_bytes());
            put(cmds, lc + 48, &size.to_le_bytes());
        } else {
            let (Ok(vmsize), Ok(size)) = (u32::try_from(vmsize), u32::try_from(size)) else {
                return too_far();
            };
            put_u32(cmds, lc + 28, vmsize);
            put_u32(cmds, lc + 36, size);
        }
    }
    for &(field, pos) in &linkedit.fixups {
        let Some(off) = linkedit_target
            .checked_add(pos as u64)
            .and_then(|off| u32::try_from(off).ok())
        else {
            return too_far();
        };
        put_u32(cmds, field, off);
    }
    // The output is a file of its own, laid out as a file and not as the
    // cache maps it.
    let flags = get_u32(mach_header, 24).unwrap_or(0);
    put_u32(mach_header, 24, flags & !MH_DYLIB_IN_CACHE);

    Ok(ExtractPlan {
        header_file,
        header_fileoff,
        is64,
        mh_size,
        sizeofcmds,
        segments,
        out_size,
        compact,
        header_segment,
        header,
        linkedit,
    })
}

fn write_plan(
    cache: &DyldSharedCache,
    plan: &ExtractPlan,
    out: &mut File,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(ExtractProgress<'_>),
) -> Result<(), WriteError> {
    out.set_len(plan.out_size)?;

    let bytes_total: u64 = plan
        .segments
        .iter()
        .fold(0u64, |acc, p| acc.saturating_add(p.size));
    let mut bytes_done: u64 = 0;
    for (i, p) in plan.segments.iter().enumerate() {
        let source: &[u8] = if plan.linkedit.segment == Some(i) {
            &plan.linkedit.data
        } else {
            // `source_fileoff + size` was checked to be inside the file.
            let data: &Image = cache.file_image(p.source_file).ok_or(WriteError::Source)?;
            data.slice(p.source_fileoff, p.size)
                .ok_or(WriteError::Source)?
        };
        let mut copied: u64 = 0;
        while copied < p.size {
            if cancel.load(Ordering::Relaxed) {
                return Err(WriteError::Cancelled);
            }
            let n = COPY_CHUNK.min(p.size - copied);
            let chunk = source
                .get(copied as usize..(copied + n) as usize)
                .ok_or(WriteError::Source)?;
            let target = p
                .target_fileoff
                .checked_add(copied)
                .ok_or(WriteError::Source)?;
            out.seek(SeekFrom::Start(target))?;
            out.write_all(chunk)?;
            copied += n;
            bytes_done += n;
            progress(ExtractProgress {
                segment: &p.name,
                bytes_done,
                bytes_total,
            });
        }
    }

    // The header goes in last: its segment was copied with the load
    // commands the image has in the cache. When that segment is not at the
    // start of the file (raw layout), the copy inside it is replaced too.
    let mut header_offsets = vec![0];
    if let Some(p) = plan.header_segment.and_then(|i| plan.segments.get(i)) {
        if p.target_fileoff != 0 && plan.header.len() as u64 <= p.size {
            header_offsets.push(p.target_fileoff);
        }
    }
    for off in header_offsets {
        out.seek(SeekFrom::Start(off))?;
        out.write_all(&plan.header)?;
    }
    out.flush()?;
    Ok(())
}

enum WriteError {
    Io,
    Source,
    Cancelled,
}

impl From<std::io::Error> for WriteError {
    fn from(_: std::io::Error) -> Self {
        WriteError::Io
    }
}

/// Extract `image` from `cache` into the file `output` (created or
/// truncated). With `options.dry_run` nothing is written.
///
/// `cancel` is polled between 1 MiB chunks; when it becomes true the partial
/// output file is removed and the error has `cancelled == true`. `progress`
/// is called after every chunk written.
pub fn extract_image(
    cache: &DyldSharedCache,
    image: &CacheImage,
    output: &Path,
    options: &ExtractOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(ExtractProgress<'_>),
) -> Result<ExtractOutcome, ExtractError> {
    let plan = plan_extraction(cache, image, options)?;
    let outcome = ExtractOutcome {
        image_path: image.path.clone(),
        output: output.to_path_buf(),
        compact: plan.compact,
        dry_run: options.dry_run,
        size: plan.out_size,
        segments: plan.segments.len(),
    };
    if options.dry_run {
        return Ok(outcome);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(ExtractError {
            message: b"extraction cancelled".to_vec(),
            cancelled: true,
        });
    }

    let output_bytes = output.as_os_str().as_encoded_bytes();
    let mut file = File::create(output)
        .map_err(|_| ExtractError::new("cannot open output file: ", output_bytes))?;
    match write_plan(cache, &plan, &mut file, cancel, progress) {
        Ok(()) => Ok(outcome),
        Err(e) => {
            drop(file);
            let _ = std::fs::remove_file(output);
            Err(match e {
                WriteError::Cancelled => ExtractError {
                    message: b"extraction cancelled".to_vec(),
                    cancelled: true,
                },
                // The original tool ignored write errors and reported
                // success; failing loudly is deliberate.
                WriteError::Io | WriteError::Source => {
                    ExtractError::new("cannot write output file: ", output_bytes)
                }
            })
        }
    }
}

/// One-call extraction for the GUI: open `cache_path`, pick the first image
/// whose path equals `selector` (or contains it unless `exact`) and write it
/// to `output`. `log` receives human-readable progress lines (no trailing
/// newline).
pub fn extract_from_cache_file(
    cache_path: &Path,
    selector: &str,
    exact: bool,
    output: &Path,
    options: &ExtractOptions,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(&str),
) -> Result<ExtractOutcome, ExtractError> {
    let cache = open_cache(cache_path).map_err(|e| ExtractError::new("", e.0.as_bytes()))?;
    let matched = select_images(&cache, selector.as_bytes(), exact);
    let Some(image) = matched.first() else {
        return Err(ExtractError::new("image not found: ", selector.as_bytes()));
    };
    if matched.len() > 1 {
        log(&format!(
            "warning: selector matched {} images, using first: {}",
            matched.len(),
            image.path_str()
        ));
    }
    let mut last_percent = u64::MAX;
    let mut progress = |p: ExtractProgress<'_>| {
        let percent = p
            .bytes_done
            .saturating_mul(100)
            .checked_div(p.bytes_total)
            .unwrap_or(100);
        if percent != last_percent {
            last_percent = percent;
            log(&format!("copying {}: {}%", utf8_safe(p.segment), percent));
        }
    };
    let outcome = extract_image(&cache, image, output, options, cancel, &mut progress)?;
    for line in utf8_safe(&outcome.text()).lines() {
        log(line);
    }
    Ok(outcome)
}

/// Make sure `path` is a directory, creating it (not its parents) if
/// needed. The error is the user-facing message.
pub fn ensure_directory(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("output directory path is empty".into());
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if !meta.is_dir() {
            return Err(format!("output path exists but is not a directory: {path}"));
        }
        return Ok(());
    }
    std::fs::create_dir(path).map_err(|_| format!("cannot create output directory: {path}"))
}

/// Output file names for batch extraction: `<basename>.macho`, with `.N`
/// inserted before `.macho` for the N-th repeat of a basename.
#[derive(Default)]
pub struct BatchNamer {
    counts: HashMap<Vec<u8>, u32>,
}

impl BatchNamer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_name(&mut self, image_path: &[u8]) -> Vec<u8> {
        let base = match image_path.iter().rposition(|&c| c == b'/') {
            Some(pos) => &image_path[pos + 1..],
            None => image_path,
        };
        let base = if base.is_empty() { &b"image"[..] } else { base };
        let count = self.counts.entry(base.to_vec()).or_insert(0);
        let mut name = base.to_vec();
        if *count > 0 {
            name.extend_from_slice(format!(".{count}").as_bytes());
        }
        *count = count.saturating_add(1);
        name.extend_from_slice(b".macho");
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::dyld_cache::testutil::{build_cache, modern_cache, parse};
    use crate::macho::dyld_cache::CacheMapping;

    const BASE: u64 = 0x1_8000_0000;

    fn seg64(name: &str, vmaddr: u64, fileoff: u64, filesize: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        v.extend_from_slice(&72u32.to_le_bytes());
        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name.as_bytes());
        v.extend_from_slice(&n);
        for x in [vmaddr, filesize, fileoff, filesize] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&[0u8; 16]);
        v
    }

    fn symtab(symoff: u32, stroff: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [LC_SYMTAB, 24, symoff, 1, stroff, 8] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    /// A cache whose only image lives at file offset 0x1000: __TEXT (0x400
    /// bytes, holding the header) and __LINKEDIT (0x100 bytes at 0x3000).
    fn sample_cache() -> DyldSharedCache {
        let mapping = CacheMapping {
            address: BASE,
            size: 0x4000,
            file_offset: 0,
            max_prot: 5,
            init_prot: 5,
        };
        let mut data = build_cache(
            &[mapping],
            &[
                (BASE + 0x1000, "/usr/lib/libfoo.dylib"),
                (BASE + 0x2000, "/usr/lib/libbad.dylib"),
                (0x10, "/unmapped"),
            ],
            0x4000,
        );
        let cmds = [
            seg64("__TEXT", BASE + 0x1000, 0, 0x400),
            seg64("__LINKEDIT", BASE + 0x3000, 0x8000, 0x100),
            seg64("__EMPTY", BASE + 0x3800, 0x9000, 0),
            symtab(0x8010, 0x8020),
        ]
        .concat();
        let mut header = Vec::new();
        for w in [MH_MAGIC_64, 0x0100000c, 0, 6, 4, cmds.len() as u32, 0, 0] {
            header.extend_from_slice(&w.to_le_bytes());
        }
        header.extend_from_slice(&cmds);
        data[0x1000..0x1000 + header.len()].copy_from_slice(&header);
        for (i, b) in data[0x3000..0x3100].iter_mut().enumerate() {
            *b = i as u8;
        }
        data[0x3010..0x3028].copy_from_slice(&SAMPLE_LINKEDIT);
        data[0x2000..0x2004].copy_from_slice(b"junk");
        parse(data).unwrap()
    }

    /// The one symbol of the sample images (`_foo`, at string offset 1)
    /// followed by its string table. The symbol table is at offset 0x10 of
    /// the cache's `__LINKEDIT` and the strings at 0x20; this is also the
    /// whole `__LINKEDIT` of an extracted sample image.
    const SAMPLE_LINKEDIT: [u8; 24] = [
        1, 0, 0, 0, 0x0f, 1, 0, 0, 0, 0x10, 0, 0x80, 1, 0, 0, 0, // nlist_64
        0, b'_', b'f', b'o', b'o', 0, 0, 0,
    ];

    fn u32_at(bytes: &[u8], off: usize) -> u32 {
        get_u32(bytes, off).unwrap()
    }

    fn u64_at(bytes: &[u8], off: usize) -> u64 {
        get_u64(bytes, off).unwrap()
    }

    fn tmp(name: &str) -> PathBuf {
        // Keep test output inside the workspace's target directory.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("moex-core-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn extract(
        cache: &DyldSharedCache,
        idx: usize,
        out: &Path,
        options: ExtractOptions,
    ) -> Result<ExtractOutcome, ExtractError> {
        let images: Vec<_> = cache.images().collect();
        extract_image(
            cache,
            &images[idx],
            out,
            &options,
            &AtomicBool::new(false),
            &mut |_| {},
        )
    }

    #[test]
    fn matching() {
        assert!(filter_matches(b"/usr/lib/libobjc.A.dylib", b"", false));
        assert!(filter_matches(b"/usr/lib/libobjc.A.dylib", b"", true));
        assert!(filter_matches(
            b"/usr/lib/libobjc.A.dylib",
            b"libobjc",
            false
        ));
        assert!(!filter_matches(
            b"/usr/lib/libobjc.A.dylib",
            b"libobjc",
            true
        ));
        assert!(filter_matches(
            b"/usr/lib/libobjc.A.dylib",
            b"/usr/lib/libobjc.A.dylib",
            true
        ));

        assert!(selector_matches(
            b"/usr/lib/libobjc.A.dylib",
            b"libobjc",
            false
        ));
        assert!(!selector_matches(
            b"/usr/lib/libobjc.A.dylib",
            b"libobjc",
            true
        ));
        assert!(selector_matches(
            b"/usr/lib/libobjc.A.dylib",
            b"/usr/lib/libobjc.A.dylib",
            true
        ));
        assert!(selector_matches(b"/a", b"", false));
        assert!(!selector_matches(b"/a", b"", true));
        assert!(selector_matches(b"", b"", true));
        assert!(!selector_matches(b"/a", b"/ab", false));
    }

    #[test]
    fn listing_is_sorted_and_filtered() {
        let cache = sample_cache();
        let all: Vec<String> = image_paths(&cache);
        assert_eq!(
            all,
            [
                "/unmapped",
                "/usr/lib/libbad.dylib",
                "/usr/lib/libfoo.dylib"
            ]
        );
        assert_eq!(list_images(&cache, b"lib/lib", false).len(), 2);
        assert_eq!(list_images(&cache, b"lib/lib", true).len(), 0);
        let selected = select_images(&cache, b"lib", false);
        assert_eq!(selected[0].path, b"/usr/lib/libfoo.dylib");
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape(b"a\"b\\c\n\r\t\0"), b"a\\\"b\\\\c\\n\\r\\t\0");
    }

    #[test]
    fn raw_extraction() {
        let cache = sample_cache();
        let out = tmp("raw.macho");
        let r = extract(&cache, 0, &out, ExtractOptions::default()).unwrap();
        // __TEXT stays at 0 and __LINKEDIT at 0x8000, now 24 bytes long.
        assert_eq!((r.size, r.segments, r.compact), (0x8018, 2, false));
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), 0x8018);
        let original = cache.image.slice(0x1000, 0x400).unwrap();
        // The Mach-O header is unchanged; the load commands are patched.
        assert_eq!(&bytes[..32], &original[..32]);
        let header_len = 32 + 3 * 72 + 24;
        assert_eq!(&bytes[header_len..0x400], &original[header_len..]);
        assert!(bytes[0x400..0x8000].iter().all(|&b| b == 0));
        assert_eq!(&bytes[0x8000..], &SAMPLE_LINKEDIT);
        let linkedit = 32 + 72;
        // fileoff kept; vmsize (one arm64 page) and filesize shrunk
        assert_eq!(u64_at(&bytes, linkedit + 40), 0x8000);
        assert_eq!(u64_at(&bytes, linkedit + 32), 0x4000);
        assert_eq!(u64_at(&bytes, linkedit + 48), 24);
        // the empty segment's offset (0x9000) would be past the end
        assert_eq!(u64_at(&bytes, 32 + 144 + 40), 0x8018);
        let sym = 32 + 216;
        let fields: Vec<u32> = (2..6).map(|i| u32_at(&bytes, sym + 4 * i)).collect();
        assert_eq!(fields, [0x8000, 1, 0x8010, 8]);
        let text = String::from_utf8(r.text()).unwrap();
        assert_eq!(
            text,
            format!(
                "extracted: /usr/lib/libfoo.dylib\nmode: raw-fileoff\noutput: {} size=32792 bytes segments=2\n",
                out.display()
            )
        );
    }

    /// Segments whose recorded file offsets overlap cannot be written
    /// "raw": the compact layout is used and reported.
    #[test]
    fn raw_extraction_never_overlaps() {
        let mapping = CacheMapping {
            address: BASE,
            size: 0x4000,
            file_offset: 0,
            max_prot: 5,
            init_prot: 5,
        };
        // (__TEXT fileoff, __LINKEDIT fileoff) -> (compact, size)
        for (text_off, linkedit_off, expected) in [
            // __LINKEDIT inside __TEXT's range
            (0, 0x200, (true, 0x1018)),
            // __TEXT over the header at the start of the file
            (0x80, 0x8000, (true, 0x1018)),
            // __TEXT at its offset in the cache file: fine
            (0x1000, 0x3000, (false, 0x3018)),
        ] {
            let mut data = build_cache(&[mapping], &[(BASE + 0x1000, "/img")], 0x4000);
            let cmds = [
                seg64("__TEXT", BASE + 0x1000, text_off, 0x400),
                seg64("__LINKEDIT", BASE + 0x3000, linkedit_off, 0x100),
                symtab(linkedit_off as u32 + 0x10, linkedit_off as u32 + 0x20),
            ]
            .concat();
            let mut header = Vec::new();
            for w in [MH_MAGIC_64, 0x0100000c, 0, 6, 3, cmds.len() as u32, 0, 0] {
                header.extend_from_slice(&w.to_le_bytes());
            }
            header.extend_from_slice(&cmds);
            data[0x1000..0x1000 + header.len()].copy_from_slice(&header);
            data[0x3010..0x3028].copy_from_slice(&SAMPLE_LINKEDIT);
            let cache = parse(data).unwrap();
            let out = tmp("overlap.macho");
            let r = extract(&cache, 0, &out, ExtractOptions::default()).unwrap();
            assert_eq!((r.compact, r.size), expected, "{text_off:#x}");
            let bytes = std::fs::read(&out).unwrap();
            // Both segment commands say where the bytes are.
            let text = u64_at(&bytes, 32 + 40) as usize;
            let linkedit = u64_at(&bytes, 32 + 72 + 40) as usize;
            assert_eq!(
                (text, linkedit),
                if r.compact {
                    (0, 0x1000)
                } else {
                    (0x1000, 0x3000)
                }
            );
            assert_eq!(&bytes[linkedit..], &SAMPLE_LINKEDIT);
            assert_eq!(&bytes[text + 0x200..text + 0x400], &[0u8; 0x200]);
            // The header inside __TEXT is the patched one too.
            assert_eq!(&bytes[text..text + header.len()], &bytes[..header.len()]);
            assert_eq!(u32_at(&bytes, 32 + 144 + 8) as usize, linkedit);
            let _ = std::fs::remove_file(&out);
        }
    }

    #[test]
    fn compact_extraction_patches_offsets() {
        let cache = sample_cache();
        let out = tmp("compact.macho");
        let r = extract(
            &cache,
            0,
            &out,
            ExtractOptions {
                compact: true,
                dry_run: false,
            },
        )
        .unwrap();
        // __TEXT (with the header) at 0, __LINKEDIT at 0x1000
        assert_eq!((r.size, r.compact), (0x1018, true));
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), 0x1018);
        let header_len = 32 + 3 * 72 + 24;
        assert_eq!(
            &bytes[header_len..0x400],
            cache
                .image
                .slice(0x1000 + header_len as u64, 0x400 - header_len as u64)
                .unwrap()
        );
        assert!(bytes[0x400..0x1000].iter().all(|&b| b == 0));
        assert_eq!(&bytes[0x1000..], &SAMPLE_LINKEDIT);
        let fileoff = |lc: usize| u64_at(&bytes, lc + 40);
        assert_eq!(fileoff(32), 0);
        assert_eq!(fileoff(32 + 72), 0x1000);
        // a segment without file content cannot keep an offset that is not
        // in the file: it gets the end of the segment before it
        assert_eq!(fileoff(32 + 144), 0x1018);
        let sym = 32 + 216;
        assert_eq!(u32_at(&bytes, sym + 8), 0x1000);
        assert_eq!(u32_at(&bytes, sym + 16), 0x1010);
    }

    fn section64(name: &str, addr: u64, size: u64, offset: u32, flags: u32) -> Vec<u8> {
        let mut v = vec![0u8; 80];
        v[..name.len()].copy_from_slice(name.as_bytes());
        v[32..40].copy_from_slice(&addr.to_le_bytes());
        v[40..48].copy_from_slice(&size.to_le_bytes());
        v[48..52].copy_from_slice(&offset.to_le_bytes());
        // reloff, nreloc
        v[56..64].copy_from_slice(&[0x77; 8]);
        v[64..68].copy_from_slice(&flags.to_le_bytes());
        v
    }

    /// Section file offsets follow their segment; the flag that marks an
    /// image as part of a cache is cleared.
    #[test]
    fn extraction_patches_sections_and_header_flags() {
        let mapping = CacheMapping {
            address: BASE,
            size: 0x4000,
            file_offset: 0,
            max_prot: 5,
            init_prot: 5,
        };
        let mut data = build_cache(&[mapping], &[(BASE + 0x1000, "/img")], 0x4000);
        let mut text = seg64("__TEXT", BASE + 0x1000, 0x1000, 0x400);
        let sections = [
            section64("__text", BASE + 0x1100, 0x80, 0x1100, 0x8000_0400),
            // emptied by the cache builder: offset 0, not zero-fill
            section64("__stubs", BASE + 0x1180, 0, 0, 0x8000_0408),
            section64("__bss", BASE + 0x1200, 0x40, 0, S_ZEROFILL),
            // offset outside the segment: placed by its address
            section64("__odd", BASE + 0x1300, 8, 0x9000, 0),
        ];
        text[4..8].copy_from_slice(&(72 + 80 * 4u32).to_le_bytes());
        text[64..68].copy_from_slice(&4u32.to_le_bytes());
        let cmds = [
            text,
            sections.concat(),
            seg64("__LINKEDIT", BASE + 0x3000, 0x3000, 0x100),
        ]
        .concat();
        let mut header = Vec::new();
        let flags = 0x85 | MH_DYLIB_IN_CACHE;
        for w in [
            MH_MAGIC_64,
            0x0100000c,
            0,
            6,
            2,
            cmds.len() as u32,
            flags,
            0,
        ] {
            header.extend_from_slice(&w.to_le_bytes());
        }
        header.extend_from_slice(&cmds);
        data[0x1000..0x1000 + header.len()].copy_from_slice(&header);
        let cache = parse(data).unwrap();
        let out = tmp("sections.macho");
        for (compact, base) in [(false, 0x1000), (true, 0)] {
            let options = ExtractOptions {
                compact,
                dry_run: false,
            };
            let r = extract(&cache, 0, &out, options).unwrap();
            assert_eq!(r.compact, compact);
            let bytes = std::fs::read(&out).unwrap();
            assert_eq!(u32_at(&bytes, 24), 0x85);
            assert_eq!(u64_at(&bytes, 32 + 40), base);
            let offsets: Vec<u32> = (0..4)
                .map(|n| u32_at(&bytes, 32 + 72 + 80 * n + 48))
                .collect();
            let base = base as u32;
            assert_eq!(offsets, [base + 0x100, base + 0x180, 0, base + 0x300]);
            // relocations are not copied
            assert_eq!(u64_at(&bytes, 32 + 72 + 56), 0);
            // no linkedit data: the segment is empty and ends the file
            let linkedit = 32 + 72 + 320;
            assert_eq!(u64_at(&bytes, linkedit + 48), 0);
            assert_eq!(u64_at(&bytes, linkedit + 40), bytes.len() as u64);
        }
        let _ = std::fs::remove_file(&out);
    }

    /// A split cache on disk: the image's header and `__TEXT` are in the
    /// main file, `__DATA` in sub-cache `.01`, `__LINKEDIT` in `.02.dylddata`.
    #[test]
    fn extraction_follows_sub_cache_files() {
        let dir = tmp("split");
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = dir.join("cache");
        let mut main = modern_cache(BASE, 1, &[(2, 0x4000, ".01"), (3, 0x8000, ".02.dylddata")]);
        let cmds = [
            seg64("__TEXT", BASE + 0x800, 0x800, 0x200),
            seg64("__DATA", BASE + 0x4400, 0x400, 0x80),
            seg64("__LINKEDIT", BASE + 0x8600, 0x600, 0x40),
            symtab(0x610, 0x620),
        ]
        .concat();
        let mut header = Vec::new();
        for w in [MH_MAGIC_64, 0x0100000c, 0, 6, 4, cmds.len() as u32, 0, 0] {
            header.extend_from_slice(&w.to_le_bytes());
        }
        header.extend_from_slice(&cmds);
        main[0x800..0x800 + header.len()].copy_from_slice(&header);
        let mut sub1 = modern_cache(BASE + 0x4000, 2, &[]);
        sub1[0x400..0x480].fill(0xD1);
        let mut sub2 = modern_cache(BASE + 0x8000, 3, &[]);
        sub2[0x600..0x640].fill(0xE2);
        sub2[0x610..0x628].copy_from_slice(&SAMPLE_LINKEDIT);
        std::fs::write(&main_path, &main).unwrap();
        std::fs::write(dir.join("cache.01"), &sub1).unwrap();
        std::fs::write(dir.join("cache.02.dylddata"), &sub2).unwrap();

        let cache = open_cache(&main_path).unwrap();
        let image = cache.images().next().unwrap();
        let plan = plan_extraction(&cache, &image, &ExtractOptions::default()).unwrap();
        let sources: Vec<(usize, u64)> = plan
            .segments
            .iter()
            .map(|p| (p.source_file, p.source_fileoff))
            .collect();
        assert_eq!(sources, [(0, 0x800), (1, 0x400), (2, 0x600)]);
        // The recorded file offsets belong to three different files, so
        // they are not kept even without `compact`.
        assert!(plan.compact);

        let out = dir.join("out.macho");
        let r = extract(&cache, 0, &out, ExtractOptions::default()).unwrap();
        // Load command order: __TEXT at 0, __DATA, __LINKEDIT.
        assert_eq!((r.segments, r.size, r.compact), (3, 0x2018, true));
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[..4], &MH_MAGIC_64.to_le_bytes());
        assert!(bytes[0x1000..0x1080].iter().all(|&b| b == 0xD1));
        assert_eq!(&bytes[0x2000..], &SAMPLE_LINKEDIT);
        let offsets: Vec<u64> = (0..3).map(|n| u64_at(&bytes, 32 + 72 * n + 40)).collect();
        assert_eq!(offsets, [0, 0x1000, 0x2000]);
        let sym = 32 + 3 * 72;
        assert_eq!(u32_at(&bytes, sym + 8), 0x2000);
        assert_eq!(u32_at(&bytes, sym + 16), 0x2010);

        // Without the sub-cache file the segment cannot be located.
        std::fs::remove_file(dir.join("cache.01")).unwrap();
        let cache = open_cache(&main_path).unwrap();
        let e = plan_extraction(&cache, &image, &ExtractOptions::default()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "segment not in any cache file: __DATA image=/usr/lib/libmodern.dylib"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn nlist64(strx: u32, n_type: u8, sect: u8, desc: u16, value: u64) -> Vec<u8> {
        let mut v = strx.to_le_bytes().to_vec();
        v.extend_from_slice(&[n_type, sect]);
        v.extend_from_slice(&desc.to_le_bytes());
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    /// File offset of the shared `__LINKEDIT` of [`shared_linkedit`].
    const LE: u32 = 0x8000;
    // Offsets of its load commands.
    const DYLD_INFO: usize = 0;
    const SYMTAB: usize = 48;
    const DYSYMTAB: usize = 72;
    const FUNCTION_STARTS: usize = 152;
    const DATA_IN_CODE: usize = 168;
    const LAZY_LOAD: usize = 184;
    const CODE_SIGNATURE: usize = 200;
    const NCMDS: u32 = 8;

    /// The load commands of an image and the `__LINKEDIT` (0x140 bytes at
    /// file offset `LE`) it shares with other images. Its symbols are
    /// scattered over the shared symbol table: one local (5), two external
    /// (2, 3) and two undefined (6, 7).
    fn shared_linkedit() -> (Vec<u8>, Vec<u8>) {
        let mut linkedit = vec![0xAAu8; 0x140];
        linkedit[0x10..0x15].copy_from_slice(b"EXPRT");
        linkedit[0x20..0x26].copy_from_slice(b"FSTART");
        linkedit[0x30..0x33].copy_from_slice(b"LZY");
        // 1 _other0, 9 _local, 16 _ext, 21 _alias, 28 _undef, 35 _other1,
        // 43 _ext (again)
        let strings = b"\0_other0\0_local\0_ext\0_alias\0_undef\0_other1\0_ext\0";
        linkedit[0xe0..0x120].fill(0);
        linkedit[0xe0..0xe0 + strings.len()].copy_from_slice(strings);
        let symbols = [
            nlist64(1, 0x0e, 1, 0, 0x100),
            nlist64(35, 0x0f, 1, 0, 0x200),
            nlist64(16, 0x0f, 1, 0, 0x1000),
            // N_INDR | N_EXT: the value is the string offset of `_ext`
            nlist64(21, 0x0b, 0, 0, 43),
            nlist64(1, 0x0e, 1, 0, 0x300),
            nlist64(9, 0x0e, 1, 0, 0x1010),
            nlist64(28, 0x01, 0, 0x100, 0),
            nlist64(43, 0x01, 0, 0x200, 0),
        ]
        .concat();
        linkedit[0x40..0xc0].copy_from_slice(&symbols);
        let indirect = words(&[
            6,
            2,
            INDIRECT_SYMBOL_LOCAL,
            7,
            3,
            INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS,
        ]);
        linkedit[0xc0..0xd8].copy_from_slice(&indirect);

        let cmds = [
            // rebase, bind, weak bind, lazy bind: absent; export
            words(&[LC_DYLD_INFO_ONLY, 48, 0, 0, 0, 0, 0, 0, 0, 0, LE + 0x10, 5]),
            words(&[LC_SYMTAB, 24, LE + 0x40, 8, LE + 0xe0, 0x40]),
            words(&[
                LC_DYSYMTAB,
                80,
                5,
                1,
                2,
                2,
                6,
                2,
                // table of contents, module table, external references
                LE + 0x11,
                3,
                0,
                0,
                0,
                0,
                LE + 0xc0,
                6,
                // external and local relocations
                0x1234,
                1,
                0,
                0,
            ]),
            words(&[LC_FUNCTION_STARTS, 16, LE + 0x20, 6]),
            words(&[LC_DATA_IN_CODE, 16, LE + 0x30, 0]),
            words(&[LC_LAZY_LOAD_DYLIB_INFO, 16, LE + 0x30, 3]),
            words(&[LC_CODE_SIGNATURE, 16, LE + 0x10, 0x100]),
            words(&[LC_UUID, 24, 1, 2, 3, 4]),
        ]
        .concat();
        (cmds, linkedit)
    }

    fn rebuild(cmds: &mut [u8], linkedit: &[u8]) -> Result<RebuiltLinkedit, &'static str> {
        let commands = load_commands(cmds, NCMDS);
        rebuild_linkedit(cmds, &commands, true, linkedit, LE as u64)
    }

    #[test]
    fn linkedit_rebuild_keeps_only_the_images_data() {
        let (mut cmds, linkedit) = shared_linkedit();
        let untouched = cmds[216..].to_vec();
        let rebuilt = rebuild(&mut cmds, &linkedit).unwrap();
        let data = &rebuilt.data;
        // export info, function starts, lazy-load info, 5 symbols,
        // 6 indirect entries, 32 bytes of strings; each 8-byte aligned
        assert_eq!(data.len(), 8 + 8 + 8 + 80 + 24 + 32);

        // Place the segment at 0x3000 the way `plan_extraction` does.
        for &(field, pos) in &rebuilt.fixups {
            put_u32(&mut cmds, field, 0x3000 + pos);
        }
        let at = |off: usize| u32_at(&cmds, off);
        let table = |off_field: usize, size: usize| {
            let start = at(off_field) as usize - 0x3000;
            &data[start..start + size]
        };

        assert_eq!(table(DYLD_INFO + 40, 5), b"EXPRT");
        assert_eq!(at(DYLD_INFO + 44), 5);
        // absent tables stay absent
        for off in [8, 12, 16, 20, 24, 28, 32, 36] {
            assert_eq!(at(DYLD_INFO + off), 0, "dyld info field at {off}");
        }
        assert_eq!(table(FUNCTION_STARTS + 8, 6), b"FSTART");
        assert_eq!(table(LAZY_LOAD + 8, 3), b"LZY");
        // an empty table gets an offset inside the new segment
        assert_eq!((at(DATA_IN_CODE + 8), at(DATA_IN_CODE + 12)), (0x3010, 0));
        // dropped
        assert_eq!((at(CODE_SIGNATURE + 8), at(CODE_SIGNATURE + 12)), (0, 0));
        assert_eq!(&cmds[216..], &untouched[..]);

        // Symbols: local, external, undefined, renumbered from 0.
        assert_eq!(at(SYMTAB + 12), 5);
        let strsize = at(SYMTAB + 20) as usize;
        assert_eq!(strsize, 32);
        let strings = table(SYMTAB + 16, strsize);
        assert_eq!(
            strings, b"\0_local\0_ext\0_alias\0_undef\0\0\0\0\0\0",
            "only the image's names, each once"
        );
        let name = |strx: u32| {
            let rest = &strings[strx as usize..];
            std::str::from_utf8(&rest[..rest.iter().position(|&c| c == 0).unwrap()]).unwrap()
        };
        let symbols: Vec<(&str, u8, u16, u64)> = table(SYMTAB + 8, 80)
            .chunks_exact(16)
            .map(|s| {
                let desc = u16::from_le_bytes([s[6], s[7]]);
                (name(u32_at(s, 0)), s[4], desc, u64_at(s, 8))
            })
            .collect();
        assert_eq!(
            symbols,
            [
                ("_local", 0x0e, 0, 0x1010),
                ("_ext", 0x0f, 0, 0x1000),
                // the value of the indirect symbol is a string offset too
                ("_alias", 0x0b, 0, 8),
                ("_undef", 0x01, 0x100, 0),
                ("_ext", 0x01, 0x200, 0),
            ]
        );
        assert_eq!(name(8), "_ext");
        let ranges: Vec<u32> = (0..6).map(|i| at(DYSYMTAB + 8 + 4 * i)).collect();
        assert_eq!(ranges, [0, 1, 1, 2, 3, 2]);

        // The indirect symbol table follows the renumbering.
        assert_eq!(at(DYSYMTAB + 60), 6);
        assert_eq!(
            table(DYSYMTAB + 56, 24),
            words(&[
                3,
                1,
                INDIRECT_SYMBOL_LOCAL,
                4,
                2,
                INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS
            ])
        );
        // The tables that are not copied are gone.
        for off in [32, 36, 40, 44, 48, 52, 64, 68, 72, 76] {
            assert_eq!(at(DYSYMTAB + off), 0, "dysymtab field at {off}");
        }

        // Every table starts on an 8-byte boundary, in the order ld uses.
        let positions: Vec<u32> = rebuilt.fixups.iter().map(|f| f.1).collect();
        assert_eq!(positions, [0, 8, 16, 16, 24, 104, 128]);
    }

    /// Without `LC_DYSYMTAB` every symbol is the image's; 32-bit symbols
    /// are 12 bytes.
    #[test]
    fn linkedit_rebuild_of_32_bit_symbols() {
        let mut linkedit = vec![0u8; 0x40];
        // _b (N_INDR, value: string offset 4), _a
        linkedit[..12].copy_from_slice(&[1, 0, 0, 0, 0x0b, 0, 0, 0, 4, 0, 0, 0]);
        linkedit[12..24].copy_from_slice(&[4, 0, 0, 0, 0x0f, 1, 0, 0, 0, 0x10, 0, 0]);
        linkedit[0x20..0x27].copy_from_slice(b"\0_b\0_a\0");
        let mut cmds = words(&[LC_SYMTAB, 24, 0x100, 2, 0x120, 0x20]);
        let commands = load_commands(&cmds, 1);
        let rebuilt = rebuild_linkedit(&mut cmds, &commands, false, &linkedit, 0x100).unwrap();
        assert_eq!(rebuilt.fixups, [(8, 0), (16, 24)]);
        assert_eq!(
            &rebuilt.data[..12],
            &[1, 0, 0, 0, 0x0b, 0, 0, 0, 4, 0, 0, 0]
        );
        assert_eq!(&rebuilt.data[12..24], &linkedit[12..24]);
        assert_eq!(&rebuilt.data[24..], b"\0_b\0_a\0\0");
        assert_eq!((u32_at(&cmds, 12), u32_at(&cmds, 20)), (2, 8));
    }

    #[test]
    fn linkedit_rebuild_keeps_absent_tables_absent() {
        let mut cmds = [
            words(&[LC_SYMTAB, 24, 0, 0, 0, 0]),
            words(&[LC_DYSYMTAB, 80]),
            vec![0u8; 72],
            words(&[LC_DYLD_INFO_ONLY, 48]),
            vec![0u8; 40],
            words(&[LC_FUNCTION_STARTS, 16, 0, 0]),
        ]
        .concat();
        let before = cmds.clone();
        let commands = load_commands(&cmds, 4);
        assert_eq!(commands.len(), 4);
        // Not even a __LINKEDIT segment is needed for that.
        let rebuilt = rebuild_linkedit(&mut cmds, &commands, true, &[], 0).unwrap();
        assert!(rebuilt.data.is_empty() && rebuilt.fixups.is_empty());
        assert_eq!(cmds, before);

        // ... but a table that is there needs one.
        put_u32(&mut cmds, 24 + 80 + 48 + 8, 0x10);
        put_u32(&mut cmds, 24 + 80 + 48 + 12, 4);
        assert_eq!(
            rebuild_linkedit(&mut cmds, &commands, true, &[], 0).unwrap_err(),
            "linkedit data outside the segment"
        );
    }

    #[test]
    fn linkedit_rebuild_rejects_malformed_input() {
        // (offset in the load commands or, with `true`, in __LINKEDIT;
        // value to store there; expected error)
        let cases: [(bool, usize, u64, &str); 13] = [
            (false, SYMTAB + 12, 100, "symbol table outside the segment"),
            (
                false,
                SYMTAB + 8,
                0x7000,
                "symbol table outside the segment",
            ),
            (
                false,
                SYMTAB + 8,
                0xffff_fff0,
                "symbol table outside the segment",
            ),
            (
                false,
                SYMTAB + 16,
                LE as u64 + 0x130,
                "string table outside the segment",
            ),
            (
                false,
                SYMTAB + 20,
                0xffff_ffff,
                "string table outside the segment",
            ),
            // n_strx of the local symbol; value of the indirect symbol
            (
                true,
                0x40 + 5 * 16,
                0x40,
                "symbol name outside the string table",
            ),
            (
                true,
                0x40 + 3 * 16 + 8,
                1 << 32,
                "symbol name outside the string table",
            ),
            (
                false,
                DYSYMTAB + 28,
                3,
                "LC_DYSYMTAB symbol range outside the symbol table",
            ),
            (
                false,
                DYSYMTAB + 8,
                0xffff_ffff,
                "LC_DYSYMTAB symbol range outside the symbol table",
            ),
            // an indirect entry naming another image's symbol
            (
                true,
                0xc0,
                4,
                "indirect symbol table names a symbol outside the image's ranges",
            ),
            (
                false,
                DYSYMTAB + 60,
                0x4000_0000,
                "indirect symbol table outside the segment",
            ),
            (
                false,
                FUNCTION_STARTS + 12,
                0xffff_ffff,
                "linkedit data outside the segment",
            ),
            (
                false,
                DYLD_INFO + 40,
                0xffff_ffff,
                "export info outside the segment",
            ),
        ];
        for (in_linkedit, off, value, expected) in cases {
            let (mut cmds, mut linkedit) = shared_linkedit();
            if in_linkedit {
                let width = if value > u32::MAX as u64 { 8 } else { 4 };
                put(&mut linkedit, off, &value.to_le_bytes()[..width]);
            } else {
                put_u32(&mut cmds, off, value as u32);
            }
            assert_eq!(
                rebuild(&mut cmds, &linkedit).unwrap_err(),
                expected,
                "{off} = {value:#x}"
            );
        }

        // Commands that together claim far more than the segment holds
        // (each one is in range) do not make the output grow without bound.
        let (_, linkedit) = shared_linkedit();
        let mut cmds = words(&[LC_FUNCTION_STARTS, 16, LE, 0x140]).repeat(100);
        let commands = load_commands(&cmds, 100);
        assert_eq!(commands.len(), 100);
        assert_eq!(
            rebuild_linkedit(&mut cmds, &commands, true, &linkedit, LE as u64).unwrap_err(),
            TOO_LARGE
        );
    }

    /// Every field of the load commands set to hostile values: an error or
    /// a consistent result, never a panic.
    #[test]
    fn linkedit_rebuild_survives_hostile_fields() {
        let (original, linkedit) = shared_linkedit();
        let values = [
            0,
            1,
            7,
            LE - 1,
            LE,
            LE + 0x13f,
            LE + 0x140,
            LE + 0x141,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fff0,
            0xffff_ffff,
        ];
        let mut accepted = 0;
        for off in (0..original.len()).step_by(4) {
            for value in values {
                let mut cmds = original.clone();
                put_u32(&mut cmds, off, value);
                if let Ok(rebuilt) = rebuild(&mut cmds, &linkedit) {
                    accepted += 1;
                    assert!(rebuilt.data.len() <= linkedit.len() + 8 * 8 + 64);
                    assert_eq!(rebuilt.data.len() % 8, 0);
                    for &(field, pos) in &rebuilt.fixups {
                        assert!(field + 4 <= cmds.len());
                        assert!(pos as usize <= rebuilt.data.len());
                    }
                }
            }
        }
        assert!(accepted > 0);

        // The same through a whole extraction: the sample image with each
        // LC_SYMTAB field set to each value.
        let out = tmp("hostile-symtab.macho");
        for field in [8, 12, 16, 20] {
            for value in values {
                let mut cache = sample_cache();
                let mut data = cache.image.bytes().to_vec();
                put_u32(&mut data, 0x1000 + 32 + 216 + field, value);
                cache = parse(data).unwrap();
                for compact in [false, true] {
                    let options = ExtractOptions {
                        compact,
                        dry_run: false,
                    };
                    match extract(&cache, 0, &out, options) {
                        Ok(r) => assert_eq!(std::fs::metadata(&out).unwrap().len(), r.size),
                        Err(e) => {
                            assert!(
                                e.to_string().starts_with("cannot rebuild __LINKEDIT ("),
                                "{e}"
                            );
                            assert!(!out.exists());
                        }
                    }
                    let _ = std::fs::remove_file(&out);
                }
            }
        }
    }

    #[test]
    fn dry_run_writes_nothing() {
        let cache = sample_cache();
        let out = tmp("dry.macho");
        let r = extract(
            &cache,
            0,
            &out,
            ExtractOptions {
                compact: true,
                dry_run: true,
            },
        )
        .unwrap();
        assert!(!out.exists());
        assert_eq!(
            String::from_utf8(r.text()).unwrap(),
            format!(
                "plan: /usr/lib/libfoo.dylib -> {} mode=compact size=4120 bytes segments=2\n",
                out.display()
            )
        );
        assert_eq!(
            String::from_utf8(r.json()).unwrap(),
            format!(
                "{{\"event\":\"plan\",\"image\":\"/usr/lib/libfoo.dylib\",\"output\":\"{}\",\"mode\":\"compact\",\"size\":4120,\"segments\":2}}\n",
                // Windows paths hold backslashes, which JSON escapes.
                String::from_utf8(json_escape(out.display().to_string().as_bytes())).unwrap()
            )
        );
    }

    #[test]
    fn failures() {
        let cache = sample_cache();
        let out = tmp("fail.macho");
        let msg = |idx: usize| {
            String::from_utf8(
                extract(&cache, idx, &out, ExtractOptions::default())
                    .unwrap_err()
                    .message,
            )
            .unwrap()
        };
        assert_eq!(msg(1), "target image is not Mach-O: /usr/lib/libbad.dylib");
        assert_eq!(
            msg(2),
            "cannot map image vmaddr to cache file offset: /unmapped"
        );
        assert!(!out.exists());
        let bad_dir = tmp("no-such-dir").join("x.macho");
        let e = extract(&cache, 0, &bad_dir, ExtractOptions::default()).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("cannot open output file: {}", bad_dir.display())
        );
    }

    #[test]
    fn hostile_load_commands_do_not_panic() {
        let mapping = CacheMapping {
            address: BASE,
            size: 0x2000,
            file_offset: 0,
            max_prot: 5,
            init_prot: 5,
        };
        let make = |ncmds: u32, sizeofcmds: u32, cmds: &[u8]| {
            let mut data = build_cache(&[mapping], &[(BASE + 0x1000, "/img")], 0x2000);
            let mut header = Vec::new();
            for w in [MH_MAGIC_64, 0, 0, 6, ncmds, sizeofcmds, 0, 0] {
                header.extend_from_slice(&w.to_le_bytes());
            }
            header.extend_from_slice(cmds);
            data[0x1000..0x1000 + header.len()].copy_from_slice(&header);
            parse(data).unwrap()
        };
        let out = tmp("hostile.macho");
        let run = |cache: &DyldSharedCache, compact: bool| {
            extract(
                cache,
                0,
                &out,
                ExtractOptions {
                    compact,
                    dry_run: false,
                },
            )
            .map_err(|e| String::from_utf8(e.message).unwrap())
        };

        assert_eq!(
            run(&make(70000, 0, &[]), false).unwrap_err(),
            "invalid load commands metadata: /img"
        );
        assert_eq!(
            run(&make(1, 0x0400_0001, &[]), false).unwrap_err(),
            "invalid load commands metadata: /img"
        );
        assert_eq!(
            run(&make(1, 0x2000, &[]), false).unwrap_err(),
            "load commands out of range: /img"
        );
        assert_eq!(
            run(&make(5, 0x100, &[]), false).unwrap_err(),
            "no loadable segments found: /img"
        );

        // cmdsize that would wrap 32-bit arithmetic
        let mut wrap = Vec::new();
        wrap.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        wrap.extend_from_slice(&0xFFFF_FFF8u32.to_le_bytes());
        assert_eq!(
            run(&make(2, 0x100, &wrap), false).unwrap_err(),
            "no loadable segments found: /img"
        );

        // segment claiming more bytes than the cache holds
        let big = seg64("__BIG", BASE, 0, 0x2001);
        assert_eq!(
            run(&make(1, 72, &big), false).unwrap_err(),
            "segment source out of range: __BIG image=/img"
        );

        // recorded offset that wraps: it cannot be kept, so the compact
        // layout is used, which ignores it
        let far = seg64("__FAR", BASE, u64::MAX - 0x10, 0x100);
        let cache = make(1, 72, &far);
        for compact in [false, true] {
            let r = extract(
                &cache,
                0,
                &out,
                ExtractOptions {
                    compact,
                    dry_run: false,
                },
            )
            .unwrap();
            assert_eq!((r.compact, r.size), (true, 0x1100));
            let _ = std::fs::remove_file(&out);
        }

        // target offset too large for the filesystem: clean failure, no
        // partial file left behind
        let big_off = seg64("__FAR", BASE, 1 << 62, 0x100);
        assert_eq!(
            run(&make(1, 72, &big_off), false).unwrap_err(),
            format!("cannot write output file: {}", out.display())
        );
        assert!(!out.exists());
    }

    #[test]
    fn cancellation_removes_partial_output() {
        let cache = sample_cache();
        let out = tmp("cancel.macho");
        let images: Vec<_> = cache.images().collect();
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let r = extract_image(
            &cache,
            &images[0],
            &out,
            &ExtractOptions::default(),
            &cancel,
            &mut |_| {
                calls += 1;
                cancel.store(true, Ordering::Relaxed);
            },
        );
        let e = r.unwrap_err();
        assert!(e.cancelled);
        assert_eq!(calls, 1);
        assert!(!out.exists());
    }

    #[test]
    fn batch_names() {
        let mut n = BatchNamer::new();
        assert_eq!(n.next_name(b"/usr/lib/libfoo.dylib"), b"libfoo.dylib.macho");
        assert_eq!(n.next_name(b"/other/libfoo.dylib"), b"libfoo.dylib.1.macho");
        assert_eq!(n.next_name(b"libfoo.dylib"), b"libfoo.dylib.2.macho");
        assert_eq!(n.next_name(b"/dir/"), b"image.macho");
        assert_eq!(n.next_name(b""), b"image.1.macho");
    }
}
