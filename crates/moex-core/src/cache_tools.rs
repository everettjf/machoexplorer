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
    /// Pack segments back to back (page aligned) and rewrite the file
    /// offsets in the load commands, instead of keeping each segment at its
    /// original file offset.
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
    pub segments: Vec<SegmentCopyPlan>,
    pub out_size: u64,
}

/// Result of a successful (or dry-run) extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractOutcome {
    pub image_path: Vec<u8>,
    pub output: PathBuf,
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

/// Work out which byte ranges of the cache make up `image`.
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
    let rd64 = |off: u64| data.u64(off).unwrap_or(0);

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
    // `header_fileoff + 32 <= cache_size` was checked above.
    if !data.in_file(header_fileoff + mh_size, sizeofcmds as u64) {
        return fail("load commands out of range: ");
    }

    // `ncmds` is capped at 65535, which bounds this list.
    let mut segments = Vec::new();
    let cmds_start = header_fileoff + mh_size;
    let cmds_size = sizeofcmds as u64;
    let mut parsed: u64 = 0;
    for _ in 0..ncmds {
        if parsed + LOAD_COMMAND_SIZE > cmds_size {
            break;
        }
        let lc = cmds_start + parsed;
        let cmd = rd32(lc);
        let cmdsize = rd32(lc + 4) as u64;
        if cmdsize < LOAD_COMMAND_SIZE || parsed + cmdsize > cmds_size {
            break;
        }
        // (vmaddr, fileoff, filesize)
        let seg = if cmd == LC_SEGMENT_64 && cmdsize >= SEGMENT_COMMAND_64_SIZE {
            Some((rd64(lc + 24), rd64(lc + 40), rd64(lc + 48)))
        } else if cmd == LC_SEGMENT && cmdsize >= SEGMENT_COMMAND_SIZE {
            Some((
                rd32(lc + 24) as u64,
                rd32(lc + 32) as u64,
                rd32(lc + 36) as u64,
            ))
        } else {
            None
        };
        if let Some((vmaddr, fileoff, filesize)) = seg {
            if filesize > 0 {
                if let Some((source_file, source_fileoff)) = cache.resolve(vmaddr) {
                    segments.push(SegmentCopyPlan {
                        name: data.cstr(lc + 8, 16).unwrap_or(&[]).to_vec(),
                        vmaddr,
                        image_fileoff: fileoff,
                        source_file,
                        source_fileoff,
                        target_fileoff: fileoff,
                        size: filesize,
                    });
                }
            }
        }
        parsed += cmdsize;
    }
    if segments.is_empty() {
        return fail("no loadable segments found: ");
    }

    let segment_error = |prefix: &str, p: &SegmentCopyPlan| {
        let mut detail = p.name.clone();
        detail.extend_from_slice(b" image=");
        detail.extend_from_slice(&image.path);
        ExtractError::new(prefix, &detail)
    };
    for p in &segments {
        let in_source = cache
            .file_image(p.source_file)
            .is_some_and(|f| f.in_file(p.source_fileoff, p.size));
        if !in_source {
            return Err(segment_error("segment source out of range: ", p));
        }
    }

    if options.compact {
        segments.sort_by(|a, b| {
            a.image_fileoff
                .cmp(&b.image_fileoff)
                .then(a.vmaddr.cmp(&b.vmaddr))
        });
        let mut next_off = mh_size + cmds_size;
        for p in &mut segments {
            let target = align_up(next_off, 0x1000);
            let end = target.and_then(|t| t.checked_add(p.size));
            let (Some(target), Some(end)) = (target, end) else {
                return Err(segment_error("segment target out of range: ", p));
            };
            p.target_fileoff = target;
            next_off = end;
        }
    }

    let mut out_size = mh_size + cmds_size;
    for p in &segments {
        let Some(end) = p.target_fileoff.checked_add(p.size) else {
            return Err(segment_error("segment target out of range: ", p));
        };
        out_size = out_size.max(end);
    }

    Ok(ExtractPlan {
        header_file,
        header_fileoff,
        is64,
        mh_size,
        sizeofcmds,
        segments,
        out_size,
    })
}

/// New value of a file offset stored in a load command: the segment whose
/// old file range contains it decides. An offset exactly at the end of a
/// segment (an empty table placed last) moves with that segment when no
/// other segment starts there. `None` when no segment holds the offset or
/// the new offset does not fit in 32 bits.
fn remap_file_offset(plans: &[SegmentCopyPlan], old_off: u32) -> Option<u32> {
    let old = old_off as u64;
    let delta_in = |p: &SegmentCopyPlan, inclusive: bool| {
        let delta = old.checked_sub(p.image_fileoff)?;
        (delta < p.size || (inclusive && delta == p.size)).then_some(delta)
    };
    let (p, delta) = plans
        .iter()
        .find_map(|p| Some((p, delta_in(p, false)?)))
        .or_else(|| plans.iter().find_map(|p| Some((p, delta_in(p, true)?))))?;
    u32::try_from(p.target_fileoff.checked_add(delta)?).ok()
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

/// Rewrite the file offsets stored in the load commands `cmds` so they match
/// the compacted segment layout.
fn patch_load_commands_for_compaction(cmds: &mut [u8], plans: &[SegmentCopyPlan], is64: bool) {
    const SYMTAB_COMMAND_SIZE: usize = 24;
    const DYSYMTAB_COMMAND_SIZE: usize = 80;
    const DYLD_INFO_COMMAND_SIZE: usize = 48;
    const LINKEDIT_DATA_COMMAND_SIZE: usize = 16;
    const TWOLEVEL_HINTS_COMMAND_SIZE: usize = 16;

    // An offset of 0 means "not present" in every one of these commands
    // and stays 0.
    fn remap_field(cmds: &mut [u8], plans: &[SegmentCopyPlan], off: usize) {
        let mapped = get_u32(cmds, off)
            .filter(|&old| old != 0)
            .and_then(|old| remap_file_offset(plans, old));
        if let Some(mapped) = mapped {
            put(cmds, off, &mapped.to_le_bytes());
        }
    }

    let total = cmds.len();
    let mut parsed = 0usize;
    while parsed + LOAD_COMMAND_SIZE as usize <= total {
        let (Some(cmd), Some(cmdsize)) = (get_u32(cmds, parsed), get_u32(cmds, parsed + 4)) else {
            break;
        };
        let cmdsize = cmdsize as usize;
        if cmdsize < LOAD_COMMAND_SIZE as usize || cmdsize > total - parsed {
            break;
        }
        let lc = parsed;
        if cmd == LC_SEGMENT_64 && cmdsize >= SEGMENT_COMMAND_64_SIZE as usize && is64 {
            if let Some(vmaddr) = get_u64(cmds, lc + 24) {
                if let Some(p) = plans.iter().find(|p| p.vmaddr == vmaddr) {
                    put(cmds, lc + 40, &p.target_fileoff.to_le_bytes());
                }
            }
        } else if cmd == LC_SEGMENT && cmdsize >= SEGMENT_COMMAND_SIZE as usize && !is64 {
            if let Some(vmaddr) = get_u32(cmds, lc + 24) {
                if let Some(p) = plans.iter().find(|p| p.vmaddr == vmaddr as u64) {
                    put(cmds, lc + 32, &(p.target_fileoff as u32).to_le_bytes());
                }
            }
        } else if cmd == LC_SYMTAB && cmdsize >= SYMTAB_COMMAND_SIZE {
            for off in [8, 16] {
                remap_field(cmds, plans, lc + off);
            }
        } else if cmd == LC_DYSYMTAB && cmdsize >= DYSYMTAB_COMMAND_SIZE {
            for off in [32, 40, 48, 56, 64, 72] {
                remap_field(cmds, plans, lc + off);
            }
        } else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY)
            && cmdsize >= DYLD_INFO_COMMAND_SIZE
        {
            for off in [8, 16, 24, 32, 40] {
                remap_field(cmds, plans, lc + off);
            }
        } else if matches!(
            cmd,
            LC_FUNCTION_STARTS
                | LC_DATA_IN_CODE
                | LC_CODE_SIGNATURE
                | LC_SEGMENT_SPLIT_INFO
                | LC_DYLIB_CODE_SIGN_DRS
                | LC_LINKER_OPTIMIZATION_HINT
                | LC_DYLD_EXPORTS_TRIE
                | LC_DYLD_CHAINED_FIXUPS
        ) && cmdsize >= LINKEDIT_DATA_COMMAND_SIZE
        {
            remap_field(cmds, plans, lc + 8);
        } else if cmd == LC_TWOLEVEL_HINTS && cmdsize >= TWOLEVEL_HINTS_COMMAND_SIZE {
            remap_field(cmds, plans, lc + 8);
        }
        parsed += cmdsize;
    }
}

const SEGMENT_COMMAND_SIZE: u64 = crate::macho::segment::SEGMENT_COMMAND_SIZE;
const SEGMENT_COMMAND_64_SIZE: u64 = crate::macho::segment::SEGMENT_COMMAND_64_SIZE;

fn write_plan(
    cache: &DyldSharedCache,
    plan: &ExtractPlan,
    compact: bool,
    out: &mut File,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(ExtractProgress<'_>),
) -> Result<(), WriteError> {
    out.set_len(plan.out_size)?;

    // The header range was bounds-checked while planning, which also bounds
    // this buffer (at most 64 MiB + 32 bytes).
    let header_len = plan.mh_size + plan.sizeofcmds as u64;
    let mut header = cache
        .file_image(plan.header_file)
        .and_then(|data| data.slice(plan.header_fileoff, header_len))
        .ok_or(WriteError::Source)?
        .to_vec();
    if compact {
        if let Some(cmds) = header.get_mut(plan.mh_size as usize..) {
            patch_load_commands_for_compaction(cmds, &plan.segments, plan.is64);
        }
    }
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&header)?;

    let bytes_total: u64 = plan
        .segments
        .iter()
        .fold(0u64, |acc, p| acc.saturating_add(p.size));
    let mut bytes_done: u64 = 0;
    for p in &plan.segments {
        let data: &Image = cache.file_image(p.source_file).ok_or(WriteError::Source)?;
        let mut copied: u64 = 0;
        while copied < p.size {
            if cancel.load(Ordering::Relaxed) {
                return Err(WriteError::Cancelled);
            }
            let n = COPY_CHUNK.min(p.size - copied);
            // `source_fileoff + size` was checked to be inside the file.
            let chunk = data
                .slice(p.source_fileoff + copied, n)
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
        compact: options.compact,
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
    match write_plan(cache, &plan, options.compact, &mut file, cancel, progress) {
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
        data[0x2000..0x2004].copy_from_slice(b"junk");
        parse(data).unwrap()
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
        assert_eq!((r.size, r.segments), (0x8100, 2));
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), 0x8100);
        assert_eq!(&bytes[..0x400], cache.image.slice(0x1000, 0x400).unwrap());
        assert!(bytes[0x400..0x8000].iter().all(|&b| b == 0));
        assert_eq!(&bytes[0x8000..], cache.image.slice(0x3000, 0x100).unwrap());
        let text = String::from_utf8(r.text()).unwrap();
        assert_eq!(
            text,
            format!(
                "extracted: /usr/lib/libfoo.dylib\nmode: raw-fileoff\noutput: {} size=33024 bytes segments=2\n",
                out.display()
            )
        );
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
        // __TEXT at 0x1000, __LINKEDIT at 0x2000
        assert_eq!(r.size, 0x2100);
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), 0x2100);
        assert_eq!(
            &bytes[0x1000..0x1400],
            cache.image.slice(0x1000, 0x400).unwrap()
        );
        assert_eq!(&bytes[0x2000..], cache.image.slice(0x3000, 0x100).unwrap());
        let fileoff = |lc: usize| u64::from_le_bytes(bytes[lc + 40..lc + 48].try_into().unwrap());
        assert_eq!(fileoff(32), 0x1000);
        assert_eq!(fileoff(32 + 72), 0x2000);
        // segment without file content is left alone
        assert_eq!(fileoff(32 + 144), 0x9000);
        let sym = 32 + 216;
        assert_eq!(
            u32::from_le_bytes(bytes[sym + 8..sym + 12].try_into().unwrap()),
            0x2010
        );
        assert_eq!(
            u32::from_le_bytes(bytes[sym + 16..sym + 20].try_into().unwrap()),
            0x2020
        );
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

        let out = dir.join("out.macho");
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
        // __DATA (file offset 0x400) sorts first, then __LINKEDIT, __TEXT.
        assert_eq!((r.segments, r.size), (3, 0x3200));
        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes[0x1000..0x1080].iter().all(|&b| b == 0xD1));
        assert!(bytes[0x2000..0x2040].iter().all(|&b| b == 0xE2));
        assert_eq!(&bytes[0x3000..0x3004], &MH_MAGIC_64.to_le_bytes());
        let sym = 32 + 3 * 72;
        assert_eq!(
            u32::from_le_bytes(bytes[sym + 8..sym + 12].try_into().unwrap()),
            0x2010
        );

        // Without the sub-cache file the segment cannot be located.
        std::fs::remove_file(dir.join("cache.01")).unwrap();
        let cache = open_cache(&main_path).unwrap();
        let plan = plan_extraction(&cache, &image, &ExtractOptions::default()).unwrap();
        assert_eq!(plan.segments.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_keeps_absent_offsets_zero() {
        let plans = [
            SegmentCopyPlan {
                name: b"__TEXT".to_vec(),
                vmaddr: 0x1000,
                image_fileoff: 0,
                source_file: 0,
                source_fileoff: 0,
                target_fileoff: 0x1000,
                size: 0x400,
            },
            SegmentCopyPlan {
                name: b"__LINKEDIT".to_vec(),
                vmaddr: 0x3000,
                image_fileoff: 0x8000,
                source_file: 0,
                source_fileoff: 0,
                target_fileoff: 0x2000,
                size: 0x100,
            },
        ];
        // LC_DYSYMTAB: only the indirect symbol table is present.
        let mut cmds = Vec::new();
        for v in [LC_DYSYMTAB, 80] {
            cmds.extend_from_slice(&v.to_le_bytes());
        }
        cmds.resize(80, 0);
        cmds[56..60].copy_from_slice(&0x8040u32.to_le_bytes());
        // LC_DYLD_INFO_ONLY: only export info, and one that is not in any
        // segment (left alone).
        for v in [LC_DYLD_INFO_ONLY, 48] {
            cmds.extend_from_slice(&v.to_le_bytes());
        }
        cmds.resize(128, 0);
        cmds[80 + 40..80 + 44].copy_from_slice(&0x8080u32.to_le_bytes());
        cmds[80 + 8..80 + 12].copy_from_slice(&0x7000u32.to_le_bytes());
        patch_load_commands_for_compaction(&mut cmds, &plans, true);
        let at = |off: usize| get_u32(&cmds, off).unwrap();
        // tocoff, modtaboff, extrefsymoff, extreloff, locreloff stay 0
        for off in [32, 40, 48, 64, 72] {
            assert_eq!(at(off), 0, "dysymtab field at {off}");
        }
        assert_eq!(at(56), 0x2040);
        assert_eq!(at(80 + 8), 0x7000);
        for off in [16, 24, 32] {
            assert_eq!(at(80 + off), 0, "dyld info field at {off}");
        }
        assert_eq!(at(80 + 40), 0x2080);
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
                "plan: /usr/lib/libfoo.dylib -> {} mode=compact size=8448 bytes segments=2\n",
                out.display()
            )
        );
        assert_eq!(
            String::from_utf8(r.json()).unwrap(),
            format!(
                "{{\"event\":\"plan\",\"image\":\"/usr/lib/libfoo.dylib\",\"output\":\"{}\",\"mode\":\"compact\",\"size\":8448,\"segments\":2}}\n",
                out.display()
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

        // target offset that wraps: refused while planning, so a dry run
        // reports it too and nothing is created
        let far = seg64("__FAR", BASE, u64::MAX - 0x10, 0x100);
        let cache = make(1, 72, &far);
        assert_eq!(
            run(&cache, false).unwrap_err(),
            "segment target out of range: __FAR image=/img"
        );
        assert!(!out.exists());
        let dry = extract(
            &cache,
            0,
            &out,
            ExtractOptions {
                compact: false,
                dry_run: true,
            },
        );
        assert_eq!(
            String::from_utf8(dry.unwrap_err().message).unwrap(),
            "segment target out of range: __FAR image=/img"
        );
        // compact mode does not use the stored offset
        assert!(run(&cache, true).is_ok());
        let _ = std::fs::remove_file(&out);

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

    #[test]
    fn remap() {
        let plans = [SegmentCopyPlan {
            name: b"__LINKEDIT".to_vec(),
            vmaddr: 0,
            image_fileoff: 0x8000,
            source_file: 0,
            source_fileoff: 0,
            target_fileoff: 0x2000,
            size: 0x100,
        }];
        assert_eq!(remap_file_offset(&plans, 0x8010), Some(0x2010));
        // The end of the segment moves with it (an empty trailing table).
        assert_eq!(remap_file_offset(&plans, 0x8100), Some(0x2100));
        assert_eq!(remap_file_offset(&plans, 0x8101), None);
        assert_eq!(remap_file_offset(&plans, 0x7fff), None);
        // ... unless another segment starts there.
        let two = [
            plans[0].clone(),
            SegmentCopyPlan {
                image_fileoff: 0x8100,
                target_fileoff: 0x5000,
                ..plans[0].clone()
            },
        ];
        assert_eq!(remap_file_offset(&two, 0x8100), Some(0x5000));
        let far = [SegmentCopyPlan {
            target_fileoff: 0xFFFF_FFF0,
            ..plans[0].clone()
        }];
        assert_eq!(remap_file_offset(&far, 0x8010), None);
        assert_eq!(remap_file_offset(&far, 0x800f), Some(0xFFFF_FFFF));
    }
}
