//! Attach by PID: resolve a process's executable path, or rebuild its main
//! Mach-O image from memory (macOS). The snapshot algorithm is safe code
//! over the [`RemoteReader`] trait; the Mach calls live in `attach_macos`.

use std::path::PathBuf;

pub const MSG_PATH_UNRESOLVED: &str =
    "Unable to resolve process executable path.\nOn macOS this may require extra privileges for target PID.";
pub const MSG_SNAPSHOT_MAC_ONLY: &str = "Memory snapshot attach is only available on macOS.";

/// Whether "Attach by PID (Executable Path)" can work on this platform.
pub fn executable_path_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

pub fn snapshot_supported() -> bool {
    cfg!(target_os = "macos")
}

/// A PID as typed by the user: a positive 32-bit integer.
pub fn parse_pid(text: &str) -> Option<i32> {
    text.trim().parse::<i32>().ok().filter(|p| *p >= 1)
}

/// Path of the executable of `pid`.
pub fn executable_path(pid: i32) -> Result<PathBuf, String> {
    let path = platform_executable_path(pid).ok_or_else(|| MSG_PATH_UNRESOLVED.to_string())?;
    if !path.exists() {
        return Err(format!(
            "Resolved executable path does not exist:\n{}",
            path.display()
        ));
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn platform_executable_path(pid: i32) -> Option<PathBuf> {
    crate::attach_macos::pid_path(pid).map(PathBuf::from)
}

#[cfg(target_os = "linux")]
fn platform_executable_path(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_executable_path(_pid: i32) -> Option<PathBuf> {
    None
}

/// Dump the main image of `pid` to a temp file and return its path.
pub fn memory_snapshot(pid: i32) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        let (task, infos_addr) = crate::attach_macos::Task::open(pid)?;
        let exec_path = crate::attach_macos::pid_path(pid).unwrap_or_default();
        let image = snapshot_main_image(&task, infos_addr, &exec_path)?;
        let name = format!(
            "MachOExplorer-attach-{pid}-{}.macho",
            crate::util::utc_stamp_now()
        );
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, image)
            .map_err(|_| format!("Write snapshot failed: {}", path.display()))?;
        Ok(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Err(MSG_SNAPSHOT_MAC_ONLY.to_string())
    }
}

/// Reads another process's memory.
pub trait RemoteReader {
    /// Fill `buf` from remote address `addr`, or fail without partial data.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), String>;
}

const MH_MAGIC: u32 = 0xfeed_face;
const MH_CIGAM: u32 = 0xcefa_edfe;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const PATH_MAX: usize = 4096;
const MAX_IMAGES: u32 = 4096;
const MAX_OUTPUT: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn read_cstring(reader: &dyn RemoteReader, addr: u64, max_len: usize) -> Option<String> {
    // Paths rarely sit at the very end of a mapping, but a full-size read can
    // still cross into an unmapped page; retry with smaller windows.
    for len in [max_len, 1024, 256] {
        let mut buf = vec![0u8; len];
        if reader.read(addr, &mut buf).is_ok() {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            return Some(String::from_utf8_lossy(&buf[..end]).into_owned());
        }
    }
    None
}

/// Segment commands of a Mach-O header blob (`header + load commands`).
pub fn parse_segments(
    blob: &[u8],
    header_size: usize,
    ncmds: u32,
    sizeofcmds: u32,
) -> Result<Vec<Segment>, String> {
    let mut segments = Vec::new();
    let mut consumed: u64 = 0;
    for _ in 0..ncmds {
        if consumed + 8 > sizeofcmds as u64 {
            return Err("Malformed remote load commands (truncated command)".into());
        }
        let at = header_size + consumed as usize;
        let (Some(cmd), Some(cmdsize)) = (u32_at(blob, at), u32_at(blob, at + 4)) else {
            return Err("Malformed remote load commands (truncated command)".into());
        };
        if cmdsize < 8 || consumed + cmdsize as u64 > sizeofcmds as u64 {
            return Err("Malformed remote load commands (invalid cmdsize)".into());
        }
        // segment_command_64: cmd, cmdsize, segname[16], vmaddr, vmsize, fileoff, filesize (72 bytes)
        // segment_command:    cmd, cmdsize, segname[16], 4 x u32                      (56 bytes)
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            if let (Some(vmaddr), Some(vmsize), Some(fileoff), Some(filesize)) = (
                u64_at(blob, at + 24),
                u64_at(blob, at + 32),
                u64_at(blob, at + 40),
                u64_at(blob, at + 48),
            ) {
                segments.push(Segment {
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                });
            }
        } else if cmd == LC_SEGMENT && cmdsize >= 56 {
            if let (Some(vmaddr), Some(vmsize), Some(fileoff), Some(filesize)) = (
                u32_at(blob, at + 24),
                u32_at(blob, at + 28),
                u32_at(blob, at + 32),
                u32_at(blob, at + 36),
            ) {
                segments.push(Segment {
                    vmaddr: vmaddr as u64,
                    vmsize: vmsize as u64,
                    fileoff: fileoff as u64,
                    filesize: filesize as u64,
                });
            }
        }
        consumed += cmdsize as u64;
    }
    if segments.is_empty() {
        return Err("No segment commands found in remote image".into());
    }
    Ok(segments)
}

/// `(vmaddr of the segment mapping file offset 0, output file size)`.
pub fn snapshot_layout(segments: &[Segment]) -> Result<(u64, u64), String> {
    let base = segments
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .map(|s| s.vmaddr)
        .ok_or("Cannot determine image slide (missing fileoff=0 segment)")?;
    let size = segments
        .iter()
        .map(|s| s.fileoff.saturating_add(s.filesize))
        .max()
        .unwrap_or(0);
    if size == 0 || size > MAX_OUTPUT {
        return Err(format!("Suspicious output size: {size}"));
    }
    Ok((base, size))
}

/// Rebuild the on-disk layout of a process's main image from its memory.
/// `all_image_infos` is the remote address of `dyld_all_image_infos`;
/// `exec_path` selects the main executable among the loaded images (the
/// first image is used when it is empty or not found).
pub fn snapshot_main_image(
    reader: &dyn RemoteReader,
    all_image_infos: u64,
    exec_path: &str,
) -> Result<Vec<u8>, String> {
    // struct dyld_all_image_infos { u32 version; u32 infoArrayCount; u64 infoArray; ... }
    let mut head = [0u8; 16];
    reader.read(all_image_infos, &mut head)?;
    let count = u32_at(&head, 4).unwrap();
    let array = u64_at(&head, 8).unwrap();
    if array == 0 || count == 0 {
        return Err("Remote dyld infoArray is empty".into());
    }
    // struct dyld_image_info { u64 imageLoadAddress; u64 imageFilePath; u64 imageFileModDate; }
    let count = count.min(MAX_IMAGES) as usize;
    let mut infos = vec![0u8; count * 24];
    reader.read(array, &mut infos)?;

    let mut load_addr = u64_at(&infos, 0).unwrap();
    if !exec_path.is_empty() {
        for i in 0..count {
            let addr = u64_at(&infos, i * 24).unwrap();
            let path_addr = u64_at(&infos, i * 24 + 8).unwrap();
            if addr == 0 || path_addr == 0 {
                continue;
            }
            if read_cstring(reader, path_addr, PATH_MAX - 1).as_deref() == Some(exec_path) {
                load_addr = addr;
                break;
            }
        }
    }

    // mach_header_64 is 32 bytes, mach_header 28; magic/ncmds/sizeofcmds
    // sit at the same offsets (0, 16, 20) in both.
    let mut hdr = [0u8; 32];
    reader.read(load_addr, &mut hdr)?;
    let magic = u32_at(&hdr, 0).unwrap();
    let is64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
    let is32 = magic == MH_MAGIC || magic == MH_CIGAM;
    if !is64 && !is32 {
        return Err(format!("Remote image magic not Mach-O: 0x{magic:x}"));
    }
    let ncmds = u32_at(&hdr, 16).unwrap();
    let sizeofcmds = u32_at(&hdr, 20).unwrap();
    let header_size = if is64 { 32 } else { 28 };
    if ncmds > 65536 || sizeofcmds > 64 * 1024 * 1024 {
        return Err(format!(
            "Suspicious load commands (ncmds={ncmds} sizeofcmds={sizeofcmds})"
        ));
    }

    let mut blob = vec![0u8; header_size + sizeofcmds as usize];
    reader.read(load_addr, &mut blob)?;
    let segments = parse_segments(&blob, header_size, ncmds, sizeofcmds)?;
    let (vmaddr_file0, output_size) = snapshot_layout(&segments)?;
    let slide = load_addr.wrapping_sub(vmaddr_file0);

    let mut output = vec![0u8; output_size as usize];
    if blob.len() <= output.len() {
        output[..blob.len()].copy_from_slice(&blob);
    }
    const CHUNK: u64 = 1024 * 1024;
    for seg in &segments {
        if seg.filesize == 0 || seg.fileoff.saturating_add(seg.filesize) > output_size {
            continue;
        }
        let remote = seg.vmaddr.wrapping_add(slide);
        let mut copied = 0u64;
        while copied < seg.filesize {
            let n = CHUNK.min(seg.filesize - copied) as usize;
            let at = (seg.fileoff + copied) as usize;
            reader.read(remote.wrapping_add(copied), &mut output[at..at + n])?;
            copied += n as u64;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sparse fake address space.
    struct Fake(Vec<(u64, Vec<u8>)>);

    impl RemoteReader for Fake {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), String> {
            for (base, data) in &self.0 {
                if addr >= *base && addr + buf.len() as u64 <= base + data.len() as u64 {
                    let o = (addr - base) as usize;
                    buf.copy_from_slice(&data[o..o + buf.len()]);
                    return Ok(());
                }
            }
            Err(format!("mach_vm_read_overwrite failed at 0x{addr:x}"))
        }
    }

    fn seg64(name: &str, vmaddr: u64, vmsize: u64, fileoff: u64, filesize: u64) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend(LC_SEGMENT_64.to_le_bytes());
        c.extend(72u32.to_le_bytes());
        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name.as_bytes());
        c.extend(n);
        for v in [vmaddr, vmsize, fileoff, filesize] {
            c.extend(v.to_le_bytes());
        }
        c.extend([0u8; 16]); // maxprot, initprot, nsects, flags
        c
    }

    /// A 0x3000-byte image: __TEXT maps file 0..0x2000, __DATA 0x2000..0x3000.
    fn image() -> Vec<u8> {
        let cmds = [
            seg64("__TEXT", 0x1_0000_0000, 0x2000, 0, 0x2000),
            seg64("__DATA", 0x1_0000_2000, 0x4000, 0x2000, 0x1000),
        ]
        .concat();
        let mut file = Vec::new();
        file.extend(MH_MAGIC_64.to_le_bytes());
        file.extend([0u8; 12]);
        file.extend(2u32.to_le_bytes());
        file.extend((cmds.len() as u32).to_le_bytes());
        file.extend([0u8; 8]);
        file.extend(cmds);
        file.resize(0x3000, 0);
        for (i, b) in file.iter_mut().enumerate().skip(0x200) {
            *b = (i % 251) as u8;
        }
        file
    }

    fn process(file: &[u8], slide: u64) -> (Fake, u64) {
        let text = 0x1_0000_0000 + slide;
        let mut data_seg = file[0x2000..0x3000].to_vec();
        data_seg.resize(0x4000, 0); // zero-fill beyond filesize
        let infos_addr = 0x7000_0000u64;
        let array_addr = 0x7000_1000u64;
        let path_a = 0x7000_2000u64;
        let path_b = 0x7000_3000u64;
        let mut head = Vec::new();
        head.extend(15u32.to_le_bytes());
        head.extend(2u32.to_le_bytes());
        head.extend(array_addr.to_le_bytes());
        let mut array = Vec::new();
        for (addr, path) in [(0xdead_0000u64, path_a), (text, path_b)] {
            array.extend(addr.to_le_bytes());
            array.extend(path.to_le_bytes());
            array.extend(0u64.to_le_bytes());
        }
        let cstr = |s: &str| {
            let mut v = s.as_bytes().to_vec();
            v.resize(PATH_MAX, 0);
            v
        };
        (
            Fake(vec![
                (infos_addr, head),
                (array_addr, array),
                (path_a, cstr("/usr/lib/dyld")),
                (path_b, cstr("/bin/target")),
                (text, file[..0x2000].to_vec()),
                (text + 0x2000, data_seg),
            ]),
            infos_addr,
        )
    }

    #[test]
    fn snapshot_reconstructs_file_layout() {
        let file = image();
        let (fake, infos) = process(&file, 0x4_5000);
        let out = snapshot_main_image(&fake, infos, "/bin/target").unwrap();
        assert_eq!(out, file);
    }

    #[test]
    fn snapshot_errors() {
        let file = image();
        let (fake, infos) = process(&file, 0);
        // Unknown path falls back to the first image, which is unreadable.
        let err = snapshot_main_image(&fake, infos, "/nope").unwrap_err();
        assert!(
            err.contains("mach_vm_read_overwrite failed at 0xdead0000"),
            "{err}"
        );

        let mut bad = file.clone();
        bad[0] = 0;
        let (fake, infos) = process(&bad, 0);
        assert_eq!(
            snapshot_main_image(&fake, infos, "/bin/target").unwrap_err(),
            "Remote image magic not Mach-O: 0xfeedfa00"
        );

        let empty = Fake(vec![(0x10, vec![0u8; 16])]);
        assert_eq!(
            snapshot_main_image(&empty, 0x10, "").unwrap_err(),
            "Remote dyld infoArray is empty"
        );
    }

    #[test]
    fn segment_parsing_rejects_malformed_commands() {
        let mut blob = vec![0u8; 32];
        blob.extend(LC_SEGMENT_64.to_le_bytes());
        blob.extend(4u32.to_le_bytes());
        assert_eq!(
            parse_segments(&blob, 32, 1, 8).unwrap_err(),
            "Malformed remote load commands (invalid cmdsize)"
        );
        assert_eq!(
            parse_segments(&blob, 32, 1, 4).unwrap_err(),
            "Malformed remote load commands (truncated command)"
        );
        let mut other = vec![0u8; 32];
        other.extend(0x2u32.to_le_bytes());
        other.extend(8u32.to_le_bytes());
        assert_eq!(
            parse_segments(&other, 32, 1, 8).unwrap_err(),
            "No segment commands found in remote image"
        );
    }

    #[test]
    fn layout_validation() {
        let s = |fileoff, filesize| Segment {
            vmaddr: 0x1000,
            vmsize: 0x1000,
            fileoff,
            filesize,
        };
        assert_eq!(
            snapshot_layout(&[s(0, 0x1000), s(0x1000, 0x800)]).unwrap(),
            (0x1000, 0x1800)
        );
        assert!(snapshot_layout(&[s(0x1000, 0x800)])
            .unwrap_err()
            .contains("missing fileoff=0"));
        assert!(snapshot_layout(&[s(0, MAX_OUTPUT + 1)])
            .unwrap_err()
            .starts_with("Suspicious output size"));
    }

    #[test]
    fn pids() {
        assert_eq!(parse_pid(" 123 "), Some(123));
        assert_eq!(parse_pid("0"), None);
        assert_eq!(parse_pid("-4"), None);
        assert_eq!(parse_pid("abc"), None);
        assert_eq!(parse_pid("99999999999"), None);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn own_executable_path_resolves() {
        let path = executable_path(std::process::id() as i32).unwrap();
        assert_eq!(
            path.canonicalize().unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    }
}
