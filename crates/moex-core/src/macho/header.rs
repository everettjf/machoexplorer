use super::segment::Segment;
use crate::consts::*;
use crate::error::{err, Result};
use crate::image::Image;
use crate::names;
use std::sync::Arc;

/// One load command: where it is and its generic header.
#[derive(Debug, Clone, Copy)]
pub struct LoadCommand {
    /// File offset of the command.
    pub offset: u64,
    pub cmd: u32,
    pub cmdsize: u32,
}

/// A Mach-O header (32- or 64-bit) and its load command list.
pub struct MachHeader {
    pub image: Arc<Image>,
    /// File offset of the header (non-zero inside fat files and archives).
    pub offset: u64,
    pub is64: bool,
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    /// Only meaningful when `is64`.
    pub reserved: u32,
    pub loadcmds: Vec<LoadCommand>,
    /// `LC_SEGMENT` / `LC_SEGMENT_64` commands in load-command order.
    pub segments: Vec<Segment>,
}

impl MachHeader {
    pub fn parse(image: &Arc<Image>, offset: u64) -> Result<Self> {
        const OOB: &str = "Malformed file: struct read out of bounds";
        let Some(raw_magic) = image.u32(offset) else {
            return err(OOB);
        };
        let is64 = super::is_64_magic(raw_magic);
        let size = if is64 {
            MACH_HEADER_64_SIZE
        } else {
            MACH_HEADER_SIZE
        };
        if !image.in_file(offset, size) {
            return err(OOB);
        }
        // Byte-swapped headers have their fields swapped; the load commands
        // that follow are read as-is.
        let swap = raw_magic == MH_CIGAM || raw_magic == MH_CIGAM_64;
        let rd = |o: u64| {
            let v = image.u32(offset + o).unwrap_or(0);
            if swap {
                v.swap_bytes()
            } else {
                v
            }
        };
        let mut mh = MachHeader {
            image: image.clone(),
            offset,
            is64,
            magic: rd(0),
            cputype: rd(4),
            cpusubtype: rd(8),
            filetype: rd(12),
            ncmds: rd(16),
            sizeofcmds: rd(20),
            flags: rd(24),
            reserved: if is64 { rd(28) } else { 0 },
            loadcmds: Vec::new(),
            segments: Vec::new(),
        };

        let file_size = image.len();
        let sizeofcmds = mh.sizeofcmds as u64;
        if offset + size > file_size {
            return err("Malformed Mach-O: header exceeds file size");
        }
        if offset + size + sizeofcmds > file_size {
            return err("Malformed Mach-O: load commands exceed file size");
        }
        let align: u32 = if is64 { 8 } else { 4 };
        let mut cur = offset + size;
        let mut parsed: u64 = 0;
        for _ in 0..mh.ncmds {
            if parsed + LOAD_COMMAND_SIZE > sizeofcmds {
                return err("Malformed Mach-O: truncated load command");
            }
            let cmd = image.u32(cur).unwrap_or(0);
            let cmdsize = image.u32(cur + 4).unwrap_or(0);
            if (cmdsize as u64) < LOAD_COMMAND_SIZE {
                return err("Malformed Mach-O: invalid load command size");
            }
            if cmdsize % align != 0 {
                return err("Malformed Mach-O: misaligned load command size");
            }
            if parsed + cmdsize as u64 > sizeofcmds {
                return err("Malformed Mach-O: load command size overflow");
            }
            let lc = LoadCommand {
                offset: cur,
                cmd,
                cmdsize,
            };
            if cmd == LC_SEGMENT || cmd == LC_SEGMENT_64 {
                mh.segments.push(Segment::parse(image, lc, offset));
            }
            mh.loadcmds.push(lc);
            parsed += cmdsize as u64;
            cur += cmdsize as u64;
        }
        Ok(mh)
    }

    /// Size in bytes of the header struct itself.
    pub fn header_size(&self) -> u64 {
        if self.is64 {
            MACH_HEADER_64_SIZE
        } else {
            MACH_HEADER_SIZE
        }
    }

    pub fn arch(&self) -> &'static str {
        names::arch(self.cputype)
    }

    pub fn has_load_command(&self, cmds: &[u32]) -> bool {
        self.loadcmds.iter().any(|lc| cmds.contains(&lc.cmd))
    }

    pub fn find_load_command(&self, cmds: &[u32]) -> Option<&LoadCommand> {
        self.loadcmds.iter().find(|lc| cmds.contains(&lc.cmd))
    }
}

impl MachHeader {
    /// Little-endian `u32` at `off` bytes into load command `lc` (0 when out
    /// of file).
    pub fn lc_u32(&self, lc: &LoadCommand, off: u64) -> u32 {
        self.image.u32(lc.offset + off).unwrap_or(0)
    }

    pub fn lc_u64(&self, lc: &LoadCommand, off: u64) -> u64 {
        self.image.u64(lc.offset + off).unwrap_or(0)
    }

    /// NUL-terminated string referenced by an `lc_str` offset stored at
    /// `field_off` inside `lc`. `None` when the offset points outside the
    /// command. Returns the string's file offset and its bytes.
    pub fn lc_str(&self, lc: &LoadCommand, field_off: u64) -> Option<(u64, &[u8])> {
        let str_off = self.lc_u32(lc, field_off);
        if str_off >= lc.cmdsize {
            return None;
        }
        let at = lc.offset + str_off as u64;
        self.image.cstr(at, u64::MAX).map(|s| (at, s))
    }

    /// vmaddr of the segment that maps file offset 0 (the image base).
    pub fn base_address(&self) -> u64 {
        // 32-bit segments are consulted first, then 64-bit ones override.
        let pick = |want64: bool| {
            self.segments
                .iter()
                .find(|s| s.is64 == want64 && s.fileoff == 0 && s.filesize != 0)
                .map(|s| s.vmaddr)
        };
        pick(true).or_else(|| pick(false)).unwrap_or(0)
    }

    /// All sections of all segments, in file order.
    pub fn sections(&self) -> impl Iterator<Item = &super::segment::Section> {
        self.segments.iter().flat_map(|s| s.sections.iter())
    }

    /// File offset backing virtual address `vmaddr`: the first segment of
    /// this header's word size whose VM range contains it. `None` when no
    /// segment does, or the address lies past the segment's file contents or
    /// the end of the file.
    pub fn vm_to_file_offset(&self, vmaddr: u64) -> Option<u64> {
        let seg = self
            .segments
            .iter()
            .filter(|s| s.is64 == self.is64)
            .find(|s| vmaddr >= s.vmaddr && vmaddr < s.vmaddr.wrapping_add(s.vmsize))?;
        let delta = vmaddr - seg.vmaddr;
        if delta >= seg.filesize {
            return None;
        }
        let fileoff = seg.fileoff.wrapping_add(delta);
        (fileoff < self.image.len()).then_some(fileoff)
    }
}
