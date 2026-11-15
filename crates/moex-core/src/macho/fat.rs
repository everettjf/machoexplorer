use super::header::MachHeader;
use crate::consts::*;
use crate::error::{err, Result};
use crate::image::Image;
use std::sync::Arc;

pub struct FatArch {
    /// File offset of this `fat_arch` / `fat_arch_64` entry.
    pub entry_offset: u64,
    pub is_fat64: bool,
    pub cputype: u32,
    pub cpusubtype: u32,
    /// File offset of the slice.
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub mh: Arc<MachHeader>,
}

impl FatArch {
    pub fn entry_size(&self) -> u64 {
        if self.is_fat64 {
            FAT_ARCH_64_SIZE
        } else {
            FAT_ARCH_SIZE
        }
    }
}

pub struct FatHeader {
    pub offset: u64,
    /// Magic after byte-swapping to host order (so normally `FAT_MAGIC`).
    pub magic: u32,
    pub nfat_arch: u32,
    pub archs: Vec<FatArch>,
}

impl FatHeader {
    pub fn parse(image: &Arc<Image>, offset: u64) -> Result<Self> {
        if !image.in_file(offset, FAT_HEADER_SIZE) {
            return err("Malformed file: struct read out of bounds");
        }
        let raw_magic = image.u32(offset).unwrap_or(0);
        // Fat headers are big-endian on disk, so a little-endian read sees CIGAM.
        let swap = raw_magic == FAT_CIGAM || raw_magic == FAT_CIGAM_64;
        let fix32 = |v: u32| if swap { v.swap_bytes() } else { v };
        let fix64 = |v: u64| if swap { v.swap_bytes() } else { v };
        let magic = fix32(raw_magic);
        let nfat_arch = fix32(image.u32(offset + 4).unwrap_or(0));
        let fat64 = magic == FAT_MAGIC_64;

        let file_size = image.len();
        let entry_size = if fat64 {
            FAT_ARCH_64_SIZE
        } else {
            FAT_ARCH_SIZE
        };
        let table_size = nfat_arch as u64 * entry_size;
        if file_size - offset - FAT_HEADER_SIZE < table_size {
            return err("Malformed Fat Mach-O: arch table exceeds file size");
        }

        let mut archs = Vec::with_capacity(nfat_arch.min(64) as usize);
        for i in 0..nfat_arch as u64 {
            let e = offset + FAT_HEADER_SIZE + i * entry_size;
            let cputype = fix32(image.u32(e).unwrap_or(0));
            let cpusubtype = fix32(image.u32(e + 4).unwrap_or(0));
            let (obj_off, obj_size, align) = if fat64 {
                (
                    fix64(image.u64(e + 8).unwrap_or(0)),
                    fix64(image.u64(e + 16).unwrap_or(0)),
                    fix32(image.u32(e + 24).unwrap_or(0)),
                )
            } else {
                (
                    fix32(image.u32(e + 8).unwrap_or(0)) as u64,
                    fix32(image.u32(e + 12).unwrap_or(0)) as u64,
                    fix32(image.u32(e + 16).unwrap_or(0)),
                )
            };
            if obj_off > file_size || obj_size > file_size - obj_off {
                return err("Malformed Fat Mach-O: arch range exceeds file size");
            }
            if obj_size < 4 {
                return err("Malformed Fat Mach-O: arch payload too small");
            }
            if obj_off % 8 != 0 {
                return err("Malformed Fat Mach-O: arch offset is misaligned");
            }
            let mh = Arc::new(MachHeader::parse_slice(image, obj_off, obj_size)?);
            archs.push(FatArch {
                entry_offset: e,
                is_fat64: fat64,
                cputype,
                cpusubtype,
                offset: obj_off,
                size: obj_size,
                align,
                mh,
            });
        }
        Ok(FatHeader {
            offset,
            magic,
            nfat_arch,
            archs,
        })
    }
}
