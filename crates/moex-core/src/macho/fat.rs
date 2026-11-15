use super::archive::{is_archive_magic, Archive};
use super::header::MachHeader;
use crate::consts::*;
use crate::error::{err, Result};
use crate::image::Image;
use std::sync::Arc;

/// What one slice of a fat file holds.
pub enum SliceContent {
    MachO(Arc<MachHeader>),
    /// A static library (fat `.a` files hold one archive per architecture).
    Archive(Arc<Archive>),
    /// Anything else, e.g. the per-architecture payloads of a `.metallib`,
    /// or a Mach-O / archive too damaged to parse (the reason is kept).
    Unknown(String),
}

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
    pub content: SliceContent,
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
            // Slices need not be Mach-O, and their alignment is whatever the
            // entry declares, so neither is grounds for rejecting the file.
            let head = image.slice(obj_off, obj_size.min(8)).unwrap_or(&[]);
            let magic = image.u32(obj_off).unwrap_or(0);
            let content = if is_archive_magic(head) {
                match Archive::parse_range(image, obj_off, obj_size) {
                    Ok(archive) => SliceContent::Archive(Arc::new(archive)),
                    Err(e) => SliceContent::Unknown(e.to_string()),
                }
            } else if obj_size >= 4 && super::is_valid_magic(magic) && !super::is_fat_magic(magic) {
                match MachHeader::parse_slice(image, obj_off, obj_size) {
                    Ok(mh) => SliceContent::MachO(Arc::new(mh)),
                    Err(e) => SliceContent::Unknown(e.to_string()),
                }
            } else {
                SliceContent::Unknown("Not a Mach-O or archive".to_string())
            };
            archs.push(FatArch {
                entry_offset: e,
                is_fat64: fat64,
                cputype,
                cpusubtype,
                offset: obj_off,
                size: obj_size,
                align,
                content,
            });
        }
        // A fat file none of whose slices can be read is reported with the
        // first slice's reason, as a thin file would be.
        if !archs.is_empty()
            && archs
                .iter()
                .all(|a| matches!(a.content, SliceContent::Unknown(_)))
        {
            if let Some(SliceContent::Unknown(reason)) = archs.first().map(|a| &a.content) {
                return err(&format!("No readable slice in fat file: {reason}"));
            }
        }
        Ok(FatHeader {
            offset,
            magic,
            nfat_arch,
            archs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fat file with one slice per payload, each at a 4-byte-aligned
    /// offset.
    fn fat(payloads: &[&[u8]]) -> Arc<Image> {
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&(payloads.len() as u32).to_be_bytes());
        let mut offset = (FAT_HEADER_SIZE + payloads.len() as u64 * FAT_ARCH_SIZE) as u32;
        let mut body = Vec::new();
        for p in payloads {
            for v in [CPU_TYPE_ARM64, 0, offset, p.len() as u32, 2] {
                data.extend_from_slice(&v.to_be_bytes());
            }
            body.extend_from_slice(p);
            while body.len() % 4 != 0 {
                body.push(0);
            }
            offset = (FAT_HEADER_SIZE + payloads.len() as u64 * FAT_ARCH_SIZE) as u32
                + body.len() as u32;
        }
        data.extend_from_slice(&body);
        Arc::new(Image::from_vec(data).unwrap())
    }

    fn archive_bytes() -> Vec<u8> {
        let mut a = b"!<arch>\n".to_vec();
        a.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "a.txt/", "0", "0", "0", "100644", "6"
            )
            .as_bytes(),
        );
        a.extend_from_slice(b"hello!");
        a
    }

    #[test]
    fn archive_slices_at_unaligned_offsets() {
        // The second slice starts at an offset that is a multiple of 4 but
        // not of 8, as in real fat static libraries.
        let image = fat(&[&archive_bytes(), &archive_bytes()]);
        let header = FatHeader::parse(&image, 0).unwrap();
        assert_eq!(header.archs.len(), 2);
        for arch in &header.archs {
            let SliceContent::Archive(archive) = &arch.content else {
                panic!("slice is not an archive");
            };
            assert_eq!(archive.offset, arch.offset);
            assert_eq!(archive.members[0].name, b"a.txt");
            assert_eq!(archive.members[0].data_size, 6);
        }
        assert_ne!(header.archs[1].offset % 8, 0);
    }

    #[test]
    fn unknown_slices() {
        // One readable slice keeps the file; the other is listed as unknown.
        let image = fat(&[b"MTLB....", &archive_bytes()]);
        let header = FatHeader::parse(&image, 0).unwrap();
        assert!(matches!(header.archs[0].content, SliceContent::Unknown(_)));
        // No readable slice at all is an error.
        let image = fat(&[b"MTLB....", b"MTLB...."]);
        assert!(FatHeader::parse(&image, 0).is_err());
    }
}
