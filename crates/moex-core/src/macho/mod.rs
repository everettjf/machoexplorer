//! Parsed file model: what kind of file it is and its Mach-O headers.

pub mod archive;
pub mod chained_fixups;
pub mod disasm;
pub mod dyld_cache;
pub mod dyld_info;
pub mod dysymtab;
pub mod export_trie;
pub mod fat;
pub mod header;
pub mod linkedit;
pub mod objc;
pub mod ptr;
pub mod segment;
pub mod swift;
pub mod symtab;
pub mod vmaddr;
pub mod xref;

use crate::consts::*;
use crate::error::{err, Result};
use crate::image::Image;
use std::path::Path;
use std::sync::Arc;

pub use archive::{Archive, ArchiveMember, MemberKind};
pub use dyld_cache::DyldSharedCache;
pub use dysymtab::{Dysymtab, IndirectSymbol, Relocation};
pub use fat::{FatArch, FatHeader};
pub use header::{LoadCommand, MachHeader};
pub use linkedit::{DataInCodeEntry, LinkeditData, TwolevelHints, Uleb128Data};
pub use segment::{Section, Segment};
pub use symtab::{Symbol, Symtab};

pub enum Kind {
    MachO(Arc<MachHeader>),
    Fat(Arc<FatHeader>),
    /// `ar` archive (`.a`).
    Archive(Arc<Archive>),
    DyldSharedCache(Arc<DyldSharedCache>),
}

pub struct Binary {
    pub image: Arc<Image>,
    pub kind: Kind,
}

pub fn is_fat_magic(magic: u32) -> bool {
    matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64)
}

pub fn is_64_magic(magic: u32) -> bool {
    matches!(
        magic,
        FAT_MAGIC_64 | FAT_CIGAM_64 | MH_MAGIC_64 | MH_CIGAM_64
    )
}

pub fn is_valid_magic(magic: u32) -> bool {
    is_fat_magic(magic) || is_64_magic(magic) || magic == MH_MAGIC || magic == MH_CIGAM
}

impl Binary {
    /// Map and parse the file at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        Self::parse_with_path(Arc::new(Image::open(path)?), Some(path))
    }

    pub fn parse(image: Arc<Image>) -> Result<Self> {
        Self::parse_with_path(image, None)
    }

    /// `path` is where `image` was read from; a dyld shared cache uses it to
    /// find its sibling `.map` file.
    pub fn parse_with_path(image: Arc<Image>, path: Option<&Path>) -> Result<Self> {
        let data = image.bytes();
        let kind = if archive::is_archive_magic(data) {
            Kind::Archive(Arc::new(Archive::parse(&image)?))
        } else if dyld_cache::is_shared_cache_magic(data) {
            Kind::DyldSharedCache(Arc::new(DyldSharedCache::parse(&image, path)?))
        } else {
            const NOT_MACHO: &str = "Not a MachO file, archive, or dyld shared cache";
            let Some(magic) = image.u32(0) else {
                return err(NOT_MACHO);
            };
            if !is_valid_magic(magic) {
                return err(NOT_MACHO);
            }
            if is_fat_magic(magic) {
                Kind::Fat(Arc::new(FatHeader::parse(&image, 0)?))
            } else {
                Kind::MachO(Arc::new(MachHeader::parse(&image, 0)?))
            }
        };
        Ok(Binary { image, kind })
    }

    /// Every Mach-O header in the file: one per fat slice or per Mach-O
    /// archive member; none for a dyld shared cache.
    pub fn headers(&self) -> Vec<Arc<MachHeader>> {
        match &self.kind {
            Kind::MachO(mh) => vec![mh.clone()],
            Kind::Fat(fat) => fat
                .archs
                .iter()
                .flat_map(|a| match &a.content {
                    fat::SliceContent::MachO(mh) => vec![mh.clone()],
                    fat::SliceContent::Archive(archive) => archive.headers(),
                    fat::SliceContent::Unknown(_) => Vec::new(),
                })
                .collect(),
            Kind::Archive(archive) => archive.headers(),
            Kind::DyldSharedCache(_) => Vec::new(),
        }
    }
}
