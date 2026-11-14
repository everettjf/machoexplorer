use super::header::LoadCommand;
use crate::hex::utf8_safe;
use crate::image::Image;

pub const SEGMENT_COMMAND_SIZE: u64 = 56;
pub const SEGMENT_COMMAND_64_SIZE: u64 = 72;
pub const SECTION_SIZE: u64 = 68;
pub const SECTION_64_SIZE: u64 = 80;

/// Fixed 16-byte name field: bytes up to the first NUL.
pub fn name16(image: &Image, off: u64) -> String {
    utf8_safe(image.cstr(off, 16).unwrap_or(&[]))
}

#[derive(Debug, Clone)]
pub struct Section {
    /// File offset of the `section` / `section_64` header.
    pub header_offset: u64,
    pub is64: bool,
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    /// The `offset` field: relative to the start of the Mach-O header.
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
    /// File offset of the section contents (`mach header offset + offset`).
    pub data_offset: u64,
    /// Content size clipped to the end of the file (0 when out of file),
    /// truncated to 32 bits like the original implementation.
    pub data_size: u32,
}

impl Section {
    fn parse(image: &Image, at: u64, is64: bool, mh_offset: u64) -> Section {
        let u32_ = |o: u64| image.u32(at + o).unwrap_or(0);
        let u64_ = |o: u64| image.u64(at + o).unwrap_or(0);
        let (addr, size, rest) = if is64 {
            (u64_(32), u64_(40), 48)
        } else {
            (u32_(32) as u64, u32_(36) as u64, 40)
        };
        let offset = u32_(rest);
        let data_offset = mh_offset + offset as u64;
        let data_size = if data_offset >= image.len() {
            0
        } else {
            size.min(image.len() - data_offset) as u32
        };
        Section {
            header_offset: at,
            is64,
            sectname: name16(image, at),
            segname: name16(image, at + 16),
            addr,
            size,
            offset,
            align: u32_(rest + 4),
            reloff: u32_(rest + 8),
            nreloc: u32_(rest + 12),
            flags: u32_(rest + 16),
            reserved1: u32_(rest + 20),
            reserved2: u32_(rest + 24),
            reserved3: if is64 { u32_(rest + 28) } else { 0 },
            data_offset,
            data_size,
        }
    }

    pub fn header_size(&self) -> u64 {
        if self.is64 {
            SECTION_64_SIZE
        } else {
            SECTION_SIZE
        }
    }

    /// Section contents (clipped to the file).
    pub fn data<'a>(&self, image: &'a Image) -> &'a [u8] {
        image
            .slice(self.data_offset, self.data_size as u64)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub lc: LoadCommand,
    pub is64: bool,
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<Section>,
}

impl Segment {
    pub fn parse(image: &Image, lc: LoadCommand, mh_offset: u64) -> Segment {
        let is64 = lc.cmd == crate::consts::LC_SEGMENT_64;
        let at = lc.offset;
        let u32_ = |o: u64| image.u32(at + o).unwrap_or(0);
        let u64_ = |o: u64| image.u64(at + o).unwrap_or(0);
        let (vmaddr, vmsize, fileoff, filesize, rest, cmd_size, sect_size) = if is64 {
            (
                u64_(24),
                u64_(32),
                u64_(40),
                u64_(48),
                56,
                SEGMENT_COMMAND_64_SIZE,
                SECTION_64_SIZE,
            )
        } else {
            (
                u32_(24) as u64,
                u32_(28) as u64,
                u32_(32) as u64,
                u32_(36) as u64,
                40,
                SEGMENT_COMMAND_SIZE,
                SECTION_SIZE,
            )
        };
        let nsects = u32_(rest + 8);
        let avail = (lc.cmdsize as u64).saturating_sub(cmd_size);
        let count = (avail / sect_size).min(nsects as u64);
        let sections = (0..count)
            .map(|i| Section::parse(image, at + cmd_size + i * sect_size, is64, mh_offset))
            .collect();
        Segment {
            lc,
            is64,
            name: name16(image, at + 8),
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot: u32_(rest),
            initprot: u32_(rest + 4),
            nsects,
            flags: u32_(rest + 12),
            sections,
        }
    }
}
