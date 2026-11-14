//! `linkedit_data_command` load commands (`LC_FUNCTION_STARTS`,
//! `LC_DATA_IN_CODE`, `LC_SEGMENT_SPLIT_INFO`, `LC_CODE_SIGNATURE`,
//! `LC_DYLD_EXPORTS_TRIE`, `LC_DYLD_CHAINED_FIXUPS`, ...) and
//! `LC_TWOLEVEL_HINTS`.

use super::header::{LoadCommand, MachHeader};
use crate::consts::{LC_DATA_IN_CODE, LC_FUNCTION_STARTS, LC_TWOLEVEL_HINTS};
use crate::leb::read_uleb128;

pub const DATA_IN_CODE_ENTRY_SIZE: u64 = 8;

/// The `(dataoff, datasize)` blob of a `linkedit_data_command`.
#[derive(Debug, Clone, Copy)]
pub struct LinkeditData {
    pub lc: LoadCommand,
    /// Relative to the start of the Mach-O header.
    pub dataoff: u32,
    pub datasize: u32,
    /// File offset of the blob (`mach header offset + dataoff`).
    pub file_offset: u64,
}

/// One ULEB128 value and where it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uleb128Data {
    /// File offset of the first byte.
    pub offset: u64,
    pub occupy_size: u32,
    pub data: u64,
}

/// One `data_in_code_entry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataInCodeEntry {
    /// File offset of the entry. Fields: `offset` +0 (4 bytes), `length`
    /// +4 (2 bytes), `kind` +6 (2 bytes).
    pub file_offset: u64,
    pub offset: u32,
    pub length: u16,
    pub kind: u16,
}

impl DataInCodeEntry {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            1 => "DICE_KIND_DATA",
            2 => "DICE_KIND_JUMP_TABLE8",
            3 => "DICE_KIND_JUMP_TABLE16",
            4 => "DICE_KIND_JUMP_TABLE32",
            5 => "DICE_KIND_ABS_JUMP_TABLE32",
            _ => "unknown",
        }
    }
}

/// `LC_TWOLEVEL_HINTS`.
#[derive(Debug, Clone, Copy)]
pub struct TwolevelHints {
    pub lc: LoadCommand,
    /// Relative to the start of the Mach-O header.
    pub offset: u32,
    pub nhints: u32,
    /// File offset of the hint table.
    pub file_offset: u64,
}

impl MachHeader {
    /// The first load command of type `cmd`, read as a
    /// `linkedit_data_command`.
    pub fn linkedit_data(&self, cmd: u32) -> Option<LinkeditData> {
        let lc = *self.find_load_command(&[cmd])?;
        let dataoff = self.lc_u32(&lc, 8);
        Some(LinkeditData {
            lc,
            dataoff,
            datasize: self.lc_u32(&lc, 12),
            file_offset: self.offset.saturating_add(dataoff as u64),
        })
    }

    /// The first `LC_TWOLEVEL_HINTS` command, if any.
    pub fn twolevel_hints(&self) -> Option<TwolevelHints> {
        let lc = *self.find_load_command(&[LC_TWOLEVEL_HINTS])?;
        let offset = self.lc_u32(&lc, 8);
        Some(TwolevelHints {
            lc,
            offset,
            nhints: self.lc_u32(&lc, 12),
            file_offset: self.offset.saturating_add(offset as u64),
        })
    }

    /// Bytes of a linkedit blob, clipped to the file. `None` when the blob
    /// starts past the end of the file.
    pub fn linkedit_bytes(&self, data: &LinkeditData) -> Option<&[u8]> {
        let len = self.image.len();
        if data.file_offset > len {
            return None;
        }
        self.image.slice(
            data.file_offset,
            (data.datasize as u64).min(len - data.file_offset),
        )
    }

    /// The ULEB128 sequence of `LC_FUNCTION_STARTS`, read until the blob
    /// ends or a value is malformed. Padding zeros are returned as entries.
    pub fn function_starts(&self) -> Vec<Uleb128Data> {
        let Some(data) = self.linkedit_data(LC_FUNCTION_STARTS) else {
            return Vec::new();
        };
        let Some(bytes) = self.linkedit_bytes(&data) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut pos = 0usize;
        while let Some(rest) = bytes.get(pos..).filter(|r| !r.is_empty()) {
            let Some((value, used)) = read_uleb128(rest) else {
                break;
            };
            out.push(Uleb128Data {
                offset: data.file_offset + pos as u64,
                occupy_size: used,
                data: value,
            });
            pos += used as usize;
        }
        out
    }

    /// The whole entries of `LC_DATA_IN_CODE` that fit in the file.
    pub fn data_in_code(&self) -> Vec<DataInCodeEntry> {
        let Some(data) = self.linkedit_data(LC_DATA_IN_CODE) else {
            return Vec::new();
        };
        let Some(bytes) = self.linkedit_bytes(&data) else {
            return Vec::new();
        };
        let image = &self.image;
        (0..bytes.len() as u64 / DATA_IN_CODE_ENTRY_SIZE)
            .filter_map(|i| {
                let at = data.file_offset.checked_add(i * DATA_IN_CODE_ENTRY_SIZE)?;
                Some(DataInCodeEntry {
                    file_offset: at,
                    offset: image.u32(at)?,
                    length: image.u16(at.checked_add(4)?)?,
                    kind: image.u16(at.checked_add(6)?)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::*;
    use crate::image::Image;
    use crate::macho::MachHeader;
    use std::sync::Arc;

    fn with_linkedit(cmd: u32, datasize: u32, payload: &[u8]) -> Arc<MachHeader> {
        let mut f = Vec::new();
        for v in [
            0xfeedfacfu32,
            0x0100_0007,
            3,
            1,
            1,
            16,
            0,
            0,
            cmd,
            16,
            48,
            datasize,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(payload);
        let image = Arc::new(Image::from_vec(f).unwrap());
        Arc::new(MachHeader::parse(&image, 0).unwrap())
    }

    #[test]
    fn function_starts_stop_at_bad_value() {
        let mh = with_linkedit(LC_FUNCTION_STARTS, 100, &[0x90, 0x1f, 0x34, 0x00, 0x80]);
        let f = mh.function_starts();
        let got: Vec<_> = f
            .iter()
            .map(|u| (u.offset, u.occupy_size, u.data))
            .collect();
        assert_eq!(got, [(48, 2, 0xf90), (50, 1, 0x34), (51, 1, 0)]);
        assert!(mh.linkedit_data(LC_DATA_IN_CODE).is_none());
        assert!(mh.data_in_code().is_empty());
    }

    #[test]
    fn data_in_code_whole_entries_only() {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x10, 0, 0, 0, 4, 0, 2, 0]);
        p.extend_from_slice(&[0x20, 0, 0, 0, 8]);
        let mh = with_linkedit(LC_DATA_IN_CODE, u32::MAX, &p);
        let d = mh.data_in_code();
        assert_eq!(d.len(), 1);
        assert_eq!(
            (d[0].file_offset, d[0].offset, d[0].length, d[0].kind),
            (48, 0x10, 4, 2)
        );
        assert_eq!(d[0].kind_name(), "DICE_KIND_JUMP_TABLE8");
    }

    #[test]
    fn blob_past_end_of_file() {
        let mut f = Vec::new();
        for v in [
            0xfeedfacfu32,
            0x0100_0007,
            3,
            1,
            1,
            16,
            0,
            0,
            LC_FUNCTION_STARTS,
            16,
            0xffff_fff0,
            0x40,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        let image = Arc::new(Image::from_vec(f).unwrap());
        let mh = MachHeader::parse(&image, 0).unwrap();
        assert!(mh.function_starts().is_empty());
        let d = mh.linkedit_data(LC_FUNCTION_STARTS).unwrap();
        assert_eq!(
            (d.dataoff, d.datasize, d.file_offset),
            (0xffff_fff0, 0x40, 0xffff_fff0)
        );
        assert!(mh.linkedit_bytes(&d).is_none());
    }
}
