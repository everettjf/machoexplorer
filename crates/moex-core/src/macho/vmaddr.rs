//! Virtual address → file offset translation and bounds-checked reads at
//! virtual addresses, shared by the ObjC/Swift metadata readers.

use super::header::MachHeader;
use super::segment::Segment;

/// Looks `vmaddr` up in `segments`. `None`: no segment contains it.
/// `Some(None)`: the first containing segment has no file bytes there.
fn lookup<'a>(
    segments: impl Iterator<Item = &'a Segment>,
    file_len: u64,
    vmaddr: u64,
) -> Option<Option<u64>> {
    for seg in segments {
        if vmaddr < seg.vmaddr || vmaddr >= seg.vmaddr.wrapping_add(seg.vmsize) {
            continue;
        }
        let delta = vmaddr - seg.vmaddr;
        if delta >= seg.filesize {
            return Some(None);
        }
        let fileoff = seg.fileoff.wrapping_add(delta);
        return Some((fileoff < file_len).then_some(fileoff));
    }
    None
}

impl MachHeader {
    /// File offset backing `vmaddr`, searching only `LC_SEGMENT_64`
    /// (`seg64`) or only `LC_SEGMENT` commands. The first segment whose VM
    /// range contains the address decides; `None` when it has no file bytes
    /// there or the offset is past the end of the file.
    // QUIRK(parity): the segment's `fileoff` is used as an offset from the
    // start of the *file*, not of the Mach-O header, so inside a fat file
    // the result is off by the slice offset.
    pub fn vm_to_file_offset_in(&self, seg64: bool, vmaddr: u64) -> Option<u64> {
        lookup(
            self.segments.iter().filter(|s| s.is64 == seg64),
            self.image.len(),
            vmaddr,
        )
        .flatten()
    }

    /// Like [`vm_to_file_offset_in`](Self::vm_to_file_offset_in) but
    /// consults the 64-bit segments first and the 32-bit ones only when no
    /// 64-bit segment contains the address.
    pub fn vm_to_file_offset_any(&self, vmaddr: u64) -> Option<u64> {
        let len = self.image.len();
        match lookup(self.segments.iter().filter(|s| s.is64), len, vmaddr) {
            Some(found) => found,
            None => lookup(self.segments.iter().filter(|s| !s.is64), len, vmaddr).flatten(),
        }
    }
}

/// Which segments a [`VmReader`] searches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentSet {
    /// Only `LC_SEGMENT` (`false`) or only `LC_SEGMENT_64` (`true`).
    Only64(bool),
    /// 64-bit segments first, then 32-bit ones.
    Any,
}

/// Bounds-checked reads addressed by virtual address.
#[derive(Clone, Copy)]
pub struct VmReader<'a> {
    pub mh: &'a MachHeader,
    pub segments: SegmentSet,
}

impl<'a> VmReader<'a> {
    pub fn new(mh: &'a MachHeader, segments: SegmentSet) -> Self {
        VmReader { mh, segments }
    }

    /// File offset of `vmaddr` (see [`MachHeader::vm_to_file_offset_in`]).
    pub fn file_offset(&self, vmaddr: u64) -> Option<u64> {
        match self.segments {
            SegmentSet::Only64(seg64) => self.mh.vm_to_file_offset_in(seg64, vmaddr),
            SegmentSet::Any => self.mh.vm_to_file_offset_any(vmaddr),
        }
    }

    /// File offset of a `size`-byte object at `vmaddr`: `None` when the
    /// address is 0, unmapped, or the object does not fit in the file.
    pub fn object_offset(&self, vmaddr: u64, size: u64) -> Option<u64> {
        if vmaddr == 0 {
            return None;
        }
        let off = self.file_offset(vmaddr)?;
        self.mh.image.in_file(off, size).then_some(off)
    }

    /// Pointer-sized little-endian value at `vmaddr`.
    pub fn pointer(&self, vmaddr: u64, is64: bool) -> Option<u64> {
        if is64 {
            self.mh.image.u64(self.object_offset(vmaddr, 8)?)
        } else {
            self.mh
                .image
                .u32(self.object_offset(vmaddr, 4)?)
                .map(u64::from)
        }
    }

    /// Up to `max` bytes starting at `vmaddr`, clipped to the end of the
    /// file (not to the segment). `None` when the address is unmapped.
    pub fn bytes(&self, vmaddr: u64, max: u64) -> Option<&'a [u8]> {
        let off = self.file_offset(vmaddr)?;
        let image: &'a crate::image::Image = &self.mh.image;
        let len = image.len();
        if off >= len {
            return None;
        }
        image.slice(off, max.min(len - off))
    }
}

/// `field_vmaddr + rel` for a 32-bit relative pointer stored at
/// `field_vmaddr` (two's-complement wraparound).
pub fn relative_target(field_vmaddr: u64, rel: i32) -> u64 {
    field_vmaddr.wrapping_add(rel as i64 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;
    use std::sync::Arc;

    /// 64-bit Mach-O with one `LC_SEGMENT_64` (vm 0x1000..0x3000, file
    /// 0xc0..0x100) and one `LC_SEGMENT` (vm 0x1000..0x2000, file 0..0x100) in a 0x200-byte file.
    fn sample() -> MachHeader {
        let mut f = Vec::new();
        let put32 = |f: &mut Vec<u8>, v: u32| f.extend_from_slice(&v.to_le_bytes());
        let put64 = |f: &mut Vec<u8>, v: u64| f.extend_from_slice(&v.to_le_bytes());
        for v in [0xfeedfacfu32, 0x0100_000c, 0, 2, 2, 72 + 56, 0, 0] {
            put32(&mut f, v);
        }
        put32(&mut f, 0x19);
        put32(&mut f, 72);
        f.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        for v in [0x1000u64, 0x2000, 0xc0, 0x40] {
            put64(&mut f, v);
        }
        for v in [7u32, 5, 0, 0] {
            put32(&mut f, v);
        }
        put32(&mut f, 0x1);
        put32(&mut f, 56);
        f.extend_from_slice(b"__OLD\0\0\0\0\0\0\0\0\0\0\0");
        for v in [0x1000u32, 0x1000, 0, 0x100, 7, 5, 0, 0] {
            put32(&mut f, v);
        }
        f.resize(0x200, 0xAA);
        f[0xc8..0xcc].copy_from_slice(b"hi\0\x01");
        let image = Arc::new(Image::from_vec(f).unwrap());
        MachHeader::parse(&image, 0).unwrap()
    }

    #[test]
    fn translation_per_segment_class() {
        let mh = sample();
        assert_eq!(mh.vm_to_file_offset_in(true, 0x1008), Some(0xc8));
        assert_eq!(mh.vm_to_file_offset_in(false, 0x1008), Some(0x8));
        // Inside the 64-bit segment's VM range but past its file contents.
        assert_eq!(mh.vm_to_file_offset_in(true, 0x1040), None);
        assert_eq!(mh.vm_to_file_offset_in(true, 0x3000), None);
        assert_eq!(mh.vm_to_file_offset_in(false, 0x2000), None);
        // "Any": the 64-bit segment wins, even when it has no bytes there.
        assert_eq!(mh.vm_to_file_offset_any(0x1008), Some(0xc8));
        assert_eq!(mh.vm_to_file_offset_any(0x1040), None);
        assert_eq!(mh.vm_to_file_offset_any(0x0fff), None);
    }

    #[test]
    fn reader_objects_and_bytes() {
        let mh = sample();
        let r = VmReader::new(&mh, SegmentSet::Only64(true));
        assert_eq!(r.object_offset(0, 4), None);
        assert_eq!(r.object_offset(0x1008, 4), Some(0xc8));
        // Fits in the file even though it leaves the segment.
        assert_eq!(r.object_offset(0x103c, 0x104), Some(0xfc));
        assert_eq!(r.object_offset(0x103c, 0x105), None);
        assert_eq!(r.pointer(0x1008, false), Some(0x0100_6968));
        assert_eq!(r.bytes(0x1008, 3), Some(&b"hi\0"[..]));
        assert_eq!(r.bytes(0x103f, 1024).map(<[u8]>::len), Some(0x101));
        assert_eq!(r.bytes(0x5000, 4), None);
    }

    #[test]
    fn relative_targets_wrap() {
        assert_eq!(relative_target(0x1000, -16), 0xff0);
        assert_eq!(relative_target(0x1000, 0x20), 0x1020);
        assert_eq!(relative_target(4, -8), u64::MAX - 3);
        assert_eq!(relative_target(u64::MAX, 2), 1);
    }
}
