//! Objective-C 2 runtime structures as laid out in `__objc_*` sections
//! (32- and 64-bit), plus `__cfstring` entries and `objc_image_info`.
//!
//! Every decoder takes a file offset and returns `None` when the struct does
//! not lie entirely inside the file.

use super::vmaddr::{SegmentSet, VmReader};
use super::MachHeader;
use crate::image::Image;

/// `objc_image_info.flags` bits.
pub const OBJC_IMAGE_IS_REPLACEMENT: u32 = 1 << 0;
pub const OBJC_IMAGE_SUPPORTS_GC: u32 = 1 << 1;
pub const OBJC_IMAGE_GC_ONLY: u32 = 1 << 2;

/// `class_ro_t.flags` bits.
pub const RO_META: u32 = 1 << 0;
pub const RO_ROOT: u32 = 1 << 1;
pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 2;

/// Size of the `{ entsize, count }` header of method, ivar and property
/// lists (both word sizes).
pub const LIST_HEADER_SIZE: u64 = 8;

/// `N` consecutive pointer-sized words at file offset `off`.
fn words<const N: usize>(image: &Image, off: u64, is64: bool) -> Option<[u64; N]> {
    let step: u64 = if is64 { 8 } else { 4 };
    let mut out = [0u64; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = off.checked_add(i as u64 * step)?;
        *slot = if is64 {
            image.u64(at)?
        } else {
            u64::from(image.u32(at)?)
        };
    }
    Some(out)
}

/// Struct sizes for one pointer width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcLayout {
    pub is64: bool,
}

impl ObjcLayout {
    pub fn ptr_size(self) -> u64 {
        if self.is64 {
            8
        } else {
            4
        }
    }
    /// `class_t`: isa, superclass, cache, vtable, data.
    pub fn class_size(self) -> u64 {
        5 * self.ptr_size()
    }
    /// `class_ro_t`.
    pub fn class_ro_size(self) -> u64 {
        if self.is64 {
            72
        } else {
            40
        }
    }
    /// `method_t`: name, types, imp.
    pub fn method_size(self) -> u64 {
        3 * self.ptr_size()
    }
    /// `ivar_t`: offset, name, type, alignment, size.
    pub fn ivar_size(self) -> u64 {
        3 * self.ptr_size() + 8
    }
    /// `objc_property`: name, attributes.
    pub fn property_size(self) -> u64 {
        2 * self.ptr_size()
    }
    /// `protocol_t` (the eight leading pointers).
    pub fn protocol_size(self) -> u64 {
        8 * self.ptr_size()
    }
    /// `category_t`.
    pub fn category_size(self) -> u64 {
        6 * self.ptr_size()
    }
    /// `protocol_list_t` header: a pointer-sized count.
    pub fn protocol_list_header_size(self) -> u64 {
        self.ptr_size()
    }
    /// `cfstring_t`: four pointer-sized words.
    pub fn cfstring_size(self) -> u64 {
        4 * self.ptr_size()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcImageInfo {
    pub version: u32,
    pub flags: u32,
}

impl ObjcImageInfo {
    pub const SIZE: u64 = 8;

    pub fn read(image: &Image, off: u64) -> Option<Self> {
        Some(ObjcImageInfo {
            version: image.u32(off)?,
            flags: image.u32(off.checked_add(4)?)?,
        })
    }

    /// Names of the flag bits that are set, in bit order.
    pub fn flag_names(&self) -> Vec<(u32, &'static str)> {
        [
            (OBJC_IMAGE_IS_REPLACEMENT, "OBJC_IMAGE_IS_REPLACEMENT"),
            (OBJC_IMAGE_SUPPORTS_GC, "OBJC_IMAGE_SUPPORTS_GC"),
            (OBJC_IMAGE_GC_ONLY, "OBJC_IMAGE_GC_ONLY"),
        ]
        .into_iter()
        .filter(|(bit, _)| self.flags & bit != 0)
        .collect()
    }
}

/// One `__cfstring` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfString {
    pub ptr: u64,
    pub data: u64,
    pub cstr: u64,
    pub size: u64,
}

impl CfString {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [ptr, data, cstr, size] = words(image, off, is64)?;
        Some(CfString {
            ptr,
            data,
            cstr,
            size,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcClass {
    pub isa: u64,
    pub superclass: u64,
    pub cache: u64,
    pub vtable: u64,
    /// `class_ro_t *` with flag bits in the low bits; see
    /// [`ObjcClass::ro_address`].
    pub data: u64,
}

impl ObjcClass {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [isa, superclass, cache, vtable, data] = words(image, off, is64)?;
        Some(ObjcClass {
            isa,
            superclass,
            cache,
            vtable,
            data,
        })
    }

    /// `data` with the low flag bits (3 on 64-bit, 2 on 32-bit) cleared.
    pub fn ro_address(&self, is64: bool) -> u64 {
        if is64 {
            self.data & !0x7
        } else {
            self.data & !0x3
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcClassRo {
    pub flags: u32,
    pub instance_start: u32,
    pub instance_size: u32,
    pub ivar_layout: u64,
    pub name: u64,
    pub base_methods: u64,
    pub base_protocols: u64,
    pub ivars: u64,
    pub weak_ivar_layout: u64,
    pub base_properties: u64,
}

impl ObjcClassRo {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let flags = image.u32(off)?;
        let instance_start = image.u32(off.checked_add(4)?)?;
        let instance_size = image.u32(off.checked_add(8)?)?;
        // 64-bit has a 4-byte `reserved` field before the pointers.
        let rest = off.checked_add(if is64 { 16 } else { 12 })?;
        let [ivar_layout, name, base_methods, base_protocols, ivars, weak_ivar_layout, base_properties] =
            words(image, rest, is64)?;
        Some(ObjcClassRo {
            flags,
            instance_start,
            instance_size,
            ivar_layout,
            name,
            base_methods,
            base_protocols,
            ivars,
            weak_ivar_layout,
            base_properties,
        })
    }

    pub fn is_meta(&self) -> bool {
        self.flags & RO_META != 0
    }
}

/// `{ entsize, count }` header of a method, ivar or property list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcListHeader {
    /// Raw value; method and ivar lists keep flags in the low two bits.
    pub entsize: u32,
    pub count: u32,
}

impl ObjcListHeader {
    pub fn read(image: &Image, off: u64) -> Option<Self> {
        Some(ObjcListHeader {
            entsize: image.u32(off)?,
            count: image.u32(off.checked_add(4)?)?,
        })
    }

    /// `entsize` without the two low flag bits.
    pub fn entry_size(&self) -> u32 {
        self.entsize & !0x3
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcMethod {
    pub name: u64,
    pub types: u64,
    pub imp: u64,
}

impl ObjcMethod {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [name, types, imp] = words(image, off, is64)?;
        Some(ObjcMethod { name, types, imp })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcIvar {
    /// Address of the variable holding the ivar offset.
    pub offset: u64,
    pub name: u64,
    pub type_: u64,
    pub alignment: u32,
    pub size: u32,
}

impl ObjcIvar {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [offset, name, type_] = words(image, off, is64)?;
        let rest = off.checked_add(if is64 { 24 } else { 12 })?;
        Some(ObjcIvar {
            offset,
            name,
            type_,
            alignment: image.u32(rest)?,
            size: image.u32(rest.checked_add(4)?)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcProperty {
    pub name: u64,
    pub attributes: u64,
}

impl ObjcProperty {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [name, attributes] = words(image, off, is64)?;
        Some(ObjcProperty { name, attributes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcProtocol {
    pub isa: u64,
    pub name: u64,
    pub protocols: u64,
    pub instance_methods: u64,
    pub class_methods: u64,
    pub optional_instance_methods: u64,
    pub optional_class_methods: u64,
    pub instance_properties: u64,
}

impl ObjcProtocol {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [isa, name, protocols, instance_methods, class_methods, optional_instance_methods, optional_class_methods, instance_properties] =
            words(image, off, is64)?;
        Some(ObjcProtocol {
            isa,
            name,
            protocols,
            instance_methods,
            class_methods,
            optional_instance_methods,
            optional_class_methods,
            instance_properties,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcCategory {
    pub name: u64,
    pub cls: u64,
    pub instance_methods: u64,
    pub class_methods: u64,
    pub protocols: u64,
    pub instance_properties: u64,
}

impl ObjcCategory {
    pub fn read(image: &Image, off: u64, is64: bool) -> Option<Self> {
        let [name, cls, instance_methods, class_methods, protocols, instance_properties] =
            words(image, off, is64)?;
        Some(ObjcCategory {
            name,
            cls,
            instance_methods,
            class_methods,
            protocols,
            instance_properties,
        })
    }
}

/// Resolves the virtual addresses stored in ObjC metadata.
#[derive(Clone, Copy)]
pub struct ObjcResolver<'a> {
    pub reader: VmReader<'a>,
    pub layout: ObjcLayout,
}

impl<'a> ObjcResolver<'a> {
    /// `is64` selects both the pointer width and which segment commands
    /// (`LC_SEGMENT_64` or `LC_SEGMENT`) map addresses.
    pub fn new(mh: &'a MachHeader, is64: bool) -> Self {
        ObjcResolver {
            reader: VmReader::new(mh, SegmentSet::Only64(is64)),
            layout: ObjcLayout { is64 },
        }
    }

    pub fn image(&self) -> &'a Image {
        &self.reader.mh.image
    }

    pub fn is64(&self) -> bool {
        self.layout.is64
    }

    /// File offset of `vmaddr`, when mapped.
    pub fn file_offset(&self, vmaddr: u64) -> Option<u64> {
        self.reader.file_offset(vmaddr)
    }

    /// File offset of a `size`-byte struct at `vmaddr`; `None` for address
    /// 0, unmapped addresses and structs that run past the end of the file.
    pub fn struct_offset(&self, vmaddr: u64, size: u64) -> Option<u64> {
        self.reader.object_offset(vmaddr, size)
    }

    /// Pointer-sized value stored at `vmaddr`.
    pub fn pointer(&self, vmaddr: u64) -> Option<u64> {
        self.reader.pointer(vmaddr, self.layout.is64)
    }

    /// NUL-terminated string at `vmaddr`. Empty when the address is 0 or
    /// unmapped, or no terminator is found within 1024 bytes / the file.
    pub fn cstring(&self, vmaddr: u64) -> &'a [u8] {
        if vmaddr == 0 {
            return &[];
        }
        let Some(bytes) = self.reader.bytes(vmaddr, 1024) else {
            return &[];
        };
        match bytes.iter().position(|&c| c == 0) {
            Some(end) => bytes.get(..end).unwrap_or(&[]),
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(bytes: Vec<u8>) -> Image {
        Image::from_vec(bytes).unwrap()
    }

    fn le64(vals: &[u64]) -> Vec<u8> {
        vals.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn le32(vals: &[u32]) -> Vec<u8> {
        vals.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn layout_sizes() {
        let (l32, l64) = (ObjcLayout { is64: false }, ObjcLayout { is64: true });
        assert_eq!((l32.class_size(), l64.class_size()), (20, 40));
        assert_eq!((l32.class_ro_size(), l64.class_ro_size()), (40, 72));
        assert_eq!((l32.method_size(), l64.method_size()), (12, 24));
        assert_eq!((l32.ivar_size(), l64.ivar_size()), (20, 32));
        assert_eq!((l32.property_size(), l64.property_size()), (8, 16));
        assert_eq!((l32.protocol_size(), l64.protocol_size()), (32, 64));
        assert_eq!((l32.category_size(), l64.category_size()), (24, 48));
        assert_eq!((l32.cfstring_size(), l64.cfstring_size()), (16, 32));
    }

    #[test]
    fn class_and_ro() {
        let img = image(le64(&[1, 2, 3, 4, 0x1000_0007]));
        let c = ObjcClass::read(&img, 0, true).unwrap();
        assert_eq!((c.isa, c.superclass, c.data), (1, 2, 0x1000_0007));
        assert_eq!(c.ro_address(true), 0x1000_0000);
        assert_eq!(c.ro_address(false), 0x1000_0004);
        assert!(ObjcClass::read(&img, 1, true).is_none());

        let mut ro = le32(&[RO_META, 8, 16, 0]);
        ro.extend(le64(&[10, 11, 12, 13, 14, 15, 16]));
        let img = image(ro);
        let r = ObjcClassRo::read(&img, 0, true).unwrap();
        assert!(r.is_meta());
        assert_eq!((r.instance_start, r.instance_size), (8, 16));
        assert_eq!(
            (
                r.name,
                r.base_methods,
                r.base_protocols,
                r.ivars,
                r.base_properties
            ),
            (11, 12, 13, 14, 16)
        );

        let img = image(le32(&[0, 4, 8, 20, 21, 22, 23, 24, 25, 26]));
        let r = ObjcClassRo::read(&img, 0, false).unwrap();
        assert!(!r.is_meta());
        assert_eq!(
            (r.ivar_layout, r.name, r.base_methods, r.base_properties),
            (20, 21, 22, 26)
        );
        assert!(ObjcClassRo::read(&img, 4, false).is_none());
    }

    #[test]
    fn lists_and_entries() {
        let img = image(le32(&[0x8000_000f, 3, 7, 8, 9, 2, 4]));
        let h = ObjcListHeader::read(&img, 0).unwrap();
        assert_eq!(
            (h.entsize, h.count, h.entry_size()),
            (0x8000_000f, 3, 0x8000_000c)
        );
        let m = ObjcMethod::read(&img, 8, false).unwrap();
        assert_eq!((m.name, m.types, m.imp), (7, 8, 9));
        let iv = ObjcIvar::read(&img, 8, false).unwrap();
        assert_eq!(
            (iv.offset, iv.name, iv.type_, iv.alignment, iv.size),
            (7, 8, 9, 2, 4)
        );
        let p = ObjcProperty::read(&img, 8, false).unwrap();
        assert_eq!((p.name, p.attributes), (7, 8));
        assert!(ObjcIvar::read(&img, 12, false).is_none());
    }

    #[test]
    fn image_info_flags() {
        let img = image(le32(&[0, 0x45]));
        let info = ObjcImageInfo::read(&img, 0).unwrap();
        assert_eq!(
            info.flag_names(),
            [(1, "OBJC_IMAGE_IS_REPLACEMENT"), (4, "OBJC_IMAGE_GC_ONLY")]
        );
        assert!(ObjcImageInfo::read(&img, 4).is_none());
    }

    #[test]
    fn cfstring_both_widths() {
        let img = image(le32(&[1, 2, 3, 4]));
        assert_eq!(
            CfString::read(&img, 0, false),
            Some(CfString {
                ptr: 1,
                data: 2,
                cstr: 3,
                size: 4
            })
        );
        assert!(CfString::read(&img, 0, true).is_none());
    }
}
