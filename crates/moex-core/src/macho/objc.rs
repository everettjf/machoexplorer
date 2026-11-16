//! Objective-C 2 runtime structures as laid out in `__objc_*` sections
//! (32- and 64-bit), plus `__cfstring` entries and `objc_image_info`.
//!
//! Every decoder takes a file offset and returns `None` when the struct does
//! not lie entirely inside the file. Pointer fields are decoded (chained
//! fixups, authenticated pointers) into the address they refer to; a field
//! bound to a symbol of another image reads as 0 and
//! [`ObjcResolver::pointer_at`] tells which symbol.

use super::ptr::{relative_target, Pointer, PointerDecoder, Segments, SliceReader};
use super::MachHeader;
use crate::image::Image;

/// `objc_image_info.flags` bits.
pub const OBJC_IMAGE_IS_REPLACEMENT: u32 = 1 << 0;
pub const OBJC_IMAGE_SUPPORTS_GC: u32 = 1 << 1;
pub const OBJC_IMAGE_GC_ONLY: u32 = 1 << 2;
pub const OBJC_IMAGE_OPTIMIZED_BY_DYLD: u32 = 1 << 3;
pub const OBJC_IMAGE_SIGNED_CLASS_RO: u32 = 1 << 4;
pub const OBJC_IMAGE_IS_SIMULATED: u32 = 1 << 5;
pub const OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES: u32 = 1 << 6;
pub const OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE: u32 = 1 << 7;

/// `class_ro_t.flags` bits.
pub const RO_META: u32 = 1 << 0;
pub const RO_ROOT: u32 = 1 << 1;
pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 2;

/// Size of the `{ entsize, count }` header of method, ivar and property
/// lists (both word sizes).
pub const LIST_HEADER_SIZE: u64 = 8;

/// `N` consecutive pointer-sized words at file offset `off`, each decoded
/// as a pointer (words that are not pointers come back unchanged).
fn words<const N: usize>(r: &ObjcResolver<'_>, off: u64) -> Option<[u64; N]> {
    let step = r.layout.ptr_size();
    let mut out = [0u64; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = r.address_at(off.checked_add(i as u64 * step)?)?;
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
    /// Relative `method_t`: three 32-bit offsets.
    pub fn relative_method_size(self) -> u64 {
        12
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
            (OBJC_IMAGE_OPTIMIZED_BY_DYLD, "OBJC_IMAGE_OPTIMIZED_BY_DYLD"),
            (OBJC_IMAGE_SIGNED_CLASS_RO, "OBJC_IMAGE_SIGNED_CLASS_RO"),
            (OBJC_IMAGE_IS_SIMULATED, "OBJC_IMAGE_IS_SIMULATED"),
            (
                OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES,
                "OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES",
            ),
            (
                OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE,
                "OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE",
            ),
        ]
        .into_iter()
        .filter(|(bit, _)| self.flags & bit != 0)
        .collect()
    }

    /// The Swift ABI version byte (bits 8..16); 0 for images without Swift.
    pub fn swift_version(&self) -> u32 {
        (self.flags >> 8) & 0xff
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
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [ptr, data, cstr, size] = words(r, off)?;
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
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [isa, superclass, cache, vtable, data] = words(r, off)?;
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
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let image = r.image();
        let flags = image.u32(off)?;
        let instance_start = image.u32(off.checked_add(4)?)?;
        let instance_size = image.u32(off.checked_add(8)?)?;
        // 64-bit has a 4-byte `reserved` field before the pointers.
        let rest = off.checked_add(if r.is64() { 16 } else { 12 })?;
        let [ivar_layout, name, base_methods, base_protocols, ivars, weak_ivar_layout, base_properties] =
            words(r, rest)?;
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

/// `method_list_t.entsize` flag: entries are three 32-bit relative offsets.
pub const METHOD_LIST_IS_RELATIVE: u32 = 0x8000_0000;
/// `method_list_t.entsize` flag: a relative name offset leads straight to
/// the selector string instead of to a selector reference.
pub const METHOD_LIST_DIRECT_SELECTORS: u32 = 0x4000_0000;
/// The bits of `method_list_t.entsize` that are flags (the high half and
/// the "uniqued" / "sorted" bits), not part of the entry size.
pub const METHOD_LIST_FLAGS_MASK: u32 = 0xffff_0003;

/// `{ entsize, count }` header of a method, ivar or property list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcListHeader {
    /// Raw value; in a method list it also carries flags, see
    /// [`METHOD_LIST_FLAGS_MASK`]. Ivar and property lists have none.
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

    /// Entry size of a method list: `entsize` without its flag bits.
    pub fn method_entry_size(&self) -> u32 {
        self.entsize & !METHOD_LIST_FLAGS_MASK
    }

    /// Whether a method list holds relative ("small") methods.
    pub fn has_relative_methods(&self) -> bool {
        self.entsize & METHOD_LIST_IS_RELATIVE != 0
    }

    /// Whether relative method names skip the selector reference.
    pub fn has_direct_selectors(&self) -> bool {
        self.entsize & METHOD_LIST_DIRECT_SELECTORS != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcMethod {
    pub name: u64,
    pub types: u64,
    pub imp: u64,
}

impl ObjcMethod {
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [name, types, imp] = words(r, off)?;
        Some(ObjcMethod { name, types, imp })
    }

    /// A relative method at file offset `off`, which is mapped at
    /// `vmaddr`: three 32-bit offsets, each relative to its own field. The
    /// name offset leads to a selector reference (a pointer to the string)
    /// unless the list has `direct_selectors`; an `imp` offset of 0 means
    /// no implementation.
    pub fn read_relative(
        r: &ObjcResolver<'_>,
        off: u64,
        vmaddr: u64,
        direct_selectors: bool,
    ) -> Option<Self> {
        let image = r.image();
        let rel = |i: u64| Some(image.u32(off.checked_add(4 * i)?)? as i32);
        let target = |i: u64, rel: i32| relative_target(vmaddr.wrapping_add(4 * i), rel);
        let (name_rel, types_rel, imp_rel) = (rel(0)?, rel(1)?, rel(2)?);
        let name_field = target(0, name_rel);
        let name = if direct_selectors {
            name_field
        } else {
            let word = r.layout.ptr_size();
            r.struct_offset(name_field, word)
                .and_then(|at| r.address_at(at))
                .unwrap_or(0)
        };
        Some(ObjcMethod {
            name,
            types: target(1, types_rel),
            imp: if imp_rel == 0 { 0 } else { target(2, imp_rel) },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcIvar {
    /// Address of the 32-bit variable holding the ivar offset.
    pub offset: u64,
    pub name: u64,
    pub type_: u64,
    pub alignment: u32,
    pub size: u32,
}

impl ObjcIvar {
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [offset, name, type_] = words(r, off)?;
        let rest = off.checked_add(3 * r.layout.ptr_size())?;
        let image = r.image();
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
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [name, attributes] = words(r, off)?;
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
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [isa, name, protocols, instance_methods, class_methods, optional_instance_methods, optional_class_methods, instance_properties] =
            words(r, off)?;
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
    pub fn read(r: &ObjcResolver<'_>, off: u64) -> Option<Self> {
        let [name, cls, instance_methods, class_methods, protocols, instance_properties] =
            words(r, off)?;
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

/// Resolves the virtual addresses and pointers stored in ObjC metadata.
pub struct ObjcResolver<'a> {
    pub reader: SliceReader<'a>,
    pub layout: ObjcLayout,
    decoder: PointerDecoder<'a>,
}

impl<'a> ObjcResolver<'a> {
    /// `is64` selects both the pointer width and which segment commands
    /// (`LC_SEGMENT_64` or `LC_SEGMENT`) map addresses. The fixup tables of
    /// the image are read for this resolver alone; see
    /// [`with_decoder`](Self::with_decoder) to share them.
    pub fn new(mh: &'a MachHeader, is64: bool) -> Self {
        Self::with_decoder(mh, is64, PointerDecoder::new(mh))
    }

    /// Like [`new`](Self::new), decoding pointers with `decoder`.
    pub fn with_decoder(mh: &'a MachHeader, is64: bool, decoder: PointerDecoder<'a>) -> Self {
        ObjcResolver {
            reader: SliceReader::new(mh, Segments::Only64(is64)),
            layout: ObjcLayout { is64 },
            decoder,
        }
    }

    pub fn image(&self) -> &'a Image {
        self.reader.image()
    }

    pub fn is64(&self) -> bool {
        self.layout.is64
    }

    /// File offset of `vmaddr`, when mapped.
    pub fn file_offset(&self, vmaddr: u64) -> Option<u64> {
        self.reader.file_offset(vmaddr)
    }

    /// File offset of a `size`-byte struct at `vmaddr`; `None` for address
    /// 0, unmapped addresses and structs that run past the file contents of
    /// their segment.
    pub fn struct_offset(&self, vmaddr: u64, size: u64) -> Option<u64> {
        self.reader.object_offset(vmaddr, size)
    }

    /// The pointer stored at file offset `off`, decoded.
    pub fn pointer_at(&self, off: u64) -> Option<Pointer<'_>> {
        self.decoder.read(off, self.layout.is64)
    }

    /// The address the pointer at file offset `off` refers to; 0 for a
    /// pointer bound to another image.
    pub fn address_at(&self, off: u64) -> Option<u64> {
        self.pointer_at(off).map(|p| p.address())
    }

    /// The 32-bit value at `vmaddr` (an ivar offset variable).
    pub fn u32_at(&self, vmaddr: u64) -> Option<u32> {
        self.reader.u32(vmaddr)
    }

    /// NUL-terminated string at `vmaddr`. Empty when the address is 0 or
    /// unmapped, or no terminator is found within 1024 bytes / the segment.
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
    use std::sync::Arc;

    fn image(bytes: Vec<u8>) -> Image {
        Image::from_vec(bytes).unwrap()
    }

    /// A header without load commands over `bytes`: enough for the
    /// decoders, which work on file offsets.
    fn header(bytes: Vec<u8>) -> MachHeader {
        MachHeader {
            size: bytes.len() as u64,
            big_endian: false,
            image: Arc::new(image(bytes)),
            offset: 0,
            is64: true,
            magic: 0,
            cputype: 0,
            cpusubtype: 0,
            filetype: 0,
            ncmds: 0,
            sizeofcmds: 0,
            flags: 0,
            reserved: 0,
            loadcmds: Vec::new(),
            segments: Vec::new(),
        }
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
        assert_eq!(
            (l32.relative_method_size(), l64.relative_method_size()),
            (12, 12)
        );
        assert_eq!((l32.ivar_size(), l64.ivar_size()), (20, 32));
        assert_eq!((l32.property_size(), l64.property_size()), (8, 16));
        assert_eq!((l32.protocol_size(), l64.protocol_size()), (32, 64));
        assert_eq!((l32.category_size(), l64.category_size()), (24, 48));
        assert_eq!((l32.cfstring_size(), l64.cfstring_size()), (16, 32));
    }

    #[test]
    fn class_and_ro() {
        let mh = header(le64(&[1, 2, 3, 4, 0x1000_0007]));
        let r = ObjcResolver::new(&mh, true);
        let c = ObjcClass::read(&r, 0).unwrap();
        assert_eq!((c.isa, c.superclass, c.data), (1, 2, 0x1000_0007));
        assert_eq!(c.ro_address(true), 0x1000_0000);
        assert_eq!(c.ro_address(false), 0x1000_0004);
        assert!(ObjcClass::read(&r, 1).is_none());

        let mut ro = le32(&[RO_META, 8, 16, 0]);
        ro.extend(le64(&[10, 11, 12, 13, 14, 15, 16]));
        let mh = header(ro);
        let r = ObjcClassRo::read(&ObjcResolver::new(&mh, true), 0).unwrap();
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

        let mh = header(le32(&[0, 4, 8, 20, 21, 22, 23, 24, 25, 26]));
        let res = ObjcResolver::new(&mh, false);
        let r = ObjcClassRo::read(&res, 0).unwrap();
        assert!(!r.is_meta());
        assert_eq!(
            (r.ivar_layout, r.name, r.base_methods, r.base_properties),
            (20, 21, 22, 26)
        );
        assert!(ObjcClassRo::read(&res, 4).is_none());
    }

    #[test]
    fn lists_and_entries() {
        let mh = header(le32(&[0x8000_000f, 3, 7, 8, 9, 2, 4]));
        let r = ObjcResolver::new(&mh, false);
        let h = ObjcListHeader::read(r.image(), 0).unwrap();
        assert_eq!((h.entsize, h.count), (0x8000_000f, 3));
        // The flag bits are not part of the entry size.
        assert_eq!(h.method_entry_size(), 12);
        assert!(h.has_relative_methods());
        assert!(!h.has_direct_selectors());
        let plain = ObjcListHeader {
            entsize: 24 | 0x4000_0003,
            count: 1,
        };
        assert_eq!(plain.method_entry_size(), 24);
        assert!(!plain.has_relative_methods());
        assert!(plain.has_direct_selectors());

        let m = ObjcMethod::read(&r, 8).unwrap();
        assert_eq!((m.name, m.types, m.imp), (7, 8, 9));
        let iv = ObjcIvar::read(&r, 8).unwrap();
        assert_eq!(
            (iv.offset, iv.name, iv.type_, iv.alignment, iv.size),
            (7, 8, 9, 2, 4)
        );
        let p = ObjcProperty::read(&r, 8).unwrap();
        assert_eq!((p.name, p.attributes), (7, 8));
        assert!(ObjcIvar::read(&r, 12).is_none());
    }

    #[test]
    fn relative_methods() {
        // Entry at file offset 8, mapped at 0x1008: name +0x100 (direct),
        // types -8, no implementation; then one with an implementation.
        let mh = header(le32(&[0, 0, 0x100, (-8i32) as u32, 0, 4, 4, 0x20]));
        let r = ObjcResolver::new(&mh, true);
        let m = ObjcMethod::read_relative(&r, 8, 0x1008, true).unwrap();
        assert_eq!((m.name, m.types, m.imp), (0x1108, 0x1004, 0));
        let m = ObjcMethod::read_relative(&r, 20, 0x1014, true).unwrap();
        assert_eq!((m.name, m.types, m.imp), (0x1018, 0x101c, 0x103c));
        // Through a selector reference that is not mapped: no name.
        let m = ObjcMethod::read_relative(&r, 8, 0x1008, false).unwrap();
        assert_eq!((m.name, m.types), (0, 0x1004));
        assert!(ObjcMethod::read_relative(&r, 24, 0x1018, true).is_none());
    }

    #[test]
    fn image_info_flags() {
        let img = image(le32(&[0, 0x45]));
        let info = ObjcImageInfo::read(&img, 0).unwrap();
        assert_eq!(
            info.flag_names(),
            [
                (1, "OBJC_IMAGE_IS_REPLACEMENT"),
                (4, "OBJC_IMAGE_GC_ONLY"),
                (0x40, "OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES")
            ]
        );
        assert_eq!(info.swift_version(), 0);
        let swift = ObjcImageInfo {
            version: 0,
            flags: 0x0507_0740,
        };
        assert_eq!(swift.swift_version(), 7);
        assert!(ObjcImageInfo::read(&img, 4).is_none());
    }

    #[test]
    fn cfstring_both_widths() {
        let mh = header(le32(&[1, 2, 3, 4]));
        assert_eq!(
            CfString::read(&ObjcResolver::new(&mh, false), 0),
            Some(CfString {
                ptr: 1,
                data: 2,
                cstr: 3,
                size: 4
            })
        );
        assert!(CfString::read(&ObjcResolver::new(&mh, true), 0).is_none());
    }
}
