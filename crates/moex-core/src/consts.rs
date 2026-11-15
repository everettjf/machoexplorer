//! Mach-O constants (values from `<mach-o/loader.h>`, `<mach-o/fat.h>`,
//! `<mach/machine.h>`).
#![allow(non_upper_case_globals)]

pub const MH_MAGIC: u32 = 0xfeedface;
pub const MH_CIGAM: u32 = 0xcefaedfe;
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;
pub const FAT_MAGIC_64: u32 = 0xcafebabf;
pub const FAT_CIGAM_64: u32 = 0xbfbafeca;

pub const MACH_HEADER_SIZE: u64 = 28;
pub const MACH_HEADER_64_SIZE: u64 = 32;
pub const FAT_HEADER_SIZE: u64 = 8;
pub const FAT_ARCH_SIZE: u64 = 20;
pub const FAT_ARCH_64_SIZE: u64 = 32;
pub const LOAD_COMMAND_SIZE: u64 = 8;

// CPU types
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
pub const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;
pub const CPU_TYPE_ANY: u32 = 0xffff_ffff;
pub const CPU_TYPE_VAX: u32 = 1;
pub const CPU_TYPE_MC680x0: u32 = 6;
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_I386: u32 = CPU_TYPE_X86;
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_MC98000: u32 = 10;
pub const CPU_TYPE_HPPA: u32 = 11;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
pub const CPU_TYPE_MC88000: u32 = 13;
pub const CPU_TYPE_SPARC: u32 = 14;
pub const CPU_TYPE_I860: u32 = 15;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;

pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
pub const CPU_SUBTYPE_LIB64: u32 = 0x8000_0000;
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
pub const CPU_SUBTYPE_ARM64_X1: u32 = 3;
pub const CPU_SUBTYPE_ARM64E_X1: u32 = 12;
/// arm64e subtypes only: the top byte carries a versioned
/// pointer-authentication ABI.
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;
pub const CPU_SUBTYPE_ARM64E_KERNEL_ABI: u32 = 0x4000_0000;
pub const CPU_SUBTYPE_ARM64_PTR_AUTH_MASK: u32 = 0x0f00_0000;

// File types
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_FVMLIB: u32 = 0x3;
pub const MH_CORE: u32 = 0x4;
pub const MH_PRELOAD: u32 = 0x5;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;
pub const MH_DYLIB_STUB: u32 = 0x9;
pub const MH_DSYM: u32 = 0xa;
pub const MH_KEXT_BUNDLE: u32 = 0xb;
pub const MH_FILESET: u32 = 0xc;

// Load commands
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_SYMSEG: u32 = 0x3;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOADFVMLIB: u32 = 0x6;
pub const LC_IDFVMLIB: u32 = 0x7;
pub const LC_IDENT: u32 = 0x8;
pub const LC_FVMFILE: u32 = 0x9;
pub const LC_PREPAGE: u32 = 0xa;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_ID_DYLINKER: u32 = 0xf;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ROUTINES_64: u32 = 0x1a;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
pub const LC_LINKER_OPTION: u32 = 0x2D;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_NOTE: u32 = 0x31;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

// VM protections
pub const VM_PROT_NONE: u32 = 0x00;
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;
pub const VM_PROT_NO_CHANGE: u32 = 0x08;
pub const VM_PROT_COPY: u32 = 0x10;
pub const VM_PROT_IS_MASK: u32 = 0x40;
