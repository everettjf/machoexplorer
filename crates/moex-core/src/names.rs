//! Value-to-name tables. Lookups keep the first entry on duplicate keys,
//! matching the behaviour of the original tables.

use crate::consts::*;

fn lookup(table: &[(u32, &'static str)], key: u32) -> &'static str {
    table
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .unwrap_or("unknown")
}

macro_rules! named {
    ($($name:ident),* $(,)?) => { &[$(($name, stringify!($name))),*] };
}

const LOAD_COMMANDS: &[(u32, &str)] = named![
    LC_SEGMENT,
    LC_SYMTAB,
    LC_SYMSEG,
    LC_THREAD,
    LC_UNIXTHREAD,
    LC_LOADFVMLIB,
    LC_IDFVMLIB,
    LC_IDENT,
    LC_FVMFILE,
    LC_PREPAGE,
    LC_DYSYMTAB,
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_DYLINKER,
    LC_ID_DYLINKER,
    LC_PREBOUND_DYLIB,
    LC_ROUTINES,
    LC_SUB_FRAMEWORK,
    LC_SUB_UMBRELLA,
    LC_SUB_CLIENT,
    LC_SUB_LIBRARY,
    LC_TWOLEVEL_HINTS,
    LC_PREBIND_CKSUM,
    LC_LOAD_WEAK_DYLIB,
    LC_SEGMENT_64,
    LC_ROUTINES_64,
    LC_UUID,
    LC_RPATH,
    LC_CODE_SIGNATURE,
    LC_SEGMENT_SPLIT_INFO,
    LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_ENCRYPTION_INFO,
    LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY,
    LC_LOAD_UPWARD_DYLIB,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_IPHONEOS,
    LC_FUNCTION_STARTS,
    LC_DYLD_ENVIRONMENT,
    LC_MAIN,
    LC_DATA_IN_CODE,
    LC_SOURCE_VERSION,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_ENCRYPTION_INFO_64,
    LC_LINKER_OPTION,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    LC_NOTE,
    LC_BUILD_VERSION,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
    LC_FILESET_ENTRY,
];

/// `LC_*` name, or `"unknown"`.
pub fn cmd_type(cmd: u32) -> &'static str {
    lookup(LOAD_COMMANDS, cmd)
}

/// Same as [`cmd_type`] but also knows the bare `LC_REQ_DYLD` flag.
pub fn load_command_type(cmd: u32) -> &'static str {
    if cmd == LC_REQ_DYLD {
        return "LC_REQ_DYLD";
    }
    lookup(LOAD_COMMANDS, cmd)
}

pub fn magic(magic: u32) -> &'static str {
    lookup(
        named![
            MH_MAGIC,
            MH_CIGAM,
            MH_MAGIC_64,
            MH_CIGAM_64,
            FAT_MAGIC,
            FAT_CIGAM,
            FAT_MAGIC_64,
            FAT_CIGAM_64
        ],
        magic,
    )
}

pub fn cpu_type(t: u32) -> &'static str {
    lookup(
        named![
            CPU_TYPE_ANY,
            CPU_TYPE_VAX,
            CPU_TYPE_MC680x0,
            CPU_TYPE_X86,
            CPU_TYPE_I386,
            CPU_TYPE_X86_64,
            CPU_TYPE_MC98000,
            CPU_TYPE_HPPA,
            CPU_TYPE_ARM,
            CPU_TYPE_ARM64,
            CPU_TYPE_MC88000,
            CPU_TYPE_SPARC,
            CPU_TYPE_I860,
            CPU_TYPE_POWERPC,
            CPU_TYPE_POWERPC64,
        ],
        t,
    )
}

/// Short architecture name used in node titles ("arm64", "x86_64", ...).
pub fn arch(t: u32) -> &'static str {
    lookup(
        &[
            (CPU_TYPE_ANY, "any"),
            (CPU_TYPE_VAX, "vax"),
            (CPU_TYPE_MC680x0, "mc680x0"),
            (CPU_TYPE_X86, "x86"),
            (CPU_TYPE_X86_64, "x86_64"),
            (CPU_TYPE_MC98000, "mc98000"),
            (CPU_TYPE_HPPA, "hppa"),
            (CPU_TYPE_ARM, "arm"),
            (CPU_TYPE_ARM64, "arm64"),
            (CPU_TYPE_MC88000, "mc88000"),
            (CPU_TYPE_SPARC, "sparc"),
            (CPU_TYPE_I860, "i860"),
            (CPU_TYPE_POWERPC, "powerpc"),
            (CPU_TYPE_POWERPC64, "powerpc64"),
        ],
        t,
    )
}

fn cpu_subtype_table(cputype: u32) -> Option<&'static [(u32, &'static str)]> {
    Some(match cputype {
        CPU_TYPE_POWERPC => &[
            (0, "CPU_SUBTYPE_POWERPC_ALL"),
            (1, "CPU_SUBTYPE_POWERPC_601"),
            (2, "CPU_SUBTYPE_POWERPC_602"),
            (3, "CPU_SUBTYPE_POWERPC_603"),
            (4, "CPU_SUBTYPE_POWERPC_603e"),
            (5, "CPU_SUBTYPE_POWERPC_603ev"),
            (6, "CPU_SUBTYPE_POWERPC_604"),
            (7, "CPU_SUBTYPE_POWERPC_604e"),
            (8, "CPU_SUBTYPE_POWERPC_620"),
            (9, "CPU_SUBTYPE_POWERPC_750"),
            (10, "CPU_SUBTYPE_POWERPC_7400"),
            (11, "CPU_SUBTYPE_POWERPC_7450"),
            (100, "CPU_SUBTYPE_POWERPC_970"),
        ],
        CPU_TYPE_ARM => &[
            (0, "CPU_SUBTYPE_ARM_ALL"),
            (5, "CPU_SUBTYPE_ARM_V4T"),
            (6, "CPU_SUBTYPE_ARM_V6"),
            (7, "CPU_SUBTYPE_ARM_V5TEJ"),
            (8, "CPU_SUBTYPE_ARM_XSCALE"),
            (9, "CPU_SUBTYPE_ARM_V7"),
            (10, "CPU_SUBTYPE_ARM_V7F"),
            (11, "CPU_SUBTYPE_ARM_V7S"),
            (12, "CPU_SUBTYPE_ARM_V7K"),
            (14, "CPU_SUBTYPE_ARM_V6M"),
            (15, "CPU_SUBTYPE_ARM_V7M"),
            (16, "CPU_SUBTYPE_ARM_V7EM"),
            (13, "CPU_SUBTYPE_ARM_V8"),
        ],
        CPU_TYPE_ARM64 => &[(0, "CPU_SUBTYPE_ARM64_ALL"), (1, "CPU_SUBTYPE_ARM64_V8")],
        CPU_TYPE_I386 => &[(3, "CPU_SUBTYPE_I386_ALL")],
        CPU_TYPE_X86_64 => &[(3, "CPU_SUBTYPE_X86_64_ALL")],
        CPU_TYPE_ANY => &[
            (0xffff_ffff, "CPU_SUBTYPE_MULTIPLE"),
            (0, "CPU_SUBTYPE_LITTLE_ENDIAN"),
            (1, "CPU_SUBTYPE_BIG_ENDIAN"),
        ],
        _ => return None,
    })
}

/// Decomposed CPU subtype as `(value, name)` entries: the optional
/// `CPU_SUBTYPE_LIB64` capability bit followed by the base subtype. Empty
/// when the base subtype is not known for this CPU type.
pub fn cpu_subtype_array(cputype: u32, subtype: u32) -> Vec<(u32, &'static str)> {
    let base = subtype & !CPU_SUBTYPE_MASK;
    let Some(name) = cpu_subtype_table(cputype)
        .and_then(|t| t.iter().find(|(k, _)| *k == base))
        .map(|(_, v)| *v)
    else {
        return Vec::new();
    };
    let mut res = Vec::with_capacity(2);
    if subtype & CPU_SUBTYPE_LIB64 == CPU_SUBTYPE_LIB64 {
        res.push((CPU_SUBTYPE_LIB64, "CPU_SUBTYPE_LIB64"));
    }
    res.push((base, name));
    res
}

pub fn cpu_subtype(cputype: u32, subtype: u32) -> String {
    let res = cpu_subtype_array(cputype, subtype);
    match res.len() {
        0 => "unknown".to_string(),
        1 => res[0].1.to_string(),
        _ => format!("{},{}", res[0].1, res[1].1),
    }
}

pub fn file_type(t: u32) -> &'static str {
    lookup(
        named![
            MH_OBJECT,
            MH_EXECUTE,
            MH_FVMLIB,
            MH_CORE,
            MH_PRELOAD,
            MH_DYLIB,
            MH_DYLINKER,
            MH_BUNDLE,
            MH_DYLIB_STUB,
            MH_DSYM,
            MH_KEXT_BUNDLE
        ],
        t,
    )
}

const MH_FLAGS: &[(u32, &str)] = &[
    (0x1, "MH_NOUNDEFS"),
    (0x2, "MH_INCRLINK"),
    (0x4, "MH_DYLDLINK"),
    (0x8, "MH_BINDATLOAD"),
    (0x10, "MH_PREBOUND"),
    (0x20, "MH_SPLIT_SEGS"),
    (0x40, "MH_LAZY_INIT"),
    (0x80, "MH_TWOLEVEL"),
    (0x100, "MH_FORCE_FLAT"),
    (0x200, "MH_NOMULTIDEFS"),
    (0x400, "MH_NOFIXPREBINDING"),
    (0x800, "MH_PREBINDABLE"),
    (0x1000, "MH_ALLMODSBOUND"),
    (0x2000, "MH_SUBSECTIONS_VIA_SYMBOLS"),
    (0x4000, "MH_CANONICAL"),
    (0x8000, "MH_WEAK_DEFINES"),
    (0x10000, "MH_BINDS_TO_WEAK"),
    (0x20000, "MH_ALLOW_STACK_EXECUTION"),
    (0x40000, "MH_ROOT_SAFE"),
    (0x80000, "MH_SETUID_SAFE"),
    (0x100000, "MH_NO_REEXPORTED_DYLIBS"),
    (0x200000, "MH_PIE"),
    (0x400000, "MH_DEAD_STRIPPABLE_DYLIB"),
    (0x800000, "MH_HAS_TLV_DESCRIPTORS"),
    (0x1000000, "MH_NO_HEAP_EXECUTION"),
    (0x2000000, "MH_APP_EXTENSION_SAFE"),
];

/// The `MH_*` flags set in `flags`, in table order.
pub fn mach_flags(flags: u32) -> Vec<(u32, &'static str)> {
    MH_FLAGS
        .iter()
        .filter(|(bit, _)| bit & flags != 0)
        .copied()
        .collect()
}

/// The `VM_PROT_*` bits set in `prot`.
pub fn vm_prots(prot: u32) -> Vec<(u32, &'static str)> {
    if prot == VM_PROT_NONE {
        return vec![(VM_PROT_NONE, "VM_PROT_NONE")];
    }
    [
        (VM_PROT_READ, "VM_PROT_READ"),
        (VM_PROT_WRITE, "VM_PROT_WRITE"),
        (VM_PROT_EXECUTE, "VM_PROT_EXECUTE"),
        (VM_PROT_NO_CHANGE, "VM_PROT_NO_CHANGE"),
        (VM_PROT_COPY, "VM_PROT_COPY/VM_PROT_WANTS_COPY"),
        (VM_PROT_IS_MASK, "VM_PROT_IS_MASK"),
    ]
    .into_iter()
    .filter(|(bit, _)| prot & bit != 0)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_names() {
        assert_eq!(cpu_type(CPU_TYPE_ARM64), "CPU_TYPE_ARM64");
        assert_eq!(cpu_type(7), "CPU_TYPE_X86");
        assert_eq!(arch(CPU_TYPE_X86_64), "x86_64");
        assert_eq!(arch(0x1234), "unknown");
        assert_eq!(cpu_subtype(CPU_TYPE_X86_64, 3), "CPU_SUBTYPE_X86_64_ALL");
        assert_eq!(
            cpu_subtype(CPU_TYPE_X86_64, 0x8000_0003),
            "CPU_SUBTYPE_LIB64,CPU_SUBTYPE_X86_64_ALL"
        );
        // arm64e (subtype 2) is not in the table.
        assert_eq!(cpu_subtype(CPU_TYPE_ARM64, 0x8000_0002), "unknown");
    }

    #[test]
    fn flags() {
        let f = mach_flags(0x200085);
        let names: Vec<_> = f.iter().map(|x| x.1).collect();
        assert_eq!(
            names,
            ["MH_NOUNDEFS", "MH_DYLDLINK", "MH_TWOLEVEL", "MH_PIE"]
        );
        assert_eq!(cmd_type(LC_MAIN), "LC_MAIN");
        assert_eq!(cmd_type(0x7777), "unknown");
    }
}
