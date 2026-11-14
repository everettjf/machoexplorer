//! `moex diff`: compare the first Mach-O header of two files (load command
//! counts, section names and symbol names).

use crate::consts::LC_SYMTAB;
use crate::macho::{Binary, MachHeader};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

const NLIST_SIZE: u64 = 12;
const NLIST_64_SIZE: u64 = 16;

/// Header facts printed for each side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSummary {
    pub arch: &'static str,
    pub ncmds: u32,
    pub sizeofcmds: u32,
}

/// Sizes of the two one-sided differences and the intersection of two sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetDiff {
    pub only_a: usize,
    pub only_b: usize,
    pub common: usize,
}

impl SetDiff {
    pub fn compute<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> SetDiff {
        let common = a.intersection(b).count();
        SetDiff {
            only_a: a.len() - common,
            only_b: b.len() - common,
            common,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReport {
    pub a: HeaderSummary,
    pub b: HeaderSummary,
    pub sections: SetDiff,
    pub symbols: SetDiff,
}

/// The four-line text report.
impl fmt::Display for DiffReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "A arch={} ncmds={} sizeofcmds={}",
            self.a.arch, self.a.ncmds, self.a.sizeofcmds
        )?;
        writeln!(
            f,
            "B arch={} ncmds={} sizeofcmds={}",
            self.b.arch, self.b.ncmds, self.b.sizeofcmds
        )?;
        for (title, d) in [("Sections", &self.sections), ("Symbols", &self.symbols)] {
            writeln!(
                f,
                "{title}: onlyA={} onlyB={} common={}",
                d.only_a, d.only_b, d.common
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffError {
    /// One of the files could not be opened or parsed.
    Parse(crate::Error),
    /// A file parsed but holds no Mach-O header (for example a dyld shared
    /// cache, or an archive without Mach-O members).
    NoHeader,
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffError::Parse(e) => write!(f, "{e}"),
            DiffError::NoHeader => {
                f.write_str("unable to resolve Mach-O headers from one of the files")
            }
        }
    }
}

impl std::error::Error for DiffError {}

/// `SEGNAME/sectname` of every section, as raw bytes.
pub fn collect_sections(mh: &MachHeader) -> BTreeSet<Vec<u8>> {
    let name = |off: u64| mh.image.cstr(off, 16).unwrap_or(&[]);
    mh.sections()
        .map(|s| {
            let mut full = name(s.header_offset.saturating_add(16)).to_vec();
            full.push(b'/');
            full.extend_from_slice(name(s.header_offset));
            full
        })
        .collect()
}

/// Names of the symbols in the first `LC_SYMTAB`, as raw bytes. Entries
/// with string index 0 or an empty name are skipped.
pub fn collect_symbols(mh: &MachHeader) -> BTreeSet<Vec<u8>> {
    let mut out = BTreeSet::new();
    let Some(lc) = mh.find_load_command(&[LC_SYMTAB]) else {
        return out;
    };
    let image = &mh.image;
    let file_size = image.len();
    let symoff = mh.lc_u32(lc, 8) as u64;
    let nsyms = mh.lc_u32(lc, 12) as u64;
    let stroff = mh.lc_u32(lc, 16) as u64;
    let strsize = mh.lc_u32(lc, 20) as u64;

    let entry_size = if mh.is64 { NLIST_64_SIZE } else { NLIST_SIZE };
    let Some(table) = mh.offset.checked_add(symoff) else {
        return out;
    };
    // Clip the entry count to what the file can hold.
    let avail = if table <= file_size {
        (file_size - table) / entry_size
    } else {
        0
    };
    let Some(strings) = mh.offset.checked_add(stroff) else {
        return out;
    };

    for idx in 0..nsyms.min(avail) {
        let Some(strx) = image.u32(table + idx * entry_size) else {
            break;
        };
        let strx = strx as u64;
        if strx == 0 || strx >= strsize {
            continue;
        }
        // The name ends at the first NUL, the end of the string table or
        // the end of the file, whichever comes first.
        let Some(start) = strings.checked_add(strx) else {
            continue;
        };
        if start >= file_size {
            continue;
        }
        let name = image.cstr(start, strsize - strx).unwrap_or(&[]);
        if !name.is_empty() {
            out.insert(name.to_vec());
        }
    }
    out
}

pub fn summarize(mh: &MachHeader) -> HeaderSummary {
    HeaderSummary {
        arch: mh.arch(),
        ncmds: mh.ncmds,
        sizeofcmds: mh.sizeofcmds,
    }
}

pub fn diff_headers(a: &MachHeader, b: &MachHeader) -> DiffReport {
    DiffReport {
        a: summarize(a),
        b: summarize(b),
        sections: SetDiff::compute(&collect_sections(a), &collect_sections(b)),
        symbols: SetDiff::compute(&collect_symbols(a), &collect_symbols(b)),
    }
}

fn first_header(bin: &Binary) -> Option<Arc<MachHeader>> {
    bin.headers().into_iter().next()
}

/// Compare the first Mach-O header of `a` with the first of `b` (first fat
/// slice / first Mach-O archive member).
pub fn diff_files(a: &Path, b: &Path) -> Result<DiffReport, DiffError> {
    let bin_a = Binary::open(a).map_err(DiffError::Parse)?;
    let bin_b = Binary::open(b).map_err(DiffError::Parse)?;
    match (first_header(&bin_a), first_header(&bin_b)) {
        (Some(mh_a), Some(mh_b)) => Ok(diff_headers(&mh_a, &mh_b)),
        _ => Err(DiffError::NoHeader),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::*;
    use crate::image::Image;

    fn set(items: &[&str]) -> BTreeSet<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn set_diff() {
        let d = SetDiff::compute(&set(&["a", "b", "c"]), &set(&["b", "c", "d", "e"]));
        assert_eq!(
            d,
            SetDiff {
                only_a: 1,
                only_b: 2,
                common: 2
            }
        );
        let d = SetDiff::compute(&set(&[]), &set(&["x"]));
        assert_eq!(
            d,
            SetDiff {
                only_a: 0,
                only_b: 1,
                common: 0
            }
        );
    }

    #[test]
    fn report_text() {
        let r = DiffReport {
            a: HeaderSummary {
                arch: "arm64",
                ncmds: 16,
                sizeofcmds: 744,
            },
            b: HeaderSummary {
                arch: "x86_64",
                ncmds: 15,
                sizeofcmds: 1000,
            },
            sections: SetDiff {
                only_a: 1,
                only_b: 2,
                common: 3,
            },
            symbols: SetDiff {
                only_a: 4,
                only_b: 5,
                common: 6,
            },
        };
        assert_eq!(
            r.to_string(),
            "A arch=arm64 ncmds=16 sizeofcmds=744\nB arch=x86_64 ncmds=15 sizeofcmds=1000\n\
             Sections: onlyA=1 onlyB=2 common=3\nSymbols: onlyA=4 onlyB=5 common=6\n"
        );
    }

    /// 64-bit object with one segment (two sections) and a symbol table.
    /// `strsize` and `nsyms` are taken as given so tests can lie about them.
    fn object(nsyms: u32, strsize: u32) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        seg.extend_from_slice(&(72u32 + 160).to_le_bytes());
        seg.extend_from_slice(&[0u8; 16 + 32 + 8]);
        seg.extend_from_slice(&2u32.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        for (sect, segname) in [("__text", "__TEXT"), ("__data", "__DATA")] {
            let mut s = [0u8; 80];
            s[..sect.len()].copy_from_slice(sect.as_bytes());
            s[16..16 + segname.len()].copy_from_slice(segname.as_bytes());
            seg.extend_from_slice(&s);
        }
        let cmds_len = seg.len() as u32 + 24;
        let symoff = 32 + cmds_len;
        let stroff = symoff + 4 * 16;
        let mut d = Vec::new();
        for w in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_OBJECT, 2, cmds_len, 0, 0] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&seg);
        for w in [LC_SYMTAB, 24, symoff, nsyms, stroff, strsize] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        // strx: 1 "_main", 7 "_helper", 0 (skipped), 15 "" (empty, skipped)
        for strx in [1u32, 7, 0, 15] {
            d.extend_from_slice(&strx.to_le_bytes());
            d.extend_from_slice(&[0u8; 12]);
        }
        d.extend_from_slice(b"\0_main\0_helper\0\0");
        d
    }

    fn header(data: Vec<u8>) -> MachHeader {
        MachHeader::parse(&Arc::new(Image::from_vec(data).unwrap()), 0).unwrap()
    }

    #[test]
    fn collects_sections_and_symbols() {
        let mh = header(object(4, 16));
        assert_eq!(
            collect_sections(&mh),
            set(&["__TEXT/__text", "__DATA/__data"])
        );
        assert_eq!(collect_symbols(&mh), set(&["_main", "_helper"]));
        let r = diff_headers(&mh, &mh);
        assert_eq!(
            r.sections,
            SetDiff {
                only_a: 0,
                only_b: 0,
                common: 2
            }
        );
        assert_eq!(
            r.symbols,
            SetDiff {
                only_a: 0,
                only_b: 0,
                common: 2
            }
        );
        assert_eq!(
            r.a,
            HeaderSummary {
                arch: "arm64",
                ncmds: 2,
                sizeofcmds: 256
            }
        );
    }

    #[test]
    fn symbol_table_is_clipped_to_file_and_strsize() {
        // nsyms far beyond the file: only entries that fit are read (the
        // string table bytes get read as entries, harmlessly).
        let mh = header(object(u32::MAX, 16));
        let names = collect_symbols(&mh);
        assert!(names.contains(b"_main".as_slice()));
        // strsize cuts "_helper" short and drops out-of-table indices
        let mh = header(object(4, 10));
        assert_eq!(collect_symbols(&mh), set(&["_main", "_he"]));
        // strsize larger than the file: names stop at the end of the file
        let mut data = object(4, u32::MAX);
        data.truncate(data.len() - 4);
        let mh = header(data);
        assert_eq!(collect_symbols(&mh), set(&["_main", "_help"]));
    }
}
