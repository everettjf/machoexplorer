//! "Integrity Report" node: range checks of segments, sections and the
//! linkedit tables against the bounds of the Mach-O (the fat slice or
//! archive member it lives in, or the whole file).

use crate::consts::*;
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Integrity Report", move || content(&mh)))
}

#[derive(Default)]
struct Report {
    table: Table,
    errors: u32,
    warnings: u32,
    infos: u32,
}

impl Report {
    fn issue(&mut self, severity: &str, category: &str, check: &str, details: String) {
        self.table
            .add([severity, category, check, details.as_str()]);
        match severity {
            "ERROR" => self.errors += 1,
            "WARN" => self.warnings += 1,
            _ => self.infos += 1,
        }
    }

    fn check_range(&mut self, file_size: u64, off: u64, size: u64, category: &str, check: &str) {
        if size == 0 {
            self.issue("INFO", category, check, "empty range".to_string());
        } else if !in_range(file_size, off, size) {
            self.issue(
                "ERROR",
                category,
                check,
                format!(
                    "out of file range: off=0x{:X} size=0x{:X} file=0x{:X}",
                    off, size, file_size
                ),
            );
        } else {
            // In range, so `off + size <= file_size` cannot overflow.
            self.issue(
                "INFO",
                category,
                check,
                format!("ok: [0x{:X}, 0x{:X})", off, off.saturating_add(size)),
            );
        }
    }
}

fn in_range(file_size: u64, off: u64, size: u64) -> bool {
    off <= file_size && size <= file_size - off
}

fn content(mh: &MachHeader) -> Content {
    let mut r = Report::default();
    r.table
        .set_headers(&["Severity", "Category", "Check", "Details"]);
    r.table.set_widths(&[100, 160, 220, 560]);
    // Offsets in load commands are relative to the Mach-O header, so they
    // are bounded by the size of the slice, not of the whole file.
    let file_size = mh.size;

    // 32-bit segments first, then 64-bit ones.
    for want64 in [false, true] {
        for seg in mh.segments.iter().filter(|s| s.is64 == want64) {
            if !in_range(file_size, seg.fileoff, seg.filesize) {
                r.issue(
                    "ERROR",
                    "segment",
                    &seg.name,
                    format!(
                        "segment out of range: off=0x{:X} size=0x{:X}",
                        seg.fileoff, seg.filesize
                    ),
                );
            }
            for sect in &seg.sections {
                if !in_range(file_size, sect.offset as u64, sect.size) {
                    r.issue(
                        "ERROR",
                        "section",
                        &format!("{}/{}", sect.segname, sect.sectname),
                        format!(
                            "section out of range: off=0x{:X} size=0x{:X}",
                            sect.offset, sect.size
                        ),
                    );
                }
            }
        }
    }

    let symtab = mh.symtab();
    match &symtab {
        Some(st) => {
            r.check_range(
                file_size,
                st.symoff as u64,
                st.symbol_table_total_bytes(),
                "symtab",
                "symbol table",
            );
            r.check_range(
                file_size,
                st.stroff as u64,
                st.strsize as u64,
                "symtab",
                "string table",
            );
            if st.strsize > 0 {
                let bad_strx = st.symbols().filter(|s| s.n_strx >= st.strsize).count();
                if bad_strx > 0 {
                    r.issue(
                        "WARN",
                        "symtab",
                        "string index bounds",
                        format!("{bad_strx} symbols have n_strx out of strsize"),
                    );
                } else {
                    r.issue(
                        "INFO",
                        "symtab",
                        "string index bounds",
                        "all n_strx values are in range".to_string(),
                    );
                }
            }
        }
        None => r.issue(
            "INFO",
            "symtab",
            "presence",
            "LC_SYMTAB not present".to_string(),
        ),
    }

    if let (Some(dysym), Some(st)) = (mh.dysymtab(), &symtab) {
        let nsyms = st.nsyms;
        for (idx, count, name) in [
            (dysym.ilocalsym, dysym.nlocalsym, "locals"),
            (dysym.iextdefsym, dysym.nextdefsym, "extdef"),
            (dysym.iundefsym, dysym.nundefsym, "undef"),
        ] {
            if idx > nsyms || count > nsyms - idx {
                r.issue(
                    "ERROR",
                    "dysymtab",
                    name,
                    format!("index/count overflow: idx={idx} count={count} nsyms={nsyms}"),
                );
            }
        }
    }

    if let Some(lc) = mh.find_load_command(&[LC_DYLD_INFO, LC_DYLD_INFO_ONLY]) {
        for (i, check) in ["rebase", "bind", "weak_bind", "lazy_bind", "export"]
            .into_iter()
            .enumerate()
        {
            let at = 8 + 8 * i as u64;
            r.check_range(
                file_size,
                mh.lc_u32(lc, at) as u64,
                mh.lc_u32(lc, at + 4) as u64,
                "dyld_info",
                check,
            );
        }
    }

    for (cmd, category) in [
        (LC_CODE_SIGNATURE, "code_signature"),
        (LC_FUNCTION_STARTS, "function_starts"),
        (LC_DATA_IN_CODE, "data_in_code"),
        (LC_DYLD_EXPORTS_TRIE, "dyld_exports_trie"),
        (LC_DYLD_CHAINED_FIXUPS, "dyld_chained_fixups"),
    ] {
        if let Some(d) = mh.linkedit_data(cmd) {
            r.check_range(
                file_size,
                d.dataoff as u64,
                d.datasize as u64,
                category,
                "data range",
            );
        }
    }

    r.table.separator();
    r.table.add([
        "SUMMARY".to_string(),
        "integrity".to_string(),
        "issues".to_string(),
        format!(
            "errors={} warnings={} infos={}",
            r.errors, r.warnings, r.infos
        ),
    ]);
    Content::table(r.table)
}
