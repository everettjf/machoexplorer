//! "Load Commands" node and one child per load command.

use crate::consts::*;
use crate::hex::*;
use crate::macho::{LoadCommand, MachHeader};
use crate::names;
use crate::view::{Content, NodeSource, Table, ViewNode};
use std::sync::Arc;

struct LoadCommandsNode(Arc<MachHeader>);

pub fn load_commands_node(mh: Arc<MachHeader>) -> ViewNode {
    ViewNode::new(LoadCommandsNode(mh))
}

impl NodeSource for LoadCommandsNode {
    fn name(&self) -> String {
        "Load Commands".into()
    }

    fn content(&self) -> Content {
        let mh = &self.0;
        let mut t = Table::new();
        t.set_headers(&["Information"]);
        t.set_widths(&[300]);
        t.add([format!("Number of commands : {}", mh.loadcmds.len())]);
        Content::table(t).with_binary(mh.offset + mh.header_size(), mh.sizeofcmds as u64)
    }

    fn children(&self) -> Vec<ViewNode> {
        self.0
            .loadcmds
            .iter()
            .map(|lc| {
                ViewNode::new(LoadCommandNode {
                    mh: self.0.clone(),
                    lc: *lc,
                })
            })
            .collect()
    }
}

struct LoadCommandNode {
    mh: Arc<MachHeader>,
    lc: LoadCommand,
}

pub fn platform_name(platform: u32) -> &'static str {
    match platform {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "macCatalyst",
        7 => "iOSSimulator",
        8 => "tvOSSimulator",
        9 => "watchOSSimulator",
        10 => "driverKit",
        _ => "unknown",
    }
}

fn tool_name(tool: u32) -> &'static str {
    match tool {
        1 => "clang",
        2 => "swift",
        3 => "ld",
        _ => "unknown",
    }
}

/// Last path component (the whole string when it has no `/`).
fn file_name(path: &str) -> &str {
    path.rfind('/').map_or(path, |pos| &path[pos + 1..])
}

/// `A.B.C.D.E` of an `LC_SOURCE_VERSION` value, packed as
/// `a24.b10.c10.d10.e10`.
pub fn source_version(v: u64) -> String {
    format!(
        "{}.{}.{}.{}.{}",
        v >> 40,
        (v >> 30) & 0x3ff,
        (v >> 20) & 0x3ff,
        (v >> 10) & 0x3ff,
        v & 0x3ff
    )
}

const DYLIB_CMDS: &[u32] = &[
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
];
const DYLINKER_CMDS: &[u32] = &[LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_DYLD_ENVIRONMENT];
const VERSION_MIN_CMDS: &[u32] = &[
    LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
];
const LINKEDIT_DATA_CMDS: &[u32] = &[
    LC_CODE_SIGNATURE,
    LC_SEGMENT_SPLIT_INFO,
    LC_FUNCTION_STARTS,
    LC_DATA_IN_CODE,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
];

impl LoadCommandNode {
    fn u32(&self, off: u64) -> u32 {
        self.mh.lc_u32(&self.lc, off)
    }

    fn u64(&self, off: u64) -> u64 {
        self.mh.lc_u64(&self.lc, off)
    }

    fn str_at(&self, field_off: u64) -> Option<(u64, String)> {
        self.mh
            .lc_str(&self.lc, field_off)
            .map(|(at, s)| (at, utf8_safe(s)))
    }

    /// The options of an `LC_LINKER_OPTION` command.
    fn linker_options(&self) -> Vec<String> {
        let mut options = Vec::new();
        if (self.lc.cmdsize as u64) < 12 {
            return options;
        }
        let Some(data) = self.mh.image.slice(self.lc.offset, self.lc.cmdsize as u64) else {
            return options;
        };
        let mut cur = 12usize;
        for _ in 0..self.u32(8) {
            if cur >= data.len() {
                break;
            }
            let term = data[cur..]
                .iter()
                .position(|&c| c == 0)
                .map(|p| cur + p)
                .unwrap_or(data.len());
            options.push(utf8_safe(&data[cur..term]));
            if term >= data.len() {
                break;
            }
            cur = term + 1;
        }
        options
    }

    /// `(tool, version)` entries of an `LC_BUILD_VERSION` command.
    fn build_tools(&self) -> Vec<(u32, u32)> {
        if (self.lc.cmdsize as u64) < 24 {
            return Vec::new();
        }
        let max_items = (self.lc.cmdsize as u64 - 24) / 8;
        (0..(self.u32(20) as u64).min(max_items))
            .map(|i| (self.u32(24 + i * 8), self.u32(28 + i * 8)))
            .collect()
    }

    fn note_owner(&self) -> String {
        utf8_safe(self.mh.image.cstr(self.lc.offset + 8, 16).unwrap_or(&[]))
    }

    /// Short text appended to the command name, e.g. the segment name.
    fn characteristic(&self) -> String {
        let cmd = self.lc.cmd;
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => self
                .mh
                .segments
                .iter()
                .find(|s| s.lc.offset == self.lc.offset)
                .map(|s| s.name.clone())
                .unwrap_or_default(),
            _ if DYLIB_CMDS.contains(&cmd) => self
                .str_at(8)
                .map(|(_, path)| file_name(&path).to_string())
                .unwrap_or_default(),
            LC_RPATH => self.str_at(8).map(|(_, s)| s).unwrap_or_default(),
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => format!("cryptid={}", self.u32(16)),
            LC_LINKER_OPTION => self.linker_options().into_iter().next().unwrap_or_default(),
            LC_BUILD_VERSION => platform_name(self.u32(8)).to_string(),
            LC_NOTE => self.note_owner(),
            LC_FILESET_ENTRY => self.str_at(24).map(|(_, s)| s).unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Rows specific to the command type; `None` for commands with no
    /// detail view.
    fn fill(&self, t: &mut Table) -> Option<()> {
        let o = self.lc.offset;
        let cmd = self.lc.cmd;
        // (field offset, description) lists for all-u32 commands
        let u32_rows = |t: &mut Table, fields: &[&str], fmt: fn(u64) -> String| {
            for (i, desc) in fields.iter().enumerate() {
                let off = 8 + i as u64 * 4;
                t.field(o + off, 4, desc, fmt(self.u32(off) as u64));
            }
        };
        let dec: fn(u64) -> String = |v| v.to_string();
        let hex: fn(u64) -> String = as_short_hex_string;
        let prots = |t: &mut Table, prot: u32| {
            for (value, name) in names::vm_prots(prot) {
                t.add([
                    "".to_string(),
                    as_short_hex_string(value as u64),
                    name.to_string(),
                ]);
            }
        };

        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let s = self.mh.segments.iter().find(|s| s.lc.offset == o)?;
                // (offset, size) of vmaddr, vmsize, fileoff, filesize, then the u32 tail
                let (w, tail) = if s.is64 { (8u64, 56u64) } else { (4, 40) };
                t.field(o + 8, 16, "Segment Name", s.name.clone());
                t.field(o + 24, w, "VM Address", as_short_hex_string(s.vmaddr));
                t.field(o + 24 + w, w, "VM Size", as_string(s.vmsize));
                t.field(
                    o + 24 + 2 * w,
                    w,
                    "File Offset",
                    as_short_hex_string(s.fileoff),
                );
                t.field(o + 24 + 3 * w, w, "File Size", as_string(s.filesize));
                t.field(o + tail, 4, "Maximum VM Protection", "");
                prots(t, s.maxprot);
                t.field(o + tail + 4, 4, "Initial VM Protection", "");
                prots(t, s.initprot);
                t.field(o + tail + 8, 4, "Number of Sections", as_string(s.nsects));
                t.field(o + tail + 12, 4, "Flags", as_string(s.flags));
            }
            _ if DYLIB_CMDS.contains(&cmd) => {
                t.field(
                    o + 8,
                    4,
                    "Str Offset",
                    as_short_hex_string(self.u32(8) as u64),
                );
                t.field(o + 12, 4, "Time Stamp", format_timestamp(self.u32(12)));
                t.field(o + 16, 4, "Current Version", format_version(self.u32(16)));
                t.field(
                    o + 20,
                    4,
                    "Compatibility Version",
                    format_version(self.u32(20)),
                );
                t.separator();
                let (at, path) = self.str_at(8).unwrap_or((0, String::new()));
                let name = file_name(&path).to_string();
                t.field(at, path.len() as u64, "Path", path);
                t.add(["", "Name", name.as_str()]);
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => u32_rows(
                t,
                &[
                    "Rebase Info Offset",
                    "Rebase Info Size",
                    "Binding Info Offset",
                    "Binding Info Size",
                    "Weak Binding Info Offset",
                    "Weak Binding Info Size",
                    "Lazy Binding Info Offset",
                    "Lazy Binding Info Size",
                    "Export Info Offset",
                    "Export Info Size",
                ],
                dec,
            ),
            LC_SYMTAB => u32_rows(
                t,
                &[
                    "Symbol Table Offset",
                    "Number of Symbols",
                    "String Table Offset",
                    "String Table Size",
                ],
                dec,
            ),
            LC_DYSYMTAB => u32_rows(
                t,
                &[
                    "Local Symbols Index",
                    "Number of Local Symbols",
                    "Defined External Symbols Index",
                    "Number of Defined External Symbols",
                    "Undefined External Symbols Index",
                    "Number of Undefined External Symbols",
                    "TOC Offset",
                    "TOC Entries",
                    "Module Table Offset",
                    "Module Table Entries",
                    "ExtRef Table Offset",
                    "ExtRef Table Entries",
                    "Indirect Symbol Table Offset",
                    "Indirect Symbol Table Entries",
                    "ExtReloc Table Offset",
                    "ExtReloc Table Entries",
                    "LocReloc Table Offset",
                    "LocReloc Table Entries",
                ],
                dec,
            ),
            _ if DYLINKER_CMDS.contains(&cmd) => {
                t.field(
                    o + 8,
                    4,
                    "Str Offset",
                    as_short_hex_string(self.u32(8) as u64),
                );
                t.separator();
                let (at, name) = self.str_at(8).unwrap_or((0, String::new()));
                t.field(at, name.len() as u64, "Name", name);
            }
            LC_UUID => {
                let uuid = self
                    .mh
                    .image
                    .slice(o + 8, 16)
                    .filter(|_| self.lc.cmdsize >= 24)
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())?;
                t.field(o + 8, 16, "UUID", format_uuid(&uuid).to_uppercase());
            }
            _ if VERSION_MIN_CMDS.contains(&cmd) => {
                t.field(o + 8, 4, "Version", format_version(self.u32(8)));
                t.field(o + 12, 4, "SDK", format_version(self.u32(12)));
            }
            LC_SOURCE_VERSION => t.field(o + 8, 8, "Version", source_version(self.u64(8))),
            LC_MAIN => {
                t.field(o + 8, 8, "Entry Offset", as_short_hex_string(self.u64(8)));
                t.field(o + 16, 8, "Stack Size", as_short_hex_string(self.u64(16)));
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                u32_rows(t, &["Crypt Offset", "Crypt Size", "Crypt ID"], hex)
            }
            _ if LINKEDIT_DATA_CMDS.contains(&cmd) => {
                u32_rows(t, &["Data Offset", "Data Size"], hex)
            }
            LC_RPATH => {
                t.field(
                    o + 8,
                    4,
                    "Path Offset",
                    as_short_hex_string(self.u32(8) as u64),
                );
                t.separator();
                if let Some((at, path)) = self.str_at(8) {
                    t.field(at, path.len() as u64, "Path", path);
                }
            }
            LC_LINKER_OPTION => {
                t.field(o + 8, 4, "Option Count", as_string(self.u32(8)));
                for (i, option) in self.linker_options().into_iter().enumerate() {
                    t.add(["".to_string(), format!("Option {i}"), option]);
                }
            }
            LC_BUILD_VERSION => {
                t.field(o + 8, 4, "Platform", platform_name(self.u32(8)));
                t.field(o + 12, 4, "Min OS", format_version(self.u32(12)));
                t.field(o + 16, 4, "SDK", format_version(self.u32(16)));
                t.field(o + 20, 4, "Tool Count", as_string(self.u32(20)));
                for (i, (tool, version)) in self.build_tools().into_iter().enumerate() {
                    t.add([
                        "".to_string(),
                        format!("Tool {i}"),
                        format!("{} ({})", tool_name(tool), format_version(version)),
                    ]);
                }
            }
            LC_NOTE => {
                t.add(["".to_string(), "Data Owner".to_string(), self.note_owner()]);
                t.field(o + 24, 8, "Data Offset", as_short_hex_string(self.u64(24)));
                t.field(o + 32, 8, "Data Size", as_short_hex_string(self.u64(32)));
            }
            LC_FILESET_ENTRY => {
                t.field(o + 8, 8, "VM Address", as_short_hex_string(self.u64(8)));
                t.field(o + 16, 8, "File Offset", as_short_hex_string(self.u64(16)));
                t.field(
                    o + 24,
                    4,
                    "Entry ID Offset",
                    as_short_hex_string(self.u32(24) as u64),
                );
                t.field(o + 28, 4, "Reserved", as_string(self.u32(28)));
                if let Some((at, id)) = self.str_at(24) {
                    t.separator();
                    t.field(at, id.len() as u64, "Entry ID", id);
                }
            }
            _ => return None,
        }
        Some(())
    }
}

impl NodeSource for LoadCommandNode {
    fn name(&self) -> String {
        let ty = names::load_command_type(self.lc.cmd);
        let ch = self.characteristic();
        if ch.is_empty() {
            ty.to_string()
        } else {
            format!("{ty}({ch})")
        }
    }

    fn content(&self) -> Content {
        let o = self.lc.offset;
        let mut t = Table::new();
        t.field(o, 4, "Command", names::load_command_type(self.lc.cmd));
        t.field(o + 4, 4, "Command Size", as_string(self.lc.cmdsize));
        t.separator();
        match self.fill(&mut t) {
            Some(()) => Content::table(t).with_binary(o, self.lc.cmdsize as u64),
            None => Content::default(),
        }
    }
}
