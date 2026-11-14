//! "Code Signature" node: the embedded signature super-blob, its code
//! directory and XML entitlements.

use crate::consts::LC_CODE_SIGNATURE;
use crate::hex::{as_address, as_short_hex_string, as_string, utf8_safe};
use crate::macho::MachHeader;
use crate::view::{Content, NodeSource, Table, ViewNode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const CS_MAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
const CS_MAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;
const CS_MAGIC_CODE_DIRECTORY: u32 = 0xfade0c02;
const CS_MAGIC_REQUIREMENTS: u32 = 0xfade0c01;
const CS_MAGIC_REQUIREMENT: u32 = 0xfade0c00;
const CS_MAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
const CS_MAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;
const CS_MAGIC_BLOB_WRAPPER: u32 = 0xfade0b01;
const CS_SLOT_ENTITLEMENTS: u32 = 5;
const CS_SLOT_DER_ENTITLEMENTS: u32 = 7;
const MAX_ENTITLEMENT_LINES: u32 = 1000;

fn hash_type_name(t: u8) -> &'static str {
    match t {
        0 => "none",
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "SHA-256 (truncated)",
        4 => "SHA-384",
        5 => "SHA-512",
        _ => "unknown",
    }
}

fn code_directory_flags(flags: u32) -> String {
    const TABLE: &[(u32, &str)] = &[
        (0x0000_0001, "host"),
        (0x0000_0002, "adhoc"),
        (0x0000_0004, "force-hard"),
        (0x0000_0008, "force-kill"),
        (0x0000_0100, "installer"),
        (0x0000_0200, "dyld-platform"),
        (0x0000_0400, "hard"),
        (0x0000_0800, "kill"),
        (0x0001_0000, "runtime"),
        (0x0002_0000, "linker-signed"),
    ];
    let names: Vec<&str> = TABLE
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if names.is_empty() {
        "(none)".into()
    } else {
        names.join(" | ")
    }
}

fn magic_name(magic: u32) -> &'static str {
    match magic {
        CS_MAGIC_EMBEDDED_SIGNATURE => "Embedded Signature",
        CS_MAGIC_EMBEDDED_SIGNATURE_OLD => "Embedded Signature (old)",
        CS_MAGIC_CODE_DIRECTORY => "Code Directory",
        CS_MAGIC_REQUIREMENTS => "Requirements",
        CS_MAGIC_REQUIREMENT => "Requirement",
        CS_MAGIC_EMBEDDED_ENTITLEMENTS => "Entitlements (XML)",
        CS_MAGIC_EMBEDDED_DER_ENTITLEMENTS => "Entitlements (DER)",
        CS_MAGIC_BLOB_WRAPPER => "CMS Signature",
        _ => "Unknown",
    }
}

fn slot_name(slot: u32) -> &'static str {
    match slot {
        0 => "Code Directory",
        1 => "Info.plist",
        2 => "Requirements",
        3 => "Resource Directory",
        4 => "Application",
        CS_SLOT_ENTITLEMENTS => "Entitlements",
        6 => "Repspecific",
        CS_SLOT_DER_ENTITLEMENTS => "DER Entitlements",
        0x1000 => "Alternate Code Directory",
        0x10000 => "CMS Signature",
        _ => "Slot",
    }
}

/// Big-endian u32 at `off` in `blob`; 0 when out of range.
fn be32(blob: &[u8], off: u64) -> u32 {
    usize::try_from(off)
        .ok()
        .and_then(|o| blob.get(o..o.checked_add(4)?))
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

/// C string at `off` inside `region` (empty when `off` is 0 or out of range).
fn blob_cstring(region: &[u8], off: u32) -> String {
    let off = off as usize;
    if off == 0 || off >= region.len() {
        return String::new();
    }
    let s = &region[off..];
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    utf8_safe(&s[..end])
}

fn magic_desc(magic: u32) -> String {
    format!(
        "0x{} ({})",
        as_short_hex_string(magic as u64),
        magic_name(magic)
    )
}

struct CodeSignatureNode(Arc<MachHeader>);

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(ViewNode::new(CodeSignatureNode(mh)))
}

impl NodeSource for CodeSignatureNode {
    fn name(&self) -> String {
        "Code Signature".into()
    }

    fn content(&self) -> Content {
        let mh = &self.0;
        let mut t = Table::new();
        let Some(lc) = mh.find_load_command(&[LC_CODE_SIGNATURE]) else {
            return Content::table(t);
        };
        let base_off = mh.offset + mh.lc_u32(lc, 8) as u64;
        let datasize = mh.lc_u32(lc, 12);
        fill(&mut t, mh, base_off, datasize);
        Content::table(t).with_binary(base_off, datasize as u64)
    }
}

fn fill(t: &mut Table, mh: &MachHeader, base_off: u64, datasize: u32) {
    let blob = match mh.image.slice(base_off, datasize as u64) {
        Some(b) if datasize >= 12 => b,
        _ => {
            t.add([
                as_address(base_off),
                "error".into(),
                "code signature blob out of range".into(),
            ]);
            return;
        }
    };
    let super_magic = be32(blob, 0);
    let super_len = be32(blob, 4);
    let super_count = be32(blob, 8);
    t.add([
        as_address(base_off),
        "Magic".into(),
        magic_desc(super_magic),
    ]);
    t.add([
        as_address(base_off + 4),
        "Length".into(),
        as_string(super_len),
    ]);
    if super_magic != CS_MAGIC_EMBEDDED_SIGNATURE && super_magic != CS_MAGIC_EMBEDDED_SIGNATURE_OLD
    {
        return;
    }
    t.add([
        as_address(base_off + 8),
        "Blob Count".into(),
        as_string(super_count),
    ]);
    t.separator();

    let max_indices = (datasize as u64 - 12) / 8;
    let count = (super_count as u64).min(max_indices);
    let mut entitlements_off: Option<u32> = None;
    let mut cd_off: Option<u32> = None;
    // Offsets are 32-bit in the format; additions wrap like the original.
    let fits = |off: u32, len: u32| off.wrapping_add(len) <= datasize;
    for i in 0..count {
        let idx = 12 + i * 8;
        let slot_type = be32(blob, idx);
        let blob_off = be32(blob, idx + 4);
        let (mut magic_text, mut len_text) = ("-".to_string(), "-".to_string());
        if fits(blob_off, 8) {
            let bmagic = be32(blob, blob_off as u64);
            let blen = be32(blob, blob_off as u64 + 4);
            magic_text = magic_desc(bmagic);
            len_text = as_string(blen);
            if (slot_type == CS_SLOT_ENTITLEMENTS || bmagic == CS_MAGIC_EMBEDDED_ENTITLEMENTS)
                && entitlements_off.is_none()
            {
                entitlements_off = Some(blob_off);
            }
            if bmagic == CS_MAGIC_CODE_DIRECTORY && cd_off.is_none() {
                cd_off = Some(blob_off);
            }
        }
        t.add([
            as_address(base_off + idx),
            format!("[{i}] {}", slot_name(slot_type)),
            format!("offset={blob_off} magic={magic_text} length={len_text}"),
        ]);
    }

    if let Some(cd_off) = cd_off.filter(|&o| fits(o, 44)) {
        code_directory(t, blob, base_off, datasize, cd_off);
    }

    let Some(ent_off) = entitlements_off.filter(|&o| fits(o, 8)) else {
        return;
    };
    let ent_magic = be32(blob, ent_off as u64);
    let ent_len = be32(blob, ent_off as u64 + 4);
    if ent_magic != CS_MAGIC_EMBEDDED_ENTITLEMENTS || ent_len < 8 || !fits(ent_off, ent_len) {
        return;
    }
    let xml_len = ent_len - 8;
    let Some(xml) = (ent_off as usize)
        .checked_add(8)
        .and_then(|s| blob.get(s..s.checked_add(xml_len as usize)?))
    else {
        return;
    };
    t.separator();
    t.add([
        as_address(base_off + ent_off as u64),
        "Entitlements".into(),
        format!("{xml_len} bytes (XML)"),
    ]);
    let mut line_no = 0;
    let mut i = 0usize;
    while i < xml.len() && line_no < MAX_ENTITLEMENT_LINES {
        let start = i;
        while i < xml.len() && xml[i] != b'\n' {
            i += 1;
        }
        let mut line = &xml[start..i];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        t.add([
            as_address(base_off + ent_off as u64 + 8 + start as u64),
            String::new(),
            utf8_safe(line),
        ]);
        line_no += 1;
        if i < xml.len() {
            i += 1; // skip '\n'
        }
    }
    if i < xml.len() {
        t.add([
            String::new(),
            String::new(),
            format!("... ({} more bytes truncated)", xml.len() - i),
        ]);
    }
}

fn code_directory(t: &mut Table, blob: &[u8], base_off: u64, datasize: u32, cd_off: u32) {
    let Some(cd) = blob.get(cd_off as usize..) else {
        return;
    };
    let cd_base = base_off + cd_off as u64;
    let cd_version = be32(cd, 8);
    let cd_flags = be32(cd, 12);
    let ident_off = be32(cd, 20);
    let n_special = be32(cd, 24);
    let n_code = be32(cd, 28);
    let code_limit = be32(cd, 32);
    let byte = |o: usize| cd.get(o).copied().unwrap_or(0);
    let (hash_size, hash_type, page_log2) = (byte(36), byte(37), byte(39));

    t.separator();
    t.add([
        as_address(cd_base),
        "Code Directory".into(),
        format!("version=0x{}", as_short_hex_string(cd_version as u64)),
    ]);

    let cd_len = be32(cd, 4);
    if cd_len >= 8 && cd_off as u64 + cd_len as u64 <= datasize as u64 {
        if let Some(body) = cd.get(..cd_len as usize) {
            let digest: Vec<u8> = match hash_type {
                1 => Sha1::digest(body).to_vec(),
                2 | 3 => Sha256::digest(body).to_vec(),
                _ => Vec::new(),
            };
            if !digest.is_empty() {
                // cdhash is the digest truncated to 20 bytes.
                let hex: String = digest.iter().take(20).map(|b| format!("{b:02x}")).collect();
                t.add([as_address(cd_base), "CD Hash (cdhash)".into(), hex]);
            }
        }
    }

    let identifier = blob_cstring(cd, ident_off);
    if !identifier.is_empty() {
        t.add([
            as_address(cd_base + ident_off as u64),
            "Identifier".into(),
            identifier,
        ]);
    }
    if cd_version >= 0x20200 && cd_off.wrapping_add(52) <= datasize {
        let team_off = be32(cd, 48);
        let team = blob_cstring(cd, team_off);
        if !team.is_empty() {
            t.add([
                as_address(cd_base + team_off as u64),
                "Team Identifier".into(),
                team,
            ]);
        }
    }
    t.add([
        as_address(cd_base + 37),
        "Hash Type".into(),
        format!(
            "{hash_type} ({}, {hash_size} bytes)",
            hash_type_name(hash_type)
        ),
    ]);
    t.add([
        as_address(cd_base + 12),
        "Flags".into(),
        format!(
            "0x{} ({})",
            as_short_hex_string(cd_flags as u64),
            code_directory_flags(cd_flags)
        ),
    ]);
    t.add([
        as_address(cd_base + 28),
        "Code Slots".into(),
        format!(
            "{n_code} (page size {} bytes)",
            if page_log2 < 31 { 1u32 << page_log2 } else { 0 }
        ),
    ]);
    t.add([
        as_address(cd_base + 24),
        "Special Slots".into(),
        as_string(n_special),
    ]);
    t.add([
        as_address(cd_base + 32),
        "Code Limit".into(),
        as_string(code_limit),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(code_directory_flags(0), "(none)");
        assert_eq!(code_directory_flags(0x10002), "adhoc | runtime");
        assert_eq!(
            be32(&[0xfa, 0xde, 0x0c, 0xc0], 0),
            CS_MAGIC_EMBEDDED_SIGNATURE
        );
        assert_eq!(be32(&[1, 2, 3], 0), 0);
        assert_eq!(be32(&[1, 2, 3, 4], u64::MAX), 0);
        assert_eq!(blob_cstring(b"\0abc\0def", 1), "abc");
        assert_eq!(blob_cstring(b"\0abc", 1), "abc");
        assert_eq!(blob_cstring(b"abc", 0), "");
        assert_eq!(blob_cstring(b"abc", 9), "");
    }
}
