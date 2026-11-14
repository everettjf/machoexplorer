//! Export trie walker for `LC_DYLD_EXPORTS_TRIE`, mirroring the walk in
//! `ModernExportsTrieViewNode` step by step.
//!
//! Positions are file offsets. The original does pointer arithmetic with
//! unchecked 64-bit values read from the file; that is reproduced with
//! wrapping arithmetic, and every read is bounds-checked. A position that
//! wraps to a point before the trie (but inside the file) is read from
//! there, exactly like the original.

use super::dyld_info::{
    EXPORT_SYMBOL_FLAGS_KIND_MASK, EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
    EXPORT_SYMBOL_FLAGS_REEXPORT, EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, MAX_TRIE_EDGES,
    MAX_TRIE_NODES,
};
use crate::leb::read_uleb128;
use std::collections::{HashSet, VecDeque};

/// Upper bound on the bytes of symbol names one walk hands out (each node
/// and edge repeats its whole prefix). Only crafted, deeply chained tries
/// get near it; the walk stops there.
pub const MAX_TRIE_NAME_BYTES: usize = 256 << 20;

/// What follows the first two terminal values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieTerminalTail {
    /// Regular or thread-local symbol: `value` is its address offset.
    Address,
    /// Re-export. `name` is `None` when no terminator was found, and may be
    /// empty (same name as the export).
    ///
    /// QUIRK(parity): the original skips one ULEB128 before the import
    /// name, so the name loses its leading byte(s); `at` points past them.
    Reexport { at: u64, name: Option<Vec<u8>> },
    /// Stub and resolver. `at` points past the resolver value.
    Resolver { at: u64, resolver: u64 },
    /// The extra re-export / resolver value could not be read.
    Missing,
}

/// The terminal payload of a node, as far as it could be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieTerminal {
    /// Position of the flags.
    pub flags_at: u64,
    pub flags: u64,
    /// Position of the value after the flags, the value, and what follows;
    /// `None` when the value could not be read inside the terminal.
    pub value: Option<(u64, u64, TrieTerminalTail)>,
}

impl TrieTerminal {
    pub fn kind_name(&self) -> &'static str {
        let mut kind = "regular";
        if self.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL {
            kind = "thread_local";
        }
        if self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
            kind = "reexport";
        }
        if self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
            kind = "stub_and_resolver";
        }
        kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieEdge {
    /// Position of the edge label.
    pub at: u64,
    /// Node prefix plus the edge label.
    pub name: Vec<u8>,
    /// Offset of the child node from the start of the trie.
    pub next: u64,
}

/// One visited node. All positions are relative to the start of the trie,
/// as wrapping 64-bit values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieNode {
    pub at: u64,
    /// Symbol name accumulated on the way to this node (raw bytes).
    pub prefix: Vec<u8>,
    pub terminal_size: u64,
    pub terminal: Option<TrieTerminal>,
    /// Position and value of the child count; `None` when the node ends at
    /// or past the end of the trie.
    pub child_count: Option<(u64, u8)>,
    pub edges: Vec<TrieEdge>,
}

/// ULEB128 at `pos`, reading no further than `limit`. Returns the value and
/// the position after it.
fn uleb(file: &[u8], pos: u64, limit: u64) -> Option<(u64, u64)> {
    if pos >= limit {
        return None;
    }
    let bytes = file.get(usize::try_from(pos).ok()?..usize::try_from(limit).ok()?)?;
    let (value, used) = read_uleb128(bytes)?;
    Some((value, pos.checked_add(used as u64)?))
}

/// Bytes of the NUL-terminated string at `pos`, searching no further than
/// `limit`.
fn cstr(file: &[u8], pos: u64, limit: u64) -> Option<&[u8]> {
    if pos > limit {
        return None;
    }
    let bytes = file.get(usize::try_from(pos).ok()?..usize::try_from(limit).ok()?)?;
    let len = bytes.iter().position(|&c| c == 0)?;
    bytes.get(..len)
}

fn terminal(
    file: &[u8],
    p: u64,
    terminal_end: u64,
    blob_end: u64,
    rel: impl Fn(u64) -> u64,
) -> Option<TrieTerminal> {
    let (flags, q) = uleb(file, p, blob_end).filter(|&(_, q)| q <= terminal_end)?;
    let mut t = TrieTerminal {
        flags_at: rel(p),
        flags,
        value: None,
    };
    let Some((value, r)) = uleb(file, q, blob_end).filter(|&(_, r)| r <= terminal_end) else {
        return Some(t);
    };
    let extra = || uleb(file, r, blob_end).filter(|&(_, after)| after <= terminal_end);
    let tail = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        match extra() {
            Some((_, name_at)) => TrieTerminalTail::Reexport {
                at: rel(name_at),
                name: cstr(file, name_at, terminal_end).map(<[u8]>::to_vec),
            },
            None => TrieTerminalTail::Missing,
        }
    } else if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        match extra() {
            Some((resolver, after)) => TrieTerminalTail::Resolver {
                at: rel(after),
                resolver,
            },
            None => TrieTerminalTail::Missing,
        }
    } else {
        TrieTerminalTail::Address
    };
    t.value = Some((rel(q), value, tail));
    Some(t)
}

/// Walk the trie stored at `file[blob_begin .. blob_begin + datasize]`
/// breadth-first, calling `visit` for every node in the order the original
/// reports them. Nothing is visited when the trie is not inside `file`.
pub fn walk_exports_trie(
    file: &[u8],
    blob_begin: u64,
    datasize: u32,
    mut visit: impl FnMut(&TrieNode),
) {
    let Some(blob_end) = blob_begin
        .checked_add(datasize as u64)
        .filter(|&e| e <= file.len() as u64)
    else {
        return;
    };
    let rel = |pos: u64| pos.wrapping_sub(blob_begin);

    let mut work: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut name_bytes = 0usize;
    let mut edges = 0usize;
    work.push_back((blob_begin, Vec::new()));
    let mut guard = 0usize;
    while guard < MAX_TRIE_NODES && name_bytes <= MAX_TRIE_NAME_BYTES && edges <= MAX_TRIE_EDGES {
        let Some((pos, prefix)) = work.pop_front() else {
            break;
        };
        guard += 1;
        if pos < blob_begin || pos >= blob_end || !visited.insert(rel(pos)) {
            continue;
        }
        let Some((terminal_size, p)) = uleb(file, pos, blob_end) else {
            continue;
        };
        // Unchecked in the original: a huge size wraps around.
        let terminal_end = p.wrapping_add(terminal_size);
        name_bytes = name_bytes.saturating_add(prefix.len().saturating_mul(4));
        let mut node = TrieNode {
            at: rel(pos),
            prefix,
            terminal_size,
            terminal: None,
            child_count: None,
            edges: Vec::new(),
        };
        if terminal_end <= blob_end && terminal_size > 0 {
            node.terminal = terminal(file, p, terminal_end, blob_end, rel);
        }

        let mut children = terminal_end;
        let count = if children < blob_end {
            usize::try_from(children)
                .ok()
                .and_then(|i| file.get(i))
                .copied()
        } else {
            None
        };
        let Some(child_count) = count else {
            visit(&node);
            continue;
        };
        node.child_count = Some((rel(children), child_count));
        children = children.wrapping_add(1);
        for _ in 0..child_count {
            if children >= blob_end {
                break;
            }
            let label_at = children;
            let Some(label) = cstr(file, label_at, blob_end) else {
                break;
            };
            let after_label = label_at.wrapping_add(label.len() as u64).wrapping_add(1);
            let Some((next, after)) = uleb(file, after_label, blob_end) else {
                break;
            };
            children = after;
            let mut name = Vec::with_capacity(node.prefix.len().saturating_add(label.len()));
            name.extend_from_slice(&node.prefix);
            name.extend_from_slice(label);
            name_bytes = name_bytes.saturating_add(name.len().saturating_mul(2));
            if next < datasize as u64 {
                work.push_back((blob_begin.wrapping_add(next), name.clone()));
            }
            node.edges.push(TrieEdge {
                at: rel(label_at),
                name,
                next,
            });
        }
        edges = edges.saturating_add(node.edges.len());
        visit(&node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(file: &[u8], begin: u64, size: u32) -> Vec<TrieNode> {
        let mut out = Vec::new();
        walk_exports_trie(file, begin, size, |n| out.push(n.clone()));
        out
    }

    /// 16 bytes of padding, then a trie with a regular symbol `_main`, a
    /// re-export `_re` (ordinal 2, import `_orig`) and a resolver `_rs`.
    fn sample() -> Vec<u8> {
        let mut t = vec![0x00, 0x01, b'_', 0x00, 0x05];
        // @5: three children
        t.extend([0x00, 0x03]);
        t.extend(b"main\0");
        t.push(24);
        t.extend(b"re\0");
        t.push(28);
        t.extend(b"rs\0");
        t.push(38);
        while t.len() < 24 {
            t.push(0xEE);
        }
        t.extend([0x02, 0x00, 0x20, 0x00]); // @24 regular
        t.extend([0x08, 0x08, 0x02]); // @28 reexport
        t.extend(b"_orig\0");
        t.push(0x00);
        assert_eq!(t.len(), 38);
        t.extend([0x04, 0x10, 0x30, 0x81, 0x01, 0x00]); // @38 resolver
        let mut file = vec![0xAA; 16];
        file.extend(t);
        file
    }

    #[test]
    fn walks_all_terminal_kinds() {
        let file = sample();
        let nodes = collect(&file, 16, (file.len() - 16) as u32);
        assert_eq!(nodes.len(), 5);
        assert_eq!(
            (nodes[0].at, nodes[0].terminal_size, nodes[0].child_count),
            (0, 0, Some((1, 1)))
        );
        assert_eq!(
            nodes[0].edges,
            [TrieEdge {
                at: 2,
                name: b"_".to_vec(),
                next: 5
            }]
        );
        assert_eq!(nodes[1].prefix, b"_");
        let names: Vec<&[u8]> = nodes[1].edges.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(names, [b"_main".as_slice(), b"_re", b"_rs"]);

        let main = nodes[2].terminal.as_ref().unwrap();
        assert_eq!(
            (main.flags_at, main.flags, main.kind_name()),
            (25, 0, "regular")
        );
        assert_eq!(main.value, Some((26, 0x20, TrieTerminalTail::Address)));
        assert_eq!(nodes[2].child_count, Some((27, 0)));

        let re = nodes[3].terminal.as_ref().unwrap();
        assert_eq!(re.kind_name(), "reexport");
        // The leading '_' of the import name is eaten as a ULEB128.
        assert_eq!(
            re.value,
            Some((
                30,
                2,
                TrieTerminalTail::Reexport {
                    at: 32,
                    name: Some(b"orig".to_vec())
                }
            ))
        );

        let rs = nodes[4].terminal.as_ref().unwrap();
        assert_eq!(rs.kind_name(), "stub_and_resolver");
        assert_eq!(
            rs.value,
            Some((
                40,
                0x30,
                TrieTerminalTail::Resolver {
                    at: 43,
                    resolver: 0x81
                }
            ))
        );
    }

    #[test]
    fn reexport_name_variants() {
        // flags 8, ordinal 1, then nothing left inside the terminal.
        let n = collect(&[0x02, 0x08, 0x01, 0x00], 0, 4);
        assert_eq!(
            n[0].terminal.as_ref().unwrap().value,
            Some((2, 1, TrieTerminalTail::Missing))
        );
        // One byte eaten, then the terminal ends: no terminator.
        let n = collect(&[0x03, 0x08, 0x01, 0x00, 0x00], 0, 5);
        assert_eq!(
            n[0].terminal.as_ref().unwrap().value,
            Some((2, 1, TrieTerminalTail::Reexport { at: 4, name: None }))
        );
        // One byte eaten, then an empty string.
        let n = collect(&[0x04, 0x08, 0x01, b'x', 0x00, 0x00], 0, 6);
        assert_eq!(
            n[0].terminal.as_ref().unwrap().value,
            Some((
                2,
                1,
                TrieTerminalTail::Reexport {
                    at: 4,
                    name: Some(Vec::new())
                }
            ))
        );
    }

    #[test]
    fn thread_local_and_weak_kinds() {
        let t = |flags| {
            TrieTerminal {
                flags_at: 0,
                flags,
                value: None,
            }
            .kind_name()
        };
        assert_eq!(t(1), "thread_local");
        assert_eq!(t(4), "regular");
        assert_eq!(t(9), "reexport");
        assert_eq!(t(0x18), "stub_and_resolver");
    }

    #[test]
    fn cyclic_trie_terminates() {
        // Root -> itself and -> node 6, which points back to both.
        let file = [
            0x00, 0x02, b'a', 0x00, 0x00, b'b', 0x00, 0x09, 0xEE, 0x00, 0x02, b'c', 0x00, 0x00,
            b'd', 0x00, 0x09,
        ];
        let nodes = collect(&file, 0, file.len() as u32);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].prefix, b"b");
        assert_eq!(nodes[1].edges.len(), 2);
    }

    #[test]
    fn truncated_tries() {
        assert!(collect(&[], 0, 0).is_empty());
        // Blob not inside the file.
        assert!(collect(&[0, 0], 0, 3).is_empty());
        assert!(collect(&[0, 0], 5, 1).is_empty());
        // Unterminated terminal size.
        assert!(collect(&[0x80], 0, 1).is_empty());
        // Terminal runs past the end: no terminal, no child count.
        let n = collect(&[0x05, 0x00, 0x01], 0, 3);
        assert_eq!(
            (n.len(), n[0].terminal.is_none(), n[0].child_count),
            (1, true, None)
        );
        // Flags readable but the value crosses the terminal end.
        let n = collect(&[0x01, 0x00, 0x00], 0, 3);
        assert_eq!(
            n[0].terminal,
            Some(TrieTerminal {
                flags_at: 1,
                flags: 0,
                value: None
            })
        );
        assert_eq!(n[0].child_count, Some((2, 0)));
        // Edge label without terminator, then edge without target.
        let n = collect(&[0x00, 0x02, b'a', b'b'], 0, 4);
        assert_eq!((n[0].child_count, n[0].edges.len()), (Some((1, 2)), 0));
        let n = collect(&[0x00, 0x02, b'a', 0x00], 0, 4);
        assert_eq!(n[0].edges.len(), 0);
        // Edge target outside the trie is reported but not followed.
        let n = collect(&[0x00, 0x01, b'a', 0x00, 0x7f], 0, 5);
        assert_eq!((n.len(), n[0].edges[0].next), (1, 0x7f));
    }

    #[test]
    fn wrapping_terminal_size_reads_before_the_trie() {
        // terminal_size = 2^64 - 3: "terminal end" wraps to one byte before
        // the node, where the child count is then read from.
        let mut file = vec![0x00, 0x00, 0x00, 0x00];
        file.extend([0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        file.extend([0x00, 0x00]);
        let n = collect(&file, 4, 12);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].terminal_size, u64::MAX - 2);
        assert!(n[0].terminal.is_none());
        // p = 14, end = 11 (relative 7): child count byte is file[11] = 0xff.
        assert_eq!(n[0].child_count, Some((7, 0xff)));
        // terminal_size = 2^64 - 20 wraps to before the start of the file:
        // nothing to read.
        let mut file = vec![0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        file.extend([0x00, 0x00]);
        let n = collect(&file, 0, 12);
        assert_eq!(
            (n.len(), n[0].terminal_size, n[0].child_count),
            (1, u64::MAX - 19, None)
        );
    }
}
