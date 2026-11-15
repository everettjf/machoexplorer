//! Export trie decoder, shared by the classic `LC_DYLD_INFO` export info
//! and `LC_DYLD_EXPORTS_TRIE` (the two hold the same structure).
//!
//! A node is `uleb128 terminal_size`, `terminal_size` bytes of terminal
//! payload, a one-byte child count and, per child, a NUL-terminated edge
//! label followed by the `uleb128` offset of the child node from the start
//! of the trie. The terminal payload is `uleb128 flags` followed by
//!
//! * re-export (`EXPORT_SYMBOL_FLAGS_REEXPORT`): `uleb128` dylib ordinal and
//!   the NUL-terminated name to import (empty: same name as the export);
//! * stub and resolver (`EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`): `uleb128`
//!   stub offset and `uleb128` resolver offset;
//! * anything else: `uleb128` offset of the symbol from the image base.
//!
//! All positions are byte offsets from the start of the trie, and nothing
//! is read outside it.

use super::dyld_info::{
    EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, EXPORT_SYMBOL_FLAGS_KIND_MASK,
    EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, EXPORT_SYMBOL_FLAGS_REEXPORT,
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, MAX_TRIE_EDGES,
    MAX_TRIE_NODES,
};
use crate::leb::read_uleb128;
use std::collections::{HashSet, VecDeque};

/// Upper bound on the bytes of symbol names one walk hands out (each node
/// and edge repeats its whole prefix). Only crafted, deeply chained tries
/// get near it; the walk stops there.
pub const MAX_TRIE_NAME_BYTES: usize = 256 << 20;

/// A ULEB128 value and where it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrieValue {
    pub at: u64,
    /// Encoded size in bytes.
    pub size: u64,
    pub value: u64,
}

/// What a terminal's payload holds after the flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieTerminalKind {
    /// Regular, thread-local or absolute symbol: its offset from the image
    /// base (an absolute address for the absolute kind).
    Address(TrieValue),
    /// Re-export from the dylib with this ordinal. `name` is the symbol to
    /// import: empty when it is the export's own name, `None` when it is
    /// not terminated inside the terminal.
    Reexport {
        ordinal: TrieValue,
        name_at: u64,
        name: Option<Vec<u8>>,
    },
    /// Stub and resolver function offsets from the image base.
    Resolver {
        stub: TrieValue,
        resolver: TrieValue,
    },
    /// The payload ends before the values its flags call for.
    Truncated,
}

/// The terminal payload of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieTerminal {
    pub flags: TrieValue,
    pub kind: TrieTerminalKind,
}

/// `regular`, `thread_local`, `absolute`, `reexport` or
/// `stub_and_resolver`, with `, weak_def` appended for weak definitions.
pub fn export_kind_name(flags: u64) -> String {
    let mut kind = match flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
        EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => "thread_local",
        EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => "absolute",
        _ => "regular",
    };
    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        kind = "reexport";
    } else if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        kind = "stub_and_resolver";
    }
    if flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0 {
        format!("{kind}, weak_def")
    } else {
        kind.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieEdge {
    /// Position of the edge label.
    pub at: u64,
    /// Bytes the edge occupies: label, terminator and child offset.
    pub size: u64,
    /// Node prefix plus the edge label.
    pub name: Vec<u8>,
    /// Offset of the child node from the start of the trie.
    pub next: u64,
}

/// One visited node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieNode {
    pub at: u64,
    /// Symbol name accumulated on the way to this node (raw bytes).
    pub prefix: Vec<u8>,
    pub terminal_size: TrieValue,
    /// Present when `terminal_size > 0` and the payload lies in the trie.
    pub terminal: Option<TrieTerminal>,
    /// Position and value of the child count; `None` when the terminal
    /// payload runs to or past the end of the trie.
    pub child_count: Option<(u64, u8)>,
    pub edges: Vec<TrieEdge>,
}

/// ULEB128 at `pos`, reading no further than `limit`.
fn uleb(trie: &[u8], pos: u64, limit: u64) -> Option<TrieValue> {
    let bytes = trie.get(usize::try_from(pos).ok()?..usize::try_from(limit).ok()?)?;
    let (value, used) = read_uleb128(bytes)?;
    Some(TrieValue {
        at: pos,
        size: used as u64,
        value,
    })
}

/// Bytes of the NUL-terminated string at `pos`, searching no further than
/// `limit`.
fn cstr(trie: &[u8], pos: u64, limit: u64) -> Option<&[u8]> {
    let bytes = trie.get(usize::try_from(pos).ok()?..usize::try_from(limit).ok()?)?;
    let len = bytes.iter().position(|&c| c == 0)?;
    bytes.get(..len)
}

/// Decode the terminal payload `trie[start..end]`. `None` when not even
/// the flags can be read.
fn terminal(trie: &[u8], start: u64, end: u64) -> Option<TrieTerminal> {
    let flags = uleb(trie, start, end)?;
    let first = uleb(trie, flags.at + flags.size, end);
    let kind = match first {
        None => TrieTerminalKind::Truncated,
        Some(first) => {
            let after = first.at + first.size;
            if flags.value & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
                TrieTerminalKind::Reexport {
                    ordinal: first,
                    name_at: after,
                    name: cstr(trie, after, end).map(<[u8]>::to_vec),
                }
            } else if flags.value & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                match uleb(trie, after, end) {
                    Some(resolver) => TrieTerminalKind::Resolver {
                        stub: first,
                        resolver,
                    },
                    None => TrieTerminalKind::Truncated,
                }
            } else {
                TrieTerminalKind::Address(first)
            }
        }
    };
    Some(TrieTerminal { flags, kind })
}

/// Walk `trie` breadth-first from its root at offset 0, calling `visit`
/// for every node. Each node is visited once however many edges lead to
/// it; edges that point outside the trie are reported but not followed.
pub fn walk_exports_trie(trie: &[u8], mut visit: impl FnMut(&TrieNode)) {
    let len = trie.len() as u64;
    let mut work: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut name_bytes = 0usize;
    let mut edges = 0usize;
    work.push_back((0, Vec::new()));
    let mut guard = 0usize;
    while guard < MAX_TRIE_NODES && name_bytes <= MAX_TRIE_NAME_BYTES && edges <= MAX_TRIE_EDGES {
        let Some((pos, prefix)) = work.pop_front() else {
            break;
        };
        guard += 1;
        if pos >= len || !visited.insert(pos) {
            continue;
        }
        let Some(terminal_size) = uleb(trie, pos, len) else {
            continue;
        };
        name_bytes = name_bytes.saturating_add(prefix.len().saturating_mul(4));
        let mut node = TrieNode {
            at: pos,
            prefix,
            terminal_size,
            terminal: None,
            child_count: None,
            edges: Vec::new(),
        };
        let payload = pos + terminal_size.size;
        // A terminal that does not fit in the trie ends the node: there is
        // nowhere to read its children from.
        let Some(children) = payload
            .checked_add(terminal_size.value)
            .filter(|&end| end < len)
        else {
            visit(&node);
            continue;
        };
        if terminal_size.value > 0 {
            node.terminal = terminal(trie, payload, children);
        }
        let Some(&child_count) = usize::try_from(children).ok().and_then(|i| trie.get(i)) else {
            visit(&node);
            continue;
        };
        node.child_count = Some((children, child_count));
        let mut cur = children + 1;
        for _ in 0..child_count {
            let Some(label) = cstr(trie, cur, len) else {
                break;
            };
            let Some(next) = uleb(trie, cur + label.len() as u64 + 1, len) else {
                break;
            };
            let mut name = Vec::with_capacity(node.prefix.len().saturating_add(label.len()));
            name.extend_from_slice(&node.prefix);
            name.extend_from_slice(label);
            name_bytes = name_bytes.saturating_add(name.len().saturating_mul(2));
            if next.value < len {
                work.push_back((next.value, name.clone()));
            }
            let end = next.at + next.size;
            node.edges.push(TrieEdge {
                at: cur,
                size: end - cur,
                name,
                next: next.value,
            });
            cur = end;
        }
        edges = edges.saturating_add(node.edges.len());
        visit(&node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(trie: &[u8]) -> Vec<TrieNode> {
        let mut out = Vec::new();
        walk_exports_trie(trie, |n| out.push(n.clone()));
        out
    }

    fn value(at: u64, size: u64, value: u64) -> TrieValue {
        TrieValue { at, size, value }
    }

    /// A trie with a regular symbol `_main`, a re-export `_re` (ordinal 2,
    /// import `_orig`) and a resolver `_rs`.
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
        t
    }

    #[test]
    fn walks_all_terminal_kinds() {
        let nodes = collect(&sample());
        assert_eq!(nodes.len(), 5);
        assert_eq!(
            (
                nodes[0].at,
                nodes[0].terminal_size.value,
                nodes[0].child_count
            ),
            (0, 0, Some((1, 1)))
        );
        assert_eq!(
            nodes[0].edges,
            [TrieEdge {
                at: 2,
                size: 3,
                name: b"_".to_vec(),
                next: 5
            }]
        );
        assert_eq!(nodes[1].prefix, b"_");
        let names: Vec<&[u8]> = nodes[1].edges.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(names, [b"_main".as_slice(), b"_re", b"_rs"]);

        assert_eq!(
            nodes[2].terminal,
            Some(TrieTerminal {
                flags: value(25, 1, 0),
                kind: TrieTerminalKind::Address(value(26, 1, 0x20)),
            })
        );
        assert_eq!(nodes[2].child_count, Some((27, 0)));

        // The import name follows the ordinal directly, leading '_' included.
        assert_eq!(
            nodes[3].terminal,
            Some(TrieTerminal {
                flags: value(29, 1, 8),
                kind: TrieTerminalKind::Reexport {
                    ordinal: value(30, 1, 2),
                    name_at: 31,
                    name: Some(b"_orig".to_vec()),
                },
            })
        );
        assert_eq!(nodes[3].child_count, Some((37, 0)));

        assert_eq!(
            nodes[4].terminal,
            Some(TrieTerminal {
                flags: value(39, 1, 0x10),
                kind: TrieTerminalKind::Resolver {
                    stub: value(40, 1, 0x30),
                    resolver: value(41, 2, 0x81),
                },
            })
        );
    }

    #[test]
    fn terminal_size_is_a_uleb128() {
        // Terminal of 0x82 bytes (two-byte size): flags 0, address 5, then
        // padding; the child count sits after the whole payload.
        let mut t = vec![0x82, 0x01, 0x00, 0x05];
        t.resize(2 + 0x82, 0xEE);
        t.extend([0x01, b'x', 0x00, 0x00]);
        let n = collect(&t);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].terminal_size, value(0, 2, 0x82));
        assert_eq!(
            n[0].terminal.as_ref().unwrap().kind,
            TrieTerminalKind::Address(value(3, 1, 5))
        );
        assert_eq!(n[0].child_count, Some((0x84, 1)));
        assert_eq!(n[0].edges[0].name, b"x");
    }

    #[test]
    fn reexport_name_variants() {
        // flags 8, ordinal 1, then nothing left inside the terminal.
        let n = collect(&[0x02, 0x08, 0x01, 0x00]);
        assert_eq!(
            n[0].terminal.as_ref().unwrap().kind,
            TrieTerminalKind::Reexport {
                ordinal: value(2, 1, 1),
                name_at: 3,
                name: None
            }
        );
        // An empty name: re-exported under the same name.
        let n = collect(&[0x03, 0x08, 0x01, 0x00, 0x00]);
        assert_eq!(
            n[0].terminal.as_ref().unwrap().kind,
            TrieTerminalKind::Reexport {
                ordinal: value(2, 1, 1),
                name_at: 3,
                name: Some(Vec::new())
            }
        );
        // The name may not run past the terminal.
        let n = collect(&[0x03, 0x08, 0x01, b'x', 0x00, 0x00]);
        assert!(matches!(
            n[0].terminal.as_ref().unwrap().kind,
            TrieTerminalKind::Reexport { name: None, .. }
        ));
    }

    #[test]
    fn kind_names() {
        assert_eq!(export_kind_name(0), "regular");
        assert_eq!(export_kind_name(1), "thread_local");
        assert_eq!(export_kind_name(2), "absolute");
        assert_eq!(export_kind_name(4), "regular, weak_def");
        assert_eq!(export_kind_name(8), "reexport");
        assert_eq!(export_kind_name(0x0c), "reexport, weak_def");
        assert_eq!(export_kind_name(0x10), "stub_and_resolver");
    }

    #[test]
    fn cyclic_trie_terminates() {
        // Root -> itself and -> node 9, which points back to both.
        let trie = [
            0x00, 0x02, b'a', 0x00, 0x00, b'b', 0x00, 0x09, 0xEE, 0x00, 0x02, b'c', 0x00, 0x00,
            b'd', 0x00, 0x09,
        ];
        let nodes = collect(&trie);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].prefix, b"b");
        assert_eq!(nodes[1].edges.len(), 2);
    }

    #[test]
    fn truncated_tries() {
        assert!(collect(&[]).is_empty());
        // Unterminated terminal size.
        assert!(collect(&[0x80]).is_empty());
        // Terminal runs past the end: no terminal, no child count.
        let n = collect(&[0x05, 0x00, 0x01]);
        assert_eq!(
            (n.len(), n[0].terminal.is_none(), n[0].child_count),
            (1, true, None)
        );
        // A terminal size that would wrap around is rejected the same way.
        let mut huge = vec![0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        huge.extend([0x00, 0x00]);
        let n = collect(&huge);
        assert_eq!(
            (n.len(), n[0].terminal_size.value, n[0].child_count),
            (1, u64::MAX - 2, None)
        );
        // Flags readable but no value inside the terminal.
        let n = collect(&[0x01, 0x00, 0x00]);
        assert_eq!(
            n[0].terminal,
            Some(TrieTerminal {
                flags: value(1, 1, 0),
                kind: TrieTerminalKind::Truncated
            })
        );
        assert_eq!(n[0].child_count, Some((2, 0)));
        // Resolver without its second value.
        let n = collect(&[0x02, 0x10, 0x04, 0x00]);
        assert_eq!(
            n[0].terminal.as_ref().unwrap().kind,
            TrieTerminalKind::Truncated
        );
        // Edge label without terminator, then edge without target.
        let n = collect(&[0x00, 0x02, b'a', b'b']);
        assert_eq!((n[0].child_count, n[0].edges.len()), (Some((1, 2)), 0));
        let n = collect(&[0x00, 0x02, b'a', 0x00]);
        assert_eq!(n[0].edges.len(), 0);
        // Edge target outside the trie is reported but not followed.
        let n = collect(&[0x00, 0x01, b'a', 0x00, 0x7f]);
        assert_eq!((n.len(), n[0].edges[0].next), (1, 0x7f));
    }

    #[test]
    fn overlapping_nodes_are_capped() {
        // Every byte is a node with 0x41 children labelled "A..."; the walk
        // must stay bounded.
        let mut t = vec![0x00];
        for i in 0..4000u32 {
            t.extend([0x00, 0x41, 0x00, (i % 100) as u8]);
        }
        let mut nodes = 0usize;
        let mut edges = 0usize;
        walk_exports_trie(&t, |n| {
            nodes += 1;
            edges += n.edges.len();
        });
        assert!(nodes <= MAX_TRIE_NODES);
        assert!(edges <= MAX_TRIE_EDGES + 255);
    }
}
