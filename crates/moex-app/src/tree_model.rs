//! Layout tree logic: which nodes are visible given expansion state and the
//! filter, next-match navigation and go-to-offset. No UI types.
//!
//! `ViewNode::children()` (and `table()`) are computed lazily by the core and
//! can be slow, so this model never calls them for a node unless that node
//! was reported as *loaded* (its content and children were already built on
//! a background thread, see [`load_node`] / [`load_subtree`]).

use crate::table_model::contains_ci;
use moex_core::ViewNode;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expandable {
    /// Children not computed yet; shown with a disclosure arrow.
    Unknown,
    Yes,
    No,
}

#[derive(Clone)]
pub struct TreeRow {
    pub node: ViewNode,
    pub depth: usize,
    pub expandable: Expandable,
    pub expanded: bool,
    /// Direct filter match (as opposed to an ancestor kept for context).
    pub matched: bool,
}

#[derive(Default)]
pub struct TreeModel {
    root: Option<ViewNode>,
    expanded: HashSet<usize>,
    loaded: HashSet<usize>,
    filter: String,
    rows: Vec<TreeRow>,
}

/// Qt expanded the tree to depth 1 (2 for fat files) after opening.
pub fn default_expand_depth(root: &ViewNode, root_loaded: bool) -> usize {
    let fat = root_loaded
        && root
            .children()
            .iter()
            .any(|c| c.name().starts_with("Fat Header"));
    if fat {
        2
    } else {
        1
    }
}

impl TreeModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_root(&mut self, root: Option<ViewNode>) {
        self.root = root;
        self.expanded.clear();
        self.loaded.clear();
        self.filter.clear();
        self.rebuild();
    }

    pub fn root(&self) -> Option<&ViewNode> {
        self.root.as_ref()
    }

    pub fn rows(&self) -> &[TreeRow] {
        &self.rows
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn has_filter(&self) -> bool {
        !self.filter.is_empty()
    }

    pub fn is_loaded(&self, id: usize) -> bool {
        self.loaded.contains(&id)
    }

    pub fn is_expanded(&self, id: usize) -> bool {
        self.expanded.contains(&id)
    }

    /// Record nodes whose content/children were built off-thread.
    pub fn mark_loaded(&mut self, ids: impl IntoIterator<Item = usize>) {
        self.loaded.extend(ids);
    }

    pub fn set_expanded(&mut self, id: usize, expanded: bool) {
        if expanded {
            self.expanded.insert(id);
        } else {
            self.expanded.remove(&id);
        }
    }

    /// Expand every loaded node down to `depth` (root is depth 0), collapse
    /// everything else.
    pub fn expand_to_depth(&mut self, depth: usize) {
        self.expanded.clear();
        fn walk(m: &mut TreeModel, node: &ViewNode, d: usize, depth: usize) {
            if d > depth || !m.loaded.contains(&node.id()) {
                return;
            }
            m.expanded.insert(node.id());
            for c in node.children() {
                walk(m, c, d + 1, depth);
            }
        }
        if let Some(root) = self.root.clone() {
            walk(self, &root, 0, depth);
        }
    }

    pub fn set_filter(&mut self, text: &str) {
        self.filter = text.to_lowercase();
    }

    /// Direct match: by name, or by any cell of an already built table.
    pub fn node_matches(&self, node: &ViewNode) -> bool {
        if self.filter.is_empty() {
            return false;
        }
        if contains_ci(node.name(), &self.filter) {
            return true;
        }
        if self.loaded.contains(&node.id()) {
            if let Some(t) = node.table() {
                return t
                    .rows
                    .iter()
                    .any(|r| r.cells.iter().any(|c| contains_ci(c, &self.filter)));
            }
        }
        false
    }

    fn expandable(&self, node: &ViewNode) -> Expandable {
        if !self.loaded.contains(&node.id()) {
            Expandable::Unknown
        } else if node.children().is_empty() {
            Expandable::No
        } else {
            Expandable::Yes
        }
    }

    /// Recompute the visible rows. Call after any state change.
    pub fn rebuild(&mut self) {
        let mut rows = Vec::new();
        if let Some(root) = self.root.clone() {
            if self.filter.is_empty() {
                self.push_plain(&root, 0, &mut rows);
            } else {
                self.push_filtered(&root, 0, &mut rows);
            }
        }
        self.rows = rows;
    }

    fn push_plain(&self, node: &ViewNode, depth: usize, rows: &mut Vec<TreeRow>) {
        let expandable = self.expandable(node);
        let expanded = expandable == Expandable::Yes && self.expanded.contains(&node.id());
        rows.push(TreeRow {
            node: node.clone(),
            depth,
            expandable,
            expanded,
            matched: false,
        });
        if expanded && depth < 256 {
            for c in node.children() {
                self.push_plain(c, depth + 1, rows);
            }
        }
    }

    /// Keeps matching nodes and all their ancestors; kept branches are shown
    /// expanded. Returns whether `node` (or a descendant) was kept.
    fn push_filtered(&self, node: &ViewNode, depth: usize, rows: &mut Vec<TreeRow>) -> bool {
        let matched = self.node_matches(node);
        let at = rows.len();
        rows.push(TreeRow {
            node: node.clone(),
            depth,
            expandable: Expandable::No,
            expanded: false,
            matched,
        });
        let mut any_child = false;
        if self.loaded.contains(&node.id()) && depth < 256 {
            for c in node.children() {
                any_child |= self.push_filtered(c, depth + 1, rows);
            }
        }
        if !matched && !any_child {
            rows.truncate(at);
            return false;
        }
        rows[at].expandable = if any_child {
            Expandable::Yes
        } else {
            Expandable::No
        };
        rows[at].expanded = any_child;
        true
    }

    pub fn index_of(&self, id: usize) -> Option<usize> {
        self.rows.iter().position(|r| r.node.id() == id)
    }

    pub fn parent_index(&self, index: usize) -> Option<usize> {
        let depth = self.rows.get(index)?.depth;
        if depth == 0 {
            return None;
        }
        (0..index).rev().find(|i| self.rows[*i].depth == depth - 1)
    }

    /// Row of the first direct match after `current` (wrapping), as Enter in
    /// the Qt search box did.
    pub fn next_match(&self, current: Option<usize>) -> Option<usize> {
        let matches: Vec<usize> = (0..self.rows.len())
            .filter(|i| self.rows[*i].matched)
            .collect();
        if matches.is_empty() {
            return None;
        }
        let next = match current.and_then(|c| matches.iter().position(|m| *m == c)) {
            Some(i) => (i + 1) % matches.len(),
            None => 0,
        };
        Some(matches[next])
    }

    /// Expand the loaded ancestors of `id` so it becomes visible.
    pub fn reveal(&mut self, id: usize) -> bool {
        let Some(root) = self.root.clone() else {
            return false;
        };
        let mut path = Vec::new();
        if !self.find_path(&root, id, &mut path) {
            return false;
        }
        for ancestor in &path[..path.len() - 1] {
            self.expanded.insert(*ancestor);
        }
        true
    }

    fn find_path(&self, node: &ViewNode, id: usize, path: &mut Vec<usize>) -> bool {
        path.push(node.id());
        if node.id() == id {
            return true;
        }
        if self.loaded.contains(&node.id()) && path.len() < 256 {
            for c in node.children() {
                if self.find_path(c, id, path) {
                    return true;
                }
            }
        }
        path.pop();
        false
    }

    /// Most specific loaded node whose byte range contains file `offset`.
    pub fn node_containing_offset(&self, offset: u64) -> Option<ViewNode> {
        let root = self.root.as_ref()?;
        let mut budget = 200_000usize;
        self.containing(root, offset, &mut budget).map(|(n, _)| n)
    }

    fn containing(
        &self,
        node: &ViewNode,
        offset: u64,
        budget: &mut usize,
    ) -> Option<(ViewNode, u64)> {
        if *budget == 0 || !self.loaded.contains(&node.id()) {
            return None;
        }
        *budget -= 1;
        let mut best: Option<(ViewNode, u64)> = None;
        if let Some(b) = node.binary() {
            if b.size > 0 && offset >= b.offset && offset - b.offset < b.size {
                best = Some((node.clone(), b.size));
            }
        }
        for c in node.children() {
            if let Some((hit, size)) = self.containing(c, offset, budget) {
                if best.as_ref().map(|(_, s)| size <= *s).unwrap_or(true) {
                    best = Some((hit, size));
                }
            }
        }
        best
    }
}

/// `0x4000`, `4000h`-less hex or decimal: base auto-detected from the `0x`
/// prefix, falling back to hex for bare digits that are not decimal.
pub fn parse_offset(text: &str) -> Option<u64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    t.parse::<u64>()
        .ok()
        .or_else(|| u64::from_str_radix(t, 16).ok())
}

/// Build one node's content and children. Blocking; call off the UI thread.
pub fn load_node(node: &ViewNode) -> usize {
    let _ = node.table();
    let _ = node.children();
    node.id()
}

/// Limits for background tree walks.
pub struct LoadBudget<'a> {
    pub max_nodes: usize,
    pub deadline: Option<Instant>,
    pub cancel: &'a AtomicBool,
}

impl LoadBudget<'_> {
    fn exhausted(&self, done: usize) -> bool {
        done >= self.max_nodes
            || self.cancel.load(Ordering::Relaxed)
            || self.deadline.map(|d| Instant::now() >= d).unwrap_or(false)
    }
}

/// Breadth-first: build `root` and its descendants down to `max_depth`
/// levels below it, within `budget`. Returns the ids of the nodes built.
/// Blocking; call off the UI thread.
pub fn load_subtree(root: &ViewNode, max_depth: usize, budget: &LoadBudget) -> Vec<usize> {
    let mut done = Vec::new();
    let mut level = vec![root.clone()];
    for depth in 0..=max_depth {
        let mut next = Vec::new();
        for node in &level {
            if budget.exhausted(done.len()) {
                return done;
            }
            done.push(load_node(node));
            if depth < max_depth {
                next.extend(node.children().iter().cloned());
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }
    done
}

pub fn deadline_in(ms: u64) -> Option<Instant> {
    Some(Instant::now() + Duration::from_millis(ms))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use moex_core::view::{Content, FnNode};
    use moex_core::Table;

    pub(crate) fn node(
        name: &str,
        cells: &[&str],
        range: Option<(u64, u64)>,
        children: Vec<ViewNode>,
    ) -> ViewNode {
        let cells: Vec<String> = cells.iter().map(|s| s.to_string()).collect();
        ViewNode::new(FnNode {
            name: name.to_string(),
            content: move || {
                let mut t = Table::new();
                for c in &cells {
                    t.add(["", "", c.as_str()]);
                }
                let c = Content::table(t);
                match range {
                    Some((o, s)) => c.with_binary(o, s),
                    None => c,
                }
            },
            children: move || children.clone(),
        })
    }

    pub(crate) fn sample() -> ViewNode {
        node(
            "File",
            &[],
            Some((0, 1000)),
            vec![node(
                "Mach Header (x86_64)",
                &["MH_MAGIC_64"],
                Some((0, 500)),
                vec![
                    node(
                        "Load Commands",
                        &[],
                        Some((32, 200)),
                        vec![
                            node(
                                "LC_SEGMENT_64 (__TEXT)",
                                &["__TEXT"],
                                Some((32, 72)),
                                vec![],
                            ),
                            node("LC_MAIN", &["entryoff"], Some((104, 24)), vec![]),
                        ],
                    ),
                    node("Symbol Table", &["_main"], Some((300, 100)), vec![]),
                ],
            )],
        )
    }

    fn names(m: &TreeModel) -> Vec<String> {
        m.rows()
            .iter()
            .map(|r| format!("{}{}", "  ".repeat(r.depth), r.node.name()))
            .collect()
    }

    fn load_all(m: &mut TreeModel, root: &ViewNode) {
        let cancel = AtomicBool::new(false);
        let ids = load_subtree(
            root,
            64,
            &LoadBudget {
                max_nodes: usize::MAX,
                deadline: None,
                cancel: &cancel,
            },
        );
        m.mark_loaded(ids);
    }

    #[test]
    fn unloaded_root_shows_single_unknown_row() {
        let root = sample();
        let mut m = TreeModel::new();
        m.set_root(Some(root));
        assert_eq!(names(&m), vec!["File"]);
        assert_eq!(m.rows()[0].expandable, Expandable::Unknown);
        assert!(!m.rows()[0].expanded);
    }

    #[test]
    fn default_expansion_shows_header_children_collapsed() {
        let root = sample();
        let mut m = TreeModel::new();
        m.set_root(Some(root.clone()));
        load_all(&mut m, &root);
        assert_eq!(default_expand_depth(&root, true), 1);
        m.expand_to_depth(1);
        m.rebuild();
        assert_eq!(
            names(&m),
            vec![
                "File",
                "  Mach Header (x86_64)",
                "    Load Commands",
                "    Symbol Table"
            ]
        );
        assert_eq!(m.rows()[2].expandable, Expandable::Yes);
        assert!(!m.rows()[2].expanded);
        assert_eq!(m.rows()[3].expandable, Expandable::No);
        m.set_expanded(m.rows()[2].node.id(), true);
        m.rebuild();
        assert_eq!(names(&m).len(), 6);
        assert_eq!(m.parent_index(4), Some(2));
        assert_eq!(m.parent_index(0), None);
    }

    #[test]
    fn fat_files_expand_one_level_deeper() {
        let root = node(
            "File",
            &[],
            None,
            vec![node("Fat Header", &[], None, vec![])],
        );
        load_node(&root);
        assert_eq!(default_expand_depth(&root, true), 2);
        assert_eq!(default_expand_depth(&root, false), 1);
    }

    #[test]
    fn filter_keeps_matches_and_their_ancestors() {
        let root = sample();
        let mut m = TreeModel::new();
        m.set_root(Some(root.clone()));
        load_all(&mut m, &root);
        m.set_filter("lc_main");
        m.rebuild();
        assert_eq!(
            names(&m),
            vec![
                "File",
                "  Mach Header (x86_64)",
                "    Load Commands",
                "      LC_MAIN"
            ]
        );
        assert_eq!(
            m.rows().iter().map(|r| r.matched).collect::<Vec<_>>(),
            vec![false, false, false, true]
        );
        assert!(m.rows()[2].expanded);

        // Table contents of built nodes are searched too.
        m.set_filter("_MAIN");
        m.rebuild();
        assert_eq!(
            names(&m),
            vec![
                "File",
                "  Mach Header (x86_64)",
                "    Load Commands",
                "      LC_MAIN",
                "    Symbol Table"
            ]
        );

        m.set_filter("no such thing");
        m.rebuild();
        assert!(m.rows().is_empty());

        m.set_filter("");
        m.expand_to_depth(1);
        m.rebuild();
        assert_eq!(names(&m).len(), 4);
    }

    #[test]
    fn filter_does_not_force_unloaded_nodes() {
        let root = sample();
        let mut m = TreeModel::new();
        m.set_root(Some(root.clone()));
        m.mark_loaded([load_node(&root)]);
        m.set_filter("lc_main");
        m.rebuild();
        // Only File and its direct child are known; neither matches.
        assert!(m.rows().is_empty());
        m.set_filter("mach header");
        m.rebuild();
        assert_eq!(names(&m), vec!["File", "  Mach Header (x86_64)"]);
    }

    #[test]
    fn next_match_wraps() {
        let root = sample();
        let mut m = TreeModel::new();
        m.set_root(Some(root.clone()));
        load_all(&mut m, &root);
        m.set_filter("lc_");
        m.rebuild();
        assert_eq!(m.next_match(None), Some(3));
        assert_eq!(m.next_match(Some(3)), Some(4));
        assert_eq!(m.next_match(Some(4)), Some(3));
        assert_eq!(m.next_match(Some(0)), Some(3));
        m.set_filter("");
        m.rebuild();
        assert_eq!(m.next_match(None), None);
    }

    #[test]
    fn goto_offset_picks_smallest_containing_node() {
        let root = sample();
        let mut m = TreeModel::new();
        m.set_root(Some(root.clone()));
        load_all(&mut m, &root);
        assert_eq!(m.node_containing_offset(110).unwrap().name(), "LC_MAIN");
        assert_eq!(
            m.node_containing_offset(350).unwrap().name(),
            "Symbol Table"
        );
        assert_eq!(
            m.node_containing_offset(450).unwrap().name(),
            "Mach Header (x86_64)"
        );
        assert_eq!(m.node_containing_offset(999).unwrap().name(), "File");
        assert!(m.node_containing_offset(1000).is_none());
        let target = m.node_containing_offset(110).unwrap();
        m.rebuild();
        assert!(m.index_of(target.id()).is_none());
        assert!(m.reveal(target.id()));
        m.rebuild();
        assert_eq!(m.index_of(target.id()), Some(4));
    }

    #[test]
    fn offsets_parse_like_qt() {
        assert_eq!(parse_offset("0x4000"), Some(0x4000));
        assert_eq!(parse_offset(" 4096 "), Some(4096));
        assert_eq!(parse_offset("ff"), Some(255));
        assert_eq!(parse_offset("0Xff"), Some(255));
        assert_eq!(parse_offset(""), None);
        assert_eq!(parse_offset("xyz"), None);
    }

    #[test]
    fn load_subtree_respects_depth_and_budget() {
        let root = sample();
        let cancel = AtomicBool::new(false);
        let b = |n| LoadBudget {
            max_nodes: n,
            deadline: None,
            cancel: &cancel,
        };
        assert_eq!(load_subtree(&root, 0, &b(100)).len(), 1);
        assert_eq!(load_subtree(&root, 1, &b(100)).len(), 2);
        assert_eq!(load_subtree(&root, 64, &b(100)).len(), 6);
        assert_eq!(load_subtree(&root, 64, &b(3)).len(), 3);
        cancel.store(true, Ordering::Relaxed);
        assert!(load_subtree(&root, 64, &b(100)).is_empty());
    }
}
