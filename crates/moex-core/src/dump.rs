//! Text and JSON export of a view tree (`moex dump`).
//!
//! The JSON layout is a published format (`schemaVersion` 1.1); keep it
//! stable. Keys are emitted in sorted order.

use crate::error::{Error, Result};
use crate::hex::as_short_hex_string;
use crate::view::{Row, Table, ViewNode};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::io::Write;

/// Guard against pathologically deep trees.
const MAX_DUMP_DEPTH: usize = 256;

#[derive(Debug, Clone)]
pub struct DumpOptions {
    pub json_output: bool,
    pub include_empty_nodes: bool,
    /// 0 means all rows.
    pub max_rows_per_table: usize,
    /// 0 means unlimited.
    pub max_depth: usize,
    pub format_version: String,
    pub root_path: String,
    pub name_filter: String,
    /// `full`, `headers` or `summary`.
    pub table_mode: String,
}

impl Default for DumpOptions {
    fn default() -> Self {
        DumpOptions {
            json_output: false,
            include_empty_nodes: false,
            max_rows_per_table: 0,
            max_depth: 0,
            format_version: "1.1".into(),
            root_path: String::new(),
            name_filter: String::new(),
            table_mode: "full".into(),
        }
    }
}

impl DumpOptions {
    fn include_rows(&self) -> bool {
        self.table_mode == "full"
    }
    fn include_headers(&self) -> bool {
        self.table_mode == "full" || self.table_mode == "headers"
    }
    fn depth_allows_children(&self, depth: usize) -> bool {
        (self.max_depth == 0 || depth < self.max_depth) && depth < MAX_DUMP_DEPTH
    }
}

fn rows_of(node: &ViewNode) -> Option<&Table> {
    node.table().filter(|t| !t.rows.is_empty())
}

fn has_immediate_content(node: &ViewNode) -> bool {
    rows_of(node).is_some() || node.binary().is_some()
}

fn kind(node: &ViewNode) -> &'static str {
    match (rows_of(node).is_some(), node.binary().is_some()) {
        (true, true) => "table+binary",
        (true, false) => "table",
        (false, true) => "binary",
        (false, false) => "group",
    }
}

fn should_appear(node: &ViewNode, o: &DumpOptions, depth: usize) -> bool {
    let has_content = o.include_empty_nodes || has_immediate_content(node);
    let matches_name = o.name_filter.is_empty() || node.name().contains(&o.name_filter);
    if matches_name && has_content {
        return true;
    }
    if o.max_depth > 0 && depth >= o.max_depth {
        return false;
    }
    node.children()
        .iter()
        .any(|c| should_appear(c, o, depth + 1))
}

fn sanitize_cell(s: &str) -> String {
    s.replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn row_limit(o: &DumpOptions, total: usize) -> usize {
    if o.max_rows_per_table == 0 {
        total
    } else {
        o.max_rows_per_table.min(total)
    }
}

fn dump_node_text(
    node: &ViewNode,
    o: &DumpOptions,
    depth: usize,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if !should_appear(node, o, depth) {
        return Ok(());
    }
    let indent = " ".repeat(depth * 2);
    writeln!(out, "{indent}- {}", node.name())?;

    if let Some(table) = rows_of(node) {
        let total = table.rows.len();
        let limit = row_limit(o, total);
        write!(out, "{indent}  [table headers] ")?;
        if o.include_headers() {
            let headers: Vec<String> = table.headers.iter().map(|h| sanitize_cell(h)).collect();
            write!(out, "{}", headers.join(" | "))?;
        }
        writeln!(out)?;
        if !o.include_rows() {
            writeln!(out, "{indent}  [table summary] total={total}")?;
        } else {
            for (i, row) in table.rows.iter().take(limit).enumerate() {
                let cells: Vec<String> = row.cells.iter().map(|c| sanitize_cell(c)).collect();
                writeln!(out, "{indent}  [row {i}] {}", cells.join(" | "))?;
            }
            if limit < total {
                writeln!(
                    out,
                    "{indent}  [table truncated] shown={limit} total={total}"
                )?;
            }
        }
    }

    if let Some(b) = node.binary() {
        writeln!(
            out,
            "{indent}  [binary] size={} start=0x{}",
            b.size,
            as_short_hex_string(b.start_value)
        )?;
    }

    if !o.depth_allows_children(depth) {
        return Ok(());
    }
    for child in node.children() {
        dump_node_text(child, o, depth + 1, out)?;
    }
    Ok(())
}

// The JSON dump is streamed: each wrapper below serialises one level
// straight from the view tree, so nothing but the tree itself is held in
// memory. Entries are written in sorted key order, which is the order the
// format has always had.

struct TableJson<'a>(&'a Table, &'a DumpOptions);

impl Serialize for TableJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let (table, o) = (self.0, self.1);
        let total = table.rows.len();
        let limit = row_limit(o, total);
        let mut m = ser.serialize_map(None)?;
        if o.include_headers() {
            m.serialize_entry("headers", &table.headers)?;
        }
        if o.include_rows() {
            m.serialize_entry("rows", &RowsJson(table, limit))?;
            m.serialize_entry("shownRows", &limit)?;
        } else {
            m.serialize_entry("shownRows", &0)?;
        }
        m.serialize_entry("tableMode", &o.table_mode)?;
        m.serialize_entry("totalRows", &total)?;
        if o.include_rows() && limit < total {
            m.serialize_entry("truncated", &true)?;
        }
        m.end()
    }
}

struct RowsJson<'a>(&'a Table, usize);

impl Serialize for RowsJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let (table, limit) = (self.0, self.1);
        // Key of every column a row of this table can have.
        let columns = table.rows.iter().take(limit).map(|r| r.cells.len()).max();
        let keys: Vec<String> = (0..columns.unwrap_or(0))
            .map(|col| {
                table
                    .headers
                    .get(col)
                    .cloned()
                    .unwrap_or_else(|| format!("column{col}"))
            })
            .collect();
        let mut seq = ser.serialize_seq(Some(limit))?;
        for (i, row) in table.rows.iter().take(limit).enumerate() {
            seq.serialize_element(&RowJson {
                index: i,
                row,
                keys: &keys,
            })?;
        }
        seq.end()
    }
}

struct RowJson<'a> {
    index: usize,
    row: &'a Row,
    keys: &'a [String],
}

impl Serialize for RowJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(None)?;
        if self.row.size > 0 {
            m.serialize_entry("byteLength", &self.row.size)?;
        }
        m.serialize_entry("cells", &CellsJson(self.row, self.keys))?;
        m.serialize_entry("rowIndex", &self.index)?;
        m.serialize_entry("values", &self.row.cells)?;
        m.end()
    }
}

/// The cells of a row keyed by column header. Columns sharing a header
/// collapse to the last one, as in any JSON object.
struct CellsJson<'a>(&'a Row, &'a [String]);

impl Serialize for CellsJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut entries: Vec<(&str, &String)> = self
            .1
            .iter()
            .map(String::as_str)
            .zip(self.0.cells.iter())
            .collect();
        // Stable, so the last of several equal keys stays last.
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut m = ser.serialize_map(None)?;
        for (i, (key, cell)) in entries.iter().enumerate() {
            if entries.get(i + 1).is_some_and(|next| next.0 == *key) {
                continue;
            }
            m.serialize_entry(key, cell)?;
        }
        m.end()
    }
}

struct BinaryJson(u64, u64);

impl Serialize for BinaryJson {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(Some(2))?;
        m.serialize_entry("size", &self.0)?;
        m.serialize_entry("startValue", &self.1)?;
        m.end()
    }
}

struct NodeJson<'a> {
    node: &'a ViewNode,
    o: &'a DumpOptions,
    depth: usize,
    path: String,
    child_index: usize,
}

impl Serialize for NodeJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let (node, o) = (self.node, self.o);
        let mut m = ser.serialize_map(None)?;
        if let Some(b) = node.binary() {
            m.serialize_entry("binary", &BinaryJson(b.size, b.start_value))?;
        }
        m.serialize_entry("childIndex", &self.child_index)?;
        m.serialize_entry("children", &ChildrenJson(self))?;
        m.serialize_entry("depth", &self.depth)?;
        m.serialize_entry("kind", kind(node))?;
        m.serialize_entry("name", node.name())?;
        m.serialize_entry("path", &self.path)?;
        if let Some(table) = rows_of(node) {
            m.serialize_entry("table", &TableJson(table, o))?;
        }
        m.end()
    }
}

struct ChildrenJson<'a>(&'a NodeJson<'a>);

impl Serialize for ChildrenJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let parent = self.0;
        let o = parent.o;
        let mut seq = ser.serialize_seq(None)?;
        if o.depth_allows_children(parent.depth) {
            for (i, child) in parent.node.children().iter().enumerate() {
                if !should_appear(child, o, parent.depth + 1) {
                    continue;
                }
                seq.serialize_element(&NodeJson {
                    node: child,
                    o,
                    depth: parent.depth + 1,
                    path: format!("{}/{}", parent.path, child.name()),
                    child_index: i,
                })?;
            }
        }
        seq.end()
    }
}

struct OptionsJson<'a>(&'a DumpOptions);

impl Serialize for OptionsJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let o = self.0;
        let mut m = ser.serialize_map(Some(6))?;
        m.serialize_entry("includeEmptyNodes", &o.include_empty_nodes)?;
        m.serialize_entry("maxDepth", &o.max_depth)?;
        m.serialize_entry("maxRowsPerTable", &o.max_rows_per_table)?;
        m.serialize_entry("nameFilter", &o.name_filter)?;
        m.serialize_entry("rootPath", &o.root_path)?;
        m.serialize_entry("tableMode", &o.table_mode)?;
        m.end()
    }
}

struct PayloadJson<'a> {
    root: NodeJson<'a>,
    file: &'a str,
    summary: Summary,
}

impl Serialize for PayloadJson<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(Some(7))?;
        m.serialize_entry("analysis", &self.root)?;
        m.serialize_entry("file", self.file)?;
        m.serialize_entry("format", "viewnode-json")?;
        m.serialize_entry("generator", "MachOExplorer CLI")?;
        m.serialize_entry("options", &OptionsJson(self.root.o))?;
        m.serialize_entry("schemaVersion", &self.root.o.format_version)?;
        m.serialize_entry("summary", &self.summary)?;
        m.end()
    }
}

impl Serialize for Summary {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(Some(4))?;
        m.serialize_entry("binaryNodes", &self.binary_nodes)?;
        m.serialize_entry("nodes", &self.nodes)?;
        m.serialize_entry("tableNodes", &self.table_nodes)?;
        m.serialize_entry("totalRows", &self.total_rows)?;
        m.end()
    }
}

#[derive(Default)]
struct Summary {
    nodes: usize,
    table_nodes: usize,
    binary_nodes: usize,
    total_rows: usize,
}

fn accumulate(node: &ViewNode, o: &DumpOptions, depth: usize, s: &mut Summary) {
    if !should_appear(node, o, depth) {
        return;
    }
    s.nodes += 1;
    if let Some(t) = rows_of(node) {
        s.table_nodes += 1;
        s.total_rows += t.rows.len();
    }
    if node.binary().is_some() {
        s.binary_nodes += 1;
    }
    if !o.depth_allows_children(depth) {
        return;
    }
    for child in node.children() {
        accumulate(child, o, depth + 1, s);
    }
}

fn split_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

fn find_by_path(node: &ViewNode, parts: &[String], index: usize) -> Option<ViewNode> {
    if index >= parts.len() {
        return Some(node.clone());
    }
    if node.name() != parts[index] {
        return None;
    }
    if index + 1 == parts.len() {
        return Some(node.clone());
    }
    node.children()
        .iter()
        .find_map(|c| find_by_path(c, parts, index + 1))
}

/// Dump the tree rooted at `root`. `file_label` is echoed in the output.
pub fn dump_tree(
    root: &ViewNode,
    file_label: &str,
    options: &DumpOptions,
    out: &mut dyn Write,
) -> Result<()> {
    let mut root = root.clone();
    let mut root_path_segments = vec![root.name().to_string()];
    if !options.root_path.is_empty() {
        let parts = split_path(&options.root_path);
        if parts.is_empty() {
            return Err(Error::new("root path cannot be empty"));
        }
        root = find_by_path(&root, &parts, 0)
            .ok_or_else(|| Error(format!("root path not found: {}", options.root_path)))?;
        root_path_segments = parts;
    }

    let io = |e: std::io::Error| Error(format!("write failed: {e}"));
    if options.json_output {
        let mut summary = Summary::default();
        accumulate(&root, options, 0, &mut summary);
        let payload = PayloadJson {
            root: NodeJson {
                node: &root,
                o: options,
                depth: 0,
                path: root_path_segments.join("/"),
                child_index: 0,
            },
            file: file_label,
            summary,
        };
        serde_json::to_writer_pretty(&mut *out, &payload)
            .map_err(|e| Error(format!("write failed: {e}")))?;
        writeln!(out).map_err(io)?;
    } else {
        writeln!(out, "file: {file_label}").map_err(io)?;
        if !options.root_path.is_empty() {
            writeln!(out, "root-path: {}", options.root_path).map_err(io)?;
        }
        if !options.name_filter.is_empty() {
            writeln!(out, "name-filter: {}", options.name_filter).map_err(io)?;
        }
        dump_node_text(&root, options, 0, out).map_err(io)?;
    }
    Ok(())
}

/// Parse `filepath` and dump it.
pub fn dump_file(filepath: &str, options: &DumpOptions, out: &mut dyn Write) -> Result<()> {
    let root = crate::open(filepath)?;
    dump_tree(&root, filepath, options, out)
}
