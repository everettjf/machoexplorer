//! Text and JSON export of a view tree (`moex dump`).
//!
//! The JSON layout is a published format (`schemaVersion` 1.1); keep it
//! stable. Keys are emitted in sorted order.

use crate::error::{Error, Result};
use crate::hex::as_short_hex_string;
use crate::view::{Table, ViewNode};
use serde_json::{json, Map, Value};
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

fn table_to_json(table: &Table, o: &DumpOptions) -> Value {
    let mut j = Map::new();
    if o.include_headers() {
        j.insert("headers".into(), json!(table.headers));
    }
    let total = table.rows.len();
    let limit = row_limit(o, total);
    j.insert("totalRows".into(), json!(total));
    j.insert("tableMode".into(), json!(o.table_mode));
    if !o.include_rows() {
        j.insert("shownRows".into(), json!(0));
        return Value::Object(j);
    }
    j.insert("shownRows".into(), json!(limit));
    let rows: Vec<Value> = table
        .rows
        .iter()
        .take(limit)
        .enumerate()
        .map(|(i, row)| {
            let mut r = Map::new();
            r.insert("rowIndex".into(), json!(i));
            r.insert("values".into(), json!(row.cells));
            let mut cells = Map::new();
            for (col, cell) in row.cells.iter().enumerate() {
                let key = table
                    .headers
                    .get(col)
                    .cloned()
                    .unwrap_or_else(|| format!("column{col}"));
                cells.insert(key, json!(cell));
            }
            r.insert("cells".into(), Value::Object(cells));
            if row.size > 0 {
                r.insert("byteLength".into(), json!(row.size));
            }
            Value::Object(r)
        })
        .collect();
    j.insert("rows".into(), Value::Array(rows));
    if limit < total {
        j.insert("truncated".into(), json!(true));
    }
    Value::Object(j)
}

fn node_to_json(
    node: &ViewNode,
    o: &DumpOptions,
    depth: usize,
    path: &[String],
    child_index: usize,
) -> Value {
    let mut j = Map::new();
    j.insert("name".into(), json!(node.name()));
    j.insert("depth".into(), json!(depth));
    j.insert("path".into(), json!(path.join("/")));
    j.insert("kind".into(), json!(kind(node)));
    j.insert("childIndex".into(), json!(child_index));
    if let Some(table) = rows_of(node) {
        j.insert("table".into(), table_to_json(table, o));
    }
    if let Some(b) = node.binary() {
        j.insert(
            "binary".into(),
            json!({ "size": b.size, "startValue": b.start_value }),
        );
    }
    let mut children = Vec::new();
    if o.depth_allows_children(depth) {
        for (i, child) in node.children().iter().enumerate() {
            if !should_appear(child, o, depth + 1) {
                continue;
            }
            let mut child_path = path.to_vec();
            child_path.push(child.name().to_string());
            children.push(node_to_json(child, o, depth + 1, &child_path, i));
        }
    }
    j.insert("children".into(), Value::Array(children));
    Value::Object(j)
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
        let payload = json!({
            "schemaVersion": options.format_version,
            "generator": "MachOExplorer CLI",
            "format": "viewnode-json",
            "file": file_label,
            "options": {
                "includeEmptyNodes": options.include_empty_nodes,
                "maxRowsPerTable": options.max_rows_per_table,
                "maxDepth": options.max_depth,
                "rootPath": options.root_path,
                "nameFilter": options.name_filter,
                "tableMode": options.table_mode,
            },
            "summary": {
                "nodes": summary.nodes,
                "tableNodes": summary.table_nodes,
                "binaryNodes": summary.binary_nodes,
                "totalRows": summary.total_rows,
            },
            "analysis": node_to_json(&root, options, 0, &root_path_segments, 0),
        });
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
