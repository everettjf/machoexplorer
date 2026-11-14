//! View-node model: a lazily built tree. Each node has a display name,
//! children, an optional table and an optional byte range in the file.

use crate::hex::as_address;
use std::sync::{Arc, OnceLock};

/// A byte range of the input file shown in the hex pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryRange {
    /// File offset of the first byte.
    pub offset: u64,
    pub size: u64,
    /// Address label of the first byte (usually equal to `offset`).
    pub start_value: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    pub cells: Vec<String>,
    /// File offset of the bytes this row describes, when they live in the file.
    pub offset: Option<u64>,
    /// Length in bytes of the described field (0 when the row has no data).
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub headers: Vec<String>,
    pub widths: Vec<u32>,
    pub rows: Vec<Row>,
}

impl Default for Table {
    fn default() -> Self {
        Table {
            headers: vec!["Offset".into(), "Description".into(), "Value".into()],
            widths: vec![80, 200, 200],
            rows: Vec::new(),
        }
    }
}

impl Table {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_headers(&mut self, headers: &[&str]) {
        self.headers = headers.iter().map(|s| s.to_string()).collect();
    }

    pub fn set_widths(&mut self, widths: &[u32]) {
        self.widths = widths.to_vec();
    }

    /// Row without backing bytes.
    pub fn add<S: Into<String>>(&mut self, cells: impl IntoIterator<Item = S>) {
        self.rows.push(Row {
            cells: cells.into_iter().map(Into::into).collect(),
            offset: None,
            size: 0,
        });
    }

    /// Row with backing bytes at `offset`.
    pub fn add_data<S: Into<String>>(
        &mut self,
        offset: u64,
        size: u64,
        cells: impl IntoIterator<Item = S>,
    ) {
        self.rows.push(Row {
            cells: cells.into_iter().map(Into::into).collect(),
            offset: Some(offset),
            size,
        });
    }

    /// Row with a byte length but bytes that are not addressable in the file
    /// (for example a decoded copy).
    pub fn add_sized<S: Into<String>>(&mut self, size: u64, cells: impl IntoIterator<Item = S>) {
        self.rows.push(Row {
            cells: cells.into_iter().map(Into::into).collect(),
            offset: None,
            size,
        });
    }

    /// The common `Offset | Description | Value` row for a struct field
    /// located at file offset `offset`.
    pub fn field(&mut self, offset: u64, size: u64, desc: &str, value: impl Into<String>) {
        self.add_data(
            offset,
            size,
            [as_address(offset), desc.to_string(), value.into()],
        );
    }

    pub fn separator(&mut self) {
        self.add(["", "", "", ""]);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Table and byte range of one node.
#[derive(Debug, Clone, Default)]
pub struct Content {
    pub table: Option<Table>,
    pub binary: Option<BinaryRange>,
}

impl Content {
    pub fn table(table: Table) -> Self {
        Content {
            table: Some(table),
            binary: None,
        }
    }

    /// Byte range whose address label differs from its file offset.
    pub fn with_binary_at(mut self, offset: u64, size: u64, start_value: u64) -> Self {
        self.binary = Some(BinaryRange {
            offset,
            size,
            start_value,
        });
        self
    }

    pub fn with_binary(mut self, offset: u64, size: u64) -> Self {
        self.binary = Some(BinaryRange {
            offset,
            size,
            start_value: offset,
        });
        self
    }
}

/// Implemented by each kind of node. `content` and `children` are each called
/// at most once per node and the results cached, `content` first.
pub trait NodeSource: Send + Sync {
    fn name(&self) -> String;
    fn content(&self) -> Content {
        Content::default()
    }
    fn children(&self) -> Vec<ViewNode> {
        Vec::new()
    }
}

struct Inner {
    source: Box<dyn NodeSource>,
    name: OnceLock<String>,
    content: OnceLock<Content>,
    children: OnceLock<Vec<ViewNode>>,
}

/// Cheap-to-clone handle to a node of the view tree.
#[derive(Clone)]
pub struct ViewNode(Arc<Inner>);

impl ViewNode {
    pub fn new(source: impl NodeSource + 'static) -> Self {
        ViewNode(Arc::new(Inner {
            source: Box::new(source),
            name: OnceLock::new(),
            content: OnceLock::new(),
            children: OnceLock::new(),
        }))
    }

    pub fn name(&self) -> &str {
        self.0.name.get_or_init(|| self.0.source.name())
    }

    fn content(&self) -> &Content {
        self.0.content.get_or_init(|| self.0.source.content())
    }

    pub fn table(&self) -> Option<&Table> {
        self.content().table.as_ref()
    }

    pub fn binary(&self) -> Option<BinaryRange> {
        self.content().binary
    }

    pub fn children(&self) -> &[ViewNode] {
        self.content();
        self.0.children.get_or_init(|| self.0.source.children())
    }

    /// Stable identity of this node (for UI selection state).
    pub fn id(&self) -> usize {
        Arc::as_ptr(&self.0) as *const () as usize
    }
}

/// A node defined entirely by closures; convenient for simple nodes.
pub struct FnNode<C, K>
where
    C: Fn() -> Content + Send + Sync,
    K: Fn() -> Vec<ViewNode> + Send + Sync,
{
    pub name: String,
    pub content: C,
    pub children: K,
}

impl<C, K> NodeSource for FnNode<C, K>
where
    C: Fn() -> Content + Send + Sync,
    K: Fn() -> Vec<ViewNode> + Send + Sync,
{
    fn name(&self) -> String {
        self.name.clone()
    }
    fn content(&self) -> Content {
        (self.content)()
    }
    fn children(&self) -> Vec<ViewNode> {
        (self.children)()
    }
}

/// Leaf node built from a content closure.
pub fn leaf(
    name: impl Into<String>,
    content: impl Fn() -> Content + Send + Sync + 'static,
) -> ViewNode {
    ViewNode::new(FnNode {
        name: name.into(),
        content,
        children: Vec::new,
    })
}
