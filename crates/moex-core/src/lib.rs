//! moex-core: Mach-O / Fat / archive / dyld shared cache parsing and the
//! view-node model (tree of named nodes, each with an optional table and an
//! optional byte range) shared by the CLI and the GUI.
//!
//! This crate has no UI dependencies.

pub mod cache_tools;
pub mod consts;
pub mod demangle;
pub mod diff;
pub mod dump;
pub mod error;
pub mod hex;
pub mod image;
pub mod leb;
pub mod macho;
pub mod names;
pub mod view;
pub mod views;

pub use error::{Error, Result};
pub use image::Image;
pub use view::{BinaryRange, Row, Table, ViewNode};

use std::path::Path;
use std::sync::Arc;

/// An opened file: its bytes and the root of its view tree.
#[derive(Clone)]
pub struct Document {
    pub image: Arc<Image>,
    pub root: ViewNode,
}

impl Document {
    /// Map and parse `path`. Only the top-level structure is parsed here;
    /// node tables are built lazily on first access.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let image = Arc::new(Image::open(path.as_ref())?);
        // The path lets a dyld shared cache find its sibling `.map` file.
        let binary = Arc::new(macho::Binary::parse_with_path(
            image.clone(),
            Some(path.as_ref()),
        )?);
        Ok(Document {
            image,
            root: views::file::file_node(binary),
        })
    }

    /// Parse an in-memory buffer (used by tests and fuzzing).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        Self::from_image(Arc::new(Image::from_vec(data)?))
    }

    fn from_image(image: Arc<Image>) -> Result<Self> {
        let binary = Arc::new(macho::Binary::parse(image.clone())?);
        Ok(Document {
            image,
            root: views::file::file_node(binary),
        })
    }
}

/// Parse `path` and return the root of its view tree.
pub fn open(path: impl AsRef<Path>) -> Result<ViewNode> {
    Document::open(path).map(|d| d.root)
}

/// Parse an in-memory buffer and return the root of its view tree.
pub fn open_bytes(data: Vec<u8>) -> Result<ViewNode> {
    Document::from_bytes(data).map(|d| d.root)
}
