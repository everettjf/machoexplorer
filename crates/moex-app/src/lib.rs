//! MachOExplorer desktop GUI (GPUI).
//!
//! UI-independent logic lives in plain modules (`settings`, `update`, `hex`,
//! `vscroll`, `table_model`, `tree_model`, `attach`, `cache_extract`); the
//! GPUI views (`window`, `tree_panel`, `table_panel`, `hex_view`, ...) stay
//! thin on top of them.

pub mod app;
pub mod attach;
#[cfg(target_os = "macos")]
mod attach_macos;
pub mod cache_extract;
pub mod hex;
pub mod hex_view;
pub mod log_panel;
pub mod menus;
pub mod modal;
pub mod scrollbar;
pub mod settings;
pub mod start_screen;
pub mod table_model;
pub mod table_panel;
pub mod theme;
pub mod tree_model;
pub mod tree_panel;
pub mod update;
pub mod util;
pub mod vscroll;
pub mod window;
