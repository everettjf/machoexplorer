//! Parse arbitrary bytes and walk the entire view tree.
//!
//!   cargo install cargo-fuzz
//!   cargo +nightly fuzz run parse_dump tests/corpus/bin sample -- -max_len=262144
#![no_main]

use libfuzzer_sys::fuzz_target;
use moex_core::dump::{dump_tree, DumpOptions};

fuzz_target!(|data: &[u8]| {
    let Ok(root) = moex_core::open_bytes(data.to_vec()) else { return };
    let options = DumpOptions { json_output: true, include_empty_nodes: true, ..Default::default() };
    let _ = dump_tree(&root, "fuzz", &options, &mut std::io::sink());
});
