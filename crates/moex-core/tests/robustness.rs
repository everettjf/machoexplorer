//! Malformed-input robustness: truncated and mutated corpus files must never
//! panic, hang or overflow — a clean `Err` or a partial tree is fine.
//!
//! Mutations are deterministic (fixed seed) so failures are reproducible.
//! `MOEX_ROBUSTNESS_ITERS` raises the number of mutants per file.

use moex_core::dump::{dump_tree, DumpOptions};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let root = repo_root();
    let mut files = vec![root.join("sample/simple")];
    let mut bins: Vec<PathBuf> = std::fs::read_dir(root.join("tests/corpus/bin"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    bins.sort();
    files.extend(bins);
    files
        .into_iter()
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect()
}

/// xorshift64*: small deterministic PRNG, no dependency needed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Parse and walk the whole tree, forcing every lazy table.
fn exercise(data: Vec<u8>) {
    let Ok(root) = moex_core::open_bytes(data) else {
        return;
    };
    let options = DumpOptions {
        json_output: true,
        include_empty_nodes: true,
        ..Default::default()
    };
    let mut sink = std::io::sink();
    dump_tree(&root, "mutant", &options, &mut sink).unwrap();
}

fn iters() -> usize {
    std::env::var("MOEX_ROBUSTNESS_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24)
}

#[test]
fn garbage_is_rejected() {
    assert!(moex_core::open_bytes(Vec::new()).is_err());
    assert!(moex_core::open_bytes(vec![0; 3]).is_err());
    assert!(moex_core::open_bytes(b"not a mach-o file at all".to_vec()).is_err());
    // Bare magics with nothing behind them.
    for magic in [
        0xfeedfaceu32,
        0xfeedfacf,
        0xcafebabe,
        0xcafebabf,
        0xcefaedfe,
        0xcffaedfe,
        0xbebafeca,
        0xbfbafeca,
    ] {
        exercise(magic.to_le_bytes().to_vec());
        let mut padded = magic.to_le_bytes().to_vec();
        padded.extend(std::iter::repeat(0xff).take(64));
        exercise(padded);
    }
    exercise(b"!<arch>\n".to_vec());
    exercise(b"dyld_v1  arm64e\0\0\0\0\0\0\0\0".to_vec());
}

#[test]
fn truncated_files_do_not_panic() {
    for (name, data) in corpus() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ data.len() as u64);
        // Header-area cuts are the interesting ones; add random cuts beyond.
        let mut cuts: Vec<usize> = (1..64.min(data.len())).step_by(3).collect();
        cuts.extend((0..iters()).map(|_| rng.below(data.len())));
        for cut in cuts {
            eprintln!("truncate {name} at {cut}");
            exercise(data[..cut].to_vec());
        }
    }
}

#[test]
fn mutated_files_do_not_panic() {
    for (name, data) in corpus() {
        let mut rng = Rng(0xD1B5_4A32_D192_ED03 ^ data.len() as u64);
        for i in 0..iters() {
            let mut m = data.clone();
            // Bias towards the first 4 KiB (headers, load commands).
            let span = if i % 3 == 0 {
                m.len()
            } else {
                m.len().min(4096)
            };
            let flips = 1 + rng.below(8);
            let mut log = Vec::new();
            for _ in 0..flips {
                let pos = rng.below(span);
                let val = match rng.below(4) {
                    0 => 0x00,
                    1 => 0xff,
                    2 => 0x7f,
                    _ => rng.next() as u8,
                };
                m[pos] = val;
                log.push((pos, val));
            }
            eprintln!("mutate {name} #{i}: {log:?}");
            exercise(m);
        }
    }
}

#[test]
fn every_32bit_field_extreme_in_load_commands() {
    // Overwrite each aligned u32 in the first 2 KiB with extreme values.
    for (name, data) in corpus() {
        if data.len() > 64 * 1024 || data.len() < 64 {
            continue; // keep runtime bounded; small files cover the same code
        }
        for off in (0..data.len().min(2048) - 4).step_by(4) {
            for val in [0u32, 1, 0x7fff_ffff, 0xffff_ffff] {
                let mut m = data.clone();
                m[off..off + 4].copy_from_slice(&val.to_le_bytes());
                eprintln!("field {name} @{off} = {val:#x}");
                exercise(m);
            }
        }
    }
}
