# Golden baselines

The Rust implementation replaced a C++ one (last release `v2.0.17`). To keep
the analysis output identical, the JSON dump of the C++ implementation was
recorded for a fixed set of binaries, and the Rust dump is compared against
it on every test run.

## Contents

| Path | What it is |
| --- | --- |
| `baseline/<name>.json.gz` | JSON dump of one corpus file, produced by the C++ oracle `moex-dump` with `--format json --include-empty` and `TZ=UTC`. |
| `make_baseline.sh` | Regenerates every baseline from the oracle. |
| `compare_live.py` | Differential test: runs the oracle and the Rust `moex` on arbitrary files and compares the dumps. |
| `oracle/` | Extra source of the retired C++ oracle (`moex_dump_main.cpp`) and a README on building it against the `v2.0.17` C++ tree. |

The baselines cover `sample/simple`, `sample/complex` and every file in
`tests/corpus/bin` (see [tests/corpus/README.md](../corpus/README.md)). The
baseline name is the file name of the binary.

The baselines and the corpus are marked `binary` in `.gitattributes` so they
are byte-exact on every platform.

## The golden test

```bash
cargo test -p moex-core --test golden -- --nocapture
```

It is part of `cargo test --workspace`. The test is
`crates/moex-core/tests/golden.rs`. For each entry of its `CASES` table it:

1. loads the baseline;
2. dumps the same file in process with `include_empty_nodes` set and timestamps in UTC (`MOEX_TZ=UTC`);
3. compares the two trees node by node: `name`, `path`, `depth`, `kind`, `childIndex`, the `binary` range, the whole `table` (headers, row counts, every row), and the list of children;
4. compares the top-level `summary`, `options`, `schemaVersion`, `generator`, `format` and `file` fields.

Up to 20 differences per file are reported, each with the node path. With
`--nocapture` the test prints a line such as:

```
golden: 26 files, 1369 nodes compared, 0 pending (100.0% ported)
```

### `PENDING` and `MOEX_GOLDEN_PORTED`

`PENDING` in `golden.rs` is a list of view-node display names whose subtrees
are skipped. It was used while the port was in progress and is now empty, so
the comparison is exact. While `PENDING` is not empty the test is not strict:
`childIndex` and the top-level fields of step 4 are not compared.

`MOEX_GOLDEN_PORTED` is a comma-separated list of node names to treat as
ported even though they are still in `PENDING`, to check a node before
removing its entry:

```bash
MOEX_GOLDEN_PORTED="Symbol Table,String Table" cargo test -p moex-core --test golden
```

With an empty `PENDING` the variable has no effect.

### Pointer-table normalisation

In the nodes `Literal Pointers`, `Module Init Func Pointers` and
`Module Term Func Pointers`, the C++ tool printed each value as
`<address of the entry in its own process>-><value>`. That address changes
on every run. The Rust code prints the entry's file offset instead. Before
comparing these nodes, both sides have the text up to and including `->`
removed from the `Value` cell, so only the pointer value is compared.
`compare_live.py` applies the same rule.

### Platform-gated cases

Four cases are compared on macOS only and skipped elsewhere:

| Case | Reason |
| --- | --- |
| `cxx_arm64` | Demangled C++ names come from the system `libc++abi` on macOS and from the `cpp_demangle` crate elsewhere; only the former matches the baseline text exactly. |
| `swift_arm64`, `sw_arm64`, `sw_x86_64` | Swift names are demangled by `xcrun swift-demangle`, which exists on macOS only. |

Windows and Linux runs of this test are wired in CI but not yet verified.

## When the test fails

A difference means the Rust dump no longer matches the C++ output. Either:

- the change is a regression: fix the code; or
- the change is intentional: the baseline cannot simply be regenerated from the oracle, because the oracle would still produce the old output. Record the difference in [docs/rust-port-quirks.md](../../docs/rust-port-quirks.md) and handle it in the test the way the pointer tables are handled, or replace the affected baseline deliberately and say so in the change.

`docs/rust-port-quirks.md` lists the C++ behaviours kept on purpose for
parity and the existing intentional differences.

## Regenerating baselines with the oracle

Needed only when a binary is added to the corpus. It requires the C++ oracle
`moex-dump`, which is no longer part of the build; see `oracle/README.md` for
how to build it from the `v2.0.17` tree.

```bash
MOEX_ORACLE=/path/to/moex-dump tests/golden/make_baseline.sh
```

- Without `MOEX_ORACLE` the script expects the oracle at `build/moex-dump`.
- It regenerates the baseline of `sample/simple`, `sample/complex` and every file in `tests/corpus/bin`, with `TZ=UTC` and paths relative to the repository root, so the `file` field is stable.
- If the oracle fails on a file, its stderr is kept as `baseline/<name>.err` and `[fail]` is printed.
- Review the diff: baselines of existing files should not change, apart from the pointer-table addresses described above, which differ on every oracle run.

After adding a binary, add it to `CASES` in
`crates/moex-core/tests/golden.rs`.

## Differential testing on other files

```bash
cargo build --release -p moex-cli
MOEX_ORACLE=/path/to/moex-dump tests/golden/compare_live.py [--limit N] [--max-size BYTES] PATH...
```

`PATH` may be files or directories (scanned non-recursively). Only files that
start with a Mach-O, fat or archive magic and are at most `--max-size` bytes
(default 6 MiB) are compared. The script uses `target/release/moex`
(`MOEX_BIN` overrides) and exits with `1` on any difference. Files on which
the oracle itself crashes are counted separately and only checked for a
crash on the Rust side.
