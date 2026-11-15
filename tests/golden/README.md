# Golden baselines

Snapshots of the analysis output. `baseline/<name>.json.gz` is the JSON dump
(`--format json --include-empty`, timestamps in UTC) of one corpus file:
`sample/simple`, `sample/complex` and every file in `tests/corpus/bin` (see
[tests/corpus/README.md](../corpus/README.md)). The baseline name is the file
name of the binary.

The baselines and the corpus are marked `binary` in `.gitattributes` so they
are byte-exact on every platform.

## The golden test

```bash
cargo test -p moex-core --test golden -- --nocapture
```

It is part of `cargo test --workspace`
(`crates/moex-core/tests/golden.rs`). For each entry of its `CASES` table it
dumps the file in process and requires the result to equal the baseline
exactly: every node's name, path, kind, byte range, table headers and rows,
and the top-level summary. On a mismatch it reports up to 20 differences per
file, each with the node path and the first differing row.

## Changing the output on purpose

The baselines say what the output was, not that it was right. When a change
alters the output:

1. check the new output against an independent tool for the format in
   question (`otool`, `dyld_info`, `nm`, `lipo`, `dwarfdump`, `ar`);
2. regenerate:
   ```bash
   MOEX_UPDATE_BASELINES=1 cargo test -p moex-core --test golden
   ```
3. review the diff of the dumps before committing, for example
   `git diff --text` with a `gzip -dc` textconv, or by dumping the file with
   the old and the new `moex` and diffing the two.

Baselines are written on macOS. Add a new corpus file to `CASES` and run the
same command to create its baseline.

## Platform-gated cases

C++ names are demangled by the platform's C++ runtime on macOS and Linux and
by the `cpp_demangle` crate on Windows, and the text can differ, so:

| Case | Compared on |
| --- | --- |
| `cxx_arm64` | macOS |
| `dyld_chained_x86_64.dylib`, `dyld_classic_x86_64.dylib` | macOS, Linux |
| `complex` | macOS, Linux (Capstone built with MSVC prints one negative 32-bit immediate differently) |

Everything else, including the Swift cases, is compared on every platform.
