# MachOExplorer CLI Guide

This document covers `moex`, the MachOExplorer command-line tool.

## Overview
`moex` is a single binary with five subcommands:

| Subcommand | Purpose |
| --- | --- |
| `moex dump` | Export the full analysis tree as text or JSON |
| `moex parse` | Check that files parse |
| `moex diff` | Compare two Mach-O files |
| `moex cache-list` | List the images of a dyld shared cache |
| `moex cache-extract` | Extract images from a dyld shared cache |

It is built from `crates/moex-cli` and uses the same parser and view-node tree
(`crates/moex-core`) as the desktop app. It needs no display.

```bash
moex --help
moex --version
moex <subcommand> --help
```

### Getting the binary
- Build it: `cargo build --release -p moex-cli` produces `target/release/moex`.
- The macOS app bundle contains it at `MachOExplorer.app/Contents/MacOS/moex`.

The examples below assume `moex` is on `PATH`; from a source checkout use
`./target/release/moex`.

## Migrating from 2.x
MachOExplorer 2.x had a `--cli` mode in the GUI binary and separate `moex-*`
tools. In 3.x they are subcommands:

| 2.x | 3.x |
| --- | --- |
| `MachOExplorer --cli [options] <file>` | `moex dump [options] <file>` |
| `moex-parse <file>...` | `moex parse <file>...` |
| `moex-diff <fileA> <fileB>` | `moex diff <fileA> <fileB>` |
| `moex-cache-list [options] <cache> [filter]` | `moex cache-list [options] <cache> [filter]` |
| `moex-cache-extract [options] <cache> <image> <out>` | `moex cache-extract [options] <cache> <image> <out>` |

What stays the same:
- `moex dump` takes the options that `--cli` mode took (`--format`, `--output`, `--max-rows`, `--max-depth`, `--root-path`, `--name-filter`, `--table-mode`, `--include-empty`), and the exit codes are the same.
- `moex diff`, `moex cache-list` and `moex cache-extract` keep the argument syntax of the old tools: options first, in `--flag` or `--key=value` form, then the positional arguments. Error messages keep their old prefixes (`moex-diff failed:`, `moex-cache-list failed:`, `moex-cache-extract failed:`).
- The JSON dump format is unchanged (`schemaVersion` `1.1`). The Rust dump is tested against the output of the last C++ release for every file in the test corpus.

What is gone:
- The `MachOExplorer` binary no longer accepts `--cli`; it is the GUI only. The `--cli` flag itself is not accepted by `moex dump` either.
- There are no `moex-parse`, `moex-diff`, `moex-cache-list` or `moex-cache-extract` binaries.

Intentional differences in behaviour (for example, a non-numeric `--limit=`
value is now a usage error instead of a crash) are listed in
[docs/analysis-notes.md](docs/analysis-notes.md).

## `moex dump`

```bash
moex dump [options] <file>
```

Runs the full analysis of one file and writes the view-node tree.

### Options

- `--format text|json`
  Output format. Default: `text`.
- `--output <path>`
  Write output to file (instead of stdout).
- `--max-rows <N>`
  Limit rows printed per table. `0` means unlimited (default).
- `--max-depth <N>`
  Limit analysis tree depth. `0` means unlimited (default).
- `--root-path <path>`
  Dump only the matching node subtree, for example `File/Mach Header (x86_64)`.
- `--name-filter <text>`
  Keep only nodes whose names match the text.
- `--table-mode full|headers|summary`
  Table export mode: full rows, headers only, or row counts only. Default: `full`.
- `--include-empty`
  Include nodes with no table/binary payload.
- `-h`, `--help`
  Show help.

Options may be written as `--name value` or `--name=value` and may appear
before or after the file.

### Output behavior

- `stdout` is used by default.
- `stderr` is used for errors and invalid arguments.
- JSON is pretty-printed.
- The JSON top level has `schemaVersion`, `generator`, `format`, `file`, `options`, `summary` and `analysis`.
- Each node has `name`, `path`, `depth`, `kind`, `childIndex` and `children`, plus `table` and/or `binary` when present. Table rows have `rowIndex`, `cells` (by header) and `values` (by position).
- String values are sanitized to valid UTF-8.
- Output is buffered: if the analysis fails, nothing is written.
- Timestamps are formatted in local time. Set `MOEX_TZ=UTC` for reproducible output.

### Exit codes

- `0`: success
- `1`: analysis/runtime failure (parse failure, output file cannot be written, etc.)
- `2`: invalid arguments

### What is included

`moex dump` traverses the full view tree and includes every analysis node the
desktop app shows, for example:

- File kind summary (Mach-O / Fat / Archive / dyld shared cache)
- Mach header and load command views
- Section and section-derived views (including disassembly)
- Symbol/string-related views
- Dynamic loader info views (including dyld exports trie and chained fixups views when present)
- Objective-C and Swift views
- Code signature, integrity report and xref report
- Dyld shared cache top-level views (mappings/images)

UI-only interactions (filtering, copying, CSV export) are not part of the
dump; the underlying data is.

### Examples

#### Human-readable output to terminal

```bash
moex dump sample/simple
```

#### JSON output to terminal

```bash
moex dump --format json sample/simple
```

#### JSON output to file

```bash
moex dump --format json --output simple-analysis.json sample/simple
```

#### Large file with output limits

```bash
moex dump --max-rows 100 --max-depth 4 sample/complex
```

#### Include empty nodes for schema-like traversal

```bash
moex dump --format json --include-empty sample/simple
```

#### Export one subtree

```bash
moex dump --format json --root-path "File/Mach Header (x86_64)" sample/simple
```

#### Keep only matching nodes, with table summaries

```bash
moex dump --format json --name-filter Xref --table-mode summary sample/simple
```

#### Pipe to jq

```bash
moex dump --format json sample/simple | jq '.analysis.name'
```

## `moex parse`

```bash
moex parse <file> [file...]
```

Purpose:

- Quick parser validity check
- Used by regression scripts

Prints one `[ok] <file> headers=<N>` line per file on stdout, or
`[fail] <file> error=<message>` on stderr. Exits with `1` if any file failed.

## `moex diff`

```bash
moex diff <fileA> <fileB>
```

Purpose:

- Compare first Mach-O header attributes (architecture, load command count and size)
- Compare section/symbol set differences (only in A, only in B, common)

Exit codes: `0` success, `1` a file could not be parsed or has no Mach-O
header, `2` wrong number of arguments.

## `moex cache-list`

```bash
moex cache-list [--json] [--exact] [--limit=N] [--output=file] <dyld_shared_cache_file> [path-filter]
```

- `--json`: output a JSON payload
- `--exact`: exact path match (default: substring)
- `--limit=N`: stop after N matches (`0` means unlimited)
- `--output=file`: write output to file instead of stdout

Purpose:

- List dyld shared cache images
- Optional exact/substring filtering

Options must come before the cache path and use the `--key=value` form.
Exit codes: `0` success, `1` the input is not a dyld shared cache or the
output file cannot be opened, `2` usage error.

## `moex cache-extract`

```bash
moex cache-extract [--compact] [--all] [--exact] [--dry-run] [--json] [--max=N] <dyld_shared_cache_file> <image-path-or-substr> <output-macho-or-dir>
```

- `--compact`: rewrite segment file offsets for compact output
- `--all`: extract all matched images into the output directory
- `--exact`: exact path match (default: substring)
- `--dry-run`: print the extraction plan without writing output files
- `--json`: print machine-readable JSON lines
- `--max=N`: max image count processed in `--all` mode (`0` means unlimited)

Purpose:

- Extract one or multiple images from dyld shared cache
- Optional compact rewrite of segment file offsets

Options must come before the cache path. Without `--all` the last argument
is the output file; with `--all` it is a directory and each image is written
as `<image file name>.macho`. Exit codes: `0` success, `1` no image matched
or an extraction failed (in `--all` mode the remaining images are still
processed), `2` usage error.

Images of a split cache live in sub-cache files (`<cache>.01`,
`<cache>.25.dylddata`, ...). Pass the main cache file: the sub-cache files
named in its header are read from the same directory, and each segment is
copied from the file that holds it. A sub-cache file that is missing or
belongs to another cache (different UUID) is skipped; images that need it
fail with exit code `1`. Use `--compact` for split caches: without it each
segment keeps the file offset it has in its own sub-cache file, and segments
from different files can overlap in the output.

## Automation examples

### CLI smoke check

```bash
tests/regression/run_cli_smoke.sh
```

### Full regression

```bash
tests/regression/run_all.sh
```

Both use `target/release/moex`; set `MOEX_BIN` to test another binary.

### Batch analyze samples

```bash
for f in sample/simple sample/complex; do
  moex dump --format json --output "$(basename "$f").json" "$f"
done
```

## Build reminder

```bash
cargo build --release -p moex-cli
```

## Troubleshooting

- Error: `the following required arguments were not provided: <FILE>` or `unexpected argument '...' found`
  Cause: `moex dump` requires exactly one input path.
- Error: `invalid value '...' for '--format <FORMAT>'`
  Cause: only `text` and `json` are supported.
- Error: `analysis failed: ...`
  Cause: parse failed or file is malformed/unsupported for given operation. Directories, including `.app` bundles, are rejected; pass the executable inside the bundle.
- Error: `cannot open output file: ...`
  Cause: invalid path or missing write permission.
- Error: `input is not a dyld shared cache file`
  Cause: `cache-list` / `cache-extract` were given a file that parses but is not a dyld shared cache.
