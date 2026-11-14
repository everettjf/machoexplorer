# Regression scripts

Shell-level regression for the `moex` command-line tool. The scripts run the
built binary, so they also cover argument parsing, exit codes and output
files, which the Rust tests in `cargo test` do not.

For the other test layers (unit tests, golden comparison, robustness, GUI
tests) see [DEVELOP.md](../../DEVELOP.md) and
[tests/golden/README.md](../golden/README.md).

## Run

Build the CLI first:

```bash
cargo build --release -p moex-cli
```

Run all regression checks:

```bash
tests/regression/run_all.sh
```

The scripts test `target/release/moex`. Set `MOEX_BIN` to test another
binary:

```bash
MOEX_BIN=/path/to/moex tests/regression/run_all.sh
```

If the binary is missing, the scripts exit with code `2`.

The scripts need `bash` and standard Unix tools. CI runs them on macOS and
Linux, not on Windows.

## Scripts

| Script | What it checks |
| --- | --- |
| `run_all.sh [cache]` | Runs the four scripts below in order. The optional argument is passed to the cache tools smoke test. |
| `run_regression.sh` | Every file listed in `cases.txt` must parse with `moex parse`. |
| `run_cli_smoke.sh` | `moex dump`: text and JSON output, `--output`, `--name-filter`, `--table-mode`, rejection of directories and `.app` bundles, exit codes `2` (usage) and `1` (analysis failure), a fat binary. |
| `run_cache_tools_smoke.sh [cache]` | `moex cache-list` and `moex cache-extract` against a small synthetic cache built by the script, then against a real dyld shared cache if one is found. |
| `run_crash_regression.sh` | Malformed-input crash regression, see below. |
| `common.sh` | Shared helpers (binary lookup, synthetic input builders). Sourced, not executed. |

Run one on its own:

```bash
tests/regression/run_regression.sh
tests/regression/run_cli_smoke.sh
tests/regression/run_cache_tools_smoke.sh
tests/regression/run_crash_regression.sh
```

### Cache tools smoke test

The synthetic part runs everywhere. For the real-cache part the script looks
for a main cache file in
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld` (macOS); if none
is found it reports `passed (synthetic only; ...)`. To choose a cache:

```bash
tests/regression/run_cache_tools_smoke.sh /path/to/dyld_shared_cache_arm64e
```

### Malformed-input crash regression

`run_crash_regression.sh` generates malformed inputs in a temporary directory:

- hand-built seeds: empty file, bare magics, broken archives, dyld cache headers with hostile counts and ranges, a cache with a hostile sibling `.map` file;
- single-field corruptions of a well-formed synthetic dyld cache;
- every file in `sample/` and `tests/corpus/bin`, truncated at 10, 30, 60, 75, 90 and 99 percent.

It runs `parse`, `dump` (text and JSON), `diff`, `cache-list` and
`cache-extract` on each input. Accepting an input (exit `0`) and rejecting it
(exit `1`) are both fine. A Rust panic (exit `101`) or a signal/abort
(exit `>= 128`) fails the run. A few well-formed inputs must parse
successfully.

## Add New Cases

- Parser regression: add the path of a file, relative to the repository root, to `cases.txt`. The repository ships the seed cases from `sample/`.
- Crash regression: add a generator for the new input to `run_crash_regression.sh`, next to the existing seeds. Keep inputs small and built by the script so nothing binary has to be checked in.
- A binary that should also be covered by the golden and robustness tests goes into `tests/corpus/bin`; see [tests/corpus/README.md](../corpus/README.md).
