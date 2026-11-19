# DEVELOP

This document is for contributors and maintainers.

MachOExplorer is a Cargo workspace written in Rust. The GUI uses GPUI through
`gpui-kit` 0.9.1. The earlier C++/Qt implementation (last release `v2.0.17`)
has been removed; Qt, CMake and a system Capstone are no longer needed.

## Platform status
| Platform | Status |
| --- | --- |
| macOS | Built, tested and run locally. Release pipeline is `deploy.sh`. |
| Linux | Built and tested in CI; release tarballs come from `.github/workflows/release-packages.yml`. The desktop app has not yet been run on a real desktop. |
| Windows | Built and tested in CI; the installer and portable zip come from `.github/workflows/release-packages.yml`. The desktop app has not yet been run on a real desktop. |

Platform-specific behaviour:
- Attach by PID (Memory Snapshot) works on macOS only. Attach by PID (Executable Path) is implemented for macOS and Linux.
- C++ symbol demangling uses the C++ runtime (`libc++abi` on macOS, `libstdc++` on Linux) and the `cpp_demangle` crate on Windows, where the text can differ.
- Swift demangling uses Swift's own demangler, bundled as source in `crates/moex-core/vendor/swift` (the subset the `symbolic-demangle` crate ships; see `crates/moex-core/vendor/README.md`) and compiled by `crates/moex-core/build.rs` with `cc`, so a C++ compiler is needed to build. It works on every platform and starts no process. Type sugar is not synthesised (`Swift.Optional<Swift.Int>`, not `Swift.Int?`), and manglings newer than the bundled demangler stay mangled.

## Workspace layout
| Path | Contents |
| --- | --- |
| `crates/moex-core` | Parser, view-node model, dump / diff / dyld cache tools. No UI dependencies. |
| `crates/moex-cli` | Binary `moex`: `parse`, `dump`, `diff`, `cache-list`, `cache-extract`. |
| `crates/moex-app` | GPUI desktop app, binary `MachOExplorer`. |
| `fuzz/` | cargo-fuzz target `parse_dump`. Separate workspace, not built by default. |
| `tests/regression/` | Shell regression for the `moex` binary. |
| `tests/golden/` | Snapshots of the analysis of every corpus file. |
| `tests/corpus/` | Checked-in test binaries and their sources. |
| `sample/` | Sample binaries `simple` and `complex`. |

The default workspace members are `moex-core` and `moex-cli`, so a bare
`cargo build` or `cargo test` at the root skips the GUI. Use `-p moex-app` or
`--workspace` to include it.

The version of every crate comes from `[workspace.package] version` in the
root `Cargo.toml`.

## Prerequisites
- A stable Rust toolchain (CI uses the current stable release).
- A C compiler: the `capstone` crate compiles its bundled Capstone source.
- macOS: Xcode command line tools. A universal build also needs both targets:
  ```bash
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  ```
- Linux (Debian/Ubuntu), for the GUI:
  ```bash
  sudo apt-get install -y build-essential pkg-config clang \
    libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-xcb-dev \
    libxcb1-dev libfontconfig-dev libfreetype-dev libvulkan-dev \
    libasound2-dev libssl-dev
  ```
- Windows: Rust with the MSVC toolchain. Inno Setup 6 for the installer.
- macOS release tooling: `lipo`, `codesign`, `spctl`, `xcrun notarytool`, `hdiutil`, `gh`.

## Build and run
```bash
cargo build --release -p moex-cli      # target/release/moex
cargo build --release -p moex-app      # target/release/MachOExplorer
./target/release/moex dump sample/simple
./target/release/MachOExplorer sample/simple
```

On Windows the binaries are `target\release\moex.exe` and
`target\release\MachOExplorer.exe`.

For a debug build of the GUI:
```bash
cargo run -p moex-app -- sample/simple
```

`MachOExplorer` accepts an optional file name, `-h`/`--help` and
`-v`/`--version`. It has no command-line analysis mode; use `moex` for that
(see [CLI.md](CLI.md)).

To assemble a macOS `.app` bundle without signing it:
```bash
scripts/bundle_macos.sh                # host architecture
scripts/bundle_macos.sh --universal    # arm64 + x86_64
```
The bundle is written to `dist/macos/MachOExplorer.app` and contains both
`MachOExplorer` and `moex` in `Contents/MacOS/`.

## GUI notes
- Menus and key bindings are defined in `crates/moex-app/src/menus.rs`. Shortcuts use Cmd on macOS and Ctrl elsewhere: `N` new window, `W` close window, `O` open file, `Q` quit, `F` focus the table filter.
- Settings (theme, recent files, window and pane sizes, update-check state) are stored as JSON in `<config dir>/MachOExplorer/settings.json`, where `<config dir>` is the platform configuration directory (`~/Library/Application Support` on macOS). Set `MOEX_CONFIG_DIR` to use another directory.
- The update check (`update.rs`) queries the latest GitHub release, reuses a valid response for one hour, and only accepts stable releases of this repository. Set `MOEX_NO_UPDATE_CHECK` to skip the check at startup.
- Debug builds can be driven by `MOEX_DEBUG_*` environment variables; see `debug_drive` in `crates/moex-app/src/app.rs`.

## Tests
Run all of these before and after a meaningful change:

```bash
cargo test --workspace
cargo build --release -p moex-cli
tests/regression/run_all.sh
```

`cargo test --workspace` covers:
- unit tests in all three crates;
- the golden comparison, `crates/moex-core/tests/golden.rs`: the Rust JSON dump of every file in `sample/` and `tests/corpus/bin` must equal the snapshot in `tests/golden/baseline/*.json.gz`. See [tests/golden/README.md](tests/golden/README.md);
- malformed-input robustness, `crates/moex-core/tests/robustness.rs`: truncated and mutated corpus files must not panic. Mutations are deterministic. `MOEX_ROBUSTNESS_ITERS` sets the number of mutants per file (default 24);
- GUI tests, `crates/moex-app/tests/ui.rs`, which open headless windows.

`tests/regression/run_all.sh` exercises the release `moex` binary; see
[tests/regression/README.md](tests/regression/README.md).

To run only the parser and CLI tests (what CI runs on every platform):
```bash
cargo test --release -p moex-core -p moex-cli
```

### Fuzzing
```bash
cargo install cargo-fuzz
cargo +nightly fuzz run parse_dump tests/corpus/bin sample -- -max_len=262144
```

### Analysis notes
[docs/analysis-notes.md](docs/analysis-notes.md) describes how the output
differs from the C++ releases and lists the known limits.

## CI
`.github/workflows/rust.yml` runs on pushes to `master`, on pull requests and
on manual dispatch, on macOS, Ubuntu 24.04 and Windows:
- `core + cli`: release build and tests of `moex-core` and `moex-cli`, then `tests/regression/run_all.sh` (not on Windows);
- `gui`: builds `moex-app` on all three; runs the GUI tests on macOS only.

## Key Scripts
- `scripts/inc_patch_version.sh`: bump the patch version in `Cargo.toml`, refresh `Cargo.lock`, update the README version strings; prints the new version
- `scripts/bundle_macos.sh [--universal] [--version X.Y.Z]`: build and assemble `dist/macos/MachOExplorer.app`
- `deploy.sh`: one-command macOS release pipeline
- `scripts/release_homebrew.sh`: update the Homebrew cask (supports `--dry-run`)
- `scripts/package_linux.sh [--version X.Y.Z]`: Linux tarball
- `scripts/build_windows_installer.ps1`: Windows build, staging and Inno Setup installer
- `scripts/build_windows_release.ps1`: Windows installer + portable zip + GitHub release asset upload

## Packaging
- macOS icon: `packaging/macos/MachOExplorer.icns`
- Linux desktop entry and icon: `packaging/linux/`
- Windows Inno Setup script: `packaging/windows/MachOExplorer.iss`
- Packaging notes: [docs/release_packaging.md](docs/release_packaging.md)

## Full Release (macOS)
```bash
./deploy.sh
```

Optional flags:
- `--no-bump`
- `--host-arch-only`
- `--no-homebrew`
- `--no-release`
- `--no-tag`
- `--no-push`

Steps, required environment variables and the Windows and Linux follow-up
are described in [docs/release_packaging.md](docs/release_packaging.md).

## Coding & PR Checklist
- Keep changes scoped and avoid unrelated refactors.
- Parser logic belongs in `crates/moex-core`, UI logic in `crates/moex-app`.
- Preserve existing style in touched areas.
- Run `cargo test --workspace` and `tests/regression/run_all.sh` before commit.
- Update docs if workflow/behavior changed.
