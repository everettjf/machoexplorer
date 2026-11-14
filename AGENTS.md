# MachOExplorer AGENTS Guide

This guide describes how autonomous contributors should work in this repository safely and effectively.

## Project Snapshot
- App: `MachOExplorer` (Rust, GUI built on GPUI via `gpui-kit` 0.9.1)
- Domain: Mach-O / Fat Mach-O / `.a` archive / dyld shared cache analysis
- Current release line: `v3.0.x`. The version lives in one place: `[workspace.package] version` in the root `Cargo.toml`.
- Platforms: macOS is built, tested and run locally. Windows and Linux builds are wired in CI and in the packaging scripts but are not yet verified by anyone; do not claim they work until someone has built and run them.
- The earlier C++/Qt implementation (last release `v2.0.17`) is gone from the tree. No Qt, CMake or system Capstone is needed; Capstone is compiled from the source bundled in the `capstone` crate.

## Repository Layout
- `Cargo.toml`, `Cargo.lock`: Cargo workspace (members below; default members are `moex-core` and `moex-cli`, so a bare `cargo build` does not build the GUI)
- `crates/`:
  - `moex-core/` parser, view-node model, dump / diff / dyld cache tools; no UI dependencies
  - `moex-cli/` binary `moex` with subcommands `parse`, `dump`, `diff`, `cache-list`, `cache-extract`
  - `moex-app/` GPUI desktop app, binary `MachOExplorer`
- `fuzz/`: cargo-fuzz target `parse_dump` (its own workspace, not built by `cargo build`/`cargo test`)
- `tests/`:
  - `regression/` shell regression for the `moex` binary; `run_all.sh` is the entry
  - `golden/` JSON baselines from the last C++ release plus tooling (see `tests/golden/README.md`)
  - `corpus/` checked-in test binaries and their sources (see `tests/corpus/README.md`)
- `sample/`: reproducible sample binaries (`simple`, `complex`)
- `scripts/`:
  - `bundle_macos.sh` builds the binaries and assembles `dist/macos/MachOExplorer.app`
  - `inc_patch_version.sh` patch version bump helper
  - `release_homebrew.sh` Homebrew cask updater
  - `package_linux.sh` Linux tarball
  - `build_windows_installer.ps1` Windows build + stage + Inno Setup installer
  - `build_windows_release.ps1` Windows installer + portable zip + GitHub release upload
- `packaging/`: `macos/MachOExplorer.icns`, `linux/machoexplorer.desktop` + icon, `windows/MachOExplorer.iss` (Inno Setup)
- `deploy.sh`: one-command macOS release pipeline (bump/test/bundle/sign/notarize/tag/release/homebrew)
- `.github/workflows/rust.yml`: CI (macOS / Linux / Windows matrix)
- `docs/`: `release_packaging.md`, `rust-port-quirks.md` (C++ quirks kept for output parity, and intentional differences)

## Build & Run (macOS)
Requirements: a stable Rust toolchain and the Xcode command line tools.

```bash
cargo build --release -p moex-cli      # target/release/moex
cargo build --release -p moex-app      # target/release/MachOExplorer
./target/release/moex dump sample/simple
./target/release/MachOExplorer sample/simple
```

During development, `cargo run -p moex-app -- sample/simple` runs a debug build of the GUI.

## Tests (required before/after meaningful changes)
```bash
cargo test --workspace
cargo build --release -p moex-cli
tests/regression/run_all.sh
```

- `cargo test --workspace` runs the unit tests, the golden comparison against the C++ baselines (`crates/moex-core/tests/golden.rs`), the malformed-input robustness tests (`crates/moex-core/tests/robustness.rs`) and the GUI tests (`crates/moex-app/tests/ui.rs`, headless windows).
- `tests/regression/run_all.sh` drives the release `moex` binary (`target/release/moex`, override with `MOEX_BIN`).
- The golden test requires the Rust JSON dump to equal the baselines exactly. If a change alters dump output on purpose, read `tests/golden/README.md` and `docs/rust-port-quirks.md` first.

## Release Workflows

### Patch bump only
```bash
scripts/inc_patch_version.sh
```
Bumps the workspace version in `Cargo.toml`, refreshes `Cargo.lock`, updates the version strings in `README.md` / `README.zh-CN.md`, and prints the new version.

### Homebrew cask update
- Dry run:
```bash
scripts/release_homebrew.sh --version <x.y.z> --dry-run
```
- Real push (requires DMG):
```bash
scripts/release_homebrew.sh --version <x.y.z> --dmg /path/to/MachOExplorer.dmg
```
Always pass `--version`.

### Full deploy pipeline
```bash
./deploy.sh
```
Requires a clean working tree. Default behavior:
1. bump patch
2. run `cargo test --workspace --locked`
3. build `moex` and run `tests/regression/run_all.sh`
4. build the universal (arm64 + x86_64) `.app` with `scripts/bundle_macos.sh --universal`
5. sign `.app` with `Developer ID Application`
6. package `.dmg`
7. notarize `.dmg` + staple
8. commit + push
9. tag + push tag
10. GitHub release upload
11. Homebrew cask update

macOS release env:
- `CODE_SIGN_IDENTITY`
- `NOTARYTOOL_PROFILE` preferred, or `APPLE_ID` + `APPLE_TEAM_ID` + `APPLE_APP_SPECIFIC_PASSWORD`

Flags:
- `--no-bump` (release the version already in `Cargo.toml`)
- `--host-arch-only` (skip the universal build)
- `--no-homebrew`
- `--no-release`
- `--no-tag`
- `--no-push`

Do not run `deploy.sh` unless explicitly asked: it signs, pushes to `master`, tags and publishes.

## Windows Packaging Guidance
Not yet verified: these scripts have not been run on a Windows machine since the Rust rewrite.

- Installer tool for classic Next/Next/Finish: **Inno Setup 6**
- Build helper:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_windows_installer.ps1
```
- Build + upload to an existing GitHub release:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_windows_release.ps1
```
- The installer helper needs `cargo` (MSVC toolchain) and finds `ISCC` on `PATH` or in the default Inno Setup 6 install directory (`-ISCCPath` overrides). It links the C runtime statically (`-C target-feature=+crt-static`), so no MSVC runtime DLLs are staged.

## Linux Packaging Guidance
Not yet verified: the script has not been run on a Linux machine.

```bash
scripts/package_linux.sh
```
Produces `dist/linux/MachOExplorer-<version>-linux-<arch>.tar.gz`. Build dependencies are listed at the top of the script.

## Coding Expectations
- Preserve existing code style and architecture boundaries:
  - parser logic in `crates/moex-core`
  - UI logic in `crates/moex-app`
  - command-line argument handling in `crates/moex-cli`
- `moex-core` must stay free of UI dependencies.
- Avoid broad formatting-only churn.
- Keep changes scoped and reversible.
- Add/adjust regression coverage for parser hardening changes when possible (a robustness or golden case, or an input in `tests/regression/run_crash_regression.sh`).
- Behaviour kept only for output parity with the C++ implementation is marked `QUIRK(parity)` in the code and listed in `docs/rust-port-quirks.md`; update that file when such behaviour changes.

## Safety Rules
- Do not use destructive git commands (`reset --hard`, forced checkout) unless explicitly requested.
- Do not revert unrelated local changes.
- If unexpected external modifications appear, pause and confirm before continuing.

## Quick QA Checklist for PRs
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `tests/regression/run_all.sh` passes
- [ ] Relevant docs updated (`README*`, `CLI*`, packaging notes, this file when workflow changes)
- [ ] No unrelated refactors included
