# MachOExplorer

[Discord](https://discord.gg/eGzEaP6TzR)

Repository: <https://github.com/everettjf/machoexplorer>

> A focused desktop explorer for Mach-O binaries, Fat/Universal binaries, `.a` archives, and the dyld shared cache — built for people who reverse engineer and inspect Apple binaries.

Language: **English** | [简体中文](README.zh-CN.md)

![MachOExplorer Screenshot](image/screenshot.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/everettjf/MachOExplorer/actions/workflows/rust.yml/badge.svg)](https://github.com/everettjf/MachOExplorer/actions/workflows/rust.yml)
[![Latest Release](https://img.shields.io/github/v/release/everettjf/MachOExplorer)](https://github.com/everettjf/MachOExplorer/releases/latest)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%26%20Windows%20(unverified)-lightgrey)](#install)

MachOExplorer turns an opaque Mach-O file into a navigable tree. Open a binary and drill from the
file structure all the way down to load commands, sections, symbols, disassembly, and Apple-specific
metadata (Objective-C, Swift, code signing) — in one window, or fully scripted from the command line.

Current major release: `v3.0.0` ([release page](https://github.com/everettjf/MachOExplorer/releases/tag/v3.0.0)).
Version 3 is a rewrite in Rust with a [GPUI](https://www.gpui.rs/) interface; it replaces the
C++/Qt implementation of the 2.x releases. If you used the 2.x command-line tools, see
[Migrating from 2.x](#migrating-from-2x).

## Contents
- [Features](#features)
- [Supported formats](#supported-formats)
- [Install](#install)
- [Quick start](#quick-start)
- [Command line](#command-line)
- [Migrating from 2.x](#migrating-from-2x)
- [Build from source](#build-from-source)
- [Docs](#docs)
- [Contributing](#contributing)
- [License](#license)

## Features

### Structure & navigation
- Layout tree: file → header → load commands → sections / symbols / link-edit data.
- Search box that filters the layout tree by node name **and** matches the contents of tables you have already opened.
- Go-to-offset box: type a file offset to jump to the node that contains it.
- Hex view stays in sync with the selected node — jump from any table row to the exact bytes.

### Apple binary internals
- Load commands, sections, symbol & string tables, relocations, indirect symbols, function starts, data-in-code.
- **Code signing**: parses the embedded-signature SuperBlob (Code Directory, Requirements, CMS) and decodes the **entitlements** plist.
- **Objective-C** metadata: classes, methods, ivars, properties, and protocols.
- **Swift** semantic graph over the `__swift5_*` sections.
- **dyld info**: rebase / bind / lazy-bind / exports trie and chained-fixups structures.

### Code & cross-references
- [Capstone](https://www.capstone-engine.org/) disassembly of `__TEXT,__text` (arm64, x86_64, arm, i386). Capstone is built in; nothing extra to install.
- Xref report that resolves call / jump targets and ties them back to symbols.

### dyld shared cache
- List images, extract a single image or all of them, and drill straight into an extracted image.

### Productivity & UX
- Parsing runs **off the UI thread**, so opening a large binary or a multi-gigabyte shared cache keeps the window responsive.
- Tables: row filter across all columns, copy cell / row / all visible rows, CSV export, keyboard navigation.
- Open a running process by PID: by its executable path (macOS, Linux) or from a memory snapshot of its main image (macOS only).
- Light and dark themes, or follow the system setting.
- Built-in update check reads stable GitHub Releases over HTTPS. Successful results are cached for one hour; downloads open the matching release in your browser.

### Automation
- The `moex` command-line tool prints the full analysis as text or **stable JSON** — ideal for scripting, diffing, and CI.

### Built for suspicious files
The parser is bounds- and alignment-checked throughout — LEB128 streams, load-command walking,
string tables, and code-signature blobs — and is covered by malformed-input tests that run it
against truncated and mutated binaries, plus a fuzz target. Opening a hostile or corrupted file
is meant to degrade gracefully instead of crashing.

## Supported formats
| Format | Notes |
| --- | --- |
| Mach-O | 32-bit and 64-bit |
| Fat / Universal | Multiple architecture slices |
| Static archive | `.a` with Mach-O members |
| dyld shared cache | List, extract, and inspect images |

## Install

| Platform | Status |
| --- | --- |
| macOS 13 or later (Apple silicon and Intel) | Supported. Signed and notarized releases. |
| Linux | Not yet verified. The build is wired in CI and in `scripts/package_linux.sh`, but nobody has built or run it yet. |
| Windows | Not yet verified. The build is wired in CI and in `scripts/build_windows_installer.ps1`, but nobody has built or run it yet. |

### macOS
- Download the latest release: <https://github.com/everettjf/MachOExplorer/releases/latest>
- Or install via Homebrew:

```bash
brew update && brew tap everettjf/homebrew-tap && brew install --cask machoexplorer
```

The app bundle also contains the command-line tool, at
`MachOExplorer.app/Contents/MacOS/moex`.

### Linux / Windows
Build from source (see [Build from source](#build-from-source)) and please report what you find.

Attaching to a process by memory snapshot is macOS only. Swift symbols are demangled by
Swift's own demangler, built into the tool, on every platform. C++ symbols are demangled by
the system `libc++abi` on macOS and by the `cpp_demangle` crate elsewhere, so demangled text
can differ slightly between platforms.

## Quick start
1. Launch MachOExplorer, or open a file directly: `MachOExplorer <path>`. You can also drop a
   file onto the window.
2. Open a bundled sample (`sample/simple`, `sample/complex`) or your own binary.
3. Walk the **Layout** tree; type in the search box to jump to a section, symbol, or value; select a
   node to see its table and the matching bytes in the hex view.

Keyboard shortcuts (Cmd on macOS, Ctrl elsewhere): `N` new window, `W` close window, `O` open
file, `F` focus the table filter, `Q` quit.

## Command line
The `moex` tool runs the same analysis without the GUI:

```bash
moex dump sample/simple
moex dump --format json --output simple-analysis.json sample/simple
```

| Subcommand | Purpose |
| --- | --- |
| `moex dump [options] <file>` | Export the full analysis tree as text or JSON |
| `moex parse <file>...` | Check that files parse |
| `moex diff <fileA> <fileB>` | Compare header, sections and symbols of two files |
| `moex cache-list ...` | List the images of a dyld shared cache |
| `moex cache-extract ...` | Extract images from a dyld shared cache |

Common `moex dump` options:

| Option | Description |
| --- | --- |
| `--format text\|json` | Output format (default `text`) |
| `--output <path>` | Write analysis output to a file |
| `--max-rows <N>` | Limit rows per table (`0` = unlimited) |
| `--max-depth <N>` | Limit tree depth (`0` = unlimited) |
| `--root-path <path>` | Export only one matching analysis subtree |
| `--name-filter <text>` | Keep nodes whose display names match the text |
| `--table-mode <full\|headers\|summary>` | Control table payload size |
| `--include-empty` | Include empty nodes |

The JSON output is automation-friendly and stable: it includes `schemaVersion`, a `summary`, node
`path` / `kind` / `childIndex`, and row `cells` / `rowIndex`. String values are sanitized to valid
UTF-8 so output stays well-formed even on malformed input. See [CLI.md](CLI.md) for the full guide.

## Migrating from 2.x
The 2.x releases shipped a Qt application with a `--cli` mode and separate `moex-*` tools. They
are now subcommands of one binary:

| 2.x | 3.x |
| --- | --- |
| `MachOExplorer --cli [options] <file>` | `moex dump [options] <file>` |
| `moex-parse <file>...` | `moex parse <file>...` |
| `moex-diff <fileA> <fileB>` | `moex diff <fileA> <fileB>` |
| `moex-cache-list ...` | `moex cache-list ...` |
| `moex-cache-extract ...` | `moex cache-extract ...` |

Options and exit codes are the same, and on the test corpus the JSON dump is checked against the
output of the last C++ release. The few intentional differences are listed in
[docs/rust-port-quirks.md](docs/rust-port-quirks.md). `MachOExplorer --cli` itself no longer
exists: the `MachOExplorer` binary is the GUI only. Details are in
[CLI.md](CLI.md#migrating-from-2x).

## Build from source
Requirements: a stable [Rust](https://www.rust-lang.org/tools/install) toolchain and a C compiler.
Qt, CMake and a system Capstone are no longer needed.

```bash
cargo build --release -p moex-cli      # command-line tool: target/release/moex
cargo build --release -p moex-app      # desktop app:       target/release/MachOExplorer
./target/release/MachOExplorer sample/simple
```

On macOS, `scripts/bundle_macos.sh` assembles `dist/macos/MachOExplorer.app`.

On Debian/Ubuntu the desktop app needs these packages first (not yet verified):

```bash
sudo apt-get install -y build-essential pkg-config clang \
  libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-xcb-dev \
  libxcb1-dev libfontconfig-dev libfreetype-dev libvulkan-dev \
  libasound2-dev libssl-dev
```

On Windows use the MSVC toolchain; the binaries are `target\release\MachOExplorer.exe` and
`target\release\moex.exe` (not yet verified).

See [DEVELOP.md](DEVELOP.md) for the full developer, testing, and release workflow.

## Docs
- Developer guide (build / test / release): [DEVELOP.md](DEVELOP.md)
- CLI guide: [CLI.md](CLI.md)
- Packaging notes: [docs/release_packaging.md](docs/release_packaging.md)
- Differences from the C++ implementation: [docs/rust-port-quirks.md](docs/rust-port-quirks.md)

## Contributing
Issues and pull requests are welcome:
- Project: <https://github.com/everettjf/MachOExplorer>
- Issues: <https://github.com/everettjf/MachOExplorer/issues>

Before opening a PR, please run `cargo test --workspace` and `tests/regression/run_all.sh`.

## License
MIT. See [LICENSE](LICENSE).

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=everettjf/MachOExplorer)](https://star-history.com/#everettjf/MachOExplorer)
