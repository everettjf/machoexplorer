# Release Packaging Notes

The version of every artifact comes from `[workspace.package] version` in the
root `Cargo.toml`. All packaging scripts read it from there unless a version
is passed explicitly.

| Platform | Script | Output | Status |
| --- | --- | --- | --- |
| macOS | `deploy.sh`, `scripts/bundle_macos.sh` | `dist/macos/MachOExplorer.app`, `dist/macos/MachOExplorer.dmg` | Used for releases |
| Windows | `scripts/build_windows_installer.ps1`, `scripts/build_windows_release.ps1` | `dist/windows/installer/MachOExplorer-Setup-<version>.exe`, `dist/windows/MachOExplorer-<version>-windows-x64-portable.zip` | Not yet verified |
| Linux | `scripts/package_linux.sh` | `dist/linux/MachOExplorer-<version>-linux-<arch>.tar.gz` | Not yet verified |

"Not yet verified" means the script exists and matches the Cargo build, but
nobody has run it on that platform yet.

## Version bump

```bash
scripts/inc_patch_version.sh
```

Increments the patch component of the workspace version in `Cargo.toml`,
refreshes `Cargo.lock` (`cargo update --workspace`), and rewrites these
strings in the READMEs:

- ``Current major release: `v<version>` `` in `README.md`
- ``当前发布版本：`v<version>` `` in `README.zh-CN.md`
- `releases/tag/v<version>` links in both

It prints the new version. The version must be a plain `major.minor.patch`.
To change the major or minor version, edit `Cargo.toml` and the README
strings by hand.

## macOS app bundle

```bash
scripts/bundle_macos.sh [--universal] [--version X.Y.Z]
```

- Builds `moex-app` and `moex-cli` in release mode (`--locked`).
- `--universal` builds `aarch64-apple-darwin` and `x86_64-apple-darwin` and merges them with `lipo`. Both rustup targets must be installed:
  ```bash
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  ```
  Without it only the host architecture is built.
- Writes `dist/macos/MachOExplorer.app` with `Contents/MacOS/MachOExplorer`, `Contents/MacOS/moex`, the icon from `packaging/macos/MachOExplorer.icns` and a generated `Info.plist` (bundle id `com.everettjf.machoexplorer`).
- The minimum macOS version is `MACOSX_DEPLOYMENT_TARGET`, default `13.0`.
- The bundle is not signed; `deploy.sh` does that.

## macOS Signed + Notarized Release

```bash
./deploy.sh [--no-bump] [--host-arch-only] [--no-homebrew] [--no-release] [--no-tag] [--no-push]
```

Before doing anything, `deploy.sh` checks that:

- `git`, `cargo`, `lipo`, `hdiutil`, `gh`, `codesign`, `security`, `xcrun` and `spctl` are available;
- the working tree is clean;
- `gh` is authenticated;
- the signing identity is in the keychain;
- notarization credentials are set.

Then it runs:

1. bump the patch version with `scripts/inc_patch_version.sh` (`--no-bump` releases the version already in `Cargo.toml`)
2. `cargo test --workspace --locked`
3. `cargo build --release --locked -p moex-cli` and `tests/regression/run_all.sh`
4. `scripts/bundle_macos.sh --version <version> --universal` (`--host-arch-only` drops `--universal`)
5. sign `Contents/MacOS/moex` and then the `.app` with the Developer ID identity (hardened runtime, timestamp); verify with `codesign --verify` and `spctl --assess`
6. create `dist/macos/MachOExplorer.dmg` with `hdiutil`
7. submit the `.dmg` to Apple notarization and wait
8. staple the notarization ticket and validate it
9. commit `Cargo.toml`, `Cargo.lock`, `README.md` and `README.zh-CN.md` as `release: bump to v<version>` (only when the version was bumped)
10. `git push origin master` (skipped by `--no-push`)
11. create tag `v<version>` and push it (skipped by `--no-tag`; the push also by `--no-push`). An existing tag is an error.
12. create the GitHub release with the `.dmg`, or upload it to the existing release (skipped by `--no-release`)
13. update the Homebrew cask (skipped by `--no-homebrew`)

Required environment variables:

```bash
export CODE_SIGN_IDENTITY="Developer ID Application: <name> (<team-id>)"
export NOTARYTOOL_PROFILE="<keychain-profile>"
```

`CODE_SIGN_IDENTITY` has a default in `deploy.sh`; set it if your identity
differs.

Or use direct Apple credentials instead of `NOTARYTOOL_PROFILE`:

```bash
export APPLE_ID="<apple-id>"
export APPLE_TEAM_ID="<team-id>"
export APPLE_APP_SPECIFIC_PASSWORD="<app-specific-password>"
```

Recommended notarization credential setup:

```bash
xcrun notarytool store-credentials "<profile-name>" \
  --apple-id "<apple-id>" \
  --team-id "<team-id>" \
  --password "<app-specific-password>"
```

Then run:

```bash
NOTARYTOOL_PROFILE="<profile-name>" ./deploy.sh
```

## macOS Homebrew (Cask)

`deploy.sh` calls this as its last step. To run it by hand:

```bash
scripts/release_homebrew.sh --version <x.y.z> --dmg /path/to/MachOExplorer.dmg
```

Test without pushing:

```bash
scripts/release_homebrew.sh --version <x.y.z> --dry-run
```

Always pass `--version`.

Default target tap:

- `everettjf/homebrew-tap` (override with `TAP_REPO`)
- cask path: `Casks/machoexplorer.rb` (override with `CASK_PATH`)

The script clones the tap into `tmp/homebrew-tap`, rewrites the cask with the
version, the `.dmg` URL of release tag `v<version>` (`--tag` overrides) and
the `.dmg` SHA-256, then commits and pushes. The generated cask installs
`MachOExplorer.app` only; the `moex` binary inside the bundle is not linked
onto `PATH`.

## Windows Installer

Not yet verified on a Windows machine.

- Installer tool: **Inno Setup 6**
- Inno Setup script: `packaging/windows/MachOExplorer.iss`
- Build helper: `scripts/build_windows_installer.ps1`
- Release helper: `scripts/build_windows_release.ps1`

Requirements: Rust with the MSVC toolchain, Inno Setup 6, and for the
release helper `gh` authenticated with release upload access.

### Build and installer

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_windows_installer.ps1
```

Parameters: `-Version <x.y.z>`, `-ISCCPath <path to ISCC.exe>`, `-SkipTests`,
`-SkipInstaller`.

Flow:

1. Set `RUSTFLAGS=-C target-feature=+crt-static` so the C runtime is linked statically and no VC++ redistributable is needed.
2. `cargo test --locked -p moex-core -p moex-cli` (skipped by `-SkipTests`).
3. `cargo build --release --locked -p moex-app -p moex-cli`.
4. Stage `MachOExplorer.exe`, `moex.exe` and `LICENSE` in `dist/windows/MachOExplorer`.
5. Run `ISCC` on `packaging/windows/MachOExplorer.iss` (skipped by `-SkipInstaller`), producing `dist/windows/installer/MachOExplorer-Setup-<version>.exe`.

`ISCC` is taken from `-ISCCPath`, then `PATH`, then
`Program Files (x86)\Inno Setup 6\ISCC.exe` on `D:` or `C:`.

### Release upload

After the macOS release and tag are published:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_windows_release.ps1
```

Parameters: `-Version`, `-Tag` (default `v<version>`), `-Repo <owner/name>`,
`-ISCCPath`, `-SkipTests`, `-SkipUpload`, `-NoClobber`.

Notes:

- The script first checks `gh auth status` and that the release for the tag exists, even with `-SkipUpload`.
- It runs `build_windows_installer.ps1`, then zips the staged directory as `dist/windows/MachOExplorer-<version>-windows-x64-portable.zip`.
- It uploads two assets: the portable zip and the Inno Setup installer. Existing assets are replaced unless `-NoClobber` is given.
- Use `-SkipUpload` to build and package without uploading.

## Linux Tarball

Not yet verified on a Linux machine.

```bash
scripts/package_linux.sh [--version X.Y.Z]
```

Build dependencies (Debian/Ubuntu):

```bash
sudo apt-get install -y build-essential pkg-config clang \
  libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-xcb-dev \
  libxcb1-dev libfontconfig-dev libfreetype-dev libvulkan-dev \
  libasound2-dev libssl-dev
```

The script builds `moex-app` and `moex-cli` in release mode and writes
`dist/linux/MachOExplorer-<version>-linux-<arch>.tar.gz` containing:

- `bin/MachOExplorer`, `bin/moex`
- `share/applications/machoexplorer.desktop`
- `share/icons/hicolor/512x512/apps/machoexplorer.png`
- `LICENSE`, `README.md`

The tarball is not uploaded anywhere by the script.

## CI

`.github/workflows/rust.yml` builds and tests on macOS, Ubuntu 24.04 and
Windows. It does not produce release artifacts.
