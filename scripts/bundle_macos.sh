#!/usr/bin/env bash
# Build the Rust GUI + CLI and assemble dist/macos/MachOExplorer.app.
#
#   scripts/bundle_macos.sh [--universal] [--version X.Y.Z]
#
# --universal builds arm64 + x86_64 and lipo-merges them (needs both rustup
# targets). Without it, only the host architecture is built.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="${ROOT_DIR}/dist/macos/MachOExplorer.app"
ICON_PATH="${ROOT_DIR}/packaging/macos/MachOExplorer.icns"
UNIVERSAL=0
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --universal) UNIVERSAL=1; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT_DIR}/Cargo.toml" | head -1)"
fi
[[ -n "${VERSION}" ]] || { echo "cannot determine version" >&2; exit 1; }

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
cd "${ROOT_DIR}"

BIN_DIR="${ROOT_DIR}/target/bundle-bin"
rm -rf "${BIN_DIR}" && mkdir -p "${BIN_DIR}"
if [[ "${UNIVERSAL}" -eq 1 ]]; then
  for target in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --locked --target "${target}" -p moex-app -p moex-cli
  done
  for bin in MachOExplorer moex; do
    lipo -create \
      "target/aarch64-apple-darwin/release/${bin}" \
      "target/x86_64-apple-darwin/release/${bin}" \
      -output "${BIN_DIR}/${bin}"
  done
else
  cargo build --release --locked -p moex-app -p moex-cli
  cp target/release/MachOExplorer target/release/moex "${BIN_DIR}/"
fi

rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Resources"
cp "${BIN_DIR}/MachOExplorer" "${APP_DIR}/Contents/MacOS/MachOExplorer"
# The CLI ships inside the bundle next to the GUI binary.
cp "${BIN_DIR}/moex" "${APP_DIR}/Contents/MacOS/moex"
[[ -f "${ICON_PATH}" ]] && cp "${ICON_PATH}" "${APP_DIR}/Contents/Resources/MachOExplorer.icns"

cat > "${APP_DIR}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>MachOExplorer</string>
  <key>CFBundleIdentifier</key><string>com.everettjf.machoexplorer</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleIconFile</key><string>MachOExplorer.icns</string>
  <key>CFBundleName</key><string>MachOExplorer</string>
  <key>CFBundleDisplayName</key><string>MachOExplorer</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>${MACOSX_DEPLOYMENT_TARGET}</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key><true/>
  <key>NSRequiresAquaSystemAppearance</key><false/>
  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key><string>Mach-O binary</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>LSHandlerRank</key><string>Alternate</string>
      <key>LSItemContentTypes</key>
      <array>
        <string>public.data</string>
        <string>public.unix-executable</string>
        <string>com.apple.mach-o-binary</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
PLIST

echo "bundled: ${APP_DIR} (version ${VERSION})"
