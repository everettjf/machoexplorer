#!/usr/bin/env bash
# Build the Rust GUI + CLI on Linux and package them as a tarball.
#
#   scripts/package_linux.sh [--version X.Y.Z]
#
# Build dependencies (Debian/Ubuntu):
#   sudo apt-get install -y build-essential pkg-config clang \
#     libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-xcb-dev \
#     libxcb1-dev libfontconfig-dev libfreetype-dev libvulkan-dev \
#     libasound2-dev libssl-dev
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
if [[ -z "${VERSION}" ]]; then
  VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT_DIR}/Cargo.toml" | head -1)"
fi
ARCH="$(uname -m)"
NAME="MachOExplorer-${VERSION}-linux-${ARCH}"
STAGE="${ROOT_DIR}/dist/linux/${NAME}"

cd "${ROOT_DIR}"
cargo build --release --locked -p moex-app -p moex-cli

rm -rf "${STAGE}"
mkdir -p "${STAGE}/bin" "${STAGE}/share/applications" "${STAGE}/share/icons/hicolor/512x512/apps"
cp target/release/MachOExplorer target/release/moex "${STAGE}/bin/"
cp LICENSE README.md "${STAGE}/"
cp packaging/linux/machoexplorer.desktop "${STAGE}/share/applications/"
cp packaging/linux/machoexplorer.png "${STAGE}/share/icons/hicolor/512x512/apps/"

tar -C "${ROOT_DIR}/dist/linux" -czf "${ROOT_DIR}/dist/linux/${NAME}.tar.gz" "${NAME}"
echo "packaged: dist/linux/${NAME}.tar.gz"
