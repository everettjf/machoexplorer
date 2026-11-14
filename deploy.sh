#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${ROOT_DIR}/dist/macos/MachOExplorer.app"
DMG_PATH="${ROOT_DIR}/dist/macos/MachOExplorer.dmg"
CODE_SIGN_IDENTITY="${CODE_SIGN_IDENTITY:-Developer ID Application: Feng Zhu (YPV49M8592)}"
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-${APPLE_PASSWORD:-${APP_SPECIFIC_PASSWORD:-}}}"

NO_HOMEBREW=0
NO_RELEASE=0
NO_TAG=0
NO_PUSH=0
NO_BUMP=0
UNIVERSAL=1

usage() {
  cat <<EOF
Usage: $0 [--no-bump] [--host-arch-only] [--no-homebrew] [--no-release] [--no-tag] [--no-push]

Default behavior:
  1) bump patch version (skip with --no-bump to release the current version)
  2) build app (universal arm64 + x86_64) + run tests + dmg
  3) sign app with Developer ID
  4) notarize dmg + staple ticket
  5) commit + push
  6) create git tag + push tag
  7) create/update GitHub release + upload dmg
  8) update Homebrew cask

Required env for macOS release:
  CODE_SIGN_IDENTITY              default: Developer ID Application: Feng Zhu (YPV49M8592)
  NOTARYTOOL_PROFILE              preferred keychain profile for xcrun notarytool
  or APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-homebrew) NO_HOMEBREW=1; shift ;;
    --no-release) NO_RELEASE=1; shift ;;
    --no-tag) NO_TAG=1; shift ;;
    --no-push) NO_PUSH=1; shift ;;
    --no-bump) NO_BUMP=1; shift ;;
    --host-arch-only) UNIVERSAL=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

require_cmd git
require_cmd cargo
require_cmd lipo
require_cmd hdiutil
require_cmd gh
require_cmd codesign
require_cmd security
require_cmd xcrun
require_cmd spctl

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree is not clean; commit or stash first" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh not authenticated. run: gh auth login" >&2
  exit 1
fi

if ! security find-identity -v -p codesigning | grep -Fq "\"${CODE_SIGN_IDENTITY}\""; then
  cat >&2 <<EOF
Signing identity not available in keychain:
  ${CODE_SIGN_IDENTITY}

Available code signing identities:
$(security find-identity -v -p codesigning | sed 's/^/  /')
EOF
  exit 1
fi

if [[ -z "${NOTARYTOOL_PROFILE}" ]] && { [[ -z "${APPLE_ID}" ]] || [[ -z "${APPLE_TEAM_ID}" ]] || [[ -z "${APPLE_APP_SPECIFIC_PASSWORD}" ]]; }; then
  cat >&2 <<EOF
Notarization credentials missing.
Set one of:
  1) NOTARYTOOL_PROFILE=<keychain-profile-name>
  2) APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD
EOF
  exit 1
fi

if [[ "${NO_BUMP}" -eq 0 ]]; then
  new_version="$("${ROOT_DIR}/scripts/inc_patch_version.sh")"
else
  new_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT_DIR}/Cargo.toml" | head -1)"
fi
tag="v${new_version}"
echo "release version: ${new_version}"

cd "${ROOT_DIR}"
# Unit tests, golden baseline comparison, malformed-input robustness, GUI tests.
cargo test --workspace --locked
cargo build --release --locked -p moex-cli
"${ROOT_DIR}/tests/regression/run_all.sh"

bundle_args=(--version "${new_version}")
if [[ "${UNIVERSAL}" -eq 1 ]]; then
  bundle_args+=(--universal)
fi
"${ROOT_DIR}/scripts/bundle_macos.sh" "${bundle_args[@]}"

mkdir -p "${ROOT_DIR}/dist/macos"
codesign --force --options runtime --timestamp --sign "${CODE_SIGN_IDENTITY}" "${APP_DIR}/Contents/MacOS/moex"
codesign --force --options runtime --timestamp --sign "${CODE_SIGN_IDENTITY}" "${APP_DIR}"
codesign --verify --deep --strict --verbose=2 "${APP_DIR}"
spctl --assess -vv "${APP_DIR}"
hdiutil create -volname "MachOExplorer" -srcfolder "${APP_DIR}" -ov -format UDZO "${DMG_PATH}"

echo "Submitting DMG for notarization..."
if [[ -n "${NOTARYTOOL_PROFILE}" ]]; then
  xcrun notarytool submit "${DMG_PATH}" --keychain-profile "${NOTARYTOOL_PROFILE}" --wait
else
  xcrun notarytool submit "${DMG_PATH}" \
    --apple-id "${APPLE_ID}" \
    --team-id "${APPLE_TEAM_ID}" \
    --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
    --wait
fi

echo "Stapling notarization ticket..."
xcrun stapler staple "${DMG_PATH}"
xcrun stapler validate "${DMG_PATH}"

if [[ "${NO_BUMP}" -eq 0 ]]; then
  git add "${ROOT_DIR}/Cargo.toml" "${ROOT_DIR}/Cargo.lock" "${ROOT_DIR}/README.md" "${ROOT_DIR}/README.zh-CN.md"
  git commit -m "release: bump to ${tag}"
fi

if [[ "${NO_PUSH}" -eq 0 ]]; then
  git push origin HEAD
fi

if [[ "${NO_TAG}" -eq 0 ]]; then
  if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "tag already exists: ${tag}" >&2
    exit 1
  fi
  git tag "${tag}"
  if [[ "${NO_PUSH}" -eq 0 ]]; then
    git push origin "${tag}"
  fi
fi

if [[ "${NO_RELEASE}" -eq 0 ]]; then
  if gh release view "${tag}" >/dev/null 2>&1; then
    gh release upload "${tag}" "${DMG_PATH}" --clobber
  else
    gh release create "${tag}" "${DMG_PATH}" -t "${tag}" -n "MachOExplorer ${tag}"
  fi
fi

if [[ "${NO_HOMEBREW}" -eq 0 ]]; then
  "${ROOT_DIR}/scripts/release_homebrew.sh" --version "${new_version}" --dmg "${DMG_PATH}"
fi

echo "deploy done: ${tag}"
