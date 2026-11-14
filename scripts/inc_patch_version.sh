#!/usr/bin/env bash
# Bump the patch version in the workspace Cargo.toml (and Cargo.lock, README
# links). Prints the new version.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="${ROOT_DIR}/Cargo.toml"
README_EN="${ROOT_DIR}/README.md"
README_ZH="${ROOT_DIR}/README.zh-CN.md"

current="$(sed -n 's/^version = "\(.*\)"/\1/p' "${CARGO_TOML}" | head -1)"
if [[ -z "${current}" ]]; then
  echo "failed to parse workspace version from ${CARGO_TOML}" >&2
  exit 1
fi

IFS='.' read -r major minor patch <<<"${current}"
if ! [[ "${major:-}" =~ ^[0-9]+$ && "${minor:-}" =~ ^[0-9]+$ && "${patch:-}" =~ ^[0-9]+$ ]]; then
  echo "invalid semantic version: ${current}" >&2
  exit 1
fi

next="${major}.${minor}.$((patch + 1))"

# Portable in-place edit (BSD and GNU sed differ on -i).
replace() { # replace <file> <sed-expression>
  local tmp
  tmp="$(mktemp)"
  sed "$2" "$1" >"${tmp}" && cat "${tmp}" >"$1" && rm -f "${tmp}"
}

replace "${CARGO_TOML}" "s/^version = \"${current}\"/version = \"${next}\"/"
# Keep Cargo.lock in step with the workspace version.
(cd "${ROOT_DIR}" && cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null)

if [[ -f "${README_EN}" ]]; then
  replace "${README_EN}" "s/Current major release: \`v${current}\`/Current major release: \`v${next}\`/"
  replace "${README_EN}" "s/releases\\/tag\\/v${current}/releases\\/tag\\/v${next}/g"
fi
if [[ -f "${README_ZH}" ]]; then
  replace "${README_ZH}" "s/当前发布版本：\`v${current}\`/当前发布版本：\`v${next}\`/"
  replace "${README_ZH}" "s/releases\\/tag\\/v${current}/releases\\/tag\\/v${next}/g"
fi

echo "${next}"
