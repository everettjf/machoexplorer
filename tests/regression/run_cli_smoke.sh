#!/usr/bin/env bash
# Smoke test of `moex dump` (the replacement for `MachOExplorer --cli`).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SAMPLE_FILE="${ROOT_DIR}/sample/simple"
FAT_SAMPLE_FILE="${ROOT_DIR}/sample/complex"

require_moex

if [[ ! -f "${SAMPLE_FILE}" ]]; then
  echo "cli-smoke: missing sample file: ${SAMPLE_FILE}"
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/moex-cli-smoke.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
OUT_TEXT="${TMP_DIR}/smoke.txt"
OUT_JSON="${TMP_DIR}/smoke.json"
OUT_FAT="${TMP_DIR}/smoke-fat.txt"

"${MOEX_BIN}" dump --max-rows 8 "${SAMPLE_FILE}" >"${OUT_TEXT}"
"${MOEX_BIN}" dump --format json --max-rows 8 "${SAMPLE_FILE}" >"${OUT_JSON}"
"${MOEX_BIN}" dump --format json --name-filter "Mach Header" --table-mode summary "${SAMPLE_FILE}" >"${OUT_JSON}.filtered"

if ! grep -qE "^file:" "${OUT_TEXT}"; then
  echo "cli-smoke: missing text output header"
  exit 1
fi

if ! grep -qE '"analysis"' "${OUT_JSON}"; then
  echo "cli-smoke: missing json analysis field"
  exit 1
fi

if ! grep -qE '"schemaVersion"' "${OUT_JSON}"; then
  echo "cli-smoke: missing schemaVersion field"
  exit 1
fi

if ! grep -qE '"path"' "${OUT_JSON}"; then
  echo "cli-smoke: missing node path field"
  exit 1
fi

rm -f "${OUT_JSON}"
"${MOEX_BIN}" dump --format json --max-rows=4 --output "${OUT_JSON}" "${SAMPLE_FILE}" >/dev/null
if [[ ! -s "${OUT_JSON}" ]]; then
  echo "cli-smoke: output file not written"
  exit 1
fi

if ! grep -qE '"tableMode": "summary"' "${OUT_JSON}.filtered"; then
  echo "cli-smoke: filtered summary output missing tableMode"
  exit 1
fi

# Directories (including .app bundles) must be rejected with a clear message.
mkdir -p "${TMP_DIR}/Fake.app" "${TMP_DIR}/plain-dir"
check_dir_rejected() {
  local dir_case="$1" message="$2"
  if "${MOEX_BIN}" dump "${dir_case}" >"${TMP_DIR}/dir.out" 2>"${TMP_DIR}/dir.err"; then
    echo "cli-smoke: directory path should fail gracefully: ${dir_case}"
    exit 1
  fi
  if ! grep -q "${message}" "${TMP_DIR}/dir.err"; then
    echo "cli-smoke: rejection message missing for ${dir_case}: ${message}"
    exit 1
  fi
}
check_dir_rejected "${TMP_DIR}/Fake.app" "Application bundles are directories"
check_dir_rejected "${TMP_DIR}/plain-dir" "Path is a directory"

# Invalid arguments exit with 2, analysis failures with 1.
set +e
"${MOEX_BIN}" dump >/dev/null 2>&1
usage_rc=$?
"${MOEX_BIN}" dump "${TMP_DIR}/does-not-exist" >/dev/null 2>&1
missing_rc=$?
set -e
if [[ "${usage_rc}" -ne 2 || "${missing_rc}" -ne 1 ]]; then
  echo "cli-smoke: unexpected exit codes (usage=${usage_rc} missing-file=${missing_rc})"
  exit 1
fi

# Fat binaries exercise the Fat Header view.
if [[ -f "${FAT_SAMPLE_FILE}" ]]; then
  if ! "${MOEX_BIN}" dump "${FAT_SAMPLE_FILE}" >"${OUT_FAT}" 2>/dev/null; then
    echo "cli-smoke: fat binary analysis failed"
    exit 1
  fi
  if [[ ! -s "${OUT_FAT}" ]]; then
    echo "cli-smoke: fat binary produced no output"
    exit 1
  fi
fi

echo "cli-smoke: passed"
