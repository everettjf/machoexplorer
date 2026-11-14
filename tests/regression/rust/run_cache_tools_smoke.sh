#!/usr/bin/env bash
# Smoke test of `moex cache-list` / `moex cache-extract`.
#
# Part 1 runs against a small synthetic cache built here, so it works on any
# machine. Part 2 runs against a real dyld shared cache when one is found
# (pass a path as $1 to choose one).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
CACHE_DIR="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"
CACHE_FILE="${1:-}"

require_moex

"${MOEX_BIN}" cache-list --help >/dev/null 2>&1
"${MOEX_BIN}" cache-extract --help >/dev/null 2>&1

fail() {
  echo "cache-smoke: $*"
  exit 1
}

# expect_rc <expected> <command...>
expect_rc() {
  local want="$1" rc
  shift
  set +e
  "$@" >/dev/null 2>&1
  rc=$?
  set -e
  [[ "${rc}" -eq "${want}" ]] || fail "expected exit ${want}, got ${rc}: $*"
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/moex-cache-smoke.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# --- Part 1: synthetic cache -------------------------------------------------
SYN="${TMP_DIR}/synthetic.cache"
make_synthetic_cache "${SYN}"

"${MOEX_BIN}" cache-list "${SYN}" >"${TMP_DIR}/list.txt"
grep -q "^0x10200 /usr/lib/libsynthetic.dylib$" "${TMP_DIR}/list.txt" || fail "image missing from text listing"
grep -q "^shown: 2$" "${TMP_DIR}/list.txt" || fail "wrong image count in text listing"
"${MOEX_BIN}" cache-list --json --limit=1 "${SYN}" libsynthetic >"${TMP_DIR}/list.json"
grep -q '"images":\[{"address":"0x10200","path":"/usr/lib/libsynthetic.dylib"}\],"shown":1}' "${TMP_DIR}/list.json" \
  || fail "unexpected json listing"
"${MOEX_BIN}" cache-list --exact --output="${TMP_DIR}/exact.txt" "${SYN}" libsynthetic
grep -q "^shown: 0$" "${TMP_DIR}/exact.txt" || fail "--exact should not match a substring"

"${MOEX_BIN}" cache-extract "${SYN}" libsynthetic "${TMP_DIR}/raw.macho" >"${TMP_DIR}/extract.txt"
grep -q "^extracted: /usr/lib/libsynthetic.dylib$" "${TMP_DIR}/extract.txt" || fail "missing extracted line"
grep -q "size=16512 bytes segments=2$" "${TMP_DIR}/extract.txt" || fail "unexpected raw extraction summary"
[[ "$(wc -c < "${TMP_DIR}/raw.macho" | tr -d ' ')" -eq 16512 ]] || fail "raw output has the wrong size"
cmp -s -n 256 "${TMP_DIR}/raw.macho" <(tail -c +513 "${SYN}") || fail "raw output does not start with the image's __TEXT"

"${MOEX_BIN}" cache-extract --compact --json "${SYN}" libsynthetic "${TMP_DIR}/compact.macho" >"${TMP_DIR}/extract.json"
grep -q '"event":"extracted".*"mode":"compact","size":8320,"segments":2}' "${TMP_DIR}/extract.json" \
  || fail "unexpected compact extraction summary"
[[ "$(wc -c < "${TMP_DIR}/compact.macho" | tr -d ' ')" -eq 8320 ]] || fail "compact output has the wrong size"
# The extracted images are themselves parseable Mach-O files.
"${MOEX_BIN}" parse "${TMP_DIR}/raw.macho" "${TMP_DIR}/compact.macho" >/dev/null || fail "extracted image does not parse"

"${MOEX_BIN}" cache-extract --dry-run --all "${SYN}" libsynthetic "${TMP_DIR}/never-created" >"${TMP_DIR}/plan.txt"
grep -q "^plan: /usr/lib/libsynthetic.dylib -> ${TMP_DIR}/never-created/libsynthetic.dylib.macho " "${TMP_DIR}/plan.txt" \
  || fail "unexpected dry-run plan"
grep -q "^batch: matched=1 processed=1 extracted=1$" "${TMP_DIR}/plan.txt" || fail "unexpected batch summary"
[[ ! -e "${TMP_DIR}/never-created" ]] || fail "--dry-run created the output directory"

expect_rc 1 "${MOEX_BIN}" cache-extract "${SYN}" libnotmacho "${TMP_DIR}/bad.macho"
[[ ! -e "${TMP_DIR}/bad.macho" ]] || fail "failed extraction left an output file"
expect_rc 1 "${MOEX_BIN}" cache-extract "${SYN}" no-such-image "${TMP_DIR}/none.macho"
expect_rc 1 "${MOEX_BIN}" cache-extract --all "${SYN}" lib "${TMP_DIR}/all"   # one of two images fails
[[ -s "${TMP_DIR}/all/libsynthetic.dylib.macho" ]] || fail "--all did not write the good image"
expect_rc 1 "${MOEX_BIN}" cache-list "${ROOT_DIR}/sample/simple"
expect_rc 2 "${MOEX_BIN}" cache-list
expect_rc 2 "${MOEX_BIN}" cache-extract "${SYN}" libsynthetic

# --- Part 2: real cache ------------------------------------------------------
if [[ -z "${CACHE_FILE}" ]]; then
  # The main cache file is the one without a ".NN" / ".map" style suffix.
  for candidate in "${CACHE_DIR}/dyld_shared_cache_arm64e" "${CACHE_DIR}"/dyld_shared_cache_*; do
    if [[ -f "${candidate}" && "$(basename "${candidate}")" != *.* ]]; then
      CACHE_FILE="${candidate}"
      break
    fi
  done
fi

if [[ -z "${CACHE_FILE}" || ! -f "${CACHE_FILE}" ]]; then
  echo "cache-smoke: passed (synthetic only; real cache not found: ${CACHE_FILE:-${CACHE_DIR}})"
  exit 0
fi

"${MOEX_BIN}" cache-list --json --limit=1 "${CACHE_FILE}" libobjc >/dev/null
# Images of a split cache live in sub-cache files that the extractor does not
# follow, so the plan may legitimately fail (exit 1); it must not crash.
set +e
"${MOEX_BIN}" cache-extract --dry-run --compact --all --max=1 "${CACHE_FILE}" libswift "${TMP_DIR}/real" >/dev/null 2>&1
rc=$?
set -e
if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  fail "dry-run extraction exited with ${rc} on ${CACHE_FILE}"
fi

echo "cache-smoke: passed"
