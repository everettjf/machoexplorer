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
# Raw layout: __TEXT at 0, the rebuilt __LINKEDIT (one nlist + 8 bytes of
# strings) at its recorded offset 0x4000.
grep -q "^mode: raw-fileoff$" "${TMP_DIR}/extract.txt" || fail "raw extraction did not keep the recorded offsets"
grep -q "size=16408 bytes segments=2$" "${TMP_DIR}/extract.txt" || fail "unexpected raw extraction summary"
[[ "$(wc -c < "${TMP_DIR}/raw.macho" | tr -d ' ')" -eq 16408 ]] || fail "raw output has the wrong size"
cmp -s -n 32 "${TMP_DIR}/raw.macho" <(tail -c +513 "${SYN}") || fail "raw output does not start with the image's Mach-O header"
cmp -s <(tail -c 24 "${TMP_DIR}/raw.macho") <(tail -c +1025 "${SYN}" | head -c 24) \
  || fail "raw output does not end with the image's symbol and string table"

"${MOEX_BIN}" cache-extract --compact --json "${SYN}" libsynthetic "${TMP_DIR}/compact.macho" >"${TMP_DIR}/extract.json"
grep -q '"event":"extracted".*"mode":"compact","size":4120,"segments":2}' "${TMP_DIR}/extract.json" \
  || fail "unexpected compact extraction summary"
[[ "$(wc -c < "${TMP_DIR}/compact.macho" | tr -d ' ')" -eq 4120 ]] || fail "compact output has the wrong size"
# The extracted images are themselves parseable Mach-O files, and their
# symbol table is where LC_SYMTAB says.
"${MOEX_BIN}" parse "${TMP_DIR}/raw.macho" "${TMP_DIR}/compact.macho" >/dev/null || fail "extracted image does not parse"
for extracted in raw compact; do
  "${MOEX_BIN}" dump "${TMP_DIR}/${extracted}.macho" | grep -q "_syn" || fail "${extracted} output lost its symbol"
done

"${MOEX_BIN}" cache-extract --dry-run --all "${SYN}" libsynthetic "${TMP_DIR}/never-created" >"${TMP_DIR}/plan.txt"
grep -q "^plan: /usr/lib/libsynthetic.dylib -> ${TMP_DIR}/never-created/libsynthetic.dylib.macho " "${TMP_DIR}/plan.txt" \
  || fail "unexpected dry-run plan"
grep -q "^batch: matched=1 processed=1 extracted=1$" "${TMP_DIR}/plan.txt" || fail "unexpected batch summary"
[[ ! -e "${TMP_DIR}/never-created" ]] || fail "--dry-run created the output directory"

# Local symbols the cache builder moved out of the image. Old layout: a
# dyld_cache_local_symbols_info in the cache file itself (header fields at
# 72 / 80), with 32-bit entries that name the image by the file offset of its
# header. Here: one nlist_64 (_local), 8 bytes of strings, one entry.
# patch_hex <file> <offset> <hex>: overwrite bytes in place.
patch_hex() {
  # shellcheck disable=SC2059
  printf "$(printf '%s' "$3" | sed 's/../\\x&/g')" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
# local_symbols_info <hex of the entry's dylibOffset>: the info with one
# entry (nlistStartIndex 0, nlistCount 1), as hex.
local_symbols_info() {
  printf '%s' "$(le32 24)$(le32 1)$(le32 40)$(le32 8)$(le32 48)$(le32 1)"
  printf '%s' "$(le32 1)0e010000$(le64 0x10210)"          # nlist_64: _local, N_SECT
  printf '%s' "$(hexstr '' 1)$(hexstr '_local' 7)"        # strings
  printf '%s' "$1$(le32 0)$(le32 1)"
}
SYN_LOCALS="${TMP_DIR}/synthetic-locals.cache"
cp "${SYN}" "${SYN_LOCALS}"
patch_hex "${SYN_LOCALS}" 2560 "$(local_symbols_info "$(le32 0x200)")"
patch_hex "${SYN_LOCALS}" 72 "$(le64 2560)$(le64 60)"
"${MOEX_BIN}" cache-extract --compact "${SYN_LOCALS}" libsynthetic "${TMP_DIR}/locals.macho" >"${TMP_DIR}/locals.txt" 2>"${TMP_DIR}/locals.err"
# Two nlists and 16 bytes of strings after the 4096-byte __TEXT.
grep -q "size=4144 bytes segments=2 local-symbols=1$" "${TMP_DIR}/locals.txt" || fail "local symbols of the cache were not merged"
[[ ! -s "${TMP_DIR}/locals.err" ]] || fail "unexpected diagnostics while merging local symbols"
"${MOEX_BIN}" dump "${TMP_DIR}/locals.macho" >"${TMP_DIR}/locals.dump"
grep -q "_local" "${TMP_DIR}/locals.dump" || fail "merged local symbol missing from the output"
grep -q "_syn" "${TMP_DIR}/locals.dump" || fail "output with merged local symbols lost its own symbol"
# Local symbols info that is not in the file: a warning, and the image is
# extracted without them.
patch_hex "${SYN_LOCALS}" 72 "$(le64 0x7fffffffffff)"
"${MOEX_BIN}" cache-extract --compact "${SYN_LOCALS}" libsynthetic "${TMP_DIR}/locals.macho" >"${TMP_DIR}/locals.txt" 2>"${TMP_DIR}/locals.err" \
  || fail "unusable local symbols info made the extraction fail"
grep -q "^warning: local symbols of the cache not used: local symbols info outside the file$" "${TMP_DIR}/locals.err" \
  || fail "missing warning about unusable local symbols info"
grep -q "size=4120 bytes segments=2$" "${TMP_DIR}/locals.txt" || fail "unexpected summary without local symbols"

# Current layout: the header (0x1d0 bytes here) names a separate
# <cache>.symbols file by symbolFileUUID (at 0x190); that file's header has
# its UUID at 88 and the info's place at 72 / 80, and the entries are 64-bit
# and name the image by its offset from the cache's base address.
# modern_header <uuid byte> <symbolFileUUID byte> <imagesOffset> <imagesCount>:
# the header and one mapping (vm 0x10000 -> file 0), as hex.
modern_header() {
  local u="" s="" i
  for (( i = 0; i < 16; i++ )); do u+="$1"; s+="$2"; done
  printf '%s' "$(hexstr 'dyld_v1  arm64e' 16)$(le32 0x1d0)$(le32 1)$(hexstr '' 64)${u}$(hexstr '' 296)${s}"
  printf '%s' "$(hexstr '' 32)$(le32 "$3")$(le32 "$4")$(hexstr '' 8)"
  printf '%s' "$(le64 0x10000)$(le64 0x1000)$(le64 0)$(le32 5)$(le32 5)"
}
MOD="${TMP_DIR}/modern.cache"
: > "${MOD}"
write_hex "${MOD}" "$(modern_header 01 09 0x600 1)"
pad_to "${MOD}" 512
tail -c +513 "${SYN}" | head -c 1024 >> "${MOD}"          # the image, as in ${SYN}
write_hex "${MOD}" "$(le64 0x10200)$(le64 0)$(le64 0)$(le32 0x620)$(le32 0)$(hexstr '/usr/lib/libsynthetic.dylib' 28)"
pad_to "${MOD}" 4096
: > "${MOD}.symbols"
write_hex "${MOD}.symbols" "$(modern_header 09 00 0 0)"
pad_to "${MOD}.symbols" 512
write_hex "${MOD}.symbols" "$(local_symbols_info "$(le64 0x200)")"
patch_hex "${MOD}.symbols" 72 "$(le64 512)$(le64 64)"
"${MOEX_BIN}" cache-extract --compact --json "${MOD}" libsynthetic "${TMP_DIR}/modern.macho" >"${TMP_DIR}/modern.json" 2>"${TMP_DIR}/modern.err"
grep -q '"mode":"compact","size":4144,"segments":2,"local_symbols":1}' "${TMP_DIR}/modern.json" \
  || fail "local symbols of the .symbols file were not merged"
[[ ! -s "${TMP_DIR}/modern.err" ]] || fail "unexpected diagnostics while reading the .symbols file"
"${MOEX_BIN}" dump "${TMP_DIR}/modern.macho" | grep -q "_local" || fail "symbol of the .symbols file missing from the output"
# A .symbols file of another cache, then none at all: a warning each time,
# and the image is extracted without the symbols.
patch_hex "${MOD}.symbols" 88 "08"
"${MOEX_BIN}" cache-extract --compact "${MOD}" libsynthetic "${TMP_DIR}/modern.macho" >"${TMP_DIR}/modern.txt" 2>"${TMP_DIR}/modern.err" \
  || fail "a foreign .symbols file made the extraction fail"
grep -q "^warning: local symbols file not used (its UUID is not the cache's symbolFileUUID): ${MOD}.symbols$" "${TMP_DIR}/modern.err" \
  || fail "missing warning about a foreign .symbols file"
grep -q "size=4120 bytes segments=2$" "${TMP_DIR}/modern.txt" || fail "a foreign .symbols file was used"
rm "${MOD}.symbols"
"${MOEX_BIN}" cache-extract --compact --json "${MOD}" libsynthetic "${TMP_DIR}/modern.macho" >"${TMP_DIR}/modern.json" 2>"${TMP_DIR}/modern.err" \
  || fail "a missing .symbols file made the extraction fail"
grep -q '^{"event":"warning","message":"local symbols file not used (cannot be read): ' "${TMP_DIR}/modern.err" \
  || fail "missing json warning about a missing .symbols file"

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
# A sub-cache file may be missing, so the plan may legitimately fail
# (exit 1); it must not crash.
set +e
"${MOEX_BIN}" cache-extract --dry-run --compact --all --max=1 "${CACHE_FILE}" libswift "${TMP_DIR}/real" >/dev/null 2>&1
rc=$?
set -e
if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  fail "dry-run extraction exited with ${rc} on ${CACHE_FILE}"
fi

# An extracted image is a file Apple's tools accept: dyld_info validates the
# segment layout before it prints anything. The image may be unavailable (a
# sub-cache file missing, another OS's cache), which is not a failure here.
REAL_IMAGE="/usr/lib/system/libsystem_c.dylib"
if command -v dyld_info >/dev/null 2>&1 \
  && "${MOEX_BIN}" cache-extract --exact "${CACHE_FILE}" "${REAL_IMAGE}" "${TMP_DIR}/real.macho" >/dev/null 2>&1; then
  dyld_info -segments -exports -fixups "${TMP_DIR}/real.macho" >"${TMP_DIR}/dyld_info.txt" 2>&1 \
    || fail "dyld_info rejects the extracted ${REAL_IMAGE}: $(head -n 3 "${TMP_DIR}/dyld_info.txt" | tr '\n' ' ')"
  grep -q "_printf" "${TMP_DIR}/dyld_info.txt" || fail "dyld_info shows no exports for the extracted ${REAL_IMAGE}"
  "${MOEX_BIN}" dump "${TMP_DIR}/real.macho" >/dev/null || fail "moex cannot read the extracted ${REAL_IMAGE}"
  echo "cache-smoke: passed (dyld_info accepts the extracted ${REAL_IMAGE})"
  exit 0
fi

echo "cache-smoke: passed"
