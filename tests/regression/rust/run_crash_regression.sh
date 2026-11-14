#!/usr/bin/env bash
# Malformed-input crash regression for the Rust tools.
#
# Generates malformed and truncated inputs and runs every `moex` subcommand
# over them. Rejecting an input (exit 1) or accepting it (exit 0) are both
# fine; a panic (exit 101) or a signal/abort (exit >= 128) is a failure.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_moex

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/moex-crash-reg.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
IN_DIR="${TMP_DIR}/in"
OUT_DIR="${TMP_DIR}/out"
mkdir -p "${IN_DIR}" "${OUT_DIR}"

# patch_hex <file> <offset> <hex>: overwrite bytes in place.
patch_hex() {
  # shellcheck disable=SC2059
  printf "$(printf '%s' "$3" | sed 's/../\\x&/g')" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

# ar member header: name[16] mtime[12] uid[6] gid[6] mode[8] size[10] fmag[2]
ar_header() {
  printf '%-16s%-12s%-6s%-6s%-8s%-10s`\n' "$1" "0" "0" "0" "100644" "$2"
}

# --- Seed corpus (same inputs as the C++ crash regression) --------------------

# Empty file.
: > "${IN_DIR}/empty.bin"

# Truncated Mach-O magic only.
printf '\xcf\xfa\xed' > "${IN_DIR}/truncated_macho.bin"

# Archive magic without member header.
printf '!<arch>\n' > "${IN_DIR}/broken_archive.a"

# Archive with invalid member size field (non-decimal).
{ printf '!<arch>\n'; ar_header "bad.o/" "12x"; } > "${IN_DIR}/bad_size_archive.a"

# dyld magic prefix but too short.
printf 'dyld_v1   arm64e' > "${IN_DIR}/truncated_dyld.cache"

# dyld header with unreasonable mapping/images count.
printf '\x64\x79\x6c\x64\x5f\x76\x31\x20\x20\x20\x61\x72\x6d\x36\x34\x65' > "${IN_DIR}/huge_count_dyld.cache"
printf '\x40\x00\x00\x00\xff\xff\xff\xff\x80\x00\x00\x00\xff\xff\xff\xff' >> "${IN_DIR}/huge_count_dyld.cache"
pad_to "${IN_DIR}/huge_count_dyld.cache" 192

# dyld header with one mapping entry whose file range is out of bounds.
bad_map="${IN_DIR}/bad_mapping_range_dyld.cache"
printf '\x64\x79\x6c\x64\x5f\x76\x31\x20\x20\x20\x61\x72\x6d\x36\x34\x65' > "${bad_map}"
printf '\x60\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> "${bad_map}"
pad_to "${bad_map}" 192
# mapping: address=0 size=0x2000 fileOffset=0x100000 maxProt=0 initProt=0
patch_hex "${bad_map}" 96 "0000000000000000002000000000000000001000000000000000000000000000"

# Valid minimal FAT64 with one x86_64 MH_MAGIC_64 image at offset 0x1000.
valid_fat64="${IN_DIR}/valid_fat64.bin"
: > "${valid_fat64}"
pad_to "${valid_fat64}" 4096
patch_hex "${valid_fat64}" 0 "cafebabf00000001"
patch_hex "${valid_fat64}" 8 "0100000700000003"
patch_hex "${valid_fat64}" 16 "0000000000001000"
patch_hex "${valid_fat64}" 24 "0000000000000020"
patch_hex "${valid_fat64}" 32 "0000000c00000000"
write_hex "${valid_fat64}" "cffaedfe070000010300000002000000000000000000000000000000000000000"0

# --- Archives -----------------------------------------------------------------

macho64_header="cffaedfe0c00000100000000010000000000000000000000000000000000000"0

# Member whose payload is only a Mach-O magic.
{ printf '!<arch>\n'; ar_header "m.o/" "4"; printf '\xcf\xfa\xed\xfe'; } > "${IN_DIR}/ar_magic_only_member.a"

# Member whose Mach-O header claims load commands past the end of the file.
{ printf '!<arch>\n'; ar_header "m.o/" "32"; } > "${IN_DIR}/ar_bad_macho_member.a"
write_hex "${IN_DIR}/ar_bad_macho_member.a" "cffaedfe0c000001000000000100000005000000ffffff7f0000000000000000"

# Member size larger than the file; the largest 10-digit size.
{ printf '!<arch>\n'; ar_header "big.o/" "9999999999"; printf 'abcd'; } > "${IN_DIR}/ar_huge_size.a"

# Bad header trailer on the second member.
{ printf '!<arch>\n'; ar_header "a.o/" "3"; printf 'abc\n'; ar_header "b.o/" "4" | sed 's/`$/x/'; printf '1234'; } > "${IN_DIR}/ar_bad_trailer.a"

# Long-name forms: BSD "#1/N" with N larger than the payload, "/#1/" with a
# huge count, GNU "/N" with and without a string table.
{ printf '!<arch>\n'; ar_header "#1/200" "8"; printf 'abcdefgh'; } > "${IN_DIR}/ar_bsd_name_overrun.a"
{ printf '!<arch>\n'; ar_header "/#1/99999999999" "8"; printf 'abcdefgh'; } > "${IN_DIR}/ar_slash_hash_huge.a"
{ printf '!<arch>\n'; ar_header "//" "6"; printf 'x.o/\n\n'; ar_header "/0" "2"; printf 'ab'; ar_header "/99999" "2"; printf 'cd'; } > "${IN_DIR}/ar_gnu_names.a"

# Odd-sized last member with no padding byte; a header cut short at EOF.
{ printf '!<arch>\n'; ar_header "odd.o/" "3"; printf 'abc'; } > "${IN_DIR}/ar_odd_tail.a"
{ printf '!<arch>\n'; ar_header "a.o/" "2"; printf 'ab'; ar_header "b.o/" "0" | head -c 59; } > "${IN_DIR}/ar_cut_header.a"

# Valid archive: a data member and a minimal Mach-O member.
{ printf '!<arch>\n'; ar_header "notes.txt/" "5"; printf 'hello\n'; ar_header "m.o/" "32"; } > "${IN_DIR}/ar_valid.a"
write_hex "${IN_DIR}/ar_valid.a" "${macho64_header}"

# --- dyld shared caches -------------------------------------------------------

# A well-formed synthetic cache, then single-field corruptions of it.
# Layout (see make_synthetic_cache): header 0..112, mapping at 112, image
# table at 144, Mach-O image at 0x200 (load commands at 0x220).
good_cache="${IN_DIR}/dyld_valid.cache"
make_synthetic_cache "${good_cache}"

mutate() { # mutate <name> <offset> <hex>
  cp "${good_cache}" "${IN_DIR}/dyld_$1.cache"
  patch_hex "${IN_DIR}/dyld_$1.cache" "$2" "$3"
}
mutate mapping_offset_max      16 "ffffffff"
mutate mapping_count_million   20 "40420f00"
mutate images_offset_at_end    24 "$(le32 4064)"
mutate images_offset_past_end  24 "$(le32 4090)"
mutate images_count_10m        28 "80969800"
mutate mapping_addr_wraps     112 "00f0ffffffffffff"
mutate mapping_size_plus_one  120 "$(le64 4097)"
mutate mapping_fileoff_max    128 "ffffffffffffffff"
mutate image_addr_unmapped    144 "$(le64 0x7000000000)"
mutate image_addr_at_end      144 "$(le64 0x10ff0)"
mutate image_addr_last_byte   144 "$(le64 0x10fff)"
mutate path_offset_max        168 "ffffffff"
mutate path_offset_last_byte  168 "$(le32 4095)"
mutate path_control_chars     208 "2f01027f"
mutate macho_magic_32         512 "cefaedfe"
mutate macho_magic_swapped    512 "feedfacf"
mutate macho_ncmds_max        528 "ffff0000"
mutate macho_ncmds_over       528 "00000100"
mutate macho_sizeofcmds_max   532 "ffffffff"
mutate macho_sizeofcmds_64m   532 "00000004"
mutate macho_sizeofcmds_short 532 "$(le32 100)"
mutate lc_cmdsize_zero        548 "00000000"
mutate lc_cmdsize_wraps       548 "f8ffffff"
mutate lc_cmdsize_small       548 "$(le32 16)"
mutate seg_vmaddr_unmapped    568 "$(le64 0x90000)"
mutate seg_fileoff_huge       584 "f0ffffffffffffff"
mutate seg_filesize_max       592 "ffffffffffffffff"
mutate seg_filesize_past_end  592 "$(le64 0xe01)"
mutate seg2_fileoff_overlaps  656 "$(le64 0x10)"
mutate seg2_filesize_max      664 "ffffffffffffff7f"

# Cache without an image table but with a hostile sibling .map file.
cp "${good_cache}" "${IN_DIR}/dyld_map_fallback.cache"
patch_hex "${IN_DIR}/dyld_map_fallback.cache" 24 "0000000000000000"
{
  printf '/usr/lib/libsynthetic.dylib\n\t__TEXT 0x10200 -> 0x10300\n'
  printf '/no/text/line\n/huge/addr\n  __TEXT 0xfffffffffffffffffffffffff\n'
  printf '/bin\xff\xfe/ary\n__TEXT 0xZZ\n\n__TEXT\n/unterminated'
} > "${IN_DIR}/dyld_map_fallback.cache.map"

# --- Truncated real binaries --------------------------------------------------
# Cutting real files mid-stream exercises the bounds checks of every view
# (load commands, symbol tables, LEB128 streams, code signatures, ...) against
# genuine data.
for src_bin in "${ROOT_DIR}"/sample/simple "${ROOT_DIR}"/sample/complex "${ROOT_DIR}"/tests/corpus/bin/*; do
  [[ -f "${src_bin}" ]] || continue
  total_bytes="$(wc -c < "${src_bin}" | tr -d ' ')"
  for frac in 10 30 60 75 90 99; do
    cut_bytes=$(( total_bytes * frac / 100 ))
    [[ "${cut_bytes}" -gt 0 ]] || continue
    head -c "${cut_bytes}" "${src_bin}" > "${IN_DIR}/trunc_$(basename "${src_bin}")_${frac}.bin"
  done
done

# --- Run ----------------------------------------------------------------------

FAIL=0
RUNS=0
# check <label> <file> <command...>: run and flag panics / signals.
check() {
  local label="$1" file="$2" rc
  shift 2
  RUNS=$((RUNS + 1))
  set +e
  "$@" >/dev/null 2>"${TMP_DIR}/stderr.txt"
  rc=$?
  set -e
  if is_crash_rc "${rc}"; then
    echo "[fail] ${label} crashed (exit=${rc}) for: $(basename "${file}")"
    grep -m 2 -E "panicked|overflow|out of range|index out of bounds" "${TMP_DIR}/stderr.txt" | sed 's/^/        /' || true
    FAIL=1
  fi
  LAST_RC="${rc}"
}

TOTAL=0
REJECTED=0
ACCEPTED=0
for f in "${IN_DIR}"/*; do
  [[ "${f}" == *.map ]] && continue
  TOTAL=$((TOTAL + 1))
  check "parse" "${f}" "${MOEX_BIN}" parse "${f}"
  if [[ "${LAST_RC}" -eq 0 ]]; then
    ACCEPTED=$((ACCEPTED + 1))
  else
    REJECTED=$((REJECTED + 1))
  fi

  # Deep pass: the full view tree, in both formats.
  check "dump text" "${f}" "${MOEX_BIN}" dump --format text --include-empty "${f}"
  check "dump json" "${f}" "${MOEX_BIN}" dump --format json --include-empty "${f}"
  check "diff self" "${f}" "${MOEX_BIN}" diff "${f}" "${f}"
  check "diff sample" "${f}" "${MOEX_BIN}" diff "${ROOT_DIR}/sample/simple" "${f}"

  # Cache tools (they reject non-cache inputs after parsing them).
  check "cache-list" "${f}" "${MOEX_BIN}" cache-list "${f}"
  check "cache-list json" "${f}" "${MOEX_BIN}" cache-list --json --limit=3 "${f}" lib
  check "cache-extract dry-run" "${f}" "${MOEX_BIN}" cache-extract --dry-run --all --json "${f}" "" "${OUT_DIR}/dry"
  rm -rf "${OUT_DIR}/raw" "${OUT_DIR}/compact" "${OUT_DIR}/one.macho"
  check "cache-extract raw" "${f}" "${MOEX_BIN}" cache-extract --all "${f}" "" "${OUT_DIR}/raw"
  check "cache-extract compact" "${f}" "${MOEX_BIN}" cache-extract --compact --all "${f}" "" "${OUT_DIR}/compact"
  check "cache-extract single" "${f}" "${MOEX_BIN}" cache-extract "${f}" lib "${OUT_DIR}/one.macho"
  # Whatever was extracted must itself be handled safely.
  for extracted in "${OUT_DIR}"/raw/* "${OUT_DIR}"/compact/* "${OUT_DIR}/one.macho"; do
    [[ -f "${extracted}" ]] || continue
    check "dump of extracted image" "${f}" "${MOEX_BIN}" dump --format json --include-empty "${extracted}"
  done
done
rm -rf "${OUT_DIR}"

echo "[ok] ${TOTAL} malformed inputs exercised (runs=${RUNS} rejected=${REJECTED} accepted=${ACCEPTED})"

# Sanity: inputs that are well-formed must be accepted.
for valid in valid_fat64.bin ar_valid.a dyld_valid.cache dyld_map_fallback.cache; do
  set +e
  "${MOEX_BIN}" parse "${IN_DIR}/${valid}" >/dev/null 2>&1
  valid_rc=$?
  set -e
  if [[ "${valid_rc}" -ne 0 ]]; then
    echo "[fail] well-formed input should parse successfully: ${valid}"
    FAIL=1
  else
    echo "[ok] well-formed input parsed successfully: ${valid}"
  fi
done

if [[ "${FAIL}" -ne 0 ]]; then
  echo "crash-regression: failed"
  exit 1
fi

echo "crash-regression: passed (total=${TOTAL} rejected=${REJECTED} accepted=${ACCEPTED} runs=${RUNS})"
