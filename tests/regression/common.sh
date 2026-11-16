# Shared setup for the Rust-tool regression scripts. Source, do not execute.
#
# MOEX_BIN overrides the binary under test (default: target/release/moex).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MOEX_BIN="${MOEX_BIN:-${ROOT_DIR}/target/release/moex}"

require_moex() {
  if [[ ! -x "${MOEX_BIN}" ]]; then
    echo "missing moex binary: ${MOEX_BIN}"
    echo "build first: cargo build --release -p moex-cli (or set MOEX_BIN)"
    exit 2
  fi
}

# A Rust panic exits with 101; an abort or other signal with >= 128. Clean
# failures use 1 (runtime error) or 2 (usage error).
is_crash_rc() {
  [[ "$1" -eq 101 || "$1" -ge 128 ]]
}

# Little-endian hex encoders and a hex -> binary writer, for building small
# synthetic inputs without external tools.
le32() {
  printf '%02x%02x%02x%02x' $(( $1 & 255 )) $(( ($1 >> 8) & 255 )) $(( ($1 >> 16) & 255 )) $(( ($1 >> 24) & 255 ))
}
le64() {
  le32 $(( $1 & 0xffffffff ))
  le32 $(( ($1 >> 32) & 0xffffffff ))
}
# ASCII string as hex, NUL padded to $2 bytes.
hexstr() {
  local s="$1" width="$2" out="" i
  for (( i = 0; i < ${#s}; i++ )); do
    out+="$(printf '%02x' "'${s:i:1}")"
  done
  for (( i = ${#s}; i < width; i++ )); do
    out+="00"
  done
  printf '%s' "${out}"
}
# write_hex <file> <hex>: append the bytes to <file>.
write_hex() {
  # shellcheck disable=SC2059
  printf "$(printf '%s' "$2" | sed 's/../\\x&/g')" >> "$1"
}
# pad_to <file> <size>: zero-extend <file> to <size> bytes.
pad_to() {
  local cur
  cur="$(wc -c < "$1" | tr -d ' ')"
  if [[ "${cur}" -lt "$2" ]]; then
    dd if=/dev/zero bs=1 count=$(( $2 - cur )) >> "$1" 2>/dev/null
  fi
}

# make_synthetic_cache <file>: a 0x1000-byte single-file dyld shared cache
# with one mapping (vm 0x10000 -> file 0) and two images:
#   /usr/lib/libsynthetic.dylib  64-bit Mach-O at file offset 0x200 with a
#                                __TEXT segment (0x100 bytes), a
#                                __LINKEDIT segment (0x80 bytes at 0x400,
#                                recorded file offset 0x4000) and an
#                                LC_SYMTAB with one symbol, _syn: nlist at
#                                0x400, 8 bytes of strings at 0x410
#   /usr/lib/libnotmacho.dylib   points at zero bytes
make_synthetic_cache() {
  local f="$1" h=""
  : > "${f}"
  h+="$(hexstr 'dyld_v1  arm64e' 16)"
  h+="$(le32 112)$(le32 1)$(le32 144)$(le32 2)"        # mappingOffset/Count imagesOffset/Count
  h+="$(hexstr '' 80)"                                  # rest of the 112-byte header
  h+="$(le64 0x10000)$(le64 0x1000)$(le64 0)$(le32 5)$(le32 5)"   # mapping
  h+="$(le64 0x10200)$(le64 0)$(le64 0)$(le32 208)$(le32 0)"      # image 0
  h+="$(le64 0x10800)$(le64 0)$(le64 0)$(le32 236)$(le32 0)"      # image 1
  h+="$(hexstr '/usr/lib/libsynthetic.dylib' 28)"       # at 208
  h+="$(hexstr '/usr/lib/libnotmacho.dylib' 27)"        # at 236
  write_hex "${f}" "${h}"
  pad_to "${f}" 512
  h="$(le32 0xfeedfacf)$(le32 0x0100000c)$(le32 0)$(le32 6)$(le32 3)$(le32 168)$(le32 0)$(le32 0)"
  h+="$(le32 0x19)$(le32 72)$(hexstr '__TEXT' 16)$(le64 0x10200)$(le64 0x100)$(le64 0)$(le64 0x100)$(le32 5)$(le32 5)$(le32 0)$(le32 0)"
  h+="$(le32 0x19)$(le32 72)$(hexstr '__LINKEDIT' 16)$(le64 0x10400)$(le64 0x80)$(le64 0x4000)$(le64 0x80)$(le32 1)$(le32 1)$(le32 0)$(le32 0)"
  h+="$(le32 0x2)$(le32 24)$(le32 0x4000)$(le32 1)$(le32 0x4010)$(le32 8)"   # LC_SYMTAB
  write_hex "${f}" "${h}"
  pad_to "${f}" 1024
  h="$(le32 1)0f010000$(le64 0x10200)"                  # nlist_64: _syn, N_SECT | N_EXT
  h+="$(hexstr '' 1)$(hexstr '_syn' 7)"                 # string table
  write_hex "${f}" "${h}"
  pad_to "${f}" 4096
}
