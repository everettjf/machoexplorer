#!/usr/bin/env bash
# Parser regression: every case in ../cases.txt must parse (`moex parse`).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
CASE_FILE="${ROOT_DIR}/tests/regression/cases.txt"

require_moex

if [[ ! -f "${CASE_FILE}" ]]; then
  echo "missing cases file: ${CASE_FILE}"
  exit 2
fi

FAIL=0
while IFS= read -r relpath; do
  [[ -z "${relpath}" ]] && continue
  [[ "${relpath}" =~ ^# ]] && continue
  abspath="${ROOT_DIR}/${relpath}"
  if [[ ! -f "${abspath}" ]]; then
    echo "[skip] missing case ${relpath}"
    continue
  fi
  if ! "${MOEX_BIN}" parse "${abspath}"; then
    FAIL=1
  fi
done < "${CASE_FILE}"

if [[ "${FAIL}" -ne 0 ]]; then
  echo "regression: failed"
  exit 1
fi
echo "regression: passed"
