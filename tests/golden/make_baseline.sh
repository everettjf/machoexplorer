#!/usr/bin/env bash
# Regenerate golden JSON baselines from the C++ oracle (build/moex-dump).
# Paths are passed relative to the repo root so the "file" field is stable.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ORACLE="${MOEX_ORACLE:-${ROOT_DIR}/build/moex-dump}"
OUT_DIR="${ROOT_DIR}/tests/golden/baseline"
cd "${ROOT_DIR}"
# Timestamps are rendered in local time; pin the zone for reproducibility.
export TZ=UTC
[[ -x "${ORACLE}" ]] || { echo "missing oracle: ${ORACLE}"; exit 2; }
mkdir -p "${OUT_DIR}"
for f in sample/simple sample/complex tests/corpus/bin/*; do
  name="$(basename "$f")"
  if "${ORACLE}" --format json --include-empty "$f" 2>"${OUT_DIR}/${name}.err" | gzip -n -9 >"${OUT_DIR}/${name}.json.gz"; then
    rm -f "${OUT_DIR}/${name}.err"
    echo "[ok] $f"
  else
    echo "[fail] $f"
  fi
done
