#!/usr/bin/env bash
# All Rust-tool regression checks. $1 (optional): dyld shared cache path for
# the cache tools smoke test.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${HERE}/run_regression.sh"
"${HERE}/run_cli_smoke.sh"
"${HERE}/run_cache_tools_smoke.sh" "${1:-}"
"${HERE}/run_crash_regression.sh"

echo "regression-all: passed"
