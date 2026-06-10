#!/usr/bin/env bash
# run_time_fuzz.sh - Run already built fuzzer binary and export exit code and time‑to‑crash into a JSON file
# Usage: ./run_time_fuzz.sh <fuzz_target_name> -- [cargo-fuzz / LibFuzzer arguments]
# Example: ./run_time_fuzz.sh suit_fuzz_unauth -- -timeout=30 -max_total_time=3600
#
# IMPORTANT: build the target BEFORE calling this script, otherwise the build process will be counted into the runtime 
#   --> cargo fuzz build <fuzz_target_name>
#
# Execute from project root
# -------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <fuzz_target_name> -- [cargo-fuzz / LibFuzzer arguments]"
  echo "  Example: $0 suit_fuzz_unauth -- -timeout=10 -max_total_time=3600"
  exit 2
fi

TARGET="$1"
METRICS_DIR="fuzz/results/metrics/$(date +%Y-%m-%d_%H%M%S)"
OUTFILE="${METRICS_DIR}/${TARGET}_time_to_exit.json"
shift || true

LIBFUZZER_ARGS=()
echo "${1:-}"
if [[ "${1:-}" == "--" ]]; then
  shift
  LIBFUZZER_ARGS=("$@")
fi
echo "${LIBFUZZER_ARGS}"

mkdir -p "${METRICS_DIR}"

START_NS=$(date +%s%N)
set +e
cargo fuzz run "${TARGET}" -- "${LIBFUZZER_ARGS[@]}"
RC=$?
set -e
END_NS=$(date +%s%N)

ELAPSED_NS=$((END_NS - START_NS))
ELAPSED_MS=$((ELAPSED_NS / 1000000))

cat > "$OUTFILE" <<EOF
{
  "target": "${TARGET}",
  "exit_code": ${RC},
  "elapsed_ms": ${ELAPSED_MS}
}
EOF

echo "Wrote ${OUTFILE}"
exit "${RC}"
