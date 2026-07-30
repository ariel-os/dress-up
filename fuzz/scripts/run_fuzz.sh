#!/usr/bin/env bash
# run_fuzz.sh - Run already built fuzzer binary and export exit code and time‑to‑crash into a JSON file
# Usage: ./run_fuzz.sh <fuzz_target_name> -- [cargo-fuzz / LibFuzzer arguments]
# Example: ./run_fuzz.sh raw_unauth -- -timeout=30 -max_total_time=3600
#
# IMPORTANT: build the target BEFORE calling this script, otherwise the build process will be counted into the runtime
#   --> cargo fuzz build <fuzz_target_name>
#
# Execute from project root
# -------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <fuzz_target_name> -- [cargo-fuzz / LibFuzzer arguments]"
  echo "  Example: $0 raw_unauth -- -timeout=10 -max_total_time=3600"
  exit 2
fi

# Targets that need prepopulated corpora
PREPOP_TARGETS=(
  raw_auth
  raw_unauth
)

TARGET="$1"
METRICS_DIR="fuzz/results/metrics/$(date +%Y-%m-%d)"
OUTFILE="${METRICS_DIR}/$(date +%Y-%m-%d_%H%M%S)_${TARGET}_time_to_exit.json"
shift || true

# Prepopulate corpus if needed for target
for pre in "${PREPOP_TARGETS[@]}"; do
  if [[ "${TARGET}" == "${pre}" ]]; then
    mkdir -p "fuzz/corpus/${TARGET}"
    cp -r fuzz/corpus_prepop/* fuzz/corpus/${TARGET}
  fi
done

LIBFUZZER_ARGS=()
echo "${1:-}"
if [[ "${1:-}" == "--" ]]; then
  shift
  LIBFUZZER_ARGS=("$@")
fi
echo "${LIBFUZZER_ARGS}"

mkdir -p "${METRICS_DIR}"

# Measure runtime for time-to-crash comparison
START_NS=$(date +%s%N)
set +e
cargo fuzz run "${TARGET}" -- "${LIBFUZZER_ARGS[@]}"
RC=$?
set -e
END_NS=$(date +%s%N)

ELAPSED_NS=$((END_NS - START_NS))
ELAPSED_MS=$((ELAPSED_NS / 1000000))

# Write metrics to JSON
cat > "$OUTFILE" <<EOF
{
  "target": "${TARGET}",
  "exit_code": ${RC},
  "elapsed_ms": ${ELAPSED_MS}
}
EOF

echo "Wrote ${OUTFILE}"
exit "${RC}"
