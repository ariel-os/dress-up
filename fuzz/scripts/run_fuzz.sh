#!/usr/bin/env bash
# run_fuzz.sh - Run already built fuzzer binary and export exit code and time‑to‑crash into a JSON file
# Usage: ./run_fuzz.sh <fuzz_target_name> -- [cargo-fuzz / LibFuzzer arguments]
# Example: ./run_fuzz.sh unaware -- -timeout=30 -max_total_time=3600
#
# IMPORTANT: build the target BEFORE calling this script, otherwise the build process will be counted into the runtime
#   --> cargo fuzz build <fuzz_target_name> <metrics_outfile>
#
# Execute from project root
# -------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <fuzz_target_name> <metrics_outfile> -- [cargo-fuzz / LibFuzzer arguments]"
  echo "  Example: $0 unaware results/metrics/time_to_exit.json -- -timeout=10 -max_total_time=3600"
  exit 2
fi

TARGET="$1"
OUTFILE="$2"
shift 2 || true

# set NO_CORPUS to 0 if it is not set
NO_CORPUS=${NO_CORPUS:-0}

# skip prepop corpora for targets
if [[ "${NO_CORPUS}" -eq 1 ]]; then
  echo "Skipping corpus copy for target ${TARGET} (NO_CORPUS variable set)"
  mkdir -p "fuzz/corpus/${TARGET}"
else
  # use prepop corpora for targets
  if [[ "${TARGET}" == "unaware" ]]; then
    mkdir -p "fuzz/corpus/${TARGET}"
    cp -r fuzz/corpus_complete_manifest/* fuzz/corpus/${TARGET}
  elif [[ "${TARGET}" == "envlp_wrap" ]]; then
    mkdir -p "fuzz/corpus/${TARGET}"
    cp -r fuzz/corpus_inner_manifest/* fuzz/corpus/${TARGET}
  fi
fi

LIBFUZZER_ARGS=()
echo "${1:-}"
if [[ "${1:-}" == "--" ]]; then
  shift
  LIBFUZZER_ARGS=("$@")
fi
printf '<%s>\n' "${LIBFUZZER_ARGS[@]}"

# Measure runtime for time-to-crash comparison
START_NS=$(date +%s%N)
set +e
echo "running command: cargo fuzz run ${TARGET} -- ${LIBFUZZER_ARGS[@]}"
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
