#!/usr/bin/env bash
# run_tests.sh – Run list of fuzzing targets for specific time
# Usage: ./run_tests.sh [--skip-cov] <runtime> [TARGET ...]
#
# Execute from project root
#----------------------------------------------------------

set -euo pipefail

# Extract optional flags and keep positional arguments
SKIP_COV=0
POSITIONAL_ARGS=()

for arg in "$@"; do
  case $arg in
    --skip-cov)
      SKIP_COV=1
      ;;
    *)
      POSITIONAL_ARGS+=("$arg")
      ;;
  esac
done

# Restore positional parameters (runtime and targets)
if [[ ${#POSITIONAL_ARGS[@]} -gt 0 ]]; then
  set -- "${POSITIONAL_ARGS[@]}"
else
  set --
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 [--skip-cov] <runtime> [TARGET ...]"
  echo "  --skip-cov: optionally skip generating coverage reports"
  echo "  <runtime>:  value passed to -max_total_time (e.g. 60, 300)"
  echo "  TARGET:     optional list of cargo-fuzz targets; if omitted uses: cargo fuzz list"
  exit 2
fi

TEST_ARGS=(
  -seed=0
  -max_len=2048
  -timeout=5
  -rss_limit_mb=2048
  -print_final_stats=1
)

RUNTIME="$1"
shift || true

# Dates/paths
DATE="$(date +%F)"
DATE_TIME="$(date +%F_%H-%M-%S)"

RESULTS_DIR="fuzz/results/${DATE}/${DATE_TIME}"
LOG_DIR="${RESULTS_DIR}/test_logs"
COV_DIR="${RESULTS_DIR}/cov_reports"
METRICS_DIR="${RESULTS_DIR}/metrics"

# Use venv if existing
if [[ -d ".venv" ]]; then
  source .venv/bin/activate
fi

mkdir -p \
  "${LOG_DIR}" \
  "${COV_DIR}" \
  "${METRICS_DIR}"

# Backup existing corpus/artifacts at beginning
if [[ -d "fuzz/corpus" ]]; then
  echo "Backing up fuzz/corpus -> fuzz/corpus_bkp_${DATE_TIME}"
  mv "fuzz/corpus" "fuzz/corpus_bkp_${DATE_TIME}"
fi

if [[ -d "fuzz/artifacts" ]]; then
  echo "Backing up fuzz/artifacts -> fuzz/artifacts_bkp_${DATE_TIME}"
  mv "fuzz/artifacts" "fuzz/artifacts_bkp_${DATE_TIME}"
fi

# Build target list
if [[ $# -gt 0 ]]; then
  TARGETS=("$@")
else
  mapfile -t TARGETS < <(cargo fuzz list)
fi

echo "======================="
echo "=== Running Targets ==="
echo "======================="

# Run targets
for target in "${TARGETS[@]}"; do
  [[ -n "${target}" ]] || continue

  echo "Running target: ${target}"
  cargo fuzz build "${target}"

  METRICS_OUTFILE="${METRICS_DIR}/${target}_time_to_exit.json"
  COV_REP_NAME="${target}_cov"

  LOG_FILE="${LOG_DIR}/testrun_${target}.txt"


  cat > "$LOG_FILE" <<EOF

=== Target Information ===

runtime=${RUNTIME}
target=${target}
date_time=${DATE_TIME}
command=./fuzz/scripts/run_fuzz.sh ${target} ${METRICS_OUTFILE} -- ${TEST_ARGS[@]} -max_total_time=${RUNTIME}

----------------------------------------

=== Run Log ===

EOF

  set +e
  ./fuzz/scripts/run_fuzz.sh \
    "${target}" \
    "${METRICS_OUTFILE}" \
    -- \
    "${TEST_ARGS[@]}" \
    -max_total_time="${RUNTIME}" \
    2>&1 | \
    awk '{ print systime(), $0; fflush() }' | \
    tee -a "${LOG_FILE}"
  set -e

done

# Generate coverage reports on default
# --> will be skipped in CI and done in separate job
if [[ "${SKIP_COV}" -eq 0 ]]; then
  echo "==================================="
  echo "=== Generating Coverage Reports ==="
  echo "==================================="

  # Generate coverage reports
  ./fuzz/scripts/fuzz_cov.sh "${COV_DIR}" "${TARGETS[@]}"
else
  echo "==================================="
  echo "=== Skipping Coverage Reports   ==="
  echo "==================================="
fi

# Move corpus and artifact directories to results directory
mv "fuzz/corpus" "${RESULTS_DIR}"
mv "fuzz/artifacts" "${RESULTS_DIR}"
