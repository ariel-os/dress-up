#!/usr/bin/env bash
# run_tests.sh – Run list of fuzzing targets for specific time
# Usage: ./run_tests.sh <runtime> [TARGET ...]
#
# Execute from project root
#----------------------------------------------------------

set -euo pipefail

usage() {
  echo "Usage: $0 RUNTIME [TARGET ...]"
  echo "  RUNTIME: value passed to -max_total_time (e.g. 60, 300)"
  echo "  TARGET:  optional list of cargo-fuzz targets; if omitted uses: cargo fuzz list"
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

RUNTIME="$1"
shift || true

# Dates/paths
DATE="$(date +%F)"              # YYYY-MM-DD
DATE_TIME="$(date +%F_%H-%M-%S)" # safe for filenames

LOG_DIR="fuzz/results/test_logs/${DATE}"
CORPUS_RESULTS_DIR="fuzz/results/corpus/${DATE}"
ARTIFACTS_RESULTS_DIR="fuzz/results/artifacts/${DATE}"

mkdir -p "${LOG_DIR}" "${CORPUS_RESULTS_DIR}" "${ARTIFACTS_RESULTS_DIR}"

# Backup existing corpus/artifacts at beginning
if [[ -d "fuzz/corpus" ]]; then
  rm -rf "fuzz/corpus_bkp"
  mv "fuzz/corpus" "fuzz/corpus_bkp"
fi

if [[ -d "fuzz/artifacts" ]]; then
  rm -rf "fuzz/artifacts_bkp"
  mv "fuzz/artifacts" "fuzz/artifacts_bkp"
fi

# Build target list
if [[ $# -gt 0 ]]; then
  TARGETS=("$@")
else
  mapfile -t TARGETS < <(cargo fuzz list)
fi

# Run targets
for target in "${TARGETS[@]}"; do
  [[ -n "${target}" ]] || continue

  echo "Running target: ${target}"
  cargo fuzz build "${target}"

  LOG_FILE="${LOG_DIR}/testrun_${DATE_TIME}_${target}.txt"

  {
    echo "runtime=${RUNTIME}"
    echo "target=${target}"
    echo "date_time=${DATE_TIME}"
    echo "command=./fuzz/scripts/run_fuzz.sh ${target} -- -timeout=10 -max_total_time=${RUNTIME}"
    echo "----------------------------------------"
  } | tee "${LOG_FILE}" >/dev/null

  ./fuzz/scripts/run_fuzz.sh "${target}" -- -timeout=10 -max_total_time="${RUNTIME}" 2>&1 | tee -a "${LOG_FILE}"

  ./fuzz/scripts/fuzz_cov.sh "${target}"
done

# Move resulting corpus/artifacts to results at end
# If destination exists, add a timestamp suffix to avoid clobbering.
move_dir_if_exists() {
  local src="$1"
  local dst_dir="$2"   # directory that should contain the moved folder (date dir)
  local name="$3"      # corpus/artifacts

  [[ -d "${src}" ]] || return 0

  local dst="${dst_dir}/${name}_${DATE_TIME}"
  mv "${src}" "${dst}"
}

move_dir_if_exists "fuzz/corpus"    "${CORPUS_RESULTS_DIR}"    "corpus"
move_dir_if_exists "fuzz/artifacts" "${ARTIFACTS_RESULTS_DIR}" "artifacts"
