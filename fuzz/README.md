# Fuzz

This directory contains fuzzing targets for dress-up as well as helper scripts, using [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer).

## Contents

### Targets
located in `fuzz_targets/`

#### pure mutation-based:

- `raw_unauth`: Tries to parse and call functions on an unauthenticated SUIT Manifest directly from arbitrary bytes.
- `raw_auth`: Tries to parse and call functions on an authenticated SUIT Manifest directly from arbitrary bytes.

#### structure-aware:
- `suit_manifest_auth`: Wraps arbitrary bytes into syntactically valid SUIT Envelope with valid authentication block. Tries to parse and call functions on an authenticated SUIT Manifest from this generated input.

### Helper Scripts
located in `scripts/`

- `run_fuzz.sh`: Runs the specified target and exports exit code and time-to-crash into a JSON file. (**Important**: build the target before running it with the script because otherwise the build process will be included in the measured time)
- `fuzz_cov.sh`: Generates code coverage reports (HTML and text) for specified target.
- `run_tests.sh`: Builds and runs all targets specified for the specified time and generates reports.

## Setup

Install Rust nightly toolchain:
```bash
rustup update nightly && rustup default nightly
```

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

Install llvm-tools (needed for coverage reports):
```bash
rustup component add --toolchain nightly llvm-tools-preview
```

## Usage

### Running targets

List available targets:
```bash
cargo fuzz list
```

Run a specific target:
```bash
cargo fuzz run <target_name>
```

Run with time limit (example: 60 seconds):
```bash
cargo fuzz run <target_name> -- -max_total_time=60
```

Run with timeout (example: 2 seconds):
```bash
cargo fuzz run <target_name> -- -timeout=2
```

### Measure runtime / time-to-crash

To get some metrics for evaluating the different targets, you can use the helper script `run_fuzz.sh`. This will run the specified target with your arguments and save the target name, exit code and elapsed time to a JSON file.

**Important**: For comparable results, you should build the target beforehand. Otherwise, the build process will be included in the measured time, which can distort the results.

Build the target:
```bash
cargo fuzz build <target_name>
```

Run the script (execute from project root):
```bash
./fuzz/scripts/run_fuzz.sh <target_name> -- [libFuzzer_arguments]
```
example:
```bash
./fuzz/scripts/run_fuzz.sh raw_unauth -- -timeout=30 -max_total_time=3600
```

The JSON with the results can then be found in `fuzz/results/metrics/`.

### Generate coverage reports

For an overview, how much of the projects code was covered by the specific target, the helper script `fuzz_cov.sh` will generate an HTML and a text code coverage report.

Run the script (execute from project root):
```bash
./fuzz/scripts/fuzz_cov.sh <target_name>
```

The coverage reports can then be found in `fuzz/results/cov_reports/`.

### Run tests locally

The script `run_tests.sh` will run all targets (or a specific list of targets) locally for a specified amount of time and generate the corresponding results / reports.

Run the script (execute from project root):
```bash
./fuzz/scripts/run_tests.sh <runtime> [TARGET ...]
```

- `<runtime>`: Amount of seconds for each target to run.
- `[TARGET ...]`: Optional list of targets that will be tested (if none provided, the script will test all available targets).

All results (including artifacts, corpora, coverage reports, metrics and the output from the targets) can be found in `fuzz/results/`.
