# Fuzz

This directory contains fuzzing tests for dress-up, using [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (LibFuzzer).

## Contents

### Targets
located in `fuzz_targets/`:

- `unaware`: Tries to parse arbitrary bytes as a complete SUIT Manifest and executes dress-up functions on it.
- `envlp_wrap`: Wraps arbitrary bytes into syntactically valid SUIT Envelope with valid authentication and tries to parse and call functions on it.



## Setup

Install Rust nightly toolchain:
```bash
rustup update nightly && rustup default nightly
```

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```


## Usage

### Using Corpus

There exists one prepopulated corpus for each of the two targets:
- `corpus_complete_manifest`: contains examples of complete SUIT Manifests including envelope; used by the target `unaware`
- `corpus_inner_manifest`: contains examples of only inner manifests without envelope or auth bloc; used by the target `envlp_wrap`

The files contained in those directories can be used as "seed" for the target.

To use the prepopulated corpus, you need to copy it before running the corresponding target:
```bash
cp -r <corpus_prepop>/* <corpus_dir>
```

For example, for the `unaware` target (executed from project root):
```bash
cp -r fuzz/corpus_complete_manifest fuzz/corpus_unaware
```

### Running targets

List available targets:
```bash
cargo fuzz list
```

Run a specific target:
```bash
cargo fuzz run <target_name>
```

Run the target with a prepopulated corpus directory:
```bash
cargo fuzz run <target_name> -- <corpus_dir>
```

Run with time limit (example: 60 seconds):
```bash
cargo fuzz run <target_name> -- -max_total_time=60
```

Run with timeout (example: 2 seconds):
```bash
cargo fuzz run <target_name> -- -timeout=2
```

For other possible parameters, have a look at the [LibFuzzer docs](https://llvm.org/docs/LibFuzzer.html).


## Example

Running the target `envlp_wrap` (from project root):

Copy the corpus directory
```bash
cp -r fuzz/corpus_inner_manifest fuzz/corpus_envlp_wrap
```
Run the target with a timeout of 5 seconds for a total duration of 5 minutes on the seed corpus
```bash
cargo fuzz run envlp_wrap -- fuzz/corpus_envlp_wrap --timeout=5 -max_total_time=300
```


## Helper scripts

Run these scripts from the project root. The GitHub Actions workflow runs the targets weekly
(Sunday at 00:01 UTC) and generates coverage in a separate job.

### `run_tests.sh`

Configures the fuzzing run, calls the other two scripts, and logs the output. The runtime is
in seconds; if no targets are specified, all targets from `cargo fuzz list` are used.

```bash
./fuzz/scripts/run_tests.sh [--skip-cov] <runtime> [TARGET ...]
```

For example, run all targets for five minutes each, or skip coverage generation:

```bash
./fuzz/scripts/run_tests.sh 300
./fuzz/scripts/run_tests.sh --skip-cov 300 unaware envlp_wrap
```

Results are saved under a timestamped directory in `fuzz/results/`, including logs, metrics,
corpora, artifacts, and coverage reports (unless `--skip-cov` is used). The weekly CI workflow
skips coverage in the fuzzing jobs and generates it in the separate coverage job.

### Result directory structure

The CI workflow uploads each fuzz run's results as an artifact. After downloading and
extracting a CI artifact, its directory structure is:

- `artifacts/` and `corpus/`: The corresponding directories produced by the fuzzing run. **Note:** If empty (e.g. because no crash was registered by the fuzzer), the `artifacts/` directory is not added.
- `cov_reports/`: Text and HTML coverage reports for each target, plus combined reports when
  multiple targets are run.
- `metrics/`: One JSON file per target with the fuzzer's exit code and actual runtime, useful
  for seeing whether it crashed and how long it ran before exiting.
- `test_logs/`: The complete fuzzer output, preceded by information about the hardware running
  the tests.

### `run_fuzz.sh`

Prepares the prepopulated corpus for a target and runs it. When calling this script directly,
build the target first so the build time is not included in the measured runtime:

```bash
cargo fuzz build unaware
mkdir -p fuzz/results/metrics
./fuzz/scripts/run_fuzz.sh unaware fuzz/results/metrics/unaware.json -- -timeout=5 -max_total_time=300
```

The arguments are the target, a metrics JSON output path, then `--` and optional LibFuzzer
arguments. `unaware` uses `corpus_complete_manifest`; `envlp_wrap` uses `corpus_inner_manifest`.
Set `NO_CORPUS=1` to skip copying the prepopulated corpus.

### `fuzz_cov.sh`

Generates HTML and text coverage reports for the specified targets, and combined reports when
more than one target is provided. It requires the `llvm-tools-preview` Rust component.

```bash
rustup component add --toolchain nightly llvm-tools-preview
./fuzz/scripts/fuzz_cov.sh fuzz/results/cov_reports unaware envlp_wrap
```
