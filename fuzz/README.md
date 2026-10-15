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
