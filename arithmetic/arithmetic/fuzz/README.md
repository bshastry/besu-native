# Arithmetic Fuzzing

Fuzz testing for the besu-native-arithmetic library using cargo-fuzz.

## Quick Start

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer (requires nightly Rust)
cargo +nightly fuzz run modexp_fuzzer
```

## Build Instructions

```bash
# Build the fuzzer
cargo +nightly fuzz build modexp_fuzzer

# Build with raw bytes mode
cargo +nightly fuzz build modexp_fuzzer --features raw_bytes_fuzzing
```

## Run Modes

### Structured Fuzzing (Default)
Tests with well-formed mathematical inputs:
```bash
cargo +nightly fuzz run modexp_fuzzer
```

### Raw Bytes Fuzzing
Tests arbitrary byte sequences:
```bash
cargo +nightly fuzz run modexp_fuzzer --features raw_bytes_fuzzing
```

## Common Commands

```bash
# Run with limited iterations
cargo +nightly fuzz run modexp_fuzzer -- -runs=100000

# Run with timeout
cargo +nightly fuzz run modexp_fuzzer -- -max_total_time=300

# Generate coverage report
cargo +nightly fuzz coverage modexp_fuzzer

# Minimize a crash input
cargo +nightly fuzz tmin modexp_fuzzer artifacts/modexp_fuzzer/crash-*
```

## Debugging Crashes

```bash
# Reproduce a crash
cargo +nightly fuzz run modexp_fuzzer artifacts/modexp_fuzzer/crash-*

# Debug with backtrace
RUST_BACKTRACE=1 cargo +nightly fuzz run modexp_fuzzer artifacts/modexp_fuzzer/crash-*
```

## Files

- `fuzz_targets/modexp_fuzzer.rs` - Main fuzzer implementation
- `corpus/` - Input corpus directory (auto-created)
- `artifacts/` - Crash/timeout/slow inputs (auto-created)
- `coverage/` - Coverage data (when using coverage command)
