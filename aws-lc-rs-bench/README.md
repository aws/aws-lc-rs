# aws-lc-rs-bench

CI benchmarking tool for aws-lc-rs that measures CPU instruction counts using Valgrind's callgrind tool.

## Overview

This tool provides deterministic and reproducible benchmark results suitable for CI environments. It measures instruction counts rather than wall-clock time, which eliminates noise from varying system loads and makes it ideal for detecting performance regressions in pull requests.

## Requirements

- **Linux only**: The instruction counting feature requires Valgrind, which is only available on Linux.
- **Valgrind**: Install via `sudo apt-get install valgrind` on Debian/Ubuntu.

## Usage

### List available benchmarks

```bash
cargo run --release -p aws-lc-rs-bench -- list
```

### Run all benchmarks (instruction counting mode)

This runs all benchmarks under Valgrind's callgrind tool and outputs instruction counts:

```bash
cargo run --release -p aws-lc-rs-bench -- run-all --output-dir results
```

The output directory will contain:
- `results.csv` - CSV file with benchmark names and instruction counts
- `callgrind/` - Directory with callgrind output files for detailed analysis

### Run benchmarks in wall-time mode (for local testing)

For quick local testing without Valgrind:

```bash
cargo run --release -p aws-lc-rs-bench -- walltime --iterations 10
```

### Compare two benchmark runs

Generate a comparison report between a baseline and candidate run:

```bash
cargo run --release -p aws-lc-rs-bench -- compare baseline-results candidate-results
```

This outputs a Markdown report showing:
- Summary of changes
- Significant regressions (⚠️) and improvements (✅)
- Full results table

For JSON output:

```bash
cargo run --release -p aws-lc-rs-bench -- compare baseline-results candidate-results --format json
```

## FIPS Mode

To benchmark with FIPS support enabled:

```bash
cargo run --release -p aws-lc-rs-bench --features fips -- run-all --output-dir fips-results
```

## Benchmark Categories

The tool includes benchmarks for:

| Category | Operations |
|----------|------------|
| **AEAD** | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (seal/open, various sizes) |
| **Digest** | SHA-256, SHA-384, SHA-512 (various sizes, incremental) |
| **HMAC** | HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 (various sizes, verify) |
| **HKDF** | HKDF-SHA256, HKDF-SHA384 (key derivation) |
| **Agreement** | X25519, ECDH P-256, ECDH P-384 (keygen, agree) |
| **Signatures** | Ed25519, ECDSA P-256/P-384, RSA-2048 (keygen, sign, verify) |

## Significance Threshold

The default significance threshold is **2%**. Changes below this threshold are not flagged as significant in the comparison report.

## CI Integration

This tool is integrated into the GitHub Actions workflow (`.github/workflows/benchmarks.yml`) which:

1. Runs on every pull request and push to main
2. Benchmarks both x86_64 and aarch64 Linux targets
3. Runs both standard and FIPS builds
4. Posts comparison results as PR comments
5. Archives results for historical tracking

## Technical Details

### Why instruction counts?

Measuring CPU instructions provides several advantages over wall-clock time:

- **Deterministic**: Same code produces the same instruction count regardless of system load
- **Reproducible**: Results are consistent across runs
- **Low noise**: No interference from other processes or CPU frequency scaling
- **Sensitive**: Can detect small changes that would be lost in timing noise

### How it works

1. The tool spawns itself under Valgrind's callgrind tool
2. Callgrind is started with instrumentation disabled (`--collect-atstart=no`)
3. Each benchmark uses crabgrind client requests to enable/disable counting
4. Only the actual cryptographic operation is measured

## License

Apache-2.0 OR ISC