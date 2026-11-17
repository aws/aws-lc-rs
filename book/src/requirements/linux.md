# Linux Requirements

## Build Requirements

### Non-FIPS Builds (`aws-lc-sys`)

For non-FIPS builds on Linux:
- **C/C++ Compiler:** Required
- **CMake:** Never required
- **Bindgen:** Never required (universal pre-generated bindings are provided)
- **Go:** Never required

### FIPS Builds (`aws-lc-fips-sys`)

For FIPS builds on Linux:
- **C/C++ Compiler:** Required
- **CMake:** Always required
- **Go:** Always required
- **Bindgen:** Required unless target has pre-generated bindings (see list below)

#### Targets with Pre-generated FIPS Bindings

The following Linux targets have pre-generated bindings for `aws-lc-fips-sys`:
- `aarch64-unknown-linux-gnu`
- `aarch64-unknown-linux-musl`
- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`

For other Linux targets using FIPS, bindgen is required.

### Summary Table

| Platform                     | *default*      | **fips**                              |
|------------------------------|----------------|---------------------------------------|
| `aarch64-unknown-linux-gnu`  | C/C++ Compiler | C/C++ Compiler, CMake & Go            |
| `aarch64-unknown-linux-musl` | C/C++ Compiler | C/C++ Compiler, CMake & Go            |
| `x86_64-unknown-linux-gnu`   | C/C++ Compiler | C/C++ Compiler, CMake & Go            |
| `x86_64-unknown-linux-musl`  | C/C++ Compiler | C/C++ Compiler, CMake & Go            |
| Other Linux targets          | C/C++ Compiler | C/C++ Compiler, CMake, Go & Bindgen   |

## C/C++ Compiler

### Amazon Linux (AL2023)

```shell
sudo dnf groupinstall -y "Development Tools"
```

### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y build-essential
```

## CMake & Go

CMake and Go are only required for FIPS builds.

### Amazon Linux (AL2023)

```shell
sudo dnf install -y cmake golang
```

### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y cmake golang
```

## Bindgen (FIPS only)

Bindgen is only required for FIPS builds on platforms that do not have pre-generated bindings.
On most platforms, `bindgen` requires `libclang` or `llvm` package to be installed.
See the [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) page in
[The bindgen User Guide] for instructions.

### libclang / LLVM

#### Amazon Linux (AL2023)

```shell
sudo dnf install -y clang-libs
```

#### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y libclang1
```

### bindgen-cli

```shell
cargo install --force --locked bindgen-cli
```

## Troubleshooting

See our [troubleshooting section](../resources.md#build-environment-variables).

### Yocto SDK

The Yocto SDK's `cargo` wrapper sets `LD_LIBRARY_PATH` to the SDK's library directories, which can cause host
executables (e.g., `/bin/sh`) to fail with glibc symbol lookup errors. When `OECORE_NATIVE_SYSROOT` is set, the
build script removes those entries from `LD_LIBRARY_PATH` for CMake and the other tools it runs (including an
external `bindgen`).

`aws-lc-fips-sys`, and `aws-lc-sys` with its default `all-bindings` feature, require bindgen for targets without
pre-generated bindings (e.g., `x86_64-poky-linux-gnu`); `aws-lc-rs` uses the universal bindings instead. If libclang
is not part of the SDK, point bindgen at a host installation and the target sysroot, for example:

```shell
export LIBCLANG_PATH=/usr/lib64
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$OECORE_TARGET_SYSROOT -isystem /usr/lib64/clang/<version>/include"
```

[The bindgen User Guide]: https://rust-lang.github.io/rust-bindgen/
