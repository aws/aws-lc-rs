# macOS & iOS Requirements

## Build Requirements

### Non-FIPS Builds (`aws-lc-sys`)

For non-FIPS builds on macOS and iOS:
- **C/C++ Compiler:** Required
- **CMake:** Never required
- **Bindgen:** Never required (universal pre-generated bindings are provided)
- **Go:** Never required

### FIPS Builds (`aws-lc-fips-sys`)

For FIPS builds on macOS:
- **C/C++ Compiler:** Required
- **CMake:** Always required
- **Go:** Always required
- **Bindgen:** Required unless target has pre-generated bindings (see list below)

> **Note:** FIPS is **not supported** on iOS targets.

#### Targets with Pre-generated FIPS Bindings

The following macOS targets have pre-generated bindings for `aws-lc-fips-sys`:
- `aarch64-apple-darwin`
- `x86_64-apple-darwin`

### Summary Table

| Platform               | *default*      | **fips**                   |
|------------------------|----------------|----------------------------|
| `aarch64-apple-darwin` | C/C++ Compiler | C/C++ Compiler, CMake & Go |
| `x86_64-apple-darwin`  | C/C++ Compiler | C/C++ Compiler, CMake & Go |
| `aarch64-apple-ios`    | C/C++ Compiler | **Not Supported**          |
| `x86_64-apple-ios`     | C/C++ Compiler | **Not Supported**          |

## C/C++ Compiler

Install [Command Line Tools for Xcode][XCODE] which provides a C/C++ compiler environment (LLVM).

## CMake

CMake is only required for FIPS builds on macOS.

### MacPorts

```shell
sudo port install cmake
```

### Homebrew

```shell
brew install cmake
```

## Go

Go is only required for FIPS builds.

### MacPorts

```shell
sudo port install go
```

### Homebrew

```shell
brew install go
```

## Bindgen (FIPS only)

Bindgen is only required for FIPS builds on platforms that do not have pre-generated bindings.
On most platforms, `bindgen` requires `libclang` or `llvm` package to be installed.
See the [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) page in
[The bindgen User Guide] for instructions.

### MacPorts

```shell
sudo port install clang
```

### Homebrew

```shell
brew install llvm
```

### bindgen-cli

```shell
cargo install --force --locked bindgen-cli
```

## FIPS Build Note

Building with the "fips" feature on macOS will result in the creation of shared libraries (named like
`libaws_lc_fips_0_xx_yy_crypto.dylib` and `libaws_lc_fips_0_xx_yy_rust_wrapper.dylib`). These shared libraries will
likely need to be distributed alongside any executable that depends on **aws-lc-rs**.

## Troubleshooting

See our [troubleshooting section](../resources.md#build-environment-variables).

[The bindgen User Guide]: https://rust-lang.github.io/rust-bindgen/

[XCODE]: https://developer.apple.com/xcode/resources/
