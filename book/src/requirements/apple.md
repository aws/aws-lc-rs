# macOS & iOS Requirements

Unless the "fips" feature is enabled, building aws-lc-rs v1.7.0 (or later) for macOS targets should only require
a C/C++ compiler. Builds for iOS will also require CMake.

| Platform               | *default*              | **fips**                   | bindgen required? |
|------------------------|------------------------|----------------------------|-------------------|
| `aarch64-apple-darwin` | C/C++ Compiler         | C/C++ Compiler, CMake & Go | No                | 
| `x86_64-apple-darwin`  | C/C++ Compiler         | C/C++ Compiler, CMake & Go | No                |
| `aarch64-apple-ios`    | C/C++ Compiler & CMake | **Not Supported**          | **_Yes_**         |
| `x86_64-apple-ios`     | C/C++ Compiler & CMake | **Not Supported**          | **_Yes_**         |

## C/C++ Compiler

Install [Command Line Tools for Xcode][XCODE] which a provides a C/C++ compiler environment (LLVM).

## CMake

### MacPorts

```shell
sudo port install cmake
```

### Homebrew

```shell
brew install cmake
```

## Bindgen

On most platforms, `bindgen` requires `libclang` or `llvm` package to be installed.
See the [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) page in
[The bindgen User Guide] for instructions.

####

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

## FIPS build

Building with the "fips" feature on this platform will result in the creation of shared libraries (named like
`libaws_lc_fips_0_xx_yy_crypto.dylib` and `libaws_lc_fips_0_xx_yy_rust_wrapper.dylib`). These shared libraries will
likely need to be distributed alongside any executable that depends on **aws-lc-rs**.

## Troubleshooting

See our [troubleshooting section](../resources.md#troubleshooting).

[The bindgen User Guide]: https://rust-lang.github.io/rust-bindgen/

[XCODE]: https://developer.apple.com/xcode/resources/
