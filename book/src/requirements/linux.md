# Linux Requirements

Unless the "fips" feature is enabled, building aws-lc-rs v1.7.0 (or later) for the following targets should only require
a C/C++ compiler.

| Platform                     | *default*              | **fips**                   | bindgen required? |
|------------------------------|------------------------|----------------------------|-------------------|
| `aarch64-unknown-linux-gnu`  | C/C++ Compiler         | C/C++ Compiler, CMake & Go | No                | 
| `aarch64-unknown-linux-musl` | C/C++ Compiler         | C/C++ Compiler, CMake & Go | No                |
| `x86_64-unknown-linux-gnu`   | C/C++ Compiler         | C/C++ Compiler, CMake & Go | No                |
| `x86_64-unknown-linux-musl`  | C/C++ Compiler         | C/C++ Compiler, CMake & Go | No                |
| `i686-unknown-linux-gnu`     | C/C++ Compiler         | **Not Supported**          | No                |  
| _Other_                      | C/C++ Compiler & CMake | **Not Supported**          | **_Yes_**         |

## C/C++ Compiler

### Amazon Linux (AL2023)

```shell
sudo dnf groupinstall -y "Development Tools"
```

#### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y build-essential
```

## CMake & Go

#### Amazon Linux (AL2023)

```shell
sudo dnf install -y cmake golang
```

#### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y cmake golang
```

## Bindgen

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

See our [troubleshooting section](../resources.md#troubleshooting).

[The bindgen User Guide]: https://rust-lang.github.io/rust-bindgen/
