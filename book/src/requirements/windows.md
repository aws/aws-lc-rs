# Windows Requirements

| Platform                  | *default*                                  | **fips**                                | bindgen required? |
|---------------------------|--------------------------------------------|-----------------------------------------|-------------------|
| `x86_64-pc-windows-msvc`  | C/C++ Compiler, CMake & NASM               | C/C++ Compiler, CMake, NASM, Go & Ninja | **_Yes_**         | 
| `x86_64-pc-windows-gnu`   | C/C++ Compiler, CMake & NASM               | **Not Supported**                       | **_Yes_**         |
| `aarch64-pc-windows-msvc` | C/C++ Compiler (`clang-cl`), CMake & Ninja | **Not Supported**                       | **_Yes_**         |
| _Other_                   | **Not Supported**                          | **Not Supported**                       | N/A               |

## C/C++ Compiler

Use the following instructions to download **Visual Studio Build Tools 2017** or later.

1. Download the [Build Tools for Visual Studio][WIN_TOOLS] installer.
2. Execute the installer.
3. If you have an existing installation chose `Modify` on the existing installation.
4. Under `Workloads` select `Visual C++ build tools`
5. Under `Individual componenets` select
    * `C++/CLI support`
    * `C++ CMake tools for Windows`
6. For ARM64/aarch64 support, also select:
    * `C++ Clang Compiler for Windows`
    * `MSBuild support for LLVM (clang-cl) toolset`
7. Confirm selections and click `Install`

## CMake

1. [Download](https://cmake.org/download/) Windows CMake Installer
2. Execute the installer
3. Add the CMake installation binary directory to your PATH.
    * `set PATH="C:\Program Files\CMake\bin;%PATH%"`

## NASM

1. [Download](https://nasm.us/) and install the Netwide Assembler (NASM)
2. Add the NASM installation directory to your PATH
    * `set PATH="C:\Program Files\NASM;%PATH%"`

### No-assembly build

It is possible to avoid the NASM requirement by setting the `AWS_LC_SYS_NO_ASM`/`AWS_LC_FIPS_SYS_NO_ASM` environment
variables. However, this severely impacts performance and can only be used for un-optimized/debug builds. See the
notes in our [troubleshooting section](../resources.md#troubleshooting).

## Ninja

1. [Download](https://github.com/ninja-build/ninja/releases) and install Ninja
2. Add the Ninja installation directory to your PATH
    * `set PATH="C:\ninja\ninja_build;%PATH%"`

## Bindgen

On most platforms, `bindgen` requires `libclang` or `llvm` package to be installed.
See the [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) page in
[The bindgen User Guide] for instructions.

### libclang / LLVM

1. Download [LLVM Installer](https://github.com/llvm/llvm-project/releases/tag/llvmorg-15.0.6)
2. Execute the installer
3. Update your environment to set `LIBCLANG_PATH` to the bin directory inside LLVM install directory.
    * `set LIBCLANG_PATH="C:\Program Files\LLVM\bin"`

### bindgen-cli

```shell
cargo install --force --locked bindgen-cli
```

## Troubleshooting

See our [troubleshooting section](../resources.md#troubleshooting).

[WIN_TOOLS]: https://aka.ms/vs/17/release/vs_BuildTools.exe
