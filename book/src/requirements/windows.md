# Windows Requirements

| Platform                  | *default*                                  | **fips**                                | bindgen required? |
|---------------------------|--------------------------------------------|-----------------------------------------|-------------------|
| `x86_64-pc-windows-msvc`  | C/C++ Compiler, CMake & \*NASM             | C/C++ Compiler, CMake, NASM, Go & Ninja | No                | 
| `x86_64-pc-windows-gnu`   | C/C++ Compiler, CMake & \*NASM             | **Not Supported**                       | No                |
| `i686-pc-windows-msvc`    | C/C++ Compiler, CMake & NASM               | **Not Supported**                       | No                |
| `aarch64-pc-windows-msvc` | C/C++ Compiler (MSVC's `clang-cl`) & CMake | **Not Supported**                       | No                |
| _Other_                   | **Not Supported**                          | **Not Supported**                       | N/A               |

* The NASM assembler is recommended on `x86-64` platforms. NASM is required for `x86` and for "fips" builds. See the
  [Prebuilt NASM objects](#prebuilt-nasm-objects) section below.

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

### Use of prebuilt NASM objects

For Windows x86 and x86-64, NASM is required for assembly code compilation. On these platforms,
we recommend that you install [the NASM assembler](https://www.nasm.us/). If NASM is
detected in the build environment *it is used* to compile the assembly files. However,
if a NASM assembler is not available, and the "fips" feature is not enabled, then the build fails unless one of the
following conditions are true:

* You are building for `x86-64` and either:
    * The `AWS_LC_SYS_PREBUILT_NASM` environment variable is found and has a value of "1"; OR
    * `AWS_LC_SYS_PREBUILT_NASM` is *not found* in the environment AND the "prebuilt-nasm" feature has been enabled.

If the above cases apply, then the crate provided prebuilt NASM objects will be used for the build. To prevent usage of
prebuilt NASM
objects, install NASM in the build environment and/or set the variable `AWS_LC_SYS_PREBUILT_NASM` to `0` in the build
environment to prevent their use.

#### About prebuilt NASM objects

Prebuilt NASM objects are generated using automation similar to the crate provided pregenerated bindings. See the
repositories
[GitHub workflow configuration](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/sys-bindings-generator.yml)
for more information.
The prebuilt NASM objects are checked into the repository
and are [available for inspection](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-sys/builder/prebuilt-nasm).
For each PR submitted,
[CI verifies](https://github.com/aws/aws-lc-rs/blob/8fb6869fc7bde92529a5cca40cf79513820984f7/.github/workflows/tests.yml#L209-L241)
that the NASM objects newly built from source match the NASM objects currently in the repository.

### No-assembly build

It is possible to avoid the NASM requirement by setting the `AWS_LC_SYS_NO_ASM`/`AWS_LC_FIPS_SYS_NO_ASM` environment
variables. However, this severely impacts performance and can only be used for un-optimized/debug builds. See the
notes in our [troubleshooting section](../resources.md#troubleshooting).

## Ninja

1. [Download](https://github.com/ninja-build/ninja/releases) and install Ninja
2. Add the Ninja installation directory to your PATH
    * `set PATH="C:\ninja\ninja_build;%PATH%"`

## Bindgen

Bindgen is not required for most Windows targets, but it can still be used if needed.
Using `bindgen` requires a `libclang` or `llvm` package to be installed.
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

## FIPS build

Building with the "fips" feature on this platform will result in the creation of shared libraries (named like
`aws_lc_fips_0_xx_yy_crypto.dll` and `aws_lc_fips_0_xx_yy_rust_wrapper.dll`). These shared libraries will likely need to
be distributed alongside any executable that depends on **aws-lc-rs**.

## Troubleshooting

See our [troubleshooting section](../resources.md#troubleshooting).

[WIN_TOOLS]: https://aka.ms/vs/17/release/vs_BuildTools.exe
