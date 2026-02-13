# Windows Requirements

## Build Requirements

For non-FIPS builds on Windows, the following requirements apply:

| Platform                  | *default*                      | **fips**                                     |
|---------------------------|--------------------------------|----------------------------------------------|
| `x86_64-pc-windows-msvc`  | C/C++ Compiler & \*NASM        | C/C++ Compiler, CMake, NASM, Go & Ninja      |
| `x86_64-pc-windows-gnu`   | C/C++ Compiler & \*NASM        | **Not Supported**                            |
| `i686-pc-windows-msvc`    | C/C++ Compiler & NASM          | **Not Supported**                            |
| `aarch64-pc-windows-msvc` | C/C++ Compiler (clang-cl)      | C/C++ Compiler (clang-cl), CMake, Go & Ninja |

\* NASM is recommended on x86-64 but can be avoided using prebuilt NASM objects. See the
[Prebuilt NASM objects](#prebuilt-nasm-objects) section below.

> **Note:** FIPS builds on Windows also require `bindgen`, as there are no pre-generated FIPS
> bindings for Windows platforms.
> See [Platform Support](../platform_support.md) for more details.

## C/C++ Compiler

Use the following instructions to download **Visual Studio Build Tools 2017** or later.

1. Download the [Build Tools for Visual Studio][WIN_TOOLS] installer.
2. Execute the installer.
3. If you have an existing installation chose `Modify` on the existing installation.
4. Under `Workloads` select `Visual C++ build tools`
5. Under `Individual components` select
    * `C++/CLI support`
    * `C++ CMake tools for Windows`
6. For ARM64/aarch64 support, also select:
    * `C++ Clang Compiler for Windows`
    * `MSBuild support for LLVM (clang-cl) toolset`
7. Confirm selections and click `Install`

### Alternative: Clang Compiler

As an alternative to MSVC, you can use the Clang compiler on Windows. This can be useful for cross-compilation
scenarios or when using MSYS2/MinGW environments. When using Clang:

* Install LLVM/Clang from [LLVM releases](https://github.com/llvm/llvm-project/releases) or via MSYS2
* Ensure `clang` or `clang-cl` is available in your PATH
* For MSYS2 environments, the `clang64` or `ucrt64` subsystems provide Clang toolchains

## CMake

CMake is only required for FIPS builds on Windows.

1. [Download](https://cmake.org/download/) Windows CMake Installer
2. Execute the installer
3. Add the CMake installation binary directory to your PATH.
    * `set PATH="C:\Program Files\CMake\bin;%PATH%"`

## NASM

NASM is required for x86 and x86-64 builds on Windows.

1. [Download](https://nasm.us/) and install the Netwide Assembler (NASM)
2. Add the NASM installation directory to your PATH
    * `set PATH="C:\Program Files\NASM;%PATH%"`

### Prebuilt NASM objects

> **Important:** Prebuilt NASM objects are **only** available for Windows platforms. They are **never** used on Linux, macOS, or any other platform.

> **Important:** If a NASM assembler is detected in your build environment, it is **always** used to compile assembly files. Prebuilt NASM objects are only used as a fallback when NASM is not available.

For Windows x86-64 (non-FIPS builds only), you can avoid installing NASM by using prebuilt NASM objects. 
The build will use prebuilt objects only when **all** of the following conditions are met:

1. No NASM assembler is found in the build environment
2. The "fips" feature is **not** enabled
3. The target is `x86_64-pc-windows-msvc` or `x86_64-pc-windows-gnu`
4. Either the `AWS_LC_SYS_PREBUILT_NASM` environment variable is set to `1`, **or** the `prebuilt-nasm` feature is enabled

To prevent usage of prebuilt NASM objects, install NASM in the build environment and/or set the variable 
`AWS_LC_SYS_PREBUILT_NASM` to `0` in the build environment.

#### About prebuilt NASM objects

Prebuilt NASM objects are generated using automation similar to the crate provided pregenerated bindings. See the
repository's
[GitHub workflow configuration](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/sys-bindings-generator.yml)
for more information.
The prebuilt NASM objects are checked into the repository
and are [available for inspection](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-sys/builder/prebuilt-nasm).
For each PR submitted,
[CI verifies](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/tests.yml)
that the NASM objects newly built from source match the NASM objects currently in the repository.

### No-assembly build

It is possible to avoid the NASM requirement by setting the `AWS_LC_SYS_NO_ASM`/`AWS_LC_FIPS_SYS_NO_ASM` environment
variables. However, this severely impacts performance and can only be used for un-optimized/debug builds. See the
notes in our [troubleshooting section](../resources.md#build-environment-variables).

## Go

Go is only required for FIPS builds.

1. [Download](https://go.dev/dl/) and install Go
2. Add the Go installation binary directory to your PATH
    * `set PATH="C:\Program Files\Go\bin;%PATH%"`

## Ninja

Ninja is only required for FIPS builds on Windows.

1. [Download](https://github.com/ninja-build/ninja/releases) and install Ninja
2. Add the Ninja installation directory to your PATH
    * `set PATH="C:\ninja\ninja_build;%PATH%"`

## Bindgen (FIPS only)

Bindgen is required for FIPS builds on Windows, as there are no pre-generated FIPS bindings for Windows platforms.
Using `bindgen` requires `libclang` or `llvm` to be installed.
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

## FIPS Build Note

Building with the "fips" feature on Windows will result in the creation of shared libraries (named like
`aws_lc_fips_0_xx_yy_crypto.dll` and `aws_lc_fips_0_xx_yy_rust_wrapper.dll`). These shared libraries will likely need to
be distributed alongside any executable that depends on **aws-lc-rs**.

## Troubleshooting

See our [troubleshooting section](../resources.md#build-environment-variables).

[WIN_TOOLS]: https://aka.ms/vs/17/release/vs_BuildTools.exe

[The bindgen User Guide]: https://rust-lang.github.io/rust-bindgen/
