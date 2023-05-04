# Windows Requirements

## C/C++ Compiler

Use the following instructions to download **Visual Studio Build Tools 2017**.

**NOTE**: Visual Studio Build Tools 2022 is **NOT** supported at this time.

1. Download the [Build Tools for Visual Studio][WIN_TOOLS] installer.
2. Execute the installer.
3. If you have an existing installation chose `Modify` on the existing installation.
4. Under `Workloads` select `Visual C++ build tools`
5. Under `Individual componenets` select
   * `C++/CLI support` 
   * `C++ CMake tools for Windows`
6. Confirm selections and click `Install`

## CMake

1. [Download](https://cmake.org/download/) Windows CMake Installer
2. Execute the installer
3. Add the CMake installation binary directory to your PATH.
   * `set PATH="C:\Program Files\CMake\bin;%PATH%"`

## NASM
1. [Download](https://nasm.us/) and install the Netwide Assembler (NASM)
2. Add the NASM installation directory to your PATH
   * `set PATH="C:\Program Files\NASM;%PATH%"`

## LLVM (When building with `bindgen` feature)

1. Download [LLVM Installer](https://github.com/llvm/llvm-project/releases/tag/llvmorg-15.0.6)
2. Execute the installer
3. Update your environment to set `LIBCLANG_PATH` to the bin directory inside LLVM install directory.
   * `set LIBCLANG_PATH="C:\Program Files\LLVM\bin"`

[WIN_TOOLS]: https://aka.ms/vs/15/release/vs_BuildTools.exe
