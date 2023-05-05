# macOS Requirements

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

## LLVM (When building with `bindgen` feature)

### MacPorts

```shell
sudo port install clang
```

### Homebrew
```shell
brew install llvm
```

[XCODE]: https://developer.apple.com/xcode/resources/
