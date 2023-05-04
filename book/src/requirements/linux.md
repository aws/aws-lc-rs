# Linux Requirements

## C/C++ Compiler

### Amazon Linux (AL2023)

```shell
sudo dnf install -y gcc gcc-c++
```

#### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y gcc g++
```

## CMake

#### Amazon Linux (AL2023)

```shell
sudo dnf install -y cmake
```

#### Ubuntu (22.04 LTS)

```shell
sudo apt-get install -y cmake
```

## LLVM (When building with `bindgen` feature)

### Amazon Linux (AL2023)
```shell
sudo dnf install -y clang-libs
```

#### Ubuntu (22.04 LTS)
```shell
sudo apt-get install -y libclang1
```