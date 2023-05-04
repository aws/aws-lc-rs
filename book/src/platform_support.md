# Platform Support

## Platforms with pre-generated bindings

`aws-lc-rs` can utilize pre-generated bindings when operating on the following
operating systems and CPU architecture combinations.

| OS    | Architecture |
|-------|--------------|
| macOS | x86-64       |
| Linux | x86-64       |
| Linux | x86          |
| Linux | aarch64      |

## Supported via `bindgen` feature.

`aws-lc-rs` can be utilized on the following platforms when built with the `bindgen` crate feature.

In addition to requiring a C/C++ compiler and CMake, LLVM is required to be installed.

```toml
[dependencies]
aws-lc-rs = { version = "1", features = ["bindgen"]}
```

| OS      | Architecture |
|---------|--------------|
| Windows | x86-64       |
| macOS   | aarch64      |
