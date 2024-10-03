# Platform Support

## Pre-generated bindings

`aws-lc-rs` can utilize pre-generated bindings when operating on the following
build targets.

| Platform                     | `aws-lc-sys` | `aws-lc-fips-sys` | 
|------------------------------|--------------|-------------------|
| `aarch64-apple-darwin`       | X            | X                 | 
| `aarch64-pc-windows-msvc`    | X            | **Not Supported** |
| `aarch64-unknown-linux-gnu`  | X            | X                 |
| `aarch64-unknown-linux-musl` | X            | X                 |
| `i686-pc-windows-msvc`       | X            | **Not Supported** |
| `i686-unknown-linux-gnu`     | X            | **Not Supported** |
| `x86_64-apple-darwin`        | X            | X                 |             
| `x86_64-pc-windows-gnu`      | X            | **Not Supported** |
| `x86_64-pc-windows-msvc`     | X            |                   |
| `x86_64-unknown-linux-gnu`   | X            | X                 |
| `x86_64-unknown-linux-musl`  | X            | X                 |

## Tested platforms

In addition to the ones listed above, the  `aws-lc-rs` CI builds and/or tests with the following platforms.
All platforms listed below require `CMake` to be available in the build environment.
They also require bindings to be generated during the build process.

### bindgen

One of the following options must be used for bindings generation.
See [requirements](requirements/README.md) page for more information.

* Enable `bindgen` feature in your `Cargo.toml`:

```toml
[dependencies]
aws-lc-rs = { version = "1", features = ["bindgen"] }
```

_**-- OR --**_

* Install `bindgen-cli` in the build envionment:

```shell
cargo install --force --locked bindgen-cli
```

### Platforms

| Platform                        | Build | Tests |  
|---------------------------------|-------|-------|
| `aarch64-apple-ios`             | X     | X     |
| `aarch64-linux-android`         | X     | X     |
| `aarch64-pc-windows-msvc`       | X     |       | 
| `armv7-linux-androideabi`       | X     | X     | 
| `arm-linux-androideabi`         | X     | X     |
| `arm-unknown-linux-gnueabihf`   | X     | X     |
| `powerpc64le-unknown-linux-gnu` | X     | X     | 
| `powerpc64-unknown-linux-gnu`   | X     | X     |
| `powerpc-unknown-linux-gnu`     | X     | X     |
| `riscv64gc-unknown-linux-gnu`   | X     | X     |
| `s390x-unknown-linux-gnu`       | X     | X     |
| `x86_64-apple-ios`              | X     |       |
| `x86_64-pc-windows-gnu`         | X     | X     |
| `x86_64-pc-windows-msvc`        | X     | X     |
