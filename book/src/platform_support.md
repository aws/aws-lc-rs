# Platform Support

## Pre-generated bindings

`aws-lc-rs` can utilize pre-generated bindings when operating on the following
build targets.

| Platform                     | `aws-lc-sys` | `aws-lc-fips-sys` | 
|------------------------------|--------------|-------------------|
| `aarch64-apple-darwin`       | ✓            | ✓                 | 
| `aarch64-pc-windows-msvc`    | ✓            | ✓ ²               |
| `aarch64-unknown-linux-gnu`  | ✓            | ✓                 |
| `aarch64-unknown-linux-musl` | ✓            | ✓                 |
| `i686-pc-windows-msvc`       | ✓            | **Not Supported** |
| `i686-unknown-linux-gnu`     | ✓            | **Not Supported** |
| `x86_64-apple-darwin`        | ✓            | ✓                 |             
| `x86_64-pc-windows-gnu`      | ✓            | **Not Supported** |
| `x86_64-pc-windows-msvc`     | ✓            | ✓ ²               |
| `x86_64-unknown-linux-gnu`   | ✓            | ✓                 |
| `x86_64-unknown-linux-musl`  | ✓            | ✓                 |

² FIPS is supported but requires bindgen (no pre-generated FIPS bindings are available for Windows platforms)

## Tested platforms

In addition to the platforms with pre-generated bindings listed above, `aws-lc-rs` CI builds and/or tests on many additional platforms.
See our [CI workflow configuration](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/cross.yml) for the complete list of tested platforms.

### Build Requirements Summary

**For non-FIPS builds (`aws-lc-sys`):**
- C/C++ Compiler: Required
- CMake: **Never** required
- Bindgen: **Never** required (universal pre-generated bindings are provided)
- Go: **Never** required

**For FIPS builds (`aws-lc-fips-sys`):**
- C/C++ Compiler: Required
- CMake: **Always** required
- Go: **Always** required
- Bindgen: Required **unless** the target has pre-generated bindings (see table above)

### Bindgen for FIPS Builds

For FIPS builds on targets without pre-generated bindings, one of the following options must be used for bindings generation.
See [requirements](requirements/README.md) page for more information.

* Enable `bindgen` feature in your `Cargo.toml`:

```toml
[dependencies]
aws-lc-rs = { version = "1", features = ["bindgen", "fips"] }
```

_**-- OR --**_

* Install `bindgen-cli` in the build environment:

```shell
cargo install --force --locked bindgen-cli
```

### Linux Platforms

| Platform                          | Build | Tests | FIPS  |
|-----------------------------------|-------|-------|-------|
| `aarch64-unknown-linux-gnu`       | ✓     | ✓     | ✓     |
| `aarch64-unknown-linux-musl`      | ✓     | ✓     | ✓     |
| `arm-unknown-linux-gnueabihf`     | ✓     | ✓     |       |
| `arm-unknown-linux-musleabi`      | ✓     | ✓     | ✓     |
| `arm-unknown-linux-musleabihf`    | ✓     | ✓     | ✓     |
| `armv7-unknown-linux-gnueabihf`   | ✓     | ✓     |       |
| `i686-unknown-linux-gnu`          | ✓     | ✓     |       |
| `mips-unknown-linux-gnu` ¹        | ✓     | ✓     |       |
| `mips-unknown-linux-musl` ¹       | ✓     | ✓     |       |
| `mips64-unknown-linux-muslabi64` ¹| ✓     | ✓     |       |
| `mips64el-unknown-linux-muslabi64` ¹| ✓   | ✓     |       |
| `powerpc-unknown-linux-gnu`       | ✓     | ✓     | ✓     |
| `powerpc64-unknown-linux-gnu`     | ✓     | ✓     | ✓     |
| `powerpc64le-unknown-linux-gnu`   | ✓     | ✓     | ✓     |
| `riscv64gc-unknown-linux-gnu`     | ✓     | ✓     |       |
| `s390x-unknown-linux-gnu`         | ✓     | ✓     |       |
| `x86_64-unknown-linux-gnu`        | ✓     | ✓     | ✓     |
| `x86_64-unknown-linux-musl`       | ✓     | ✓     | ✓     |

¹ Requires nightly Rust toolchain

### Apple Platforms

| Platform                  | Build | Tests | FIPS  |
|---------------------------|-------|-------|-------|
| `aarch64-apple-darwin`    | ✓     | ✓     | ✓     |
| `aarch64-apple-ios`       | ✓     | ✓     |       |
| `aarch64-apple-ios-sim`   | ✓     | ✓     |       |
| `aarch64-apple-tvos-sim` ¹| ✓     | ✓     |       |
| `x86_64-apple-darwin`     | ✓     | ✓     | ✓     |
| `x86_64-apple-ios`        | ✓     |       |       |

¹ Requires nightly Rust toolchain

### Windows Platforms

| Platform                  | Build | Tests | FIPS  |
|---------------------------|-------|-------|-------|
| `aarch64-pc-windows-msvc` | ✓     | ✓     | ✓     |
| `i686-pc-windows-msvc`    | ✓     | ✓     |       |
| `x86_64-pc-windows-gnu`   | ✓     | ✓     |       |
| `x86_64-pc-windows-msvc`  | ✓     | ✓     | ✓     |

### Android Platforms

| Platform                  | Build | Tests |
|---------------------------|-------|-------|
| `aarch64-linux-android`   | ✓     | ✓     |
| `arm-linux-androideabi`   | ✓     | ✓     |
| `armv7-linux-androideabi` | ✓     | ✓     |
| `i686-linux-android`      | ✓     |       |
| `x86_64-linux-android`    | ✓     |       |

### BSD Platforms

| Platform                  | Build | Tests | FIPS  |
|---------------------------|-------|-------|-------|
| `x86_64-unknown-freebsd`  | ✓     | ✓     | ✓     |
| `x86_64-unknown-netbsd`   | ✓     | ✓     |       |

### Other Platforms

| Platform                  | Build | Tests |
|---------------------------|-------|-------|
| `x86_64-unknown-illumos`  | ✓     | ✓     |
| OpenHarmony (aarch64)     | ✓     |       |
| OpenWrt (aarch64-musl)    | ✓     |       |
| Alpine Linux              | ✓     | ✓     |
