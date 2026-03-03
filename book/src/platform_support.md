# Platform Support

## Non-FIPS Builds (`aws-lc-sys`)

For non-FIPS builds, `aws-lc-sys` provides **universal pre-generated bindings** that work across
**all** supported platforms. Bindgen is never required, CMake is never required, and Go is never
required. The only build requirement is a C/C++ compiler.

This means that if your target platform is supported by both [AWS-LC] and the
[Rust compiler (with std support)][platform-support], `aws-lc-rs` should work out of the box
without any additional tooling beyond a C/C++ compiler.

## FIPS Builds (`aws-lc-fips-sys`)

FIPS builds always require **CMake** and **Go** in addition to a C/C++ compiler. FIPS builds also
require **bindgen** unless pre-generated bindings are available for the target platform.

### Pre-generated FIPS Bindings

Pre-generated bindings for `aws-lc-fips-sys` are available for the following targets. All other
FIPS targets require bindgen.

| Platform                     | Pre-generated FIPS Bindings |
|------------------------------|-----------------------------|
| `aarch64-apple-darwin`       | ✓                           |
| `aarch64-pc-windows-msvc`    | ✗ (bindgen required) ¹      |
| `aarch64-unknown-linux-gnu`  | ✓                           |
| `aarch64-unknown-linux-musl` | ✓                           |
| `x86_64-apple-darwin`        | ✓                           |
| `x86_64-pc-windows-msvc`     | ✗ (bindgen required) ¹      |
| `x86_64-unknown-linux-gnu`   | ✓                           |
| `x86_64-unknown-linux-musl`  | ✓                           |

¹ FIPS is supported on this platform but requires bindgen (no pre-generated FIPS bindings are available for Windows platforms)

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

## Tested Platforms

`aws-lc-rs` CI builds and/or tests on many platforms beyond those listed in the FIPS bindings table above.
See our [CI workflow configuration](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/cross.yml) for the complete list of tested platforms.

### Build Requirements Summary

| Requirement       | Non-FIPS (`aws-lc-sys`)            | FIPS (`aws-lc-fips-sys`)                                  |
|-------------------|------------------------------------|-----------------------------------------------------------|
| C/C++ Compiler    | Required                           | Required                                                  |
| CMake             | **Never** required                 | **Always** required                                       |
| Bindgen           | **Never** required (universal pre-generated bindings) | Required unless target has pre-generated bindings |
| Go                | **Never** required                 | **Always** required                                       |

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

[AWS-LC]: https://github.com/aws/aws-lc
[platform-support]: https://doc.rust-lang.org/rustc/platform-support.html
