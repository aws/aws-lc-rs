# Requirements

This page outlines the requirements for using `aws-lc-rs` on each target platform.

`aws-lc-rs` uses [aws-lc-sys] or [aws-lc-fips-sys] to provide raw FFI bindings to [AWS-LC]. Thus,
there are additional build tools required for building these crates into your Rust application.

## Quick Summary

| Build Type | C/C++ Compiler | CMake | Bindgen | Go |
|------------|----------------|-------|---------|-----|
| **Non-FIPS** (`aws-lc-sys`) | Required | Never required | Never required | Never required |
| **FIPS** (`aws-lc-fips-sys`) | Required | Always required | Required* | Always required |

\* Bindgen is required for FIPS builds unless the target has pre-generated bindings.

### Pre-generated Bindings

**Non-FIPS (`aws-lc-sys`):** Pre-generated "universal" bindings are provided that cover all functions
used by `aws-lc-rs`. These bindings work across all supported platforms, so **bindgen is never
required** for `aws-lc-rs` users.

> **Note:** If you take a direct dependency on `aws-lc-sys` (not through `aws-lc-rs`), it defaults
> to using the more complete target-specific bindings. See the pre-generated bindings in
> [`aws-lc-sys/src/`](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-sys/src).

**FIPS (`aws-lc-fips-sys`):** Pre-generated bindings are available for a limited set of targets.
See the [Pre-generated FIPS Bindings](../platform_support.md#pre-generated-fips-bindings) table
on the Platform Support page for the full list. Bindgen is required for all other targets.

### Universal Bindings Subset

The pre-generated universal subset is stored in one `universal_crypto.rs`, shared by Apple
and non-Apple targets. This subset excludes platform-dependent items not used by `aws-lc-rs`:
`va_list` and its implementation types, `BIO_vsnprintf`, `OPENSSL_vasprintf`,
unused libc types, the `BN_DEC_FMT1`/`BN_HEX_FMT1`/`BN_HEX_FMT2` format constants, and the
architecture-specific `armv8_enable_dit`/`armv8_disable_dit` functions.

These items are no longer exported by the universal bindings. Direct `aws-lc-sys` consumers
using `default-features = false` who need them should enable `all-bindings` (the crate's
default feature). Also enable `bindgen` if the target has no pre-generated complete bindings.
The complete target-specific bindings and FIPS bindings retain their existing APIs.

### Tested Platforms

A mostly complete set of platforms for which we test our builds can be found in our
[CI workflow configuration](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/cross.yml).

## Platform-Specific Requirements

- [Linux](linux.md)
- [macOS & iOS](apple.md)
- [Windows](windows.md)

[aws-lc-sys]: https://crates.io/crates/aws-lc-sys

[aws-lc-fips-sys]: https://crates.io/crates/aws-lc-fips-sys

[AWS-LC]: https://github.com/aws/aws-lc
