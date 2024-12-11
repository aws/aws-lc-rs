# aws-lc-sys

[![crates.io](https://img.shields.io/crates/v/aws-lc-sys.svg)](https://crates.io/crates/aws-lc-sys)
[![GitHub](https://img.shields.io/badge/GitHub-aws%2Faws--lc--rs-blue)](https://github.com/aws/aws-lc-rs)

**Autogenerated** Low-level bindings to the AWS-LC library for the Rust programming language. The versioning for this
crate will be unstable.
New releases of AWS-LC will correspond to a new `0.x.0` version of this crate. Features and/or fixes from AWS-LC
will not be backported to older versions of this crate. We do not recommend taking a direct dependency on this crate.

See our [User Guide](https://aws.github.io/aws-lc-rs/) for guidance on installing build requirements.

[Documentation](https://github.com/aws/aws-lc).

## Build Support

This crate pulls in the source code of AWS-LC to build with it. Bindings for popular platforms are pre-generated.
To generate bindings for platforms where pre-generated bindings aren't available, you can either specify our `bindgen`
feature or install the [bindgen-cli](https://crates.io/crates/bindgen-cli).

### Pregenerated Bindings Availability

Targets
-------------
aarch64_apple_darwin
aarch64_pc_windows_msvc
aarch64_unknown_linux_gnu
aarch64_unknown_linux_musl
i686_pc_windows_msvc
i686_unknown_linux_gnu
x86_64_apple_darwin
x86_64_pc_windows_gnu
x86_64_pc_windows_msvc
x86_64_unknown_linux_gnu
x86_64_unknown_linux_musl

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

## Build Prerequisites

Since this crate builds AWS-LC as a native library, most build tools needed to build AWS-LC are applicable
to `aws-lc-sys` as well. Go and Perl aren't absolutely necessary for `aws-lc-sys`, as AWS-LC provides generated build
files.

[Building AWS-LC](https://github.com/aws/aws-lc/blob/main/BUILDING.md)

AWS-LC is tested on a variety of C/C++ compiler, OS, and CPU combinations. For a complete list of tested combinations
see [tests/ci/Readme.md](https://github.com/aws/aws-lc/tree/main/tests/ci#unit-tests). If you use a different build
combination and would like us to support it, please open an issue to us
at [AWS-LC](https://github.com/aws/aws-lc/issues/new?assignees=&labels=&template=build-issue.md&title=).

## Building with a FIPS-validated module

This crate does not offer the AWS-LC FIPS build. To use AWS-LC FIPS, please use the FIPS version of this crate,
available at [aws-lc-fips-sys](https://crates.io/crates/aws-lc-fips-sys).

## Post-Quantum Cryptography

Details on the post-quantum algorithms supported by aws-lc-sys can be found at
[PQREADME](https://github.com/aws/aws-lc/tree/main/crypto/fipsmodule/PQREADME.md).

## Security Notification Process

If you discover a potential security issue in *AWS-LC* or *aws-lc-sys*, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

If you package or distribute *aws-lc-sys*, or use *aws-lc-sys* as part of a large multi-user service,
you may be eligible for pre-notification of future *aws-lc-sys* releases.
Please contact aws-lc-pre-notifications@amazon.com.

## Contribution

See contributing file at [AWS-LC](https://github.com/aws/aws-lc/blob/main/CONTRIBUTING.md)

## Licensing

See license at [AWS-LC](https://github.com/aws/aws-lc/blob/main/LICENSE)