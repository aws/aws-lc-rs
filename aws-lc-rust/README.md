# AWS Libcrypto for Rust (aws-lc-rust)

[![Crates.io](https://img.shields.io/crates/v/aws-lc-rust.svg)](https://crates.io/crates/aws-lc-rust)
[![GitHub](https://img.shields.io/badge/GitHub-awslabs%2Faws--lc--rust-blue)](https://github.com/awslabs/aws-lc-rust)

*ring*-compatible crypto library using the cryptographic operations provided by
[*AWS-LC*](https://github.com/awslabs/aws-lc).

## Feature Flags

##### - alloc (default) ####
Allows implementation to allocate values of arbitrary size. (The meaning of this feature differs
from the "alloc" feature of *ring*.) Currently, this is required by the `io::writer` module.

##### - ring-io (default) ####
Enable feature to access the  `io`  module.

##### - ring-sig-verify (default) ####
Enable feature to preserve compatibility with ring's `signature::VerificationAlgorithm::verify`
function. This adds a requirement on `untrusted = "0.7.1"`.

##### - fips ####
**EXPERIMENTAL** Enable this feature to have aws-lc-rust use the
[*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys) crate for the cryptographic
implementations. The *aws-lc-fips-sys* crate provides bindings to the FIPS variant of
[*AWS-LC*](https://github.com/aws/aws-lc).

##### - asan ####
Performs an "address sanitizer" build. This can be used to help detect memory leaks. See the
["Address Sanitizer" section](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#addresssanitizer)
of the [Rust Unstable Book](https://doc.rust-lang.org/beta/unstable-book/).

## *ring*-compatibility

Although this library attempts to be fully compatible with *ring*, there are a few places where our
behavior is observably different.

* Our implementation requires the `std` library. We currently do not support a
[`#![no_std]`](https://docs.rust-embedded.org/book/intro/no-std.html) build.
* We can only support a subset of the platforms supported by `aws-lc-sys`.  We currently support Mac
and Linux, both x86-64 and aarch64.
* `Ed25519KeyPair::from_pkcs8` and `Ed25519KeyPair::from_pkcs8_maybe_unchecked` both support
parsing of v1 or v2 PKCS#8 documents. If a v2 encoded key is provided to either function,
public key component, if present, will be verified to match the one derived from the encoded
private key.

## Motivation

As there exists no standard Rust cryptographic API, we chose the Rust cryptographic library ring (v0.16) as our target API to
build higher-level Rust bindings on top of *AWS-LC*. *ring* is one of the most used cryptographic APIs in the Rust community,
but lacked support for alternate cryptographic implementations. Our desire to build a Rust API on top of AWS-LC is to be able
to offer a FIPS validated Rust option for our customers. AWS-LC has been validated by an accredited lab,
and was submitted to NIST on 2021-12-23. *aws-lc-rust* adds to the Rust cryptographic landscape with features such as an
experimental FIPS operation mode, a stable API, and a process for
[vulnerability reporting and disclosure](https://aws.amazon.com/security/vulnerability-reporting/).


## Questions, Feedback and Contributing

* [Submit an non-security Bug/Issue/Request](https://github.com/awslabs/aws-lc-rust/issues/new/choose)
* [API documentation](https://docs.rs/aws-lc-rust/)
* [Fork our repo](https://github.com/awslabs/aws-lc-rust/fork)

If you have any questions about submitting PR's, opening issues, *aws-lc-rust* API usage or
any similar topic, we have a public chatroom available here to answer your questions
on [Gitter](https://gitter.im/aws/aws-lc).

Otherwise, if you think you might have found a security impacting issue, please instead
follow our *Security Notification Process* below.

## Security Notification Process

If you discover a potential security issue in *AWS-LC* or *aws-lc-rust*, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

If you package or distribute *aws-lc-rust*, or use *aws-lc-rust* as part of a large multi-user service,
you may be eligible for pre-notification of future *aws-lc-rust* releases.
Please contact aws-lc-pre-notifications@amazon.com.

## License

This library is licensed under the Apache-2.0 or the ISC License. For license details see []()
