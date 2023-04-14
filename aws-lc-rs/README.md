# AWS Libcrypto for Rust (aws-lc-rs)

[![Crates.io](https://img.shields.io/crates/v/aws-lc-rs.svg)](https://crates.io/crates/aws-lc-rs)
[![GitHub](https://img.shields.io/badge/GitHub-awslabs%2Faws--lc--rs-blue)](https://github.com/awslabs/aws-lc-rs)

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
**EXPERIMENTAL** Enable this feature to have aws-lc-rs use the
[*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys) crate for the cryptographic
implementations. The *aws-lc-fips-sys* crate provides bindings to the FIPS variant of
[*AWS-LC*](https://github.com/aws/aws-lc). AWS-LC has been submitted to an accredited lab
for FIPS validation testing, and upon completion will be submitted to NIST for certification.
Once NIST grants a validation certificate to AWS-LC, we will make an announcement to Rust
developers on how to leverage the FIPS mode.

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

Rust developers increasingly need to deploy applications that meet US and Canadian government
cryptographic requirements. We evaluated how to deliver FIPS validated cryptography in idiomatic
and performant Rust, built around our AWS-LC offering. We found that the popular ring (v0.16)
library fulfilled much of the cryptographic needs in the Rust community, but it did not meet the
needs of developers with FIPS requirements. Our intention is to contribute a drop-in replacement
for ring that provides FIPS support and is compatible with the ring API. Rust developers with
prescribed cryptographic requirements can seamlessly integrate aws-lc-rs into their applications
and deploy them into AWS Regions.


## Questions, Feedback and Contributing

* [Submit an non-security Bug/Issue/Request](https://github.com/awslabs/aws-lc-rs/issues/new/choose)
* [API documentation](https://docs.rs/aws-lc-rs/)
* [Fork our repo](https://github.com/awslabs/aws-lc-rs/fork)

If you have any questions about submitting PR's, opening issues, *aws-lc-rs* API usage or
any similar topic, we have a public chatroom available here to answer your questions
on [Gitter](https://gitter.im/aws/aws-lc).

Otherwise, if you think you might have found a security impacting issue, please instead
follow our *Security Notification Process* below.

## Security Notification Process

If you discover a potential security issue in *AWS-LC* or *aws-lc-rs*, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

If you package or distribute *aws-lc-rs*, or use *aws-lc-rs* as part of a large multi-user service,
you may be eligible for pre-notification of future *aws-lc-rs* releases.
Please contact aws-lc-pre-notifications@amazon.com.

## License

This library is licensed under the Apache-2.0 or the ISC License. For license details see []()
