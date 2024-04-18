# Introduction

[![aws-lc-rs](https://img.shields.io/crates/v/aws-lc-rs?label=aws-lc-rs)](https://crates.io/crates/aws-lc-rs)
[![aws-lc-sys](https://img.shields.io/crates/v/aws-lc-sys?label=aws-lc-sys)](https://crates.io/crates/aws-lc-sys)
[![aws-lc-fips-sys](https://img.shields.io/crates/v/aws-lc-fips-sys?label=aws-lc-fips-sys)](https://crates.io/crates/aws-lc-fips-sys)

**[aws-lc-rs]** is a cryptographic library using AWS Libcrypto ([AWS-LC])
for its cryptographic operations. This library strives to be API-compatible with the popular Rust library
named [ring](https://github.com/briansmith/ring) ([v0.16](https://docs.rs/ring/0.16.20/ring/index.html)).
It uses one of our auto-generated Foreign Function Interface (FFI) crates
(either **[aws-lc-sys]** or **[aws-lc-fips-sys]**) for binding to AWS-LC for the cryptographic implementations.

## Motivation

Rust developers increasingly need to deploy applications that meet US and Canadian government cryptographic
requirements. We evaluated how to deliver FIPS validated cryptography in idiomatic and performant Rust, built around our
AWS-LC offering. We found that the popular ring library fulfilled much of the cryptographic needs in the Rust
community, but it did not meet the needs of developers with FIPS requirements. Our intention is to contribute a drop-in
replacement for ring that provides FIPS support and is compatible with the ring (v0.16) API. Rust developers with
prescribed cryptographic requirements can seamlessly integrate aws-lc-rs into their applications and deploy them into
AWS Regions.

## Questions, Feedback and Contributing

* [Submit an non-security Bug/Issue/Request][ISSUES]
* [API documentation][API_DOC]
* [Fork our repo][FORK]

We use [GitHub Issues][ISSUES] for managing feature requests, bug reports, or questions about aws-lc-rs API usage.

Otherwise, if you think you might have found a security impacting issue, please instead
follow our *Security Notification Process* below.

## Security Notification Process

If you discover a potential security issue in *AWS-LC* or *aws-lc-rs*, we ask that you notify AWS
Security via our [vulnerability reporting page].
Please do **not** create a public GitHub issue.

If you package or distribute *aws-lc-rs*, or use *aws-lc-rs* as part of a large multi-user service,
you may be eligible for pre-notification of future *aws-lc-rs* releases.
Please contact aws-lc-pre-notifications@amazon.com.

## License

[aws-lc-rs] is licensed under the Apache-2.0 or the ISC License.
The [aws-lc-sys] and [aws-lc-fips-sys] libraries contain code from [AWS-LC] and are licensed under
the ISC AND ( Apache-2.0 OR ISC ) AND OpenSSL licenses.

[ISSUES]: https://github.com/awslabs/aws-lc-rs/issues/new/choose

[API_DOC]: https://docs.rs/aws-lc-rs/

[FORK]: https://github.com/awslabs/aws-lc-rs/fork

[vulnerability reporting page]: https://aws.amazon.com/security/vulnerability-reporting/

[AWS-LC]: https://github.com/aws/aws-lc

[aws-lc-rs]: https://crates.io/crates/aws-lc-rs

[aws-lc-sys]: https://crates.io/crates/aws-lc-sys

[aws-lc-fips-sys]: https://crates.io/crates/aws-lc-fips-sys
