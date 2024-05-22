# Frequently Asked Questions

## What are the differences between `aws-lc-rs` and `ring`?

While we aim to be API-compatible with `ring` v0.16 there are some differences in our implementation. Please review the
[ring-compatibility] section of our [API reference guide].

## Can I run `aws-lc-rs` on *X* platform or architecture?

The answer to this question is dependent on several factors based on the target environment:

* Must be a platform and CPU architecture supported by [AWS-LC].
* Must be a platform supported by the Rust compiler with support for the full standard library.
  See the [Rust compiler's platform support] documentation.
* If the underlying `aws-lc-sys` or `aws-lc-fips-sys` crates don't have pre-generated bindings for the desired platform
  then you must use the `bindgen` crate feature of `aws-lc-rs`, or have the [bindgen-cli] installed, to enable
  generation of the FFI bindings for the desired platform and architecture.
* See [Requirements](requirements/README.md) and [Platform Support](./platform_suppport.md) for more details on
  build requirements for various platforms.

If there is a platform or architecture you are interested in seeing support for, please create a GitHub [issue].

[ring-compatibility]: https://docs.rs/aws-lc-rs/latest/aws_lc_rs/#ring-compatibility

[API reference guide]: https://docs.rs/aws-lc-rs/latest/aws_lc_rs

[AWS-LC]: https://github.com/aws/aws-lc

[Rust compiler's platform support]: https://doc.rust-lang.org/rustc/platform-support.html

[issue]: https://github.com/awslabs/aws-lc-rs/issues/new/choose

[bindgen-cli]: https://crates.io/crates/bindgen-cli
