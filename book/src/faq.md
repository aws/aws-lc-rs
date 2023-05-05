# Frequently Asked Questions

## What are the differences between `aws-lc-rs` and `ring`?
While we aim to be API-compatible with `ring` there are some differences in our implementation. Please review the
[ring-compatibility](https://docs.rs/aws-lc-rs/1.0.1/aws_lc_rs/#ring-compatibility) section of our
[API reference guide][COMPAT].

## Can I run `aws-lc-rs` on X platform or architecture?

The answer to this question is dependent on several factors based on the target environment:
* Must be a platform and CPU architecture supported by [AWS-LC][AWS-LC].
* Must be a platform supported by the Rust compiler with support for the full standard library.
  See the Rust compiler's [platform support][rustc] documentation.
* If the underlying `aws-lc-sys` or `aws-lc-fips-sys` crate don't have pre-generated bindings for the desired platform
  then you must use the `bindgen` crate feature of `aws-lc-rs` to enable generation of the FFI bindings for the desired
  platform and architecture. See [Requirements](requirements/README.md) for more details on what build dependencies are 
  required for target platforms.

If there is a platform or architecture you are interested in seeing support for, please create a GitHub [issue].

[COMPAT]: https://docs.rs/aws-lc-rs/1.0.1/aws_lc_rs/#ring-compatibility
[AWS-LC]: https://github.com/aws/aws-lc
[rustc]: https://doc.rust-lang.org/rustc/platform-support.html
[issue]: https://github.com/awslabs/aws-lc-rs/issues/new/choose
