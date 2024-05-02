# Requirements

This page outlines the requirements for using `aws-lc-rs` on each target platform.

`aws-lc-rs` uses [aws-lc-sys] or [aws-lc-fips-sys] to provide raw FFI bindings to [AWS-LC]. Thus,
there are additional build tools required for building these crates into your Rust application.

- [Linux](linux)
- [macOS & iOS](apple)
- [Windows](windows)

[aws-lc-sys]: https://crates.io/crates/aws-lc-sys

[aws-lc-fips-sys]: https://crates.io/crates/aws-lc-fips-sys

[AWS-LC]: https://github.com/aws/aws-lc
