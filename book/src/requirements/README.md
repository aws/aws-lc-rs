# Requirements

This page outlines the requirements for using `aws-lc-rs` on each target platform.

`aws-lc-rs` uses [aws-lc-sys] or [aws-lc-fips-sys] raw FFI bindings to [AWS-LC], and thus
a minimal set of additional build environments in order to compile your Rust application.

- [Linux](linux.md)
- [macOS](macos.md)
- [Windows](windows.md)

[aws-lc-sys]: https://crates.io/crates/aws-lc-sys
[aws-lc-fips-sys]: https://crates.io/crates/aws-lc-fips-sys
[AWS-LC]: https://github.com/aws/aws-lc
