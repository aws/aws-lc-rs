# Frequently Asked Questions

## What are the differences between `aws-lc-rs` and `ring`?

While we aim to be API-compatible with `ring` v0.16 there are some differences in our implementation. Please review the
[ring-compatibility] section of our [API reference guide].

## Can I run `aws-lc-rs` on *X* platform or architecture?

**For non-FIPS builds:** If your target platform is supported by both [AWS-LC] and the
[Rust compiler (with std support)][Rust compiler's platform support], then `aws-lc-rs` should work
out of the box. The `aws-lc-sys` crate provides **universal pre-generated bindings** that work
across all supported platforms — bindgen, CMake, and Go are **never** required. The only build
requirement is a C/C++ compiler.

**For FIPS builds:** Additional tooling is always required (CMake, Go), and bindgen is also required
unless `aws-lc-fips-sys` has pre-generated bindings for your target platform. If bindgen is needed,
you can either use the `bindgen` crate feature of `aws-lc-rs`, or have the [bindgen-cli] installed.

> **Note:** If you take a direct dependency on `aws-lc-sys` (not through `aws-lc-rs`) and need access to the
> complete AWS-LC API, you may want to use target-specific bindings or enable bindgen for complete API coverage.

See [Requirements](requirements/README.md) and [Platform Support](platform_support.md) for more
details on build requirements for various platforms.

If there is a platform or architecture you are interested in seeing support for, please create a GitHub [issue].

[ring-compatibility]: https://docs.rs/aws-lc-rs/latest/aws_lc_rs/#ring-compatibility

[API reference guide]: https://docs.rs/aws-lc-rs/latest/aws_lc_rs

[AWS-LC]: https://github.com/aws/aws-lc

[Rust compiler's platform support]: https://doc.rust-lang.org/rustc/platform-support.html

[issue]: https://github.com/aws/aws-lc-rs/issues/new/choose

[bindgen-cli]: https://crates.io/crates/bindgen-cli

## How can I use a custom or deterministic RNG for testing?

The `dev-tests-only` feature unseals the `rand::SecureRandom` trait, allowing you to provide your
own implementation of `SecureRandom` for custom random number generation in tests.
This is useful when you need reproducible test vectors or want to control the random bytes returned
during testing.

To enable this functionality, either:

* Add the `dev-tests-only` feature flag:

```toml
[dev-dependencies]
aws-lc-rs = { version = "1", features = ["dev-tests-only"] }
```

* Or set the `AWS_LC_RS_DEV_TESTS_ONLY` environment variable:

```shell
AWS_LC_RS_DEV_TESTS_ONLY=1 cargo test
```

Once enabled, you can implement `aws_lc_rs::rand::unsealed::SecureRandom` for your own type.
A blanket implementation will automatically provide the public `SecureRandom` trait for your type:

```rust
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::{unsealed, SecureRandom};

#[derive(Debug)]
struct DeterministicRandom {
    seed: u8,
}

impl unsealed::SecureRandom for DeterministicRandom {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = self.seed.wrapping_add(i as u8);
        }
        Ok(())
    }
}

// DeterministicRandom now implements SecureRandom and can be used
// anywhere a &dyn SecureRandom is expected.
```

> **Note:** The `dev-tests-only` feature is restricted to dev/debug profile builds only. Attempting
> to use it in a release build will result in a compile-time error. This is a safety measure to
> prevent deterministic or weakened RNG implementations from being used in production code.

See the [`unsealed_rand_test.rs`](https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/tests/unsealed_rand_test.rs)
file in the repository for additional examples.
