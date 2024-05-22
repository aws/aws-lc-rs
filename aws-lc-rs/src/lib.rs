// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(clippy::doc_markdown)]
//! A [*ring*](https://github.com/briansmith/ring)-compatible crypto library using the cryptographic
//! operations provided by [*AWS-LC*](https://github.com/awslabs/aws-lc). It uses either the
//! auto-generated [*aws-lc-sys*](https://crates.io/crates/aws-lc-sys) or
//! [*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys)
//! Foreign Function Interface (FFI) crates found in this repository for invoking *AWS-LC*.
//!
//! # Build
//!
//! `aws-lc-rs` is available through [crates.io](https://crates.io/crates/aws-lc-rs). It can
//! be added to your project in the [standard way](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
//! using `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! aws-lc-rs = "1.0.0"
//! ```
//! Consuming projects will need a C Compiler (Clang or GCC) to build.
//! For some platforms, the build may also require CMake.
//! Building with the "fips" feature on any platform requires **CMake** and **Go**.
//!
//! See our [User Guide](https://awslabs.github.io/aws-lc-rs/) for guidance on installing build requirements.
//!
//!
//! # Feature Flags
//!
//! #### alloc (default)
//!
//! Allows implementation to allocate values of arbitrary size. (The meaning of this feature differs
//! from the "alloc" feature of *ring*.) Currently, this is required by the `io::writer` module.
//!
//! #### ring-io (default)
//!
//! Enable feature to access the  `io`  module.
//!
//! #### ring-sig-verify (default)
//!
//! Enable feature to preserve compatibility with ring's `signature::VerificationAlgorithm::verify`
//! function. This adds a requirement on `untrusted = "0.7.1"`.
//!
//! #### fips
//!
//! Enable this feature to have aws-lc-rs use the [*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys)
//! crate for the cryptographic implementations. The *aws-lc-fips-sys* crate provides bindings to
//! [AWS-LC-FIPS 2.x](https://github.com/aws/aws-lc/tree/fips-2022-11-02), which has completed
//! FIPS validation testing by an accredited lab and has been submitted to NIST for certification.
//! The static build of AWS-LC-FIPS is used.
//!
//! Refer to the
//! [NIST Cryptographic Module Validation Program's Modules In Progress List](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List)
//! for the latest status of the static or dynamic AWS-LC Cryptographic Module. A complete list of supported operating
//! environments will be made available in the vendor security policy once the validation certificate has been issued. We
//! will also update our release notes
//! and documentation to reflect any changes in FIPS certification status.
//!
//! #### asan
//!
//! Performs an "address sanitizer" build. This can be used to help detect memory leaks. See the
//! ["Address Sanitizer" section](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#addresssanitizer)
//! of the [Rust Unstable Book](https://doc.rust-lang.org/beta/unstable-book/).
//!
//! #### bindgen
//!
//! Causes `aws-lc-sys` or `aws-lc-fips-sys` to generates fresh bindings for AWS-LC instead of using
//! the pre-generated bindings. This feature requires `libclang` to be installed. See the
//! [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)
//! for [rust-bindgen](https://github.com/rust-lang/rust-bindgen)
//!
//! # *ring*-compatibility
//!
//! Although this library attempts to be fully compatible with *ring* (v0.16.x), there are a few places where our
//! behavior is observably different.
//!
//! * Our implementation requires the `std` library. We currently do not support a
//!   [`#![no_std]`](https://docs.rust-embedded.org/book/intro/no-std.html) build.
//! * We can only support a subset of the platforms supported by `aws-lc-sys`. See the list of
//!   supported platforms above.
//! * `Ed25519KeyPair::from_pkcs8` and `Ed25519KeyPair::from_pkcs8_maybe_unchecked` both support
//!   parsing of v1 or v2 PKCS#8 documents. If a v2 encoded key is provided to either function,
//!   public key component, if present, will be verified to match the one derived from the encoded
//!   private key.
//!
//! # Motivation
//!
//! Rust developers increasingly need to deploy applications that meet US and Canadian government
//! cryptographic requirements. We evaluated how to deliver FIPS validated cryptography in idiomatic
//! and performant Rust, built around our AWS-LC offering. We found that the popular ring (v0.16)
//! library fulfilled much of the cryptographic needs in the Rust community, but it did not meet the
//! needs of developers with FIPS requirements. Our intention is to contribute a drop-in replacement
//! for ring that provides FIPS support and is compatible with the ring API. Rust developers with
//! prescribed cryptographic requirements can seamlessly integrate aws-lc-rs into their applications
//! and deploy them into AWS Regions.

#![warn(missing_docs)]
#![warn(clippy::exhaustive_enums)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(feature = "fips")]
extern crate aws_lc_fips_sys as aws_lc;

extern crate alloc;
#[cfg(not(feature = "fips"))]
extern crate aws_lc_sys as aws_lc;
extern crate core;
pub mod aead;
pub mod agreement;
pub mod constant_time;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
#[cfg(feature = "ring-io")]
pub mod io;
pub mod key_wrap;
pub mod pbkdf2;
pub mod pkcs8;
pub mod rand;
pub mod signature;
pub mod test;

mod bn;
mod buffer;
mod cbb;
mod cbs;
pub mod cipher;
mod debug;
mod ec;
mod ed25519;
pub mod encoding;
mod endian;
mod evp_pkey;
mod fips;
mod hex;
pub mod iv;
#[allow(clippy::module_name_repetitions)]
pub mod kem;
mod ptr;
pub mod rsa;
pub mod tls_prf;
pub mod unstable;

pub(crate) use debug::derive_debug_via_id;
// TODO: Uncomment when MSRV >= 1.64
// use core::ffi::CStr;
use std::ffi::CStr;

use aws_lc::{
    CRYPTO_library_init, ERR_error_string, ERR_get_error, FIPS_mode, ERR_GET_FUNC, ERR_GET_LIB,
    ERR_GET_REASON,
};
use std::sync::Once;

static START: Once = Once::new();

#[inline]
/// Initialize the *AWS-LC* library. (This should generally not be needed.)
pub fn init() {
    START.call_once(|| unsafe {
        CRYPTO_library_init();
    });
}

#[cfg(feature = "fips")]
/// Panics if the underlying implementation is not FIPS, otherwise it returns.
///
/// # Panics
/// Panics if the underlying implementation is not FIPS.
pub fn fips_mode() {
    try_fips_mode().unwrap();
}

/// Indicates whether the underlying implementation is FIPS.
///
/// # Errors
/// Return an error if the underlying implementation is not FIPS, otherwise ok
pub fn try_fips_mode() -> Result<(), &'static str> {
    init();
    unsafe {
        match FIPS_mode() {
            1 => Ok(()),
            _ => Err("FIPS mode not enabled!"),
        }
    }
}

#[allow(dead_code)]
unsafe fn dump_error() {
    let err = ERR_get_error();
    let lib = ERR_GET_LIB(err);
    let reason = ERR_GET_REASON(err);
    let func = ERR_GET_FUNC(err);
    let mut buffer = [0u8; 256];
    ERR_error_string(err, buffer.as_mut_ptr().cast());
    let error_msg = CStr::from_bytes_with_nul_unchecked(&buffer);
    eprintln!("Raw Error -- {error_msg:?}\nErr: {err}, Lib: {lib}, Reason: {reason}, Func: {func}");
}

mod sealed {
    /// Traits that are designed to only be implemented internally in *aws-lc-rs*.
    //
    // Usage:
    // ```
    // use crate::sealed;
    //
    // pub trait MyType: sealed::Sealed {
    //     // [...]
    // }
    //
    // impl sealed::Sealed for MyType {}
    // ```
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use crate::{dump_error, init};

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_dump() {
        unsafe {
            dump_error();
        }
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_fips() {
        assert!({ crate::try_fips_mode().is_err() });
    }

    #[test]
    // FIPS mode is disabled for an ASAN build
    #[cfg(all(feature = "fips", not(feature = "asan")))]
    fn test_fips() {
        crate::fips_mode();
    }
}
