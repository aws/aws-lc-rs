// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Ring-compatible crypto library using the cryptographic operations provided by
//! [AWS-LC](https://github.com/awslabs/aws-lc).
//!
//! # Feature Flags
//!
//! #### - alloc (default) ####
//! Allows implementation to allocate values of arbitrary size. (The meaning of this feature differs
//! from the "alloc" feature of Ring.) Currently, this is required by the `io::writer` module.
//!
//! #### - ring-io (default) ####
//! Enable feature to access the  `io`  module.
//!
//! #### - asan ####
//! Performs an "address sanitizer" build. This can be used to help detect memory leaks. See the
//! ["Address Sanitizer" section](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#addresssanitizer)
//! of the [Rust Unstable Book](https://doc.rust-lang.org/beta/unstable-book/).
//!
//! # Ring-compatibility
//!
//! Although this library attempts to be fully compatible with Ring, there are a few places where our
//! behavior is observably different.
//!
//! * Our implementation requires the `std` library. We currently do not support a
//! [`#![no_std]`](https://docs.rust-embedded.org/book/intro/no-std.html) build.
//! * We only support a subset of the platforms supported by `aws-lc-sys`.  We currently support Mac
//! and Linux, both x86-64 and aarch64.
//! * Due to its dependence on AWS-LC, this library does not support generating or parsing
//! [PKCS#8 v2](https://tools.ietf.org/html/rfc5958). Thus, the `Ed25519KeyPair::generate_pkcs8` and
//! `Ed25519KeyPair::from_pkcs8` implementations always returns an error. Instead, you can use
//! `Ed25519KeyPair::generate_pkcs8v1` for generating and
//! `Ed25519KeyPair::from_pkcs8_maybe_unchecked` for parsing
//! [PKCS#8 v1](https://tools.ietf.org/html/rfc5208).
//! * When parsing fails, the `KeyRejected` response may differ from Ring's response on the same
//! input.
//!

#![warn(missing_docs)]

extern crate core;

pub mod aead;
pub mod agreement;
pub mod constant_time;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
#[cfg(all(feature = "ring-io"))]
pub mod io;
pub mod pbkdf2;
pub mod pkcs8;
pub mod rand;
pub mod signature;
pub mod test;

mod rsa;

mod debug;

mod endian;

mod bn;
mod cbb;
mod cbs;
mod ec;
mod ed25519;
mod ptr;

use std::ffi::CStr;
use std::sync::Once;

static START: Once = Once::new();

#[inline]
/// Initialize the AWS-LC library. (This should generally not be needed.)
pub fn init() {
    START.call_once(|| unsafe {
        aws_lc_sys::CRYPTO_library_init();
    });
}

#[allow(dead_code)]
unsafe fn dump_error() {
    let err = aws_lc_sys::ERR_get_error();
    let lib = aws_lc_sys::ERR_GET_LIB(err);
    let reason = aws_lc_sys::ERR_GET_REASON(err);
    let func = aws_lc_sys::ERR_GET_FUNC(err);
    let mut buffer = [0u8; 256];
    aws_lc_sys::ERR_error_string(err, buffer.as_mut_ptr().cast());
    let error_msg = CStr::from_bytes_with_nul_unchecked(&buffer);
    eprintln!(
        "Raw Error -- {:?}\nErr: {}, Lib: {}, Reason: {}, Func: {}",
        error_msg, err, lib, reason, func
    );
}

mod sealed {
    /// Traits that are designed to only be implemented internally in *ring*.
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
}
