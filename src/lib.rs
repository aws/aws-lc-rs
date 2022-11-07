// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: ISC

//! Ring-compatible crypto library using AWS-LC's cryptographic primitives.
//!
//! # Feature Flags
//!
//! <table>
//! <tr><th width=20%>Feature
//!     <th width=70%>Description
//! <tr><td><code>alloc (default)</code>
//!     <td>Allows implementation to allocate values of arbitrary size.
//!         Currently, this is required for <code>SealingKey::seal_in_place_separate_tag</code> with
//!         <code>CHACHA_POLY1305</code> and for the <code>io::writer</code> module.
//! <tr><td><code>threadlocal (default)</code>
//!     <td> Allows implementation to use <code>thread_local</code>, which is needed for certain structs
//!         to impl <code>Sync</code>. Used by <code>aead::SealingKey</code>, <code>aead::UnboundKey</code>,
//!         <code>aead::UnboundKey</code>, and <code>digest::Context</code>. These structs can still
//!         be used without this feature.
//! <tr><td><code>ring-io (default)</code>
//!     <td>Enable feature to access the `io` module.
//! <tr><td><code>asan</code>
//!     <td>Performs an "address sanitizer" build of the `aws-lc-sys` crate.
//! </table>
//!
//! # Ring-compatibility
//!
//! Although this library attempts to be compatible with Ring, there are a few places where our
//! behavior is observably different.
//!
//! * `SealingKey::seal_in_place_separate_tag` with `CHACHA_POLY1305` requires allocating a separate
//! buffer that can contain both the ciphertext and tag. When the `alloc` feature is disabled, this
//! function cannot be called with `CHACHA_POLY1305` keys.
//! * AWS-LC does not support parsing PKCS#8 v2. Thus, `Ed25519KeyPair::from_pkcs8` is not
//! supported. Instead, you can use `Ed25519KeyPair::from_pkcs8_maybe_unchecked` for many common
//! use-cases.
//! * We only support the platforms supported by `aws-lc-sys`.  Currently this is includes MacOS and
//! Linux, both x86-64 and ARM64.
//! * When parsing PKCS#8 fails, the reason provided for `KeyRejected` may differ from Ring.
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

mod c;

mod endian;

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
