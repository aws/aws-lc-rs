// Copyright 2015-2019 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// SPDX-License-Identifier: Apache-2.0
// Modifications Copyright Amazon.com, Inc. or its affiliates. See GitHub history for details.

//! SHA-2 and the legacy SHA-1 digest algorithm.
//!
//! If all the data is available in a single contiguous slice then the `digest`
//! function should be used. Otherwise, the digest can be calculated in
//! multiple steps using `Context`.

// Contrary to Ring's original SHA implementations, which does the hashing operations in rust,
// aws-lc-ring-facade calls the one-shot hashing APIs from AWS-LC's crypto.

use crate::{debug, derive_debug_via_id};

mod sha;
pub use sha::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};

/// A context for multi-step (Init-Update-Finish) digest calculations.
///
/// # Examples
///
/// ```
/// use aws_lc_ring_facade as ring;
/// use ring::digest;
///
/// let one_shot = digest::digest(&digest::SHA384, b"hello, world");
///
/// let mut ctx = digest::Context::new(&digest::SHA384);
/// ctx.update(b"hello");
/// ctx.update(b", ");
/// ctx.update(b"world");
/// let multi_part = ctx.finish();
///
/// assert_eq!(&one_shot.as_ref(), &multi_part.as_ref());
/// ```
#[derive(Clone)]
pub struct Context {
    /// The context's algorithm.
    pub(crate) algorithm: &'static Algorithm,
    /// Message to digest.
    msg: Vec<u8>,
}

impl Context {
    /// Constructs a new context.
    pub fn new(algorithm: &'static Algorithm) -> Self {
        Self {
            algorithm,
            msg: Default::default(),
        }
    }

    /// Updates the message to digest with all the data in `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.msg.extend(data);
    }

    /// Finalizes the digest calculation and returns the digest value.
    ///
    /// `finish` consumes the context so it cannot be (mis-)used after `finish`
    /// has been called.
    pub fn finish(mut self) -> Digest {
        // let block_len = self.algorithm.block_len as u32;
        // let max_len = (2u128.pow(block_len - 1) + ((block_len - 1) as u128)) as usize;
        assert!(self.msg.len() as u128 <= u128::MAX);

        let mut output: Vec<u8> = vec![0u8; MAX_OUTPUT_LEN];
        let msg_len = self.msg.len();
        (self.algorithm.hash)(&mut self.msg[..], msg_len, &mut output);

        Digest {
            algorithm: self.algorithm,
            digest_msg: <[u8; MAX_OUTPUT_LEN]>::try_from(&output[..MAX_OUTPUT_LEN]).unwrap(),
            digest_len: self.algorithm.output_len,
        }
    }

    /// The algorithm that this context is using.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// Returns the digest of `data` using the given digest algorithm.
///
/// # Examples:
///
/// ```
/// # #[cfg(feature = "alloc")]
/// # {
/// use ring::{digest, test};
/// let expected_hex = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
/// let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
/// let actual = digest::digest(&digest::SHA256, b"hello, world");
///
/// assert_eq!(&expected, &actual.as_ref());
/// # }
/// ```
pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish()
}

/// A calculated digest value.
///
/// Use [`Self::as_ref`] to get the value as a `&[u8]`.
#[derive(Clone, Copy)]
pub struct Digest {
    // The trait `Copy` can't be implemented for dynamic arrays, so we set a fixed array and the
    // appropriate length.
    digest_msg: [u8; MAX_OUTPUT_LEN],
    digest_len: usize,

    algorithm: &'static Algorithm,
}

impl Digest {
    /// The algorithm that was used to calculate the digest value.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl AsRef<[u8]> for Digest {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.digest_msg[..self.digest_len]
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{:?}:", self.algorithm)?;
        debug::write_hex_bytes(fmt, self.as_ref())
    }
}

/// A digest algorithm.
pub struct Algorithm {
    /// The length of a finalized digest.
    pub output_len: usize,

    /// The size of the chaining value of the digest function, in bytes. For
    /// non-truncated algorithms (SHA-1, SHA-256, SHA-512), this is equal to
    /// `output_len`. For truncated algorithms (e.g. SHA-384, SHA-512/256),
    /// this is equal to the length before truncation. This is mostly helpful
    /// for determining the size of an HMAC key that is appropriate for the
    /// digest algorithm.
    ///
    /// This function isn't actually used in aws-lc-ring-facade, and is only kept for compatibility
    /// with the original ring implementation.
    pub chaining_len: usize,

    /// The internal block length.
    pub block_len: usize,

    pub(crate) hash: fn(msg: &mut [u8], num_pending: usize, output: &mut [u8]),

    id: AlgorithmID,
}

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

derive_debug_via_id!(Algorithm);

/// The maximum block length ([`Algorithm::block_len`]) of all the algorithms
/// in this module.
pub const MAX_BLOCK_LEN: usize = 1024 / 8;

/// The maximum output length ([`Algorithm::output_len`]) of all the
/// algorithms in this module.
pub const MAX_OUTPUT_LEN: usize = 512 / 8;

/// The maximum chaining length ([`Algorithm::chaining_len`]) of all the
/// algorithms in this module.
pub const MAX_CHAINING_LEN: usize = MAX_OUTPUT_LEN;

// #[cfg(test)]
// mod tests {
//     mod max_input {
//         extern crate alloc;
//         use super::super::super::digest;
//         use alloc::vec;
//         use std::cmp::max;
//         use std::u32;
//
//         macro_rules! max_input_tests {
//             ( $algorithm_name:ident ) => {
//                 mod $algorithm_name {
//                     use super::super::super::super::digest;
//
//                     #[test]
//                     fn max_input_test() {
//                         super::max_input_test(&digest::$algorithm_name);
//                     }
//
//                     #[test]
//                     #[should_panic]
//                     fn too_long_input_test_block() {
//                         super::too_long_input_test_block(&digest::$algorithm_name);
//                     }
//
//                     #[test]
//                     #[should_panic]
//                     fn too_long_input_test_byte() {
//                         super::too_long_input_test_byte(&digest::$algorithm_name);
//                     }
//                 }
//             };
//         }
//
//         fn max_input_test(alg: &'static digest::Algorithm) {
//             let mut context = nearly_full_context(alg);
//             let next_input = vec![0u8; alg.block_len - 1];
//             context.update(&next_input);
//             let _ = context.finish(); // no panic
//         }
//
//         fn too_long_input_test_block(alg: &'static digest::Algorithm) {
//             let mut context = nearly_full_context(alg);
//             let next_input = vec![0u8; alg.block_len];
//             context.update(&next_input);
//             let _ = context.finish(); // should panic
//         }
//
//         fn too_long_input_test_byte(alg: &'static digest::Algorithm) {
//             let mut context = nearly_full_context(alg);
//             let next_input = vec![0u8; alg.block_len - 1];
//             context.update(&next_input); // no panic
//             context.update(&[0]);
//             let _ = context.finish(); // should panic
//         }
//
//         fn nearly_full_context(alg: &'static digest::Algorithm) -> digest::Context {
//             // All implementations currently support up to 2^64-1 bits
//             // of input; according to the spec, SHA-384 and SHA-512
//             // support up to 2^128-1, but that's not implemented yet.
//             // const max_bytes: u64 = 1u64 << (64-3);
//             // const max_bytes: u64 = u64::MAX as u64;
//             const max_bytes: u64 = 2u64.pow(47);
//             // let max_blocks = max_bytes / polyfill::u64_from_usize(alg.block_len);
//             let test = [0u8; max_bytes as usize];
//             digest::Context {
//                 msg: vec![1u8; max_bytes as usize],
//                 algorithm: alg,
//                 // block: digest::BlockContext {
//                 //     state: alg.initial_state,
//                 //     completed_data_blocks: max_blocks - 1,
//                 //     algorithm: alg,
//                 //     cpu_features: crate::cpu::features(),
//                 // },
//                 // pending: [0u8; digest::MAX_BLOCK_LEN],
//                 // num_pending: 0,
//             }
//         }
//
//         max_input_tests!(SHA1_FOR_LEGACY_USE_ONLY);
//         // max_input_tests!(SHA256);
//         // max_input_tests!(SHA384);
//         // max_input_tests!(SHA512);
//     }
// }
