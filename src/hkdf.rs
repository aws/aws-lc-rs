// Copyright 2015 Brian Smith.
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

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! HMAC-based Extract-and-Expand Key Derivation Function.
//!
//! HKDF is specified in [RFC 5869].
//!
//! [RFC 5869]: https://tools.ietf.org/html/rfc5869

use crate::error::Unspecified;
use crate::{digest, hmac};
use std::mem::MaybeUninit;
use zeroize::Zeroize;

/// An HKDF algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The underlying HMAC algorithm.
    #[inline]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.0
    }
}

/// HKDF using HMAC-SHA-1. Obsolete.
pub static HKDF_SHA1_FOR_LEGACY_USE_ONLY: Algorithm =
    Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// HKDF using HMAC-SHA-256.
pub static HKDF_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// HKDF using HMAC-SHA-384.
pub static HKDF_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// HKDF using HMAC-SHA-512.
pub static HKDF_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

/// General Salt length's for HKDF don't normally exceed 256 bits.
/// We set the limit to something tolerable, so that the Salt structure can be stack allocatable.
const MAX_HKDF_SALT_LEN: usize = 80;

/// General Info length's for HKDF don't normally exceed 256 bits.
/// We set the limit to something tolerable, so that the memory passed into |HKDF_expand| is
/// allocated on the stack.
const MAX_HKDF_INFO_LEN: usize = 80;

/// The maximum output size of a PRK computed by |HKDF_extract| is the maximum digest
/// size that can be outputted by AWS-LC.
const MAX_HKDF_PRK_LEN: usize = digest::MAX_OUTPUT_LEN;

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

/// A salt for HKDF operations.
#[derive(Debug)]
pub struct Salt {
    algorithm: Algorithm,
    key_bytes: [u8; MAX_HKDF_SALT_LEN],
    key_len: usize,
}

impl Drop for Salt {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl Salt {
    /// Constructs a new `Salt` with the given value based on the given digest
    /// algorithm.
    ///
    /// Constructing a `Salt` is relatively expensive so it is good to reuse a
    /// `Salt` object instead of re-constructing `Salt`s with the same value.
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Salt::try_new(algorithm, value).expect("Salt length limit exceeded.")
    }

    fn try_new(algorithm: Algorithm, value: &[u8]) -> Result<Salt, Unspecified> {
        let key_len = value.len();
        if key_len > MAX_HKDF_SALT_LEN {
            return Err(Unspecified);
        }
        let mut key_bytes = [0u8; MAX_HKDF_SALT_LEN];
        key_bytes[0..key_len].copy_from_slice(value);
        Ok(Self {
            algorithm,
            key_bytes,
            key_len,
        })
    }

    /// The [HKDF-Extract] operation.
    ///
    /// [HKDF-Extract]: https://tools.ietf.org/html/rfc5869#section-2.2
    #[inline]
    pub fn extract(&self, secret: &[u8]) -> Prk {
        Self::try_extract(self, secret).expect("HKDF_extract failed")
    }

    #[inline]
    fn try_extract(&self, secret: &[u8]) -> Result<Prk, Unspecified> {
        unsafe {
            let mut key_bytes = MaybeUninit::<[u8; MAX_HKDF_PRK_LEN]>::uninit();
            let mut key_len = MaybeUninit::<usize>::uninit();
            if 1 != aws_lc_sys::HKDF_extract(
                key_bytes.as_mut_ptr().cast(),
                key_len.as_mut_ptr(),
                digest::match_digest_type(&self.algorithm.0.digest_algorithm().id),
                secret.as_ptr(),
                secret.len(),
                self.key_bytes.as_ptr(),
                self.key_len,
            ) {
                return Err(Unspecified);
            };
            let key_bytes = key_bytes.assume_init();
            let key_len = key_len.assume_init();
            debug_assert!(key_len <= MAX_HKDF_PRK_LEN);
            Ok(Prk {
                algorithm: self.algorithm,
                key_bytes,
                key_len,
            })
        }
    }

    /// The algorithm used to derive this salt.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.algorithm.hmac_algorithm())
    }
}

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MAX_HKDF_PRK_LEN <= MAX_HKDF_SALT_LEN);

impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        let key_len = okm.prk.key_len;
        let mut key_bytes = [0u8; MAX_HKDF_SALT_LEN];
        key_bytes[0..key_len].copy_from_slice(&okm.prk.key_bytes[..key_len]);
        Self {
            algorithm: okm.prk.algorithm,
            key_bytes,
            key_len,
        }
    }
}

/// The length of the OKM (Output Keying Material) for a `Prk::expand()` call.
#[allow(clippy::len_without_is_empty)]
pub trait KeyType {
    /// The length that `Prk::expand()` should expand its input to.
    fn len(&self) -> usize;
}

/// A HKDF PRK (pseudorandom key).
#[derive(Clone, Debug)]
pub struct Prk {
    algorithm: Algorithm,
    key_bytes: [u8; MAX_HKDF_PRK_LEN],
    key_len: usize,
}

impl Drop for Prk {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl Prk {
    /// Construct a new `Prk` directly with the given value.
    ///
    /// Usually one can avoid using this. It is useful when the application
    /// intentionally wants to leak the PRK secret, e.g. to implement
    /// `SSLKEYLOGFILE` functionality.
    pub fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        Prk::try_new_less_safe(algorithm, value).expect("Prk length limit exceeded.")
    }

    fn try_new_less_safe(algorithm: Algorithm, value: &[u8]) -> Result<Prk, Unspecified> {
        let key_len = value.len();
        if key_len > MAX_HKDF_PRK_LEN {
            return Err(Unspecified);
        }
        let mut key_bytes = [0u8; MAX_HKDF_PRK_LEN];
        key_bytes[0..key_len].copy_from_slice(value);
        Ok(Self {
            algorithm,
            key_bytes,
            key_len,
        })
    }

    /// The [HKDF-Expand] operation.
    ///
    /// [HKDF-Expand]: https://tools.ietf.org/html/rfc5869#section-2.3
    ///
    /// Fails if (and only if) `len` is too large.
    #[inline]
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'_ [&'_ [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, Unspecified> {
        let len_cached = len.len();
        if len_cached > 255 * self.algorithm.0.digest_algorithm().output_len {
            return Err(Unspecified);
        }
        let mut info_bytes = [0u8; MAX_HKDF_INFO_LEN];
        let mut info_len = 0;
        for byte_ary in info {
            let new_info_len = info_len + byte_ary.len();
            if new_info_len > MAX_HKDF_INFO_LEN {
                return Err(Unspecified);
            }
            info_bytes[info_len..new_info_len].copy_from_slice(byte_ary);
            info_len = new_info_len;
        }
        Ok(Okm {
            prk: self,
            info_bytes,
            info_len,
            len,
        })
    }
}

impl From<Okm<'_, Algorithm>> for Prk {
    fn from(okm: Okm<Algorithm>) -> Self {
        okm.prk.clone()
    }
}

/// An HKDF OKM (Output Keying Material)
///
/// Intentionally not `Clone` or `Copy` as an OKM is generally only safe to
/// use once.
#[derive(Debug)]
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info_bytes: [u8; MAX_HKDF_INFO_LEN],
    info_len: usize,
    len: L,
}

impl<L: KeyType> Okm<'_, L> {
    /// The `OkmLength` given to `Prk::expand()`.
    #[inline]
    pub fn len(&self) -> &L {
        &self.len
    }

    /// Fills `out` with the output of the HKDF-Expand operation for the given
    /// inputs.
    ///
    /// Fails if (and only if) the requested output length is larger than 255
    /// times the size of the digest algorithm's output. (This is the limit
    /// imposed by the HKDF specification due to the way HKDF's counter is
    /// constructed.)
    #[inline]
    pub fn fill(self, out: &mut [u8]) -> Result<(), Unspecified> {
        if out.len() != self.len.len() {
            return Err(Unspecified);
        }
        unsafe {
            if 1 != aws_lc_sys::HKDF_expand(
                out.as_mut_ptr(),
                out.len(),
                digest::match_digest_type(&self.prk.algorithm.0.digest_algorithm().id),
                self.prk.key_bytes.as_ptr(),
                self.prk.key_len,
                self.info_bytes.as_ptr(),
                self.info_len,
            ) {
                return Err(Unspecified);
            };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hkdf;
    use crate::hkdf::{Salt, HKDF_SHA256};

    #[test]
    fn hkdf_coverage() {
        // Something would have gone horribly wrong for this to not pass, but we test this so our
        // coverage reports will look better.
        assert_ne!(hkdf::HKDF_SHA256, hkdf::HKDF_SHA384);
        assert_eq!(
            "Algorithm(Algorithm(SHA256))",
            format!("{:?}", hkdf::HKDF_SHA256)
        );
    }

    #[test]
    fn rustls_test() {
        const INFO1: &[&[u8]] = &[
            &[0, 32],
            &[13],
            &[116, 108, 115, 49, 51, 32],
            &[100, 101, 114, 105, 118, 101, 100],
            &[32],
            &[
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
            ],
        ];

        const INFO2: &[&[u8]] = &[
            &[0, 32],
            &[18],
            &[116, 108, 115, 49, 51, 32],
            &[99, 32, 104, 115, 32, 116, 114, 97, 102, 102, 105, 99],
            &[32],
            &[
                236, 20, 122, 6, 222, 163, 200, 132, 108, 2, 178, 35, 142, 65, 189, 220, 157, 137,
                249, 174, 161, 123, 94, 253, 77, 116, 130, 175, 117, 136, 28, 10,
            ],
        ];
        /*
                const SEED: &[u8] = &[
                    51, 173, 10, 28, 96, 126, 192, 59, 9, 230, 205, 152, 147, 104, 12, 226, 16, 173, 243,
                    0, 170, 31, 38, 96, 225, 178, 46, 16, 241, 112, 249, 42,
                ];

                const SECRET: &[u8] = &[
                    231, 184, 254, 248, 144, 59, 82, 12, 185, 161, 137, 113, 182, 157, 212, 93, 202, 83,
                    206, 47, 18, 191, 59, 239, 147, 21, 227, 18, 113, 223, 75, 64,
                ];
        */
        let salt = Salt::new(HKDF_SHA256, &[0u8; 32]);
        let prk = salt.extract(&[0u8; 32]);
        let okm = prk.expand(INFO1, HKDF_SHA256).unwrap();
        let okm2 = prk.expand(INFO2, HKDF_SHA256).unwrap();

        let mut output1 = [0u8; 32];
        okm.fill(&mut output1).expect("test failed");
        let mut output2 = [0u8; 32];
        okm2.fill(&mut output2).expect("test failed");

        println!("AWS-LC Result: {:?}", output1);
        println!("AWS-LC Result: {:?}", output2);

        let ring_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[0u8; 32]);
        let ring_prk = ring_salt.extract(&[0u8; 32]);
        let ring_okm = ring_prk.expand(INFO1, ring::hkdf::HKDF_SHA256).unwrap();
        let ring_okm2 = ring_prk.expand(INFO2, ring::hkdf::HKDF_SHA256).unwrap();

        let mut ring_output1 = [0u8; 32];
        ring_okm.fill(&mut ring_output1).expect("test failed");
        let mut ring_output2 = [0u8; 32];
        ring_okm2.fill(&mut ring_output2).expect("test failed");

        println!("Ring Result: {:?}", ring_output1);
        println!("Ring Result: {:?}", ring_output2);

        assert_eq!(ring_output1, output1);
        assert_eq!(ring_output2, output2);
    }
}
