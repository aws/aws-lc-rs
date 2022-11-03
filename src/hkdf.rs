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
        let algorithm = okm.prk.algorithm;
        let mut key_bytes = [0u8; MAX_HKDF_SALT_LEN];
        let key_len = okm.len().len();
        okm.fill(&mut key_bytes[..key_len]).unwrap();
        Self {
            algorithm,
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
        let algorithm = okm.len;
        let key_len = okm.len.len();
        let mut key_bytes = [0u8; MAX_HKDF_PRK_LEN];
        okm.fill(&mut key_bytes[0..key_len]).unwrap();

        Self {
            algorithm,
            key_bytes,
            key_len,
        }
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

impl<'a, L: KeyType> Drop for Okm<'a, L> {
    fn drop(&mut self) {
        self.info_bytes.zeroize()
    }
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
    use crate::hkdf::{Prk, Salt, HKDF_SHA256};

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

    #[test]
    fn okm_to_salt() {
        const SALT: &[u8; 32] = &[
            29, 113, 120, 243, 11, 202, 39, 222, 206, 81, 163, 184, 122, 153, 52, 192, 98, 195,
            240, 32, 34, 19, 160, 128, 178, 111, 97, 232, 113, 101, 221, 143,
        ];
        const SECRET1: &[u8; 32] = &[
            157, 191, 36, 107, 110, 131, 193, 6, 175, 226, 193, 3, 168, 133, 165, 181, 65, 120,
            194, 152, 31, 92, 37, 191, 73, 222, 41, 112, 207, 236, 196, 174,
        ];
        const SECRET2: &[u8; 32] = &[
            224, 63, 67, 213, 224, 104, 58, 50, 88, 209, 237, 46, 232, 170, 253, 41, 19, 19, 60,
            235, 221, 215, 226, 154, 99, 234, 27, 43, 176, 174, 101, 21,
        ];
        const INFO1: &[&[u8]] = &[
            &[
                2, 130, 61, 83, 192, 248, 63, 60, 211, 73, 169, 66, 101, 160, 196, 212, 250, 113,
            ],
            &[
                80, 46, 248, 123, 78, 204, 171, 178, 67, 204, 96, 27, 131, 24,
            ],
        ];
        const INFO2: &[&[u8]] = &[
            &[
                34, 34, 23, 86, 156, 162, 231, 236, 148, 170, 84, 187, 88, 86, 15, 165, 95, 109,
            ],
            &[243, 251, 232, 90, 98, 26, 78, 75, 114, 115, 9, 72, 183, 193],
        ];

        let alg = HKDF_SHA256;
        let salt = Salt::new(alg, SALT);
        let prk = salt.extract(SECRET1);
        let okm = prk.expand(INFO1, alg).unwrap();
        let okm_salt: Salt = okm.into();
        let prk2 = okm_salt.extract(SECRET2);
        let okm2 = prk2.expand(INFO2, alg).unwrap();

        let mut output = [0u8; 32];
        okm2.fill(&mut output).expect("test failed");

        println!("AWS-LC: {:?}", output);

        let ring_alg = ring::hkdf::HKDF_SHA256;
        let ring_salt = ring::hkdf::Salt::new(ring_alg, SALT);
        let ring_prk = ring_salt.extract(SECRET1);
        let ring_okm = ring_prk.expand(INFO1, ring_alg).unwrap();
        let ring_okm_salt: ring::hkdf::Salt = ring_okm.into();
        let ring_prk2 = ring_okm_salt.extract(SECRET2);
        let ring_okm2 = ring_prk2.expand(INFO2, ring_alg).unwrap();

        let mut ring_output = [0u8; 32];
        ring_okm2.fill(&mut ring_output).expect("test failed");

        println!("ring: {:?}", ring_output);

        assert_eq!(ring_output, output);
        assert_eq!(
            output,
            [
                29, 148, 69, 177, 104, 16, 168, 31, 95, 217, 120, 105, 45, 141, 225, 36, 142, 230,
                151, 143, 240, 12, 41, 129, 143, 119, 94, 221, 132, 167, 236, 243
            ]
        )
    }

    #[test]
    fn okm_to_prk() {
        const SALT: &[u8; 32] = &[
            29, 113, 120, 243, 11, 202, 39, 222, 206, 81, 163, 184, 122, 153, 52, 192, 98, 195,
            240, 32, 34, 19, 160, 128, 178, 111, 97, 232, 113, 101, 221, 143,
        ];
        const SECRET1: &[u8; 32] = &[
            157, 191, 36, 107, 110, 131, 193, 6, 175, 226, 193, 3, 168, 133, 165, 181, 65, 120,
            194, 152, 31, 92, 37, 191, 73, 222, 41, 112, 207, 236, 196, 174,
        ];

        const INFO1: &[&[u8]] = &[
            &[
                2, 130, 61, 83, 192, 248, 63, 60, 211, 73, 169, 66, 101, 160, 196, 212, 250, 113,
            ],
            &[
                80, 46, 248, 123, 78, 204, 171, 178, 67, 204, 96, 27, 131, 24,
            ],
        ];
        const INFO2: &[&[u8]] = &[
            &[
                34, 34, 23, 86, 156, 162, 231, 236, 148, 170, 84, 187, 88, 86, 15, 165, 95, 109,
            ],
            &[243, 251, 232, 90, 98, 26, 78, 75, 114, 115, 9, 72, 183, 193],
        ];

        let alg = HKDF_SHA256;
        let salt = Salt::new(alg, SALT);
        let prk = salt.extract(SECRET1);
        let okm = prk.expand(INFO1, alg).unwrap();
        let prk2 = Prk::from(okm);
        let okm2 = prk2.expand(INFO2, alg).unwrap();

        let mut output = [0u8; 32];
        okm2.fill(&mut output).expect("test failed");

        println!("AWS-LC: {:?}", output);

        let ring_alg = ring::hkdf::HKDF_SHA256;
        let ring_salt = ring::hkdf::Salt::new(ring_alg, SALT);
        let ring_prk = ring_salt.extract(SECRET1);
        let ring_okm = ring_prk.expand(INFO1, ring_alg).unwrap();
        let ring_prk2 = ring::hkdf::Prk::from(ring_okm);
        let ring_okm2 = ring_prk2.expand(INFO2, ring_alg).unwrap();

        let mut ring_output = [0u8; 32];
        ring_okm2.fill(&mut ring_output).expect("test failed");

        println!("ring: {:?}", ring_output);

        assert_eq!(ring_output, output);
        assert_eq!(
            output,
            [
                89, 74, 29, 169, 83, 186, 156, 217, 15, 130, 215, 15, 245, 57, 91, 192, 227, 195,
                106, 0, 10, 225, 34, 200, 10, 198, 253, 171, 44, 32, 192, 249
            ]
        )
    }
}
