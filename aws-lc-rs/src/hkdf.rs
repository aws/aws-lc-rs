// Copyright 2015 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! HMAC-based Extract-and-Expand Key Derivation Function.
//!
//! HKDF is specified in [RFC 5869].
//!
//! [RFC 5869]: https://tools.ietf.org/html/rfc5869
//!
//! # Example
//! ```
//! use aws_lc_rs::{aead, hkdf, hmac, rand};
//!
//! // Generate a (non-secret) salt value
//! let mut salt_bytes = [0u8; 32];
//! rand::fill(&mut salt_bytes).unwrap();
//!
//! // Extract pseudo-random key from secret keying materials
//! let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
//! let pseudo_random_key = salt.extract(b"secret input keying material");
//!
//! // Derive HMAC key
//! let hmac_key_material = pseudo_random_key
//!     .expand(
//!         &[b"hmac contextual info"],
//!         hkdf::HKDF_SHA256.hmac_algorithm(),
//!     )
//!     .unwrap();
//! let hmac_key = hmac::Key::from(hmac_key_material);
//!
//! // Derive UnboundKey for AES-128-GCM
//! let aes_keying_material = pseudo_random_key
//!     .expand(&[b"aes contextual info"], &aead::AES_128_GCM)
//!     .unwrap();
//! let aead_unbound_key = aead::UnboundKey::from(aes_keying_material);
//! ```

use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::{digest, hmac};
use alloc::sync::Arc;
use aws_lc::{HKDF_expand, HKDF};
use core::fmt;
use zeroize::Zeroize;

/// An HKDF algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The underlying HMAC algorithm.
    #[inline]
    #[must_use]
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
/// We set the default capacity to a value larger than should be needed
/// so that the value passed to |`HKDF_expand`| is only allocated once.
const HKDF_INFO_DEFAULT_CAPACITY_LEN: usize = 300;

/// The maximum output size of a PRK computed by |`HKDF_extract`| is the maximum digest
/// size that can be outputted by *AWS-LC*.
const MAX_HKDF_PRK_LEN: usize = digest::MAX_OUTPUT_LEN;

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

/// A salt for HKDF operations.
pub struct Salt {
    algorithm: Algorithm,
    salt_bytes: [u8; MAX_HKDF_SALT_LEN],
    salt_len: usize,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("hkdf::Salt")
            .field("algorithm", &self.algorithm.0)
            .finish()
    }
}

impl Drop for Salt {
    fn drop(&mut self) {
        self.salt_bytes.zeroize();
    }
}

impl Salt {
    /// Constructs a new `Salt` with the given value based on the given digest
    /// algorithm.
    ///
    /// Constructing a `Salt` is relatively expensive so it is good to reuse a
    /// `Salt` object instead of re-constructing `Salt`s with the same value.
    ///
    // # FIPS
    // The following conditions must be met:
    // * Algorithm is one of the following:
    //   * `HKDF_SHA1_FOR_LEGACY_USE_ONLY`
    //   * `HKDF_SHA256`
    //   * `HKDF_SHA384`
    //   * `HKDF_SHA512`
    // * `value.len() > 0` is true
    //
    /// # Panics
    /// `new` panics if the salt length exceeds the limit
    #[must_use]
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Salt::try_new(algorithm, value).expect("Salt length limit exceeded.")
    }

    fn try_new(algorithm: Algorithm, value: &[u8]) -> Result<Salt, Unspecified> {
        let salt_len = value.len();
        if salt_len > MAX_HKDF_SALT_LEN {
            return Err(Unspecified);
        }
        let mut salt_bytes = [0u8; MAX_HKDF_SALT_LEN];
        salt_bytes[0..salt_len].copy_from_slice(value);
        Ok(Self {
            algorithm,
            salt_bytes,
            salt_len,
        })
    }

    /// The [HKDF-Extract] operation.
    ///
    /// [HKDF-Extract]: https://tools.ietf.org/html/rfc5869#section-2.2
    ///
    /// # Panics
    /// Panics if the extract operation is unable to be performed
    #[inline]
    #[must_use]
    pub fn extract(&self, secret: &[u8]) -> Prk {
        Prk {
            algorithm: self.algorithm,
            mode: PrkMode::ExtractExpand {
                secret: Arc::from(ZeroizeBoxSlice::from(secret)),
                salt: self.salt_bytes,
                salt_len: self.salt_len,
            },
        }
    }

    /// The algorithm used to derive this salt.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.algorithm.hmac_algorithm())
    }
}

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MAX_HKDF_PRK_LEN <= MAX_HKDF_SALT_LEN);

impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        let algorithm = okm.prk.algorithm;
        let mut salt_bytes = [0u8; MAX_HKDF_SALT_LEN];
        let salt_len = okm.len().len();
        okm.fill(&mut salt_bytes[..salt_len]).unwrap();
        Self {
            algorithm,
            salt_bytes,
            salt_len,
        }
    }
}

/// The length of the OKM (Output Keying Material) for a `Prk::expand()` call.
#[allow(clippy::len_without_is_empty)]
pub trait KeyType {
    /// The length that `Prk::expand()` should expand its input to.
    fn len(&self) -> usize;
}

#[derive(Clone)]
enum PrkMode {
    Expand {
        key_bytes: [u8; MAX_HKDF_PRK_LEN],
        key_len: usize,
    },
    ExtractExpand {
        secret: Arc<ZeroizeBoxSlice<u8>>,
        salt: [u8; MAX_HKDF_SALT_LEN],
        salt_len: usize,
    },
}

impl PrkMode {
    fn fill(&self, algorithm: Algorithm, out: &mut [u8], info: &[u8]) -> Result<(), Unspecified> {
        let digest = *digest::match_digest_type(&algorithm.0.digest_algorithm().id);

        match &self {
            PrkMode::Expand { key_bytes, key_len } => unsafe {
                if 1 != indicator_check!(HKDF_expand(
                    out.as_mut_ptr(),
                    out.len(),
                    digest,
                    key_bytes.as_ptr(),
                    *key_len,
                    info.as_ptr(),
                    info.len(),
                )) {
                    return Err(Unspecified);
                }
            },
            PrkMode::ExtractExpand {
                secret,
                salt,
                salt_len,
            } => {
                if 1 != indicator_check!(unsafe {
                    HKDF(
                        out.as_mut_ptr(),
                        out.len(),
                        digest,
                        secret.as_ptr(),
                        secret.len(),
                        salt.as_ptr(),
                        *salt_len,
                        info.as_ptr(),
                        info.len(),
                    )
                }) {
                    return Err(Unspecified);
                }
            }
        };

        Ok(())
    }
}

impl fmt::Debug for PrkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expand { .. } => f.debug_struct("Expand").finish_non_exhaustive(),
            Self::ExtractExpand { .. } => f.debug_struct("ExtractExpand").finish_non_exhaustive(),
        }
    }
}

struct ZeroizeBoxSlice<T: Zeroize>(Box<[T]>);

impl<T: Zeroize> core::ops::Deref for ZeroizeBoxSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone + Zeroize> From<&[T]> for ZeroizeBoxSlice<T> {
    fn from(value: &[T]) -> Self {
        Self(Vec::from(value).into_boxed_slice())
    }
}

impl<T: Zeroize> Drop for ZeroizeBoxSlice<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A HKDF PRK (pseudorandom key).
#[derive(Clone)]
pub struct Prk {
    algorithm: Algorithm,
    mode: PrkMode,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Prk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("hkdf::Prk")
            .field("algorithm", &self.algorithm.0)
            .field("mode", &self.mode)
            .finish()
    }
}

impl Prk {
    /// Construct a new `Prk` directly with the given value.
    ///
    /// Usually one can avoid using this. It is useful when the application
    /// intentionally wants to leak the PRK secret, e.g. to implement
    /// `SSLKEYLOGFILE` functionality.
    ///
    // # FIPS
    // This function must not be used.
    //
    // See [`Salt::extract`].
    //
    /// # Panics
    /// Panics if the given Prk length exceeds the limit
    #[must_use]
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
            mode: PrkMode::Expand { key_bytes, key_len },
        })
    }

    /// The [HKDF-Expand] operation.
    ///
    /// [HKDF-Expand]: https://tools.ietf.org/html/rfc5869#section-2.3
    ///
    /// # Errors
    /// Returns `error::Unspecified` if:
    ///   * `len` is more than 255 times the digest algorithm's output length.
    // # FIPS
    // The following conditions must be met:
    // * `Prk` must be constructed using `Salt::extract` prior to calling
    // this method.
    // * After concatination of the `info` slices the resulting `[u8].len() > 0` is true.
    #[inline]
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, Unspecified> {
        let len_cached = len.len();
        if len_cached > 255 * self.algorithm.0.digest_algorithm().output_len {
            return Err(Unspecified);
        }
        let mut info_bytes: Vec<u8> = Vec::with_capacity(HKDF_INFO_DEFAULT_CAPACITY_LEN);
        let mut info_len = 0;
        for &byte_ary in info {
            info_bytes.extend_from_slice(byte_ary);
            info_len += byte_ary.len();
        }
        let info_bytes = info_bytes.into_boxed_slice();
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
            mode: PrkMode::Expand { key_bytes, key_len },
        }
    }
}

/// An HKDF OKM (Output Keying Material)
///
/// Intentionally not `Clone` or `Copy` as an OKM is generally only safe to
/// use once.
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info_bytes: Box<[u8]>,
    info_len: usize,
    len: L,
}

impl<'a, L: KeyType> fmt::Debug for Okm<'a, L> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("hkdf::Okm").field("prk", &self.prk).finish()
    }
}

impl<'a, L: KeyType> Drop for Okm<'a, L> {
    fn drop(&mut self) {
        self.info_bytes.zeroize();
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
    // # FIPS
    // The following conditions must be met:
    // * Algorithm is one of the following:
    //    * `HKDF_SHA1_FOR_LEGACY_USE_ONLY`
    //    * `HKDF_SHA256`
    //    * `HKDF_SHA384`
    //    * `HKDF_SHA512`
    // * The [`Okm`] was constructed from a [`Prk`] created with [`Salt::extract`] and:
    //    * The `value.len()` passed to [`Salt::new`] was non-zero.
    //    * The `info_len` from [`Prk::expand`] was non-zero.
    //
    /// # Errors
    /// `error::Unspecified` if the requested output length differs from the length specified by
    /// `L: KeyType`.
    #[inline]
    pub fn fill(self, out: &mut [u8]) -> Result<(), Unspecified> {
        if out.len() != self.len.len() {
            return Err(Unspecified);
        }

        self.prk
            .mode
            .fill(self.prk.algorithm, out, &self.info_bytes[..self.info_len])?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hkdf::{Salt, HKDF_SHA256, HKDF_SHA384};

    #[cfg(feature = "fips")]
    mod fips;

    #[test]
    fn hkdf_coverage() {
        // Something would have gone horribly wrong for this to not pass, but we test this so our
        // coverage reports will look better.
        assert_ne!(HKDF_SHA256, HKDF_SHA384);
        assert_eq!("Algorithm(Algorithm(SHA256))", format!("{HKDF_SHA256:?}"));
    }

    #[test]
    fn test_debug() {
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

        let alg = HKDF_SHA256;
        let salt = Salt::new(alg, SALT);
        let prk = salt.extract(SECRET1);
        let okm = prk.expand(INFO1, alg).unwrap();

        assert_eq!(
            "hkdf::Salt { algorithm: Algorithm(SHA256) }",
            format!("{salt:?}")
        );
        assert_eq!(
            "hkdf::Prk { algorithm: Algorithm(SHA256), mode: ExtractExpand { .. } }",
            format!("{prk:?}")
        );
        assert_eq!(
            "hkdf::Okm { prk: hkdf::Prk { algorithm: Algorithm(SHA256), mode: ExtractExpand { .. } } }",
            format!("{okm:?}")
        );
    }
}
