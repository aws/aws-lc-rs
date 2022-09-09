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

use crate::{digest, error, hmac};
use std::mem::MaybeUninit;

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

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

/// A salt for HKDF operations.
#[derive(Debug)]
pub struct Salt {
    key: hmac::Key,
}

impl Salt {
    /// Constructs a new `Salt` with the given value based on the given digest
    /// algorithm.
    ///
    /// Constructing a `Salt` is relatively expensive so it is good to reuse a
    /// `Salt` object instead of re-constructing `Salt`s with the same value.
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(algorithm.0, value),
        }
    }

    /// The [HKDF-Extract] operation.
    ///
    /// [HKDF-Extract]: https://tools.ietf.org/html/rfc5869#section-2.2
    pub fn extract(&self, secret: &[u8]) -> Prk {
        unsafe {
            let mut out_key = MaybeUninit::<[u8; digest::MAX_OUTPUT_LEN]>::uninit();
            let mut out_len = MaybeUninit::<usize>::uninit();

            if 1 != aws_lc_sys::HKDF_extract(
                out_key.as_mut_ptr().cast(),
                out_len.as_mut_ptr(),
                self.key.evp_alg,
                secret.as_ptr(),
                secret.len(),
                self.key.key_bytes.as_ptr(),
                self.key.key_bytes.len(),
            ) {
                panic!("HKDF_extract failed");
            };
            Prk {
                key: hmac::Key::new(
                    self.key.algorithm(),
                    &out_key.assume_init()[..out_len.assume_init()],
                ),
            }
        }
    }

    /// The algorithm used to derive this salt.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.key.algorithm)
    }
}

impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        Self {
            key: hmac::Key::from(Okm {
                prk: okm.prk,
                info: okm.info,
                len: okm.len().0,
                len_cached: okm.len_cached,
            }),
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
    key: hmac::Key,
}

impl Prk {
    /// Construct a new `Prk` directly with the given value.
    ///
    /// Usually one can avoid using this. It is useful when the application
    /// intentionally wants to leak the PRK secret, e.g. to implement
    /// `SSLKEYLOGFILE` functionality.
    pub fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(algorithm.hmac_algorithm(), value),
        }
    }

    /// The [HKDF-Expand] operation.
    ///
    /// [HKDF-Expand]: https://tools.ietf.org/html/rfc5869#section-2.3
    ///
    /// Fails if (and only if) `len` is too large.
    #[inline]
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, error::Unspecified> {
        let len_cached = len.len();
        if len_cached > 255 * self.key.algorithm.digest_algorithm().output_len {
            return Err(error::Unspecified);
        }
        Ok(Okm {
            prk: self,
            info,
            len,
            len_cached,
        })
    }
}

impl From<Okm<'_, Algorithm>> for Prk {
    fn from(okm: Okm<Algorithm>) -> Self {
        Self {
            key: hmac::Key::from(Okm {
                prk: okm.prk,
                info: okm.info,
                len: okm.len().0,
                len_cached: okm.len_cached,
            }),
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
    info: &'a [&'a [u8]],
    len: L,
    len_cached: usize,
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
    pub fn fill(self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        if out.len() != self.len_cached {
            return Err(error::Unspecified);
        }
        unsafe {
            let mut info_value = vec![];
            for info in self.info {
                info_value.append(&mut info.to_vec());
            }

            if 1 != aws_lc_sys::HKDF_expand(
                out.as_mut_ptr(),
                out.len(),
                self.prk.key.evp_alg,
                self.prk.key.key_bytes.as_ptr(),
                self.prk.key.key_bytes.len(),
                info_value.as_ptr(),
                info_value.len(),
            ) {
                return Err(error::Unspecified);
            };
        }

        Ok(())
    }
}
