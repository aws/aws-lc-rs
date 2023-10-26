// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Authenticated Encryption with Associated Data (AEAD).
//!
//! See [Authenticated encryption: relations among notions and analysis of the
//! generic composition paradigm][AEAD] for an introduction to the concept of
//! AEADs.
//!
//! [AEAD]: https://eprint.iacr.org/2000/025
//! [`crypto.cipher.AEAD`]: https://golang.org/pkg/crypto/cipher/#AEAD
//!
//! # Randomized Nonce API
//!
//! [`RandomizedNonceKey`] provides a simplified API interface that doesn't
//! require the caller to handle construction of a `NonceSequence` or `Nonce` values
//! themselves.
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::aead::{Aad, RandomizedNonceKey, AES_128_GCM};
//!
//! let key_bytes = &[
//!     0xa5, 0xf3, 0x8d, 0x0d, 0x2d, 0x7c, 0x48, 0x56, 0xe7, 0xf3, 0xc3, 0x63, 0x0d, 0x40, 0x5b,
//!     0x9e,
//! ];
//!
//! // Create AES-128-GCM key
//! let key = RandomizedNonceKey::new(&AES_128_GCM, key_bytes)?;
//!
//! let message = "test message";
//! let mut in_out = Vec::from(message);
//!
//! // Seal the plaintext message (in_out) and append the tag to the ciphertext.
//! // The randomized nonce used for encryption will be returned.
//! let nonce = key.seal_in_place_append_tag(Aad::empty(), &mut in_out)?;
//!
//! // Open the ciphertext message (in_out), using the provided nonce, and validating the tag.
//! let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out)?;
//!
//! assert_eq!(message.as_bytes(), plaintext);
//! #   Ok(())
//! # }
//! ```
//!
//! # TLS AEAD APIs
//!
//! Systems developers creating TLS protocol implementations should use
//! [`TlsRecordSealingKey`] and [`TlsRecordOpeningKey`] respectively for AEAD.
//!
//! # Nonce Sequence APIs
//!
//! The [`UnboundKey`], [`OpeningKey`], [`SealingKey`], and [`LessSafeKey`] types are the
//! AEAD API's provided for compatability with the original *ring* API.
//!
//! Users should prefer [`RandomizedNonceKey`] which provides a simplified experience around
//! Nonce construction.
//!
//! ```
//! use aws_lc_rs::aead::{
//!     nonce_sequence, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
//! };
//! use aws_lc_rs::rand;
//! use aws_lc_rs::test::from_hex;
//!
//! let plaintext = "plaintext value";
//!
//! // Generate random bytes for secret key
//! let mut key_bytes = [0u8; 16];
//! rand::fill(&mut key_bytes).expect("Unable to generate key");
//!
//! // Contextual information must match between encryption and decryption
//! let aad_content = "aws-lc-rs documentation";
//! let sequence_id = 0xabcdef01u32.to_be_bytes();
//!
//! // Buffer containing plaintext. This will be modified to contain the ciphertext.
//! let mut in_out_buffer = Vec::from(plaintext);
//!
//! // Construct a SealingKey for encryption
//! let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
//! let nonce_sequence = nonce_sequence::Counter64Builder::new()
//!     .identifier(sequence_id)
//!     .build();
//! let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);
//!
//! // Encrypt a value using the SealingKey
//! let aad = Aad::from(aad_content);
//! sealing_key
//!     .seal_in_place_append_tag(aad, &mut in_out_buffer)
//!     .expect("Encryption failed");
//!
//! // The buffer now contains the ciphertext followed by a "tag" value.
//! let plaintext_len = in_out_buffer.len() - AES_128_GCM.tag_len();
//!
//! // Construct an OpeningKey for decryption
//! let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
//! let nonce_sequence = nonce_sequence::Counter64Builder::new()
//!     .identifier(sequence_id)
//!     .build();
//! let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
//!
//! // Decrypt the value using the OpeningKey
//! let aad = Aad::from(aad_content);
//! opening_key
//!     .open_in_place(aad, &mut in_out_buffer)
//!     .expect("Decryption failed");
//!
//! let decrypted_plaintext = std::str::from_utf8(&in_out_buffer[0..plaintext_len]).unwrap();
//!
//! assert_eq!(plaintext, decrypted_plaintext);
//! ```

use crate::{derive_debug_via_id, error::Unspecified, hkdf};
use aead_ctx::AeadCtx;
use core::{fmt::Debug, ops::RangeFrom};

mod aead_ctx;
mod aes_gcm;
mod chacha;
pub mod chacha20_poly1305_openssh;
mod nonce;
pub mod nonce_sequence;
mod poly1305;
pub mod quic;
mod rand_nonce;
mod tls;
mod unbound_key;

pub use self::{
    aes_gcm::{AES_128_GCM, AES_128_GCM_SIV, AES_256_GCM, AES_256_GCM_SIV},
    chacha::CHACHA20_POLY1305,
    nonce::{Nonce, NONCE_LEN},
    rand_nonce::RandomizedNonceKey,
    tls::{TlsProtocolId, TlsRecordOpeningKey, TlsRecordSealingKey},
    unbound_key::UnboundKey,
};

/// A sequences of unique nonces.
///
/// A given `NonceSequence` must never return the same `Nonce` twice from
/// `advance()`.
///
/// A simple counter is a reasonable (but probably not ideal) `NonceSequence`.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the sequence.
pub trait NonceSequence {
    /// Returns the next nonce in the sequence.
    ///
    /// # Errors
    /// `error::Unspecified` if  "too many" nonces have been requested, where how many
    /// is too many is up to the implementation of `NonceSequence`. An
    /// implementation may that enforce a maximum number of records are
    /// sent/received under a key this way. Once `advance()` fails, it must
    /// fail for all subsequent calls.
    fn advance(&mut self) -> Result<Nonce, Unspecified>;
}

/// An AEAD key bound to a nonce sequence.
pub trait BoundKey<N: NonceSequence>: Debug {
    /// Constructs a new key from the given `UnboundKey` and `NonceSequence`.
    fn new(key: UnboundKey, nonce_sequence: N) -> Self;

    /// The key's AEAD algorithm.
    fn algorithm(&self) -> &'static Algorithm;
}

/// An AEAD key for authenticating and decrypting ("opening"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
///
/// Prefer [`RandomizedNonceKey`] for opening operations.
pub struct OpeningKey<N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for OpeningKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
    }
}

impl<N: NonceSequence> Debug for OpeningKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("OpeningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl<N: NonceSequence> OpeningKey<N> {
    /// Authenticates and decrypts (“opens”) data in place.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_out` must be the ciphertext followed by the tag. When
    /// `open_in_place()` returns `Ok(plaintext)`, the input ciphertext
    /// has been overwritten by the plaintext; `plaintext` will refer to the
    /// plaintext without the tag.
    ///
    /// Prefer [`RandomizedNonceKey::open_in_place`].
    ///
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128_GCM`
    // * `AES_256_GCM`
    //
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `in_out` may have been
    /// overwritten in an unspecified way.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_in_place<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .open_within(self.nonce_sequence.advance()?, aad.as_ref(), in_out, 0..)
    }

    /// Authenticates and decrypts (“opens”) data in place, with a shift.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_out[ciphertext_and_tag]` must be the ciphertext followed
    /// by the tag. When `open_within()` returns `Ok(plaintext)`, the plaintext
    /// will be at `in_out[0..plaintext.len()]`. In other words, the following
    /// two code fragments are equivalent for valid values of
    /// `ciphertext_and_tag`, except `open_within` will often be more efficient:
    ///
    ///
    /// ```skip
    /// let plaintext = key.open_within(aad, in_out, cipertext_and_tag)?;
    /// ```
    ///
    /// ```skip
    /// let ciphertext_and_tag_len = in_out[ciphertext_and_tag].len();
    /// in_out.copy_within(ciphertext_and_tag, 0);
    /// let plaintext = key.open_in_place(aad, &mut in_out[..ciphertext_and_tag_len])?;
    /// ```
    ///
    /// Similarly, `key.open_within(aad, in_out, 0..)` is equivalent to
    /// `key.open_in_place(aad, in_out)`.
    ///
    ///
    /// The shifting feature is useful in the case where multiple packets are
    /// being reassembled in place. Consider this example where the peer has
    /// sent the message “Split stream reassembled in place” split into
    /// three sealed packets:
    ///
    /// ```ascii-art
    ///                 Packet 1                  Packet 2                 Packet 3
    /// Input:  [Header][Ciphertext][Tag][Header][Ciphertext][Tag][Header][Ciphertext][Tag]
    ///                      |         +--------------+                        |
    ///               +------+   +-----+    +----------------------------------+
    ///               v          v          v
    /// Output: [Plaintext][Plaintext][Plaintext]
    ///        “Split stream reassembled in place”
    /// ```
    ///
    /// This reassembly be accomplished with three calls to `open_within()`.
    ///
    /// Prefer [`RandomizedNonceKey::open_in_place`].
    ///
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128_GCM`
    // * `AES_256_GCM`
    //
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `in_out` may have been
    /// overwritten in an unspecified way.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_within<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key.open_within(
            self.nonce_sequence.advance()?,
            aad.as_ref(),
            in_out,
            ciphertext_and_tag,
        )
    }
}

/// An AEAD key for encrypting and signing ("sealing"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
///
/// Prefer [`RandomizedNonceKey`] for sealing operations.
pub struct SealingKey<N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for SealingKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
    }
}

impl<N: NonceSequence> Debug for SealingKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("SealingKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl<N: NonceSequence> SealingKey<N> {
    /// Deprecated. Renamed to `seal_in_place_append_tag`.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_append_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// See `seal_in_place_append_tag`
    #[deprecated(note = "Renamed to `seal_in_place_append_tag`.")]
    #[inline]
    pub fn seal_in_place<A, InOut>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_append_tag(aad, in_out)
    }

    /// Encrypts and signs (“seals”) data in place, appending the tag to the
    /// resulting ciphertext.
    ///
    /// `key.seal_in_place_append_tag(aad, in_out)` is equivalent to:
    ///
    /// ```skip
    /// key.seal_in_place_separate_tag(aad, in_out.as_mut())
    ///     .map(|tag| in_out.extend(tag.as_ref()))
    /// ```
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_append_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` when `nonce_sequence` cannot be advanced.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_append_tag<A, InOut>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.key
            .seal_in_place_append_tag(Some(self.nonce_sequence.advance()?), aad.as_ref(), in_out)
            .map(|_| ())
    }

    /// Encrypts and signs (“seals”) data in place.
    ///
    /// `aad` is the additional authenticated data (AAD), if any. This is
    /// authenticated but not encrypted. The type `A` could be a byte slice
    /// `&[u8]`, a byte array `[u8; N]` for some constant `N`, `Vec<u8>`, etc.
    /// If there is no AAD then use `Aad::empty()`.
    ///
    /// The plaintext is given as the input value of `in_out`. `seal_in_place()`
    /// will overwrite the plaintext with the ciphertext and return the tag.
    /// For most protocols, the caller must append the tag to the ciphertext.
    /// The tag will be `self.algorithm.tag_len()` bytes long.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_separate_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` when `nonce_sequence` cannot be advanced.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_separate_tag<A>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .seal_in_place_separate_tag(Some(self.nonce_sequence.advance()?), aad.as_ref(), in_out)
            .map(|(_, tag)| tag)
    }
}

/// The additionally authenticated data (AAD) for an opening or sealing
/// operation. This data is authenticated but is **not** encrypted.
///
/// The type `A` could be a byte slice `&[u8]`, a byte array `[u8; N]`
/// for some constant `N`, `Vec<u8>`, etc.
pub struct Aad<A: AsRef<[u8]>>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Construct the `Aad` from the given bytes.
    #[inline]
    pub fn from(aad: A) -> Self {
        Aad(aad)
    }
}

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Aad<[u8; 0]> {
    /// Construct an empty `Aad`.
    #[must_use]
    pub fn empty() -> Self {
        Self::from([])
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// Immutable keys for use in situations where `OpeningKey`/`SealingKey` and
/// `NonceSequence` cannot reasonably be used.
///
/// Prefer [`RandomizedNonceKey`] when practical.
///
// # FIPS
// The following conditions must be met:
// * `UnboundKey`'s algorithm is one of:
//   * `AES_128_GCM`
//   * `AES_256_GCM`
// * Use `open_in_place` or `open_within` only.
pub struct LessSafeKey {
    key: UnboundKey,
}

impl LessSafeKey {
    /// Constructs a `LessSafeKey` from an `UnboundKey`.
    #[must_use]
    pub fn new(key: UnboundKey) -> Self {
        Self { key }
    }

    /// Like [`OpeningKey::open_in_place()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// Prefer [`RandomizedNonceKey::open_in_place`].
    ///
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128_GCM`
    // * `AES_256_GCM`
    //
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(nonce, aad, in_out, 0..)
    }

    /// Like [`OpeningKey::open_within()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// Prefer [`RandomizedNonceKey::open_in_place`].
    ///
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128_GCM`
    // * `AES_256_GCM`
    //
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_within<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .open_within(nonce, aad.as_ref(), in_out, ciphertext_and_tag)
    }

    /// Authenticates and decrypts (“opens”) data into another provided slice.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_ciphertext` must be the ciphertext. The tag must be provided in
    /// `in_tag`.
    ///
    /// The `out_plaintext` length must match the provided `in_ciphertext`.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `out_plaintext` may
    /// have been overwritten in an unspecified way.
    ///
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_separate_gather<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .open_separate_gather(&nonce, aad.as_ref(), in_ciphertext, in_tag, out_plaintext)
    }

    /// Deprecated. Renamed to `seal_in_place_append_tag()`.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_append_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    #[deprecated(note = "Renamed to `seal_in_place_append_tag`.")]
    #[inline]
    #[allow(clippy::missing_errors_doc)]
    pub fn seal_in_place<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_append_tag(nonce, aad, in_out)
    }

    /// Like [`SealingKey::seal_in_place_append_tag()`], except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_append_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.key
            .seal_in_place_append_tag(Some(nonce), aad.as_ref(), in_out)
            .map(|_| ())
    }

    /// Like `SealingKey::seal_in_place_separate_tag()`, except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_separate_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_separate_tag<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .seal_in_place_separate_tag(Some(nonce), aad.as_ref(), in_out)
            .map(|(_, tag)| tag)
    }

    /// Encrypts and signs (“seals”) data in place with extra plaintext.
    ///
    /// `aad` is the additional authenticated data (AAD), if any. This is
    /// authenticated but not encrypted. The type `A` could be a byte slice
    /// `&[u8]`, a byte array `[u8; N]` for some constant `N`, `Vec<u8>`, etc.
    /// If there is no AAD then use `Aad::empty()`.
    ///
    /// The plaintext is given as the input value of `in_out` and `extra_in`. `seal_in_place()`
    /// will overwrite the plaintext contained in `in_out` with the ciphertext. The `extra_in` will
    /// be encrypted into the `extra_out_and_tag`, along with the tag.
    /// The `extra_out_and_tag` length must be equal to the `extra_len` and `self.algorithm.tag_len()`.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_scatter<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key.seal_in_place_separate_scatter(
            nonce,
            aad.as_ref(),
            in_out,
            extra_in,
            extra_out_and_tag,
        )
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
    }
}

impl Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("LessSafeKey")
            .field("algorithm", self.algorithm())
            .finish()
    }
}

/// An AEAD Algorithm.
pub struct Algorithm {
    init: fn(key: &[u8], tag_len: usize) -> Result<AeadCtx, Unspecified>,
    key_len: usize,
    id: AlgorithmID,

    // /// Use `max_input_len!()` to initialize this.
    // TODO: Make this `usize`.
    max_input_len: u64,
}

impl Algorithm {
    /// The length of the key.
    #[inline]
    #[must_use]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    #[inline]
    #[must_use]
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of the nonces.
    #[inline]
    #[must_use]
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

derive_debug_via_id!(Algorithm);

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
enum AlgorithmID {
    AES_128_GCM,
    AES_256_GCM,
    AES_128_GCM_SIV,
    AES_256_GCM_SIV,
    CHACHA20_POLY1305,
}

impl PartialEq for Algorithm {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

/// An authentication tag.
#[must_use]
#[repr(C)]
pub struct Tag([u8; MAX_TAG_LEN], usize);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0[..self.1].as_ref()
    }
}

#[allow(dead_code)]
const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = 16;

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{iv::FixedLength, test::from_hex};

    #[cfg(feature = "fips")]
    mod fips;

    #[test]
    fn test_aes_128() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let og_nonce = from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap();
        let plaintext = from_hex("00112233445566778899aabbccddeeff").unwrap();
        let unbound_key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        assert_eq!(&AES_128_GCM, unbound_key.algorithm());

        assert_eq!(16, AES_128_GCM.tag_len());
        assert_eq!(12, AES_128_GCM.nonce_len());

        let less_safe_key = LessSafeKey::new(unbound_key);

        let nonce: [u8; NONCE_LEN] = og_nonce.as_slice().try_into().unwrap();
        let mut in_out = Vec::from(plaintext.as_slice());

        #[allow(deprecated)]
        less_safe_key
            // Test coverage for `seal_in_place`, which calls `seal_in_place_append_tag`.
            .seal_in_place(Nonce(FixedLength::from(nonce)), Aad::empty(), &mut in_out)
            .unwrap();

        let mut in_out_clone = in_out.clone();
        let nonce: [u8; NONCE_LEN] = og_nonce.as_slice().try_into().unwrap();
        assert!(less_safe_key
            .open_in_place(
                Nonce(FixedLength::from(nonce)),
                Aad::from("test"),
                &mut in_out_clone
            )
            .is_err());

        let mut in_out_clone = in_out.clone();
        let mut nonce: [u8; NONCE_LEN] = og_nonce.as_slice().try_into().unwrap();
        nonce[0] = 0;
        assert!(less_safe_key
            .open_in_place(
                Nonce(FixedLength::from(nonce)),
                Aad::empty(),
                &mut in_out_clone
            )
            .is_err());

        let nonce: [u8; NONCE_LEN] = og_nonce.as_slice().try_into().unwrap();
        less_safe_key
            .open_in_place(Nonce(FixedLength::from(nonce)), Aad::empty(), &mut in_out)
            .unwrap();

        assert_eq!(plaintext, in_out[..plaintext.len()]);
    }
}
