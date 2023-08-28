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
//! # Examples
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

use crate::{derive_debug_via_id, hkdf, iv::FixedLength};
use std::{fmt::Debug, ptr::null, sync::Mutex};

use crate::error::Unspecified;
use aead_ctx::AeadCtx;
use aws_lc::{
    EVP_AEAD_CTX_open, EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal, EVP_AEAD_CTX_seal_scatter,
};
use std::mem::MaybeUninit;
use std::ops::RangeFrom;

mod aead_ctx;
mod aes_gcm;
mod chacha;
pub mod chacha20_poly1305_openssh;
mod nonce;
pub mod nonce_sequence;
mod poly1305;
pub mod quic;

pub use self::{
    aes_gcm::{AES_128_GCM, AES_128_GCM_SIV, AES_256_GCM, AES_256_GCM_SIV},
    chacha::CHACHA20_POLY1305,
    nonce::{Nonce, NONCE_LEN},
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
        self.key.algorithm
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
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `in_out` may have been
    /// overwritten in an unspecified way.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(aad, in_out, 0..)
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
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `in_out` may have been
    /// overwritten in an unspecified way.
    #[inline]
    pub fn open_within<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        open_within(
            self.key.algorithm(),
            self.key.get_inner_key(),
            self.nonce_sequence.advance()?,
            aad,
            in_out,
            ciphertext_and_tag,
        )
    }
}

#[inline]
fn open_within<'in_out, A: AsRef<[u8]>>(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Nonce,
    Aad(aad): Aad<A>,
    in_out: &'in_out mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'in_out mut [u8], Unspecified> {
    let in_prefix_len = ciphertext_and_tag.start;
    let ciphertext_and_tag_len = in_out.len().checked_sub(in_prefix_len).ok_or(Unspecified)?;
    let ciphertext_len = ciphertext_and_tag_len
        .checked_sub(alg.tag_len())
        .ok_or(Unspecified)?;
    check_per_nonce_max_bytes(alg, ciphertext_len)?;

    match ctx {
        AeadCtx::AES_128_GCM_RANDNONCE(_) | AeadCtx::AES_256_GCM_RANDNONCE(_) => {
            aead_open_combined_randnonce(
                alg,
                ctx,
                nonce,
                Aad::from(aad.as_ref()),
                &mut in_out[in_prefix_len..],
            )
        }
        _ => aead_open_combined(
            alg,
            ctx,
            nonce,
            Aad::from(aad.as_ref()),
            &mut in_out[in_prefix_len..],
        ),
    }?;

    // shift the plaintext to the left
    in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

    // `ciphertext_len` is also the plaintext length.
    Ok(&mut in_out[..ciphertext_len])
}

/// An AEAD key for encrypting and signing ("sealing"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
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
        self.key.algorithm
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
        seal_in_place_append_tag(
            self.algorithm(),
            self.key.get_inner_key(),
            Some(self.nonce_sequence.advance()?),
            Aad::from(aad.as_ref()),
            in_out,
        )
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
        seal_in_place_separate_tag(
            self.algorithm(),
            self.key.get_inner_key(),
            Some(self.nonce_sequence.advance()?),
            Aad::from(aad.as_ref()),
            in_out,
        )
        .map(|(_, tag)| tag)
    }
}

#[inline]
fn seal_in_place_append_tag<'a, InOut>(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Option<Nonce>,
    aad: Aad<&[u8]>,
    in_out: &'a mut InOut,
) -> Result<Nonce, Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    check_per_nonce_max_bytes(alg, in_out.as_mut().len())?;
    match nonce {
        Some(nonce) => aead_seal_combined(alg, ctx, nonce, aad, in_out),
        None => aead_seal_combined_randnonce(alg, ctx, aad, in_out),
    }
}

#[inline]
fn seal_in_place_separate_tag(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Option<Nonce>,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(Nonce, Tag), Unspecified> {
    check_per_nonce_max_bytes(alg, in_out.len())?;
    match nonce {
        Some(nonce) => aead_seal_separate(alg, ctx, nonce, aad, in_out),
        None => aead_seal_separate_randnonce(alg, ctx, aad, in_out),
    }
}

#[inline]
fn seal_in_place_separate_scatter(
    alg: &'static Algorithm,
    key: &UnboundKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    extra_in: &[u8],
    extra_out_and_tag: &mut [u8],
) -> Result<(), Unspecified> {
    check_per_nonce_max_bytes(key.algorithm, in_out.len())?;
    let key_inner_ref = key.get_inner_key();
    aead_seal_separate_scatter(
        alg,
        key_inner_ref,
        nonce,
        aad,
        in_out,
        extra_in,
        extra_out_and_tag,
    )
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_separate_scatter(
    alg: &'static Algorithm,
    key: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    extra_in: &[u8],
    extra_out_and_tag: &mut [u8],
) -> Result<(), Unspecified> {
    // ensure that the extra lengths match
    {
        let actual = extra_in.len() + alg.tag_len();
        let expected = extra_out_and_tag.len();

        if actual != expected {
            return Err(Unspecified);
        }
    }

    let aead_ctx = key.as_ref();
    let aad_slice = aad.as_ref();
    let nonce = nonce.as_ref();
    let mut out_tag_len = extra_out_and_tag.len();

    if 1 != unsafe {
        EVP_AEAD_CTX_seal_scatter(
            *aead_ctx.as_const(),
            in_out.as_mut_ptr(),
            extra_out_and_tag.as_mut_ptr(),
            &mut out_tag_len,
            extra_out_and_tag.len(),
            nonce.as_ptr(),
            nonce.len(),
            in_out.as_ptr(),
            in_out.len(),
            extra_in.as_ptr(),
            extra_in.len(),
            aad_slice.as_ptr(),
            aad_slice.len(),
        )
    } {
        return Err(Unspecified);
    }
    Ok(())
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

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    inner: AeadCtx,
    algorithm: &'static Algorithm,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    /// # Errors
    /// `error::Unspecified` if `key_bytes.len() != algorithm.key_len()`.
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self {
            inner: (algorithm.init)(key_bytes, algorithm.tag_len())?,
            algorithm,
        })
    }

    #[inline]
    fn get_inner_key(&self) -> &AeadCtx {
        &self.inner
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
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
/// Prefer to use `OpeningKey`/`SealingKey` and `NonceSequence` when practical.
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
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
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
        open_within(
            self.key.algorithm,
            self.key.get_inner_key(),
            nonce,
            aad,
            in_out,
            ciphertext_and_tag,
        )
    }

    /// Deprecated. Renamed to `seal_in_place_append_tag()`.
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
        seal_in_place_append_tag(
            self.algorithm(),
            self.key.get_inner_key(),
            Some(nonce),
            Aad::from(aad.as_ref()),
            in_out,
        )
        .map(|_| ())
    }

    /// Like `SealingKey::seal_in_place_separate_tag()`, except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
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
        seal_in_place_separate_tag(
            self.algorithm(),
            self.key.get_inner_key(),
            Some(nonce),
            Aad::from(aad.as_ref()),
            in_out,
        )
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
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    ///
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
        seal_in_place_separate_scatter(
            self.algorithm(),
            &self.key,
            nonce,
            Aad::from(aad.as_ref()),
            in_out,
            extra_in,
            extra_out_and_tag,
        )
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm
    }
}

impl Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("LessSafeKey")
            .field("algorithm", self.algorithm())
            .finish()
    }
}

/// AEAD Cipher key using a randomized nonce.
pub struct RandomizedNonceKey {
    ctx: AeadCtx,
    algorithm: &'static Algorithm,
}

impl RandomizedNonceKey {
    /// New Random Nonce Sequence
    /// # Errors
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let ctx = match algorithm.id {
            AlgorithmID::AES_128_GCM => AeadCtx::aes_128_gcm_randnonce(
                key_bytes,
                algorithm.tag_len(),
                algorithm.nonce_len(),
            ),
            AlgorithmID::AES_256_GCM => AeadCtx::aes_256_gcm_randnonce(
                key_bytes,
                algorithm.tag_len(),
                algorithm.nonce_len(),
            ),
            AlgorithmID::AES_128_GCM_SIV
            | AlgorithmID::AES_256_GCM_SIV
            | AlgorithmID::CHACHA20_POLY1305 => return Err(Unspecified),
        }?;
        Ok(Self { ctx, algorithm })
    }

    /// Like [`OpeningKey::open_in_place()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
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
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
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
        open_within(
            self.algorithm,
            &self.ctx,
            nonce,
            aad,
            in_out,
            ciphertext_and_tag,
        )
    }

    /// Like [`SealingKey::seal_in_place_append_tag()`], except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_append_tag<'a, A, InOut>(
        &self,
        aad: Aad<A>,
        in_out: &'a mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        seal_in_place_append_tag(
            self.algorithm,
            &self.ctx,
            None,
            Aad::from(aad.as_ref()),
            in_out,
        )
    }

    /// Like `SealingKey::seal_in_place_separate_tag()`, except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_separate_tag<A>(
        &self,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let nonce = if let AlgorithmID::CHACHA20_POLY1305 = self.algorithm.id {
            Some(Nonce(FixedLength::<NONCE_LEN>::new()?))
        } else {
            None
        };
        seal_in_place_separate_tag(
            self.algorithm,
            &self.ctx,
            nonce,
            Aad::from(aad.as_ref()),
            in_out,
        )
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// The Transport Layer Security (TLS) protocol version.
pub enum TLSProtocolId {
    /// TLS 1.2 (RFC 5246)
    TLS12,

    /// TLS 1.3 (RFC 8446)
    TLS13,
}

/// AEAD Encryption key used for TLS protocol record encryption.
pub struct TLSRecordSealingKey {
    // The TLS specific construction for TLS ciphers in AWS-LC are not thread-safe!
    // The choice here was either wrap the underlying EVP_AEAD_CTX in a Mutex as done here,
    // or force this type to !Sync. Since this is an implementation detail of AWS-LC
    // we have optex to manage this behavior internally.
    ctx: Mutex<AeadCtx>,
    algorithm: &'static Algorithm,
}

impl TLSRecordSealingKey {
    /// New TLS record sealing key. Only supports `AES_128_GCM` and `AES_256_GCM`.
    ///
    /// # Errors
    /// * `Unspecified`: Returned if the length of `key_bytes` does not match the chosen algorithm,
    /// or if an unsupported algorithm is provided.
    pub fn new(
        algorithm: &'static Algorithm,
        protocol: TLSProtocolId,
        key_bytes: &[u8],
    ) -> Result<Self, Unspecified> {
        let ctx = Mutex::new(match (algorithm.id, protocol) {
            (AlgorithmID::AES_128_GCM, TLSProtocolId::TLS12) => AeadCtx::aes_128_gcm_tls12(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Seal,
            ),
            (AlgorithmID::AES_128_GCM, TLSProtocolId::TLS13) => AeadCtx::aes_128_gcm_tls13(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Seal,
            ),
            (AlgorithmID::AES_256_GCM, TLSProtocolId::TLS12) => AeadCtx::aes_256_gcm_tls12(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Seal,
            ),
            (AlgorithmID::AES_256_GCM, TLSProtocolId::TLS13) => AeadCtx::aes_256_gcm_tls13(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Seal,
            ),
            (AlgorithmID::AES_128_GCM_SIV, _)
            | (AlgorithmID::AES_256_GCM_SIV, _)
            | (AlgorithmID::CHACHA20_POLY1305, _) => Err(Unspecified),
        }?);
        Ok(Self { ctx, algorithm })
    }

    /// Accepts a `Nonce` and `Aad` construction that is unique for this key and
    /// TLS record sealing operation for the configured TLS protocol version.
    ///
    /// `nonce` must be unique and incremented per each sealing operation,
    /// otherwise an error is returned.
    ///
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
        let ctx = self.ctx.lock().map_err(|_| Unspecified)?;
        seal_in_place_append_tag(
            self.algorithm,
            &ctx,
            Some(nonce),
            Aad::from(aad.as_ref()),
            in_out,
        )
        .map(|_| ())
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// AEAD Encryption key used for TLS protocol record encryption.
pub struct TLSRecordOpeningKey {
    // The TLS specific construction for TLS ciphers in AWS-LC are not thread-safe!
    // The choice here was either wrap the underlying EVP_AEAD_CTX in a Mutex as done here,
    // or force this type to !Sync. Since this is an implementation detail of AWS-LC
    // we have optex to manage this behavior internally.
    ctx: Mutex<AeadCtx>,
    algorithm: &'static Algorithm,
}

impl TLSRecordOpeningKey {
    /// New TLS record opening key. Only supports `AES_128_GCM` and `AES_256_GCM` Algorithms.
    ///
    /// # Errors
    /// * `Unspecified`: Returned if the length of `key_bytes` does not match the chosen algorithm,
    /// or if an unsupported algorithm is provided.
    pub fn new(
        algorithm: &'static Algorithm,
        protocol: TLSProtocolId,
        key_bytes: &[u8],
    ) -> Result<Self, Unspecified> {
        let ctx = Mutex::new(match (algorithm.id, protocol) {
            (AlgorithmID::AES_128_GCM, TLSProtocolId::TLS12) => AeadCtx::aes_128_gcm_tls12(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Open,
            ),
            (AlgorithmID::AES_128_GCM, TLSProtocolId::TLS13) => AeadCtx::aes_128_gcm_tls13(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Open,
            ),
            (AlgorithmID::AES_256_GCM, TLSProtocolId::TLS12) => AeadCtx::aes_256_gcm_tls12(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Open,
            ),
            (AlgorithmID::AES_256_GCM, TLSProtocolId::TLS13) => AeadCtx::aes_256_gcm_tls13(
                key_bytes,
                algorithm.tag_len(),
                aead_ctx::AeadDirection::Open,
            ),
            (AlgorithmID::AES_128_GCM_SIV, _)
            | (AlgorithmID::AES_256_GCM_SIV, _)
            | (AlgorithmID::CHACHA20_POLY1305, _) => Err(Unspecified),
        }?);
        Ok(Self { ctx, algorithm })
    }

    /// Accepts a Noce and Aad construction that is unique for this TLS record
    /// opening operation.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
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

    /// Accepts a Noce and Aad construction that is unique for this TLS record
    /// opening operation.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// See [`OpeningKey::open_within`] for details on `ciphertext_and_tag` argument usage.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
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
        let ctx = self.ctx.lock().map_err(|_| Unspecified)?;
        open_within(self.algorithm, &ctx, nonce, aad, in_out, ciphertext_and_tag)
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
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

/// The maximum length of a nonce returned by our AEAD API.
const MAX_NONCE_LEN: usize = NONCE_LEN;

/// The maximum required tag buffer needed if using AWS-LC generated nonce construction
const MAX_TAG_NONCE_BUFFER_LEN: usize = MAX_TAG_LEN + MAX_NONCE_LEN;

#[inline]
#[must_use]
const fn u64_from_usize(x: usize) -> u64 {
    x as u64
}

#[inline]
fn check_per_nonce_max_bytes(alg: &Algorithm, in_out_len: usize) -> Result<(), Unspecified> {
    if u64_from_usize(in_out_len) > alg.max_input_len {
        return Err(Unspecified);
    }
    Ok(())
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_combined<InOut>(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut InOut,
) -> Result<Nonce, Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    let plaintext_len = in_out.as_mut().len();

    let alg_tag_len = alg.tag_len();

    debug_assert!(alg_tag_len <= MAX_TAG_LEN);

    let tag_buffer = [0u8; MAX_TAG_LEN];

    in_out.extend(tag_buffer[..alg_tag_len].iter());

    let mut out_len = MaybeUninit::<usize>::uninit();
    let mut_in_out = in_out.as_mut();
    let aad_str = aad.0;

    {
        let nonce = nonce.as_ref();

        debug_assert_eq!(nonce.len(), alg.nonce_len());

        if 1 != unsafe {
            EVP_AEAD_CTX_seal(
                *ctx.as_ref().as_const(),
                mut_in_out.as_mut_ptr(),
                out_len.as_mut_ptr(),
                plaintext_len + alg_tag_len,
                nonce.as_ptr(),
                nonce.len(),
                mut_in_out.as_ptr(),
                plaintext_len,
                aad_str.as_ptr(),
                aad_str.len(),
            )
        } {
            return Err(Unspecified);
        }
    }

    Ok(nonce)
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_combined_randnonce<InOut>(
    alg: &'static Algorithm,
    key: &AeadCtx,
    aad: Aad<&[u8]>,
    in_out: &mut InOut,
) -> Result<Nonce, Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

    let mut out_tag_len = MaybeUninit::<usize>::uninit();
    let aad_str = aad.0;

    {
        let plaintext_len = in_out.as_mut().len();
        let in_out = in_out.as_mut();

        if 1 != unsafe {
            EVP_AEAD_CTX_seal_scatter(
                *key.as_ref().as_const(),
                in_out.as_mut_ptr(),
                tag_buffer.as_mut_ptr(),
                out_tag_len.as_mut_ptr(),
                tag_buffer.len(),
                null(),
                0,
                in_out.as_ptr(),
                plaintext_len,
                null(),
                0,
                aad_str.as_ptr(),
                aad_str.len(),
            )
        } {
            return Err(Unspecified);
        }
    }

    let tag_len = alg.tag_len();
    let nonce_len = alg.nonce_len();

    let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
        &tag_buffer[tag_len..tag_len + nonce_len],
    )?);

    in_out.extend(&tag_buffer[..tag_len]);

    Ok(nonce)
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_separate(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(Nonce, Tag), Unspecified> {
    let aad_slice = aad.as_ref();
    let mut tag = [0u8; MAX_TAG_LEN];
    let mut out_tag_len = MaybeUninit::<usize>::uninit();
    {
        let nonce = nonce.as_ref();

        debug_assert_eq!(nonce.len(), alg.nonce_len());

        if 1 != unsafe {
            EVP_AEAD_CTX_seal_scatter(
                *ctx.as_ref().as_const(),
                in_out.as_mut_ptr(),
                tag.as_mut_ptr(),
                out_tag_len.as_mut_ptr(),
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                in_out.len(),
                null(),
                0usize,
                aad_slice.as_ptr(),
                aad_slice.len(),
            )
        } {
            return Err(Unspecified);
        }
    }
    Ok((nonce, Tag(tag, unsafe { out_tag_len.assume_init() })))
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_separate_randnonce(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(Nonce, Tag), Unspecified> {
    let aad_slice = aad.as_ref();
    let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

    debug_assert!(alg.tag_len() + alg.nonce_len() <= tag_buffer.len());

    let mut out_tag_len = MaybeUninit::<usize>::uninit();

    if 1 != unsafe {
        EVP_AEAD_CTX_seal_scatter(
            *ctx.as_ref().as_const(),
            in_out.as_mut_ptr(),
            tag_buffer.as_mut_ptr(),
            out_tag_len.as_mut_ptr(),
            tag_buffer.len(),
            null(),
            0,
            in_out.as_ptr(),
            in_out.len(),
            null(),
            0usize,
            aad_slice.as_ptr(),
            aad_slice.len(),
        )
    } {
        return Err(Unspecified);
    }

    let tag_len = alg.tag_len();
    let nonce_len = alg.nonce_len();

    let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
        &tag_buffer[tag_len..tag_len + nonce_len],
    )?);

    let mut tag = [0u8; MAX_TAG_LEN];
    tag.copy_from_slice(&tag_buffer[..tag_len]);

    Ok((nonce, Tag(tag, tag_len)))
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_open_combined(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(), Unspecified> {
    let nonce = nonce.as_ref();

    debug_assert_eq!(nonce.len(), alg.nonce_len());

    let plaintext_len = in_out.len() - alg.tag_len();

    let aad_str = aad.0;
    let mut out_len = MaybeUninit::<usize>::uninit();
    if 1 != unsafe {
        EVP_AEAD_CTX_open(
            *ctx.as_ref().as_const(),
            in_out.as_mut_ptr(),
            out_len.as_mut_ptr(),
            plaintext_len,
            nonce.as_ptr(),
            nonce.len(),
            in_out.as_ptr(),
            plaintext_len + alg.tag_len(),
            aad_str.as_ptr(),
            aad_str.len(),
        )
    } {
        return Err(Unspecified);
    }

    Ok(())
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_open_combined_randnonce(
    alg: &'static Algorithm,
    ctx: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(), Unspecified> {
    let nonce = nonce.as_ref();

    let alg_nonce_len = alg.nonce_len();
    let alg_tag_len = alg.tag_len();

    debug_assert_eq!(nonce.len(), alg_nonce_len);
    debug_assert!(alg_tag_len + alg_nonce_len <= MAX_TAG_NONCE_BUFFER_LEN);

    let plaintext_len = in_out.len() - alg_tag_len;

    let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

    tag_buffer[..alg_tag_len].copy_from_slice(&in_out[plaintext_len..plaintext_len + alg_tag_len]);
    tag_buffer[alg_tag_len..alg_tag_len + alg_nonce_len].copy_from_slice(nonce);

    let tag_slice = &tag_buffer[0..alg_tag_len + alg_nonce_len];

    let aad_str = aad.0;

    if 1 != unsafe {
        EVP_AEAD_CTX_open_gather(
            *ctx.as_ref().as_const(),
            in_out.as_mut_ptr(),
            null(),
            0,
            in_out.as_ptr(),
            plaintext_len,
            tag_slice.as_ptr(),
            tag_slice.len(),
            aad_str.as_ptr(),
            aad_str.len(),
        )
    } {
        return Err(Unspecified);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{iv::FixedLength, test::from_hex};
    use paste::paste;

    const TEST_128_BIT_KEY: &[u8] = &[
        0xb0, 0x37, 0x9f, 0xf8, 0xfb, 0x8e, 0xa6, 0x31, 0xf4, 0x1c, 0xe6, 0x3e, 0xb5, 0xc5, 0x20,
        0x7c,
    ];

    const TEST_256_BIT_KEY: &[u8] = &[
        0x56, 0xd8, 0x96, 0x68, 0xbd, 0x96, 0xeb, 0xff, 0x5e, 0xa2, 0x0b, 0x34, 0xf2, 0x79, 0x84,
        0x6e, 0x2b, 0x13, 0x01, 0x3d, 0xab, 0x1d, 0xa4, 0x07, 0x5a, 0x16, 0xd5, 0x0b, 0x53, 0xb0,
        0xcc, 0x88,
    ];

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

    macro_rules! test_randnonce {
        ($name:ident, $alg:expr, $key:expr) => {
            paste! {
                #[test]
                fn [<test_ $name _randnonce_unsupported>]() {
                    assert!(RandomizedNonceKey::new($alg, $key).is_err());
                }
            }
        };
        ($name:ident, $alg:expr, $key:expr, $expect_tag_len:expr, $expect_nonce_len:expr) => {
            paste! {
                #[test]
                fn [<test_ $name _randnonce>]() {
                    let plaintext = from_hex("00112233445566778899aabbccddeeff").unwrap();
                    let rand_nonce_key =
                        RandomizedNonceKey::new($alg, $key).unwrap();

                    assert_eq!($alg, rand_nonce_key.algorithm());
                    assert_eq!(*$expect_tag_len, $alg.tag_len());
                    assert_eq!(*$expect_nonce_len, $alg.nonce_len());

                    let mut in_out = Vec::from(plaintext.as_slice());

                    let nonce = rand_nonce_key
                        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
                        .unwrap();

                    assert_ne!(plaintext, in_out[..plaintext.len()]);

                    rand_nonce_key
                        .open_in_place(nonce, Aad::empty(), &mut in_out)
                        .unwrap();

                    assert_eq!(plaintext, in_out[..plaintext.len()]);

                    let mut in_out = Vec::from(plaintext.as_slice());

                    let (nonce, tag) = rand_nonce_key
                        .seal_in_place_separate_tag(Aad::empty(), &mut in_out)
                        .unwrap();

                    assert_ne!(plaintext, in_out[..plaintext.len()]);

                    in_out.extend(tag.as_ref());

                    rand_nonce_key
                        .open_in_place(nonce, Aad::empty(), &mut in_out)
                        .unwrap();

                    assert_eq!(plaintext, in_out[..plaintext.len()]);
                }
            }
        };
    }

    test_randnonce!(aes_128_gcm, &AES_128_GCM, TEST_128_BIT_KEY, &16, &12);
    test_randnonce!(aes_256_gcm, &AES_256_GCM, TEST_256_BIT_KEY, &16, &12);
    test_randnonce!(chacha20_poly1305, &CHACHA20_POLY1305, TEST_256_BIT_KEY);

    struct TlsNonceTestCase {
        nonce: &'static str,
        expect_err: bool,
    }

    const TLS_NONCE_TEST_CASES: &[TlsNonceTestCase] = &[
        TlsNonceTestCase {
            nonce: "9fab40177c900aad9fc28cc3",
            expect_err: false,
        },
        TlsNonceTestCase {
            nonce: "9fab40177c900aad9fc28cc4",
            expect_err: false,
        },
        TlsNonceTestCase {
            nonce: "9fab40177c900aad9fc28cc2",
            expect_err: true,
        },
    ];

    macro_rules! test_tls_aead {
        ($name:ident, $alg:expr, $proto:expr, $key:expr) => {
            paste! {
                #[test]
                fn [<test_ $name _tls_aead_unsupported>]() {
                    assert!(TLSRecordSealingKey::new($alg, $proto, $key).is_err());
                    assert!(TLSRecordOpeningKey::new($alg, $proto, $key).is_err());
                }
            }
        };
        ($name:ident, $alg:expr, $proto:expr, $key:expr, $expect_tag_len:expr, $expect_nonce_len:expr) => {
            paste! {
                #[test]
                fn [<test_ $name>]() {
                    let sealing_key =
                        TLSRecordSealingKey::new($alg, $proto, $key).unwrap();

                    let opening_key =
                        TLSRecordOpeningKey::new($alg, $proto, $key).unwrap();

                    for case in TLS_NONCE_TEST_CASES {
                        let plaintext = from_hex("00112233445566778899aabbccddeeff").unwrap();

                        assert_eq!($alg, sealing_key.algorithm());
                        assert_eq!(*$expect_tag_len, $alg.tag_len());
                        assert_eq!(*$expect_nonce_len, $alg.nonce_len());

                        let mut in_out = Vec::from(plaintext.as_slice());

                        let nonce = from_hex(case.nonce).unwrap();

                        let nonce_bytes = nonce.as_slice();

                        let result = sealing_key.seal_in_place_append_tag(
                            Nonce::try_assume_unique_for_key(nonce_bytes).unwrap(),
                            Aad::empty(),
                            &mut in_out,
                        );

                        match (result, case.expect_err) {
                            (Ok(()), true) => panic!("expected error for seal_in_place_append_tag"),
                            (Ok(()), false) => {}
                            (Err(_), true) => return,
                            (Err(e), false) => panic!("{e}"),
                        }

                        assert_ne!(plaintext, in_out[..plaintext.len()]);

                        opening_key
                            .open_in_place(
                                Nonce::try_assume_unique_for_key(nonce_bytes).unwrap(),
                                Aad::empty(),
                                &mut in_out,
                            )
                            .unwrap();

                        assert_eq!(plaintext, in_out[..plaintext.len()]);
                    }
                }
            }
        };
    }

    test_tls_aead!(
        aes_128_gcm_tls12,
        &AES_128_GCM,
        TLSProtocolId::TLS12,
        TEST_128_BIT_KEY,
        &16,
        &12
    );
    test_tls_aead!(
        aes_128_gcm_tls13,
        &AES_128_GCM,
        TLSProtocolId::TLS13,
        TEST_128_BIT_KEY,
        &16,
        &12
    );
    test_tls_aead!(
        aes_256_gcm_tls12,
        &AES_256_GCM,
        TLSProtocolId::TLS12,
        TEST_256_BIT_KEY,
        &16,
        &12
    );
    test_tls_aead!(
        aes_256_gcm_tls13,
        &AES_256_GCM,
        TLSProtocolId::TLS13,
        TEST_256_BIT_KEY,
        &16,
        &12
    );
    test_tls_aead!(
        chacha20_poly1305_tls12,
        &CHACHA20_POLY1305,
        TLSProtocolId::TLS12,
        TEST_256_BIT_KEY
    );
    test_tls_aead!(
        chacha20_poly1305_tls13,
        &CHACHA20_POLY1305,
        TLSProtocolId::TLS13,
        TEST_256_BIT_KEY
    );
}
