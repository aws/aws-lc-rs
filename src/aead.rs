// Copyright 2015-2021 Brian Smith.
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

#![allow(dead_code)]

use crate::aead::InnerKey::{Aes128Gcm, Aes256Gcm};
use crate::error;
pub use aes_gcm::{AES_128_GCM, AES_256_GCM};
use std::fmt;
use std::fmt::{Debug, Formatter};

mod aes_gcm;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Eq, PartialEq)]
enum AlgorithmId {
    Aes128Gcm,
    Aes256Gcm,
}

/// An authentication tag.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for Tag {
    type Error = error::Unspecified;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw_tag: [u8; TAG_LEN] = value.try_into().map_err(|_| error::Unspecified)?;
        Ok(Self::from(raw_tag))
    }
}

impl From<[u8; TAG_LEN]> for Tag {
    #[inline]
    fn from(value: [u8; TAG_LEN]) -> Self {
        Self(value)
    }
}

impl AlgorithmId {
    fn name(&self) -> &str {
        match self {
            AlgorithmId::Aes128Gcm => "AES_128_GCM",
            AlgorithmId::Aes256Gcm => "AES_256_GCM",
        }
    }
}

pub struct Algorithm {
    key_len: usize,
    id: AlgorithmId,
    seal: fn(
        key: &InnerKey,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>,
    open: fn(
        key: &InnerKey,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_prefix_len: usize,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

impl Algorithm {
    /// The length of the key.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of the nonces.
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        let value: &[u8; NONCE_LEN] = value.try_into().map_err(|_| error::Unspecified)?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }
}

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
    /// This may fail if "too many" nonces have been requested, where how many
    /// is too many is up to the implementation of `NonceSequence`. An
    /// implementation may that enforce a maximum number of records are
    /// sent/received under a key this way. Once `advance()` fails, it must
    /// fail for all subsequent calls.
    fn advance(&mut self) -> Result<Nonce, error::Unspecified>;
}

/// An AEAD key bound to a nonce sequence.
pub trait BoundKey<N: NonceSequence> {
    /// Constructs a new key from the given `UnboundKey` and `NonceSequence`.
    fn new(key: UnboundKey, nonce_sequence: N) -> Self;

    /// The key's AEAD algorithm.
    fn algorithm(&self) -> &'static Algorithm;
}

#[derive(Debug)]
enum InnerKey {
    Aes128Gcm([u8; 16]),
    Aes256Gcm([u8; 32]),
}

impl InnerKey {
    fn algorithm(&self) -> &'static Algorithm {
        match self {
            Aes128Gcm(_) => &AES_256_GCM,
            Aes256Gcm(_) => &AES_256_GCM,
        }
    }
}

/// An AEAD key without a designated role or nonce sequence.
#[derive(Debug)]
pub struct UnboundKey {
    inner: InnerKey,
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    ///
    /// Fails if `key_bytes.len() != algorithm.key_len()`.
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        let unbound_key;
        if algorithm == &AES_128_GCM {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(key_bytes);
            let inner_key = Aes128Gcm(bytes);
            unbound_key = UnboundKey { inner: inner_key }
        } else if algorithm == &AES_128_GCM {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(key_bytes);
            let inner_key = Aes256Gcm(bytes);
            unbound_key = UnboundKey { inner: inner_key }
        } else {
            return Err(error::Unspecified);
        }

        Ok(unbound_key)
    }

    fn algorithm(&self) -> &'static Algorithm {
        self.inner.algorithm()
    }
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
        self.key.algorithm()
    }
}
impl<N: NonceSequence> Debug for OpeningKey<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpeningKey")
            //.field("key", &self.key)
            //.field("nonce_sequence", &"<<>>")
            .field("algorithm", &self.key.algorithm().id.name())
            .finish()
    }
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

impl<N: NonceSequence> SealingKey<N> {
    /// Encrypts and signs (“seals”) data in place, appending the tag to the
    /// resulting ciphertext.
    ///
    /// `key.seal_in_place_append_tag(aad, in_out)` is equivalent to:
    ///
    /// ```skip
    /// key.seal_in_place_separate_tag(aad, in_out.as_mut())
    ///     .map(|tag| in_out.extend(tag.as_ref()))
    /// ```
    #[inline]
    pub fn seal_in_place_append_tag<A, InOut>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_separate_tag(aad, in_out.as_mut())
            .map(|tag| in_out.extend(tag.as_ref()))
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
    #[inline]
    pub fn seal_in_place_separate_tag<A>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let nonce = self.nonce_sequence.advance().unwrap();
        Ok((&self.key.algorithm().seal)(
            &self.key.inner,
            nonce,
            Aad::from(aad.as_ref()),
            in_out,
        ))
    }
}

impl<N: NonceSequence> Debug for SealingKey<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealingKey")
            //.field("key", &self.key)
            //.field("nonce_sequence", &"<<>>")
            .field("algorithm", &self.key.algorithm().id.name())
            .finish()
    }
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
    pub fn empty() -> Self {
        Self::from([])
    }
}
