// Copyright 2018 Brian Smith.
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

use crate::endian::{ArrayEncoding, BigEndian, Encoding};
use crate::error;
use std::convert::TryInto;
use std::mem::transmute_copy;

/// A nonce for a single AEAD opening or sealing operation.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// `Nonce` intentionally doesn't implement `Clone` to ensure that each one is
/// consumed at most once.
pub struct Nonce(pub(crate) [u8; NONCE_LEN]);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    /// # Errors
    /// `error::Unspecified` when byte slice length is not `NONCE_LEN`
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        let value: &[u8; NONCE_LEN] = value.try_into()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    #[must_use]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    #[inline]
    fn as_ref(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl From<&[u8; NONCE_LEN]> for Nonce {
    #[inline]
    fn from(bytes: &[u8; NONCE_LEN]) -> Self {
        Nonce(bytes.to_owned())
    }
}

impl From<&[u32; NONCE_LEN / 4]> for Nonce {
    #[inline]
    fn from(values: &[u32; NONCE_LEN / 4]) -> Self {
        unsafe {
            let bytes: [u8; NONCE_LEN] = transmute_copy(values);
            Nonce(bytes)
        }
    }
}

impl From<BigEndian<u32>> for Nonce {
    #[inline]
    fn from(number: BigEndian<u32>) -> Self {
        let nonce = [BigEndian::ZERO, BigEndian::ZERO, number];
        Nonce(*(nonce.as_byte_array()))
    }
}

pub const IV_LEN: usize = 16;
impl From<&[u8; IV_LEN]> for Nonce {
    #[inline]
    fn from(bytes: &[u8; IV_LEN]) -> Self {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&bytes[0..NONCE_LEN]);
        Nonce(nonce_bytes)
    }
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;
