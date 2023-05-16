// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::endian::{ArrayEncoding, BigEndian, Encoding};
use crate::error;
use crate::iv::NonceIV;
use std::mem::transmute_copy;

/// A nonce for a single AEAD opening or sealing operation.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// `Nonce` intentionally doesn't implement `Clone` to ensure that each one is
/// consumed at most once.
pub struct Nonce(pub(crate) NonceIV<NONCE_LEN>);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    /// # Errors
    /// `error::Unspecified` when byte slice length is not `NONCE_LEN`
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(Self(NonceIV::<NONCE_LEN>::try_assume_unique_for_key(
            value,
        )?))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    #[must_use]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(NonceIV::<NONCE_LEN>::assume_unique_for_key(value))
    }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    #[inline]
    fn as_ref(&self) -> &[u8; NONCE_LEN] {
        self.0.as_ref()
    }
}

impl From<&[u8; NONCE_LEN]> for Nonce {
    #[inline]
    fn from(bytes: &[u8; NONCE_LEN]) -> Self {
        Self(NonceIV::from(bytes))
    }
}

impl From<&[u32; NONCE_LEN / 4]> for Nonce {
    #[inline]
    fn from(values: &[u32; NONCE_LEN / 4]) -> Self {
        unsafe {
            let bytes: [u8; NONCE_LEN] = transmute_copy(values);
            Nonce(NonceIV::from(bytes))
        }
    }
}

impl From<BigEndian<u32>> for Nonce {
    #[inline]
    fn from(number: BigEndian<u32>) -> Self {
        let nonce = [BigEndian::ZERO, BigEndian::ZERO, number];
        Nonce(NonceIV::from(*(nonce.as_byte_array())))
    }
}

pub const IV_LEN: usize = 16;
impl From<&[u8; IV_LEN]> for Nonce {
    #[inline]
    fn from(bytes: &[u8; IV_LEN]) -> Self {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&bytes[0..NONCE_LEN]);
        Nonce(NonceIV::from(nonce_bytes))
    }
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;

#[cfg(test)]
mod tests {

    #[test]
    fn test_nonce_from_byte_array() {
        use crate::aead::nonce::IV_LEN;
        use crate::aead::Nonce;
        let iv: [u8; IV_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let nonce = Nonce::from(&iv);

        assert_eq!(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], nonce.as_ref());
    }
}
