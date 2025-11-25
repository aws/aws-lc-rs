// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::endian::{ArrayEncoding, BigEndian, Encoding, FromArray, LittleEndian};
use crate::error;
use crate::iv::FixedLength;

/// A nonce for a single AEAD opening or sealing operation.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// `Nonce` intentionally doesn't implement `Clone` to ensure that each one is
/// consumed at most once.
pub struct Nonce(pub(crate) FixedLength<NONCE_LEN>);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    /// # Errors
    /// `error::Unspecified` when byte slice length is not `NONCE_LEN`
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(Self(FixedLength::<NONCE_LEN>::try_from(value)?))
    }
    
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    #[must_use]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(FixedLength::<NONCE_LEN>::from(value))
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
        Self(FixedLength::from(bytes))
    }
}

/// All the AEADs we support use 192-bit nonces.
pub const NONCE_LEN: usize = 192 / 8;

#[cfg(test)]
mod tests {

    #[test]
    fn test_nonce_from_byte_array() {
        use crate::aead_xaes_256_gcm::nonce::NONCE_LEN;
        use crate::aead_xaes_256_gcm::Nonce;
        let iv: [u8; NONCE_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
        let nonce = Nonce::from(&iv);

        assert_eq!(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24], nonce.as_ref());
    }
}
