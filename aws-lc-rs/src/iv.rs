// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#![allow(dead_code)]

//! Initialization Vector (IV) cryptographic primitives

use crate::error::Unspecified;
use crate::{error, rand};

/// An initalization vector that must be unique for the lifetime of the associated key
/// it is used with.
pub struct FixedLength<const L: usize>([u8; L]);

impl<const L: usize> FixedLength<L> {
    /// Constructs a [`NonceIV`] with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `L` bytes long.
    /// # Errors
    /// `error::Unspecified` when byte slice length is not `L`
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        let value: &[u8; L] = value.try_into()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a [`NonceIV`] with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    #[must_use]
    pub fn assume_unique_for_key(value: [u8; L]) -> Self {
        Self(value)
    }

    /// Returns the size of the nonce in bytes.
    #[allow(clippy::must_use_candidate)]
    pub fn size(&self) -> usize {
        L
    }

    /// Constructs a new [`NonceIV`] from pseudo-random bytes.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if there is a failure generating `L` bytes.
    ///
    pub fn new() -> Result<Self, Unspecified> {
        let mut iv_bytes = [0u8; L];
        rand::fill(&mut iv_bytes)?;
        Ok(Self(iv_bytes))
    }
}

impl<const L: usize> AsMut<[u8; L]> for FixedLength<L> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8; L] {
        &mut self.0
    }
}

impl<const L: usize> AsRef<[u8; L]> for FixedLength<L> {
    #[inline]
    fn as_ref(&self) -> &[u8; L] {
        &self.0
    }
}

impl<const L: usize> From<&[u8; L]> for FixedLength<L> {
    #[inline]
    fn from(bytes: &[u8; L]) -> Self {
        FixedLength(bytes.to_owned())
    }
}

impl<const L: usize> From<[u8; L]> for FixedLength<L> {
    #[inline]
    fn from(bytes: [u8; L]) -> Self {
        FixedLength(bytes)
    }
}

impl<const L: usize> TryFrom<&[u8]> for FixedLength<L> {
    type Error = Unspecified;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        FixedLength::<L>::try_assume_unique_for_key(value)
    }
}

impl<const L: usize> TryFrom<FixedLength<L>> for [u8; L] {
    type Error = Unspecified;

    fn try_from(value: FixedLength<L>) -> Result<Self, Self::Error> {
        Ok(value.0)
    }
}
