// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::agreement::{agree, Algorithm, PrivateKey, PublicKey, UnparsedPublicKey};
use crate::error::Unspecified;
use crate::rand::SecureRandom;
use core::fmt;
use std::fmt::{Debug, Formatter};

/// An ephemeral private key for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `PrivateKey` can be
/// used for at most one key agreement.
#[allow(clippy::module_name_repetitions)]
pub struct EphemeralPrivateKey(PrivateKey);

impl Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "EphemeralPrivateKey {{ algorithm: {:?} }}",
            self.0.inner_key.algorithm()
        ))
    }
}

impl EphemeralPrivateKey {
    #[inline]
    /// Generate a new ephemeral private key for the given algorithm.
    ///
    /// # *ring* Compatibility
    ///  Our implementation ignores the `SecureRandom` parameter.
    ///
    // # FIPS
    // Use this function with one of the following algorithms:
    // * `ECDH_P256`
    // * `ECDH_P384`
    // * `ECDH_P521`
    //
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(alg: &'static Algorithm, _rng: &dyn SecureRandom) -> Result<Self, Unspecified> {
        Ok(Self(PrivateKey::generate(alg)?))
    }

    #[cfg(test)]
    #[allow(clippy::missing_errors_doc)]
    pub fn generate_for_test(
        alg: &'static Algorithm,
        rng: &dyn SecureRandom,
    ) -> Result<Self, Unspecified> {
        Ok(Self(PrivateKey::generate_for_test(alg, rng)?))
    }

    /// Computes the public key from the private key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        self.0.compute_public_key()
    }

    /// The algorithm for the private key.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.0.algorithm()
    }
}

/// Performs a key agreement with an ephemeral private key and the given public
/// key.
///
/// `my_private_key` is the ephemeral private key to use. Since it is moved, it
/// will not be usable after calling `agree_ephemeral`, thus guaranteeing that
/// the key is used for only one key agreement.
///
/// `peer_public_key` is the peer's public key. `agree_ephemeral` will return
/// `Err(error_value)` if it does not match `my_private_key's` algorithm/curve.
/// `agree_ephemeral` verifies that it is encoded in the standard form for the
/// algorithm and that the key is *valid*; see the algorithm's documentation for
/// details on how keys are to be encoded and what constitutes a valid key for
/// that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree_ephemeral` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
///
// # FIPS
// Use this function with one of the following key algorithms:
// * `ECDH_P256`
// * `ECDH_P384`
// * `ECDH_P521`
//
/// # Errors
/// `error_value` on internal failure.
#[inline]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::module_name_repetitions)]
pub fn agree_ephemeral<B: AsRef<[u8]>, F, R, E>(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
    error_value: E,
    kdf: F,
) -> Result<R, E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    agree(&my_private_key.0, peer_public_key, error_value, kdf)
}
