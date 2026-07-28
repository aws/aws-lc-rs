// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! ML-DSA specific support: the "external mu" signing and verification variant.
//!
//! ML-DSA (FIPS 204) signs and verifies the message itself. Internally it first derives a
//! 64-byte *message representative*
//!
//! ```text
//! tr = SHAKE256(public_key, 64)
//! mu = SHAKE256(tr || 0x00 || len(context) || context || message, 64)
//! ```
//!
//! and signs `mu`. The "external mu" variant lets `mu` be derived by a different party, or
//! at a different time, than the one holding the signing key -- useful when the message is
//! large, streamed, or simply not available where the key lives. NIST describes the
//! acceptability of this usage in its [FIPS 204 FAQ].
//!
//! Because `mu` is derived from the public key, an external-mu signature is
//! indistinguishable from, and interchangeable with, an ordinary ML-DSA signature over the
//! same message. It is not a different signature scheme, only a different way of feeding the
//! message in.
//!
//! This support lives in its own module rather than on [`PqdsaKeyPair`] and friends because
//! external mu is an ML-DSA-specific construction, while the `Pqdsa*` types are shared by
//! the whole post-quantum signature family. [`ExternalMuSigner`] and [`ExternalMuVerifier`]
//! can only be obtained for ML-DSA keys, so the algorithm check happens once, when the
//! handle is created, rather than on every operation.
//!
//! # Example
//!
//! ```
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::ml_dsa::{ExternalMuSigner, ExternalMuVerifier};
//! use aws_lc_rs::signature::{
//!     KeyPair, ParsedPublicKey, PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING,
//! };
//!
//! let key_pair = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING)?;
//! let public_key = ParsedPublicKey::new(&ML_DSA_44, key_pair.public_key().as_ref())?;
//!
//! // The signer derives mu and signs it.
//! let signer = ExternalMuSigner::try_from(&key_pair)?;
//! let mu = signer.compute_mu(b"hello, world")?;
//! let mut signature = vec![0u8; key_pair.algorithm().signature_len()];
//! let len = signer.sign(&mu, &mut signature)?;
//! signature.truncate(len);
//!
//! // The verifier derives the same mu from the public key and checks the signature.
//! let verifier = ExternalMuVerifier::try_from(&public_key)?;
//! assert_eq!(mu.as_ref(), verifier.compute_mu(b"hello, world")?.as_ref());
//! verifier.verify(&mu, &signature)?;
//!
//! // The same signature verifies as an ordinary ML-DSA signature over the message.
//! public_key.verify_sig(b"hello, world", &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! [FIPS 204 FAQ]:
//!     https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/faq/fips204-sec6-03192025.pdf

use crate::aws_lc::EVP_PKEY;
use crate::error::Unspecified;
use crate::evp_pkey::No_EVP_PKEY_CTX_consumer;
use crate::pqdsa::{
    compute_mu, compute_tr, external_representative_len, MAX_EXTERNAL_REPRESENTATIVE_LEN, TR_LEN,
};
use crate::ptr::LcPtr;
use crate::signature::{
    KeyPair, ParsedPublicKey, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm,
};
use core::fmt::{Debug, Formatter};

/// Returns the length in bytes of the `mu` value used by `algorithm`, or `None` if
/// `algorithm` does not support the external mu variant.
///
/// Every ML-DSA parameter set currently uses 64 bytes.
#[must_use]
pub fn external_mu_len(algorithm: &'static PqdsaVerificationAlgorithm) -> Option<usize> {
    external_representative_len(algorithm.id)
}

/// The FIPS 204 "message representative" `mu`, used by the "external mu" variant of ML-DSA.
///
/// Obtain one with [`ExternalMuSigner::compute_mu`] or [`ExternalMuVerifier::compute_mu`],
/// or, if it was derived elsewhere, with [`Self::import_less_safe`]. Use [`Self::as_ref`] to
/// get the value as a `&[u8]`, and [`external_mu_len`] to ask an algorithm how long its `mu`
/// is.
#[derive(Clone, Copy)]
pub struct ExternalMu {
    /// `Copy` cannot be implemented for a dynamically sized array, so this is a fixed buffer
    /// large enough for any algorithm plus the length actually in use, matching
    /// [`crate::digest::Digest`].
    mu: [u8; MAX_EXTERNAL_REPRESENTATIVE_LEN],
    len: usize,
    algorithm: &'static PqdsaVerificationAlgorithm,
}

impl ExternalMu {
    /// The largest `mu` length across all supported algorithms. Useful for sizing a buffer
    /// when no specific algorithm is in hand; see [`external_mu_len`] for the exact length
    /// used by a given algorithm.
    pub const MAX_LEN: usize = MAX_EXTERNAL_REPRESENTATIVE_LEN;

    /// Imports a `mu` value provided by an external source. This allows for the signing of
    /// content that might not be directly accessible.
    ///
    /// WARNING: unlike a message digest, `mu` binds the message to a *specific public key*.
    /// Signing an attacker-influenced `mu` is a blind signing operation: it yields a valid
    /// signature over a message the signer never saw and cannot inspect. Ensure the value
    /// comes from a trusted source and was derived under `algorithm` and the key it will be
    /// used with. When possible, prefer to compute `mu` directly with
    /// [`ExternalMuSigner::compute_mu`] or [`ExternalMuVerifier::compute_mu`].
    ///
    /// # Errors
    /// Returns `Unspecified` if `algorithm` does not support the external mu variant, or if
    /// `mu` is not exactly [`external_mu_len`] bytes for `algorithm`.
    pub fn import_less_safe(
        mu: &[u8],
        algorithm: &'static PqdsaVerificationAlgorithm,
    ) -> Result<Self, Unspecified> {
        let len = external_mu_len(algorithm).ok_or(Unspecified)?;
        if mu.len() != len {
            return Err(Unspecified);
        }
        let mut buffer = [0u8; MAX_EXTERNAL_REPRESENTATIVE_LEN];
        buffer[..len].copy_from_slice(mu);
        Ok(Self {
            mu: buffer,
            len,
            algorithm,
        })
    }

    /// The ML-DSA algorithm this `mu` was computed for.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaVerificationAlgorithm {
        self.algorithm
    }

    /// Fills a new `mu` of the length `algorithm` requires, via `fill`.
    fn new<F>(algorithm: &'static PqdsaVerificationAlgorithm, fill: F) -> Result<Self, Unspecified>
    where
        F: FnOnce(&mut [u8]) -> Result<(), Unspecified>,
    {
        let len = external_mu_len(algorithm).ok_or(Unspecified)?;
        let mut mu = [0u8; MAX_EXTERNAL_REPRESENTATIVE_LEN];
        fill(&mut mu[..len])?;
        Ok(Self { mu, len, algorithm })
    }
}

impl AsRef<[u8]> for ExternalMu {
    fn as_ref(&self) -> &[u8] {
        &self.mu[..self.len]
    }
}

// Mirrors `Digest`'s Debug: the algorithm followed by the value as hex.
impl Debug for ExternalMu {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExternalMu({:?}:", self.algorithm)?;
        crate::debug::write_hex_bytes(f, self.as_ref())?;
        write!(f, ")")
    }
}

/// Signs pre-computed [`ExternalMu`] values with an ML-DSA key pair.
///
/// Obtained by converting from a [`PqdsaKeyPair`]; the conversion fails for PQDSA algorithms
/// that are not ML-DSA. Caches `tr = SHAKE256(public_key)` so that deriving `mu` for many
/// messages under the same key does not re-hash the public key each time.
///
/// This holds its own counted reference to the signing key, so it remains usable after the
/// originating [`PqdsaKeyPair`] is dropped.
pub struct ExternalMuSigner {
    evp_pkey: LcPtr<EVP_PKEY>,
    algorithm: &'static PqdsaSigningAlgorithm,
    tr: [u8; TR_LEN],
}

// This holds a counted reference to the same `EVP_PKEY` as the originating `PqdsaKeyPair`,
// and only ever uses it through non-mutating operations (`EVP_PKEY_sign`), which AWS-LC
// documents as safe to call concurrently from multiple threads. See the note on
// `ParsedPublicKey` in `crate::signature` for the upstream documentation.
unsafe impl Send for ExternalMuSigner {}
unsafe impl Sync for ExternalMuSigner {}

impl ExternalMuSigner {
    /// Computes `mu` over `message` with an empty context string, bound to this key pair's
    /// public key.
    ///
    /// The result may be signed with [`Self::sign`], or verified against a signature with
    /// [`ExternalMuVerifier::verify`]. A signature over this `mu` is interchangeable with an
    /// ordinary ML-DSA signature over `message`.
    ///
    /// # Errors
    /// Returns `Unspecified` if the computation fails.
    pub fn compute_mu(&self, message: &[u8]) -> Result<ExternalMu, Unspecified> {
        ExternalMu::new(self.algorithm.verification_algorithm(), |mu| {
            compute_mu(&self.tr, b"", message, mu)
        })
    }

    /// Signs `mu`, producing a signature indistinguishable from an ordinary ML-DSA signature
    /// over the message `mu` was derived from.
    ///
    /// The signature is written to `signature`, which must be at least
    /// [`PqdsaSigningAlgorithm::signature_len`] bytes long. Returns the length of the
    /// signature on success.
    ///
    /// # Errors
    /// Returns `Unspecified` if `mu` was computed for a different ML-DSA algorithm than this
    /// key pair uses, if `signature` is too small, or if signing fails.
    //
    // # FIPS
    // Approved for all supported algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87.
    pub fn sign(&self, mu: &ExternalMu, signature: &mut [u8]) -> Result<usize, Unspecified> {
        // `mu` is bound to a public key, so a value computed for a different parameter set is
        // never meaningful here. This does not (and cannot) detect a `mu` computed for a
        // different key of the *same* parameter set.
        if mu.algorithm() != self.algorithm.verification_algorithm() {
            return Err(Unspecified);
        }
        let sig_length = self.algorithm.signature_len();
        if signature.len() < sig_length {
            return Err(Unspecified);
        }
        let sig_bytes = self
            .evp_pkey
            .sign_digest(mu.as_ref(), No_EVP_PKEY_CTX_consumer)?;
        signature[0..sig_length].copy_from_slice(&sig_bytes);
        Ok(sig_length)
    }

    /// Returns the signing algorithm associated with this signer.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaSigningAlgorithm {
        self.algorithm
    }
}

impl TryFrom<&PqdsaKeyPair> for ExternalMuSigner {
    type Error = Unspecified;

    /// # Errors
    /// Returns `Unspecified` if `key_pair` is not an ML-DSA key pair, or if `tr` cannot be
    /// computed.
    fn try_from(key_pair: &PqdsaKeyPair) -> Result<Self, Self::Error> {
        let algorithm = key_pair.algorithm();
        if external_mu_len(algorithm.verification_algorithm()).is_none() {
            return Err(Unspecified);
        }
        Ok(Self {
            evp_pkey: key_pair.evp_pkey().clone(),
            algorithm,
            tr: compute_tr(key_pair.public_key().as_ref())?,
        })
    }
}

impl Debug for ExternalMuSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalMuSigner")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Verifies signatures over pre-computed [`ExternalMu`] values with an ML-DSA public key.
///
/// Obtained by converting from a [`ParsedPublicKey`]; the conversion fails unless the key is
/// an ML-DSA key. Caches `tr = SHAKE256(public_key)` so that deriving `mu` for many messages
/// under the same key does not re-hash the public key each time.
pub struct ExternalMuVerifier {
    evp_pkey: LcPtr<EVP_PKEY>,
    algorithm: &'static PqdsaVerificationAlgorithm,
    tr: [u8; TR_LEN],
}

// See the corresponding comment on `ExternalMuSigner`.
unsafe impl Send for ExternalMuVerifier {}
unsafe impl Sync for ExternalMuVerifier {}

impl ExternalMuVerifier {
    /// Computes `mu` over `message` with an empty context string, bound to this public key.
    ///
    /// # Errors
    /// Returns `Unspecified` if the computation fails.
    pub fn compute_mu(&self, message: &[u8]) -> Result<ExternalMu, Unspecified> {
        ExternalMu::new(self.algorithm, |mu| compute_mu(&self.tr, b"", message, mu))
    }

    /// Verifies that `signature` is a valid ML-DSA signature over `mu`.
    ///
    /// # Errors
    /// Returns `Unspecified` if `mu` was computed for a different ML-DSA algorithm than this
    /// key uses, or if the signature is invalid.
    //
    // # FIPS
    // Approved for all supported algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87.
    pub fn verify(&self, mu: &ExternalMu, signature: &[u8]) -> Result<(), Unspecified> {
        // See the corresponding check in `ExternalMuSigner::sign`.
        if mu.algorithm() != self.algorithm {
            return Err(Unspecified);
        }
        self.evp_pkey
            .verify_digest_sig(mu.as_ref(), No_EVP_PKEY_CTX_consumer, signature)
    }

    /// Returns the verification algorithm associated with this verifier.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaVerificationAlgorithm {
        self.algorithm
    }
}

impl TryFrom<&ParsedPublicKey> for ExternalMuVerifier {
    type Error = Unspecified;

    /// # Errors
    /// Returns `Unspecified` if `public_key` is not an ML-DSA public key, or if `tr` cannot
    /// be computed.
    fn try_from(public_key: &ParsedPublicKey) -> Result<Self, Self::Error> {
        let algorithm = public_key
            .pqdsa_verification_algorithm()
            .ok_or(Unspecified)?;
        if external_mu_len(algorithm).is_none() {
            return Err(Unspecified);
        }
        let evp_pkey = public_key.key().clone();
        let raw_public_key = evp_pkey.as_const().marshal_raw_public_key()?;
        Ok(Self {
            evp_pkey,
            algorithm,
            tr: compute_tr(&raw_public_key)?,
        })
    }
}

impl Debug for ExternalMuVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalMuVerifier")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}
