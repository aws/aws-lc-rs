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
//! Because `mu` is derived from the public key, an external-mu signature over a message is
//! indistinguishable from, and interchangeable with, an ordinary ML-DSA signature over that
//! same message *and the same context string*. It is not a different signature scheme, only a
//! different way of feeding the message in.
//!
//! ML-DSA keys, algorithms, and ordinary (non-external-mu) signing live in
//! [`crate::signature`]: see [`PqdsaKeyPair`], [`ParsedPublicKey`], and the `ML_DSA_*`
//! constants. This module holds only what is specific to ML-DSA rather than shared by the
//! whole post-quantum signature family.
//!
//! # Deriving `mu`
//!
//! [`MuContext`] mirrors [`crate::digest::Context`]: build one from the public key, feed the
//! message in with [`MuContext::update`] as many times as needed, and call
//! [`MuContext::finish`]. Deriving `mu` needs only the *public* key, so a party that holds
//! neither the signing key nor a verification role can do it.
//! [`ExternalMuVerifier::compute_mu`] is a one-shot convenience for messages held in full.
//!
//! # Example
//!
//! ```
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::ml_dsa::{ExternalMuSigner, ExternalMuVerifier, MuContext};
//! use aws_lc_rs::signature::{
//!     KeyPair, ParsedPublicKey, PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING,
//! };
//!
//! let key_pair = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING)?;
//! let public_key = ParsedPublicKey::new(&ML_DSA_44, key_pair.public_key().as_ref())?;
//!
//! // Some party holding only the public key derives mu, streaming the message.
//! let mut mu_context = MuContext::new(&public_key)?;
//! mu_context.update(b"hello, ")?;
//! mu_context.update(b"world")?;
//! let mu = mu_context.finish()?;
//!
//! // The signing key holder signs mu without ever seeing the message.
//! let signer = ExternalMuSigner::new(&key_pair)?;
//! let mut signature = vec![0u8; key_pair.algorithm().signature_len()];
//! let len = signer.sign(&mu, &mut signature)?;
//! signature.truncate(len);
//!
//! // The verifier derives the same mu from the public key and checks the signature.
//! let verifier = ExternalMuVerifier::new(&public_key)?;
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
use crate::error::{KeyRejected, Unspecified};
use crate::evp_pkey::No_EVP_PKEY_CTX_consumer;
use crate::pqdsa::{compute_tr, external_representative_len, MuHasher, TR_LEN};
use crate::ptr::LcPtr;
use crate::signature::{
    KeyPair, ParsedPublicKey, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm,
};
use core::fmt::{Debug, Formatter};

/// The length in bytes of the ML-DSA message representative `mu`.
///
/// FIPS 204 fixes this at `ML_DSA_CRHBYTES` (64) for every ML-DSA parameter set, so it is a
/// property of the scheme rather than of any one algorithm.
pub const MU_LEN: usize = 64;

/// The FIPS 204 "message representative" `mu`, used by the "external mu" variant of ML-DSA.
///
/// Obtain one with [`MuContext`] or [`ExternalMuVerifier::compute_mu`], or, if it was
/// derived elsewhere, with [`Self::import_less_safe`]. Use [`Self::as_ref`] to get the value
/// as a `&[u8]`; it is always [`MU_LEN`] bytes.
///
/// A value produced by this crate remembers which public key it was derived under, so
/// [`ExternalMuSigner::sign`] and [`ExternalMuVerifier::verify`] can reject a `mu` belonging
/// to a different key. A value from [`Self::import_less_safe`] cannot carry that binding, and
/// is checked only for algorithm and length.
#[derive(Clone, Copy)]
pub struct ExternalMu {
    /// A fixed buffer plus the length in use, matching [`crate::digest::Digest`], so the
    /// type can be `Copy`. `external_representative_len` is the source of truth for `len`.
    mu: [u8; MU_LEN],
    len: usize,
    algorithm: &'static PqdsaVerificationAlgorithm,
    /// `tr` of the public key this `mu` was derived under, or `None` when it was imported and
    /// therefore has no provenance we can check. See [`Self::import_less_safe`].
    key_binding: Option<[u8; TR_LEN]>,
}

impl ExternalMu {
    /// Imports a `mu` value provided by an external source. This allows for the signing of
    /// content that might not be directly accessible.
    ///
    /// WARNING: unlike a message digest, `mu` binds the message to a *specific public key*.
    /// Signing an attacker-influenced `mu` is a blind signing operation: it yields a valid
    /// signature over a message the signer never saw and cannot inspect. Note also that
    /// external-mu verification does not re-derive `mu` -- it takes the supplied value on
    /// faith -- so a signature over a mismatched `mu` is accepted by
    /// [`ExternalMuVerifier::verify`] even though it is not a valid signature over any message
    /// under that key.
    ///
    /// Ensure the value comes from a trusted source and was derived under `algorithm` and the
    /// key it will be used with. An imported value carries no record of the key it came from,
    /// so [`ExternalMuSigner::sign`] and [`ExternalMuVerifier::verify`] cannot check that for
    /// you, as they can for a value derived through [`MuContext`]. When possible, prefer
    /// deriving `mu` directly.
    ///
    /// # Errors
    /// Returns `Unspecified` if `algorithm` does not support the external mu variant, or if
    /// `mu` is not exactly [`MU_LEN`] bytes.
    pub fn import_less_safe(
        mu: &[u8],
        algorithm: &'static PqdsaVerificationAlgorithm,
    ) -> Result<Self, Unspecified> {
        let len = external_representative_len(algorithm.id).ok_or(Unspecified)?;
        if mu.len() != len {
            return Err(Unspecified);
        }
        let mut buffer = [0u8; MU_LEN];
        // `get_mut` rather than a slice index: a representative longer than `MU_LEN` is an
        // error, not a panic.
        buffer
            .get_mut(..len)
            .ok_or(Unspecified)?
            .copy_from_slice(mu);
        Ok(Self {
            mu: buffer,
            len,
            algorithm,
            key_binding: None,
        })
    }

    /// The ML-DSA algorithm this `mu` was computed for.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaVerificationAlgorithm {
        self.algorithm
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

/// An in-progress derivation of an [`ExternalMu`], bound to a specific ML-DSA public key.
///
/// This mirrors [`crate::digest::Context`]: feed the message in with [`Self::update`] as many
/// times as needed, then call [`Self::finish`]. Because deriving `mu` requires only the
/// public key, a `MuContext` can be built by a party that holds neither the signing key nor a
/// verification role -- which is the point of the external mu variant.
///
/// `mu` is derived with an empty context string, matching the rest of the ML-DSA API in this
/// crate.
#[derive(Clone)]
pub struct MuContext {
    algorithm: &'static PqdsaVerificationAlgorithm,
    tr: [u8; TR_LEN],
    hasher: MuHasher,
}

impl MuContext {
    /// Starts deriving `mu` for a message to be signed or verified under `public_key`.
    ///
    /// # Errors
    /// Returns `KeyRejected` if `public_key` is not an ML-DSA public key.
    pub fn new(public_key: &ParsedPublicKey) -> Result<Self, KeyRejected> {
        let (algorithm, tr) = ml_dsa_algorithm_and_tr(public_key)?;
        Self::from_tr(algorithm, &tr).map_err(|_| KeyRejected::unexpected_error())
    }

    fn from_tr(
        algorithm: &'static PqdsaVerificationAlgorithm,
        tr: &[u8; TR_LEN],
    ) -> Result<Self, Unspecified> {
        Ok(Self {
            algorithm,
            tr: *tr,
            hasher: MuHasher::new(tr, b"")?,
        })
    }

    /// Absorbs the next chunk of the message. May be called any number of times, including
    /// zero for an empty message.
    ///
    /// # Errors
    /// Returns `Unspecified` if the computation fails.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Unspecified> {
        self.hasher.update(data)
    }

    /// Finishes the derivation and returns `mu`.
    ///
    /// # Errors
    /// Returns `Unspecified` if the computation fails.
    pub fn finish(self) -> Result<ExternalMu, Unspecified> {
        let len = external_representative_len(self.algorithm.id).ok_or(Unspecified)?;
        let mut mu = [0u8; MU_LEN];
        // See the corresponding note in `ExternalMu::import_less_safe`.
        self.hasher.finish(mu.get_mut(..len).ok_or(Unspecified)?)?;
        Ok(ExternalMu {
            mu,
            len,
            algorithm: self.algorithm,
            key_binding: Some(self.tr),
        })
    }

    /// Returns the verification algorithm `mu` is being derived for.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaVerificationAlgorithm {
        self.algorithm
    }
}

impl Debug for MuContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MuContext")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Signs pre-computed [`ExternalMu`] values with an ML-DSA key pair.
///
/// Construct one with [`Self::new`]; it fails for PQDSA algorithms that are not ML-DSA, so
/// the algorithm check happens once here rather than on every operation. Caches
/// `tr = SHAKE256(public_key)` so that [`Self::sign`] can reject a `mu` derived under a
/// different key.
///
/// A signer never needs the message: derive `mu` where the message lives, with
/// [`MuContext`] or [`ExternalMuVerifier`], and pass only `mu` to [`Self::sign`].
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
    /// Builds an external-mu signer for `key_pair`.
    ///
    /// # Errors
    /// Returns `KeyRejected` if `key_pair` is not an ML-DSA key pair.
    pub fn new(key_pair: &PqdsaKeyPair) -> Result<Self, KeyRejected> {
        let algorithm = key_pair.algorithm();
        if external_representative_len(algorithm.verification_algorithm().id).is_none() {
            return Err(KeyRejected::wrong_algorithm());
        }
        Ok(Self {
            evp_pkey: key_pair.evp_pkey().clone(),
            algorithm,
            tr: compute_tr(key_pair.public_key().as_ref())
                .map_err(|_| KeyRejected::unexpected_error())?,
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
    /// Returns `Unspecified` if `mu` was computed for a different ML-DSA algorithm or a
    /// different public key than this key pair's, if `signature` is too small, or if signing
    /// fails.
    //
    // # FIPS
    // Approved for all supported algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87.
    pub fn sign(&self, mu: &ExternalMu, signature: &mut [u8]) -> Result<usize, Unspecified> {
        check_mu(mu, self.algorithm.verification_algorithm(), &self.tr)?;
        let sig_length = self.algorithm.signature_len();
        if signature.len() < sig_length {
            return Err(Unspecified);
        }
        let sig_bytes = self
            .evp_pkey
            .sign_digest(mu.into(), No_EVP_PKEY_CTX_consumer)?;
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
    type Error = KeyRejected;

    /// See [`ExternalMuSigner::new`].
    ///
    /// # Errors
    /// Returns `KeyRejected` if `key_pair` is not an ML-DSA key pair.
    fn try_from(key_pair: &PqdsaKeyPair) -> Result<Self, Self::Error> {
        Self::new(key_pair)
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
/// Construct one with [`Self::new`]; it fails unless the key is an ML-DSA key. Caches
/// `tr = SHAKE256(public_key)` so that deriving `mu` for many messages under the same key
/// does not re-hash the public key each time.
pub struct ExternalMuVerifier {
    evp_pkey: LcPtr<EVP_PKEY>,
    algorithm: &'static PqdsaVerificationAlgorithm,
    tr: [u8; TR_LEN],
}

// See the corresponding comment on `ExternalMuSigner`.
unsafe impl Send for ExternalMuVerifier {}
unsafe impl Sync for ExternalMuVerifier {}

impl ExternalMuVerifier {
    /// Builds an external-mu verifier for `public_key`.
    ///
    /// # Errors
    /// Returns `KeyRejected` if `public_key` is not an ML-DSA public key.
    pub fn new(public_key: &ParsedPublicKey) -> Result<Self, KeyRejected> {
        let (algorithm, tr) = ml_dsa_algorithm_and_tr(public_key)?;
        Ok(Self {
            evp_pkey: public_key.key().clone(),
            algorithm,
            tr,
        })
    }

    /// Starts a streaming derivation of `mu` bound to this public key.
    ///
    /// # Errors
    /// Returns `Unspecified` if the computation cannot be started.
    pub fn mu_context(&self) -> Result<MuContext, Unspecified> {
        MuContext::from_tr(self.algorithm, &self.tr)
    }

    /// Computes `mu` over `message` in one shot, with an empty context string, bound to this
    /// public key. Use [`Self::mu_context`] for a message not held in full.
    ///
    /// # Errors
    /// Returns `Unspecified` if the computation fails.
    pub fn compute_mu(&self, message: &[u8]) -> Result<ExternalMu, Unspecified> {
        let mut context = self.mu_context()?;
        context.update(message)?;
        context.finish()
    }

    /// Verifies that `signature` is a valid ML-DSA signature over `mu`.
    ///
    /// # Errors
    /// Returns `Unspecified` if `mu` was computed for a different ML-DSA algorithm or a
    /// different public key than this one, or if the signature is invalid.
    //
    // # FIPS
    // Approved for all supported algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87.
    pub fn verify(&self, mu: &ExternalMu, signature: &[u8]) -> Result<(), Unspecified> {
        check_mu(mu, self.algorithm, &self.tr)?;
        self.evp_pkey
            .verify_digest_sig(mu.into(), No_EVP_PKEY_CTX_consumer, signature)
    }

    /// Returns the verification algorithm associated with this verifier.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaVerificationAlgorithm {
        self.algorithm
    }
}

impl TryFrom<&ParsedPublicKey> for ExternalMuVerifier {
    type Error = KeyRejected;

    /// See [`ExternalMuVerifier::new`].
    ///
    /// # Errors
    /// Returns `KeyRejected` if `public_key` is not an ML-DSA public key.
    fn try_from(public_key: &ParsedPublicKey) -> Result<Self, Self::Error> {
        Self::new(public_key)
    }
}

impl Debug for ExternalMuVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalMuVerifier")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Checks that `public_key` is an ML-DSA key supporting the external mu variant, and returns
/// its algorithm along with `tr`.
///
/// `tr` is computed from the *raw* public key encoding, re-marshalled here rather than taken
/// from the caller's input, so that a key parsed from an X.509 `SubjectPublicKeyInfo` yields
/// the same `tr` as the same key parsed from raw bytes.
fn ml_dsa_algorithm_and_tr(
    public_key: &ParsedPublicKey,
) -> Result<(&'static PqdsaVerificationAlgorithm, [u8; TR_LEN]), KeyRejected> {
    let algorithm = public_key
        .pqdsa_verification_algorithm()
        .ok_or_else(KeyRejected::wrong_algorithm)?;
    if external_representative_len(algorithm.id).is_none() {
        return Err(KeyRejected::wrong_algorithm());
    }
    let raw_public_key = public_key
        .key()
        .as_const()
        .marshal_raw_public_key()
        .map_err(|_| KeyRejected::unexpected_error())?;
    let tr = compute_tr(&raw_public_key).map_err(|_| KeyRejected::unexpected_error())?;
    Ok((algorithm, tr))
}

/// Rejects a `mu` that cannot belong to the key about to be used with it: derived for a
/// different parameter set, or -- when it carries its key binding -- under a different key
/// of the *same* parameter set, which is otherwise silent: signing it produces a signature
/// that verifies under no key at all. `tr` is a hash of a public key, so a variable-time
/// comparison is fine.
///
/// A `mu` from [`ExternalMu::import_less_safe`] carries no `tr`, and only the algorithm is
/// checked -- that is the "less safe" part of importing one.
fn check_mu(
    mu: &ExternalMu,
    algorithm: &'static PqdsaVerificationAlgorithm,
    tr: &[u8; TR_LEN],
) -> Result<(), Unspecified> {
    if mu.algorithm != algorithm {
        return Err(Unspecified);
    }
    if let Some(mu_tr) = &mu.key_binding {
        if mu_tr != tr {
            return Err(Unspecified);
        }
    }
    Ok(())
}
