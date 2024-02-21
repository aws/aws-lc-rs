// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key-Encapsulation Mechanisms (KEMs), including support for Kyber Round 3 Submission.
//!
//! # Example
//!
//! Note that this example uses the Kyber-512 Round 3 algorithm, but other algorithms can be used
//! in the exact same way by substituting
//! `kem::<desired_algorithm_here>` for `kem::KYBER512_R3`.
//!
//! ```ignore
//! use aws_lc_rs::{
//!     error::Unspecified,
//!     kem::{Ciphertext, DecapsulationKey, EncapsulationKey},
//!     unstable::kem::{AlgorithmId, get_algorithm}
//! };
//!
//! let kyber512_r3 = get_algorithm(AlgorithmId::Kyber512_R3).ok_or(Unspecified)?;
//!
//! // Alice generates their (private) decapsulation key.
//! let decapsulation_key = DecapsulationKey::generate(kyber512_r3)?;
//!
//! // Alices computes the (public) encapsulation key.
//! let encapsulation_key = decapsulation_key.encapsulation_key()?;
//!
//! let encapsulation_key_bytes = encapsulation_key.key_bytes()?;
//!
//! // Alice sends the encapsulation key bytes to bob through some
//! // protocol message.
//! let encapsulation_key_bytes = encapsulation_key_bytes.as_ref();
//!
//! // Bob constructs the (public) encapsulation key from the key bytes provided by Alice.
//! let retrieved_encapsulation_key = EncapsulationKey::new(kyber512_r3, encapsulation_key_bytes)?;
//!
//! // Bob executes the encapsulation algorithm to to produce their copy of the secret, and associated ciphertext.
//! let (ciphertext, bob_secret) = retrieved_encapsulation_key.encapsulate()?;
//!
//! // Alice recieves ciphertext bytes from bob
//! let ciphertext_bytes = ciphertext.as_ref();
//!
//! // Bob sends Alice the ciphertext computed from the encapsulation algorithm, Alice runs decapsulation to derive their
//! // copy of the secret.
//! let alice_secret = decapsulation_key.decapsulate(Ciphertext::from(ciphertext_bytes))?;
//!
//! // Alice and Bob have now arrived to the same secret
//! assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
use crate::{
    buffer::Buffer,
    encoding::generated_encodings,
    error::{KeyRejected, Unspecified},
    ptr::LcPtr,
    ptr::Pointer,
};
use alloc::borrow::Cow;
use aws_lc::{
    EVP_PKEY_CTX_kem_set_params, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id, EVP_PKEY_decapsulate,
    EVP_PKEY_encapsulate, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_kem_new_raw_public_key, EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_up_ref,
    EVP_PKEY, EVP_PKEY_KEM,
};
use core::{cmp::Ordering, ptr::null_mut};
use zeroize::Zeroize;

/// An identifier for a KEM algorithm.
pub trait AlgorithmIdentifier:
    Copy + Clone + Debug + PartialEq + crate::sealed::Sealed + 'static
{
    /// Returns the algorithm's associated AWS-LC nid.
    fn nid(self) -> i32;
}

/// A KEM algorithm
#[derive(PartialEq)]
pub struct Algorithm<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    pub(crate) id: Id,
    pub(crate) decapsulate_key_size: usize,
    pub(crate) encapsulate_key_size: usize,
    pub(crate) ciphertext_size: usize,
    pub(crate) shared_secret_size: usize,
}

impl<Id> Algorithm<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Returns the identifier for this algorithm.
    #[must_use]
    pub fn id(&self) -> Id {
        self.id
    }

    #[inline]
    pub(crate) fn decapsulate_key_size(&self) -> usize {
        self.decapsulate_key_size
    }

    #[inline]
    pub(crate) fn encapsulate_key_size(&self) -> usize {
        self.encapsulate_key_size
    }

    #[inline]
    pub(crate) fn ciphertext_size(&self) -> usize {
        self.ciphertext_size
    }

    #[inline]
    pub(crate) fn shared_secret_size(&self) -> usize {
        self.shared_secret_size
    }
}

impl<Id> Debug for Algorithm<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// A serializable decapulsation key usable with KEMs. This can be randomly generated with `DecapsulationKey::generate`.
pub struct DecapsulationKey<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    algorithm: &'static Algorithm<Id>,
    evp_pkey: LcPtr<EVP_PKEY>,
}

/// Identifier for a KEM algorithm.
///
/// See [`crate::unstable::kem::AlgorithmId`] and [`crate::unstable::kem::get_algorithm`] for
/// access to algorithms not subject to semantic versioning gurantees.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AlgorithmId {}

impl AlgorithmIdentifier for AlgorithmId {
    fn nid(self) -> i32 {
        unreachable!()
    }
}

impl crate::sealed::Sealed for AlgorithmId {}

impl<Id> DecapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Generate a new KEM decapsulation key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(alg: &'static Algorithm<Id>) -> Result<Self, Unspecified> {
        let mut secret_key_size = alg.decapsulate_key_size();
        let mut priv_key_bytes = vec![0u8; secret_key_size];
        let kyber_key = kem_key_generate(alg.id.nid())?;
        if 1 != unsafe {
            EVP_PKEY_get_raw_private_key(
                kyber_key.as_const_ptr(),
                priv_key_bytes.as_mut_ptr(),
                &mut secret_key_size,
            )
        } {
            return Err(Unspecified);
        }
        Ok(DecapsulationKey {
            algorithm: alg,
            evp_pkey: kyber_key,
        })
    }

    /// Return the algorithm associated with the given KEM decapsulation key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm<Id> {
        self.algorithm
    }

    /// Computes the KEM encapsulation key from the KEM decapsulation key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    #[allow(clippy::missing_panics_doc)]
    pub fn encapsulation_key(&self) -> Result<EncapsulationKey<Id>, Unspecified> {
        // This is pedantic this function always returns 1
        if 1 != unsafe { EVP_PKEY_up_ref(*self.evp_pkey) } {
            return Err(Unspecified);
        };

        let evp_pkey = LcPtr::new(*self.evp_pkey).expect("AWS-LC EVP_PKEY should not be null");

        Ok(EncapsulationKey {
            algorithm: self.algorithm,
            evp_pkey,
        })
    }

    /// Performs the decapsulate operation using this KEM decapsulation key on the given ciphertext.
    ///
    /// `ciphertext` is the ciphertext generated by the encapsulate operation using the KEM encapsulation key
    /// associated with this KEM decapsulation key.
    ///
    /// # Errors
    /// `Unspecified` when operation fails due to internal error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn decapsulate(&self, ciphertext: Ciphertext<'_>) -> Result<SharedSecret, Unspecified> {
        let mut shared_secret_len = self.algorithm.shared_secret_size();
        let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];

        let ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.evp_pkey, null_mut()) })?;

        let ciphertext = ciphertext.as_ref();

        if 1 != unsafe {
            EVP_PKEY_decapsulate(
                *ctx,
                shared_secret.as_mut_ptr(),
                &mut shared_secret_len,
                // AWS-LC incorrectly has this as an unqualified `uint8_t *`, it should be qualified with const
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len(),
            )
        } {
            return Err(Unspecified);
        }

        // This is currently pedantic but done for safety in-case the shared_secret buffer
        // size changes in the future. `EVP_PKEY_decapsulate` updates `shared_secret_len` with
        // the length of the shared secret in the event the buffer provided was larger then the secret.
        // This truncates the buffer to the proper length to match the shared secret written.
        debug_assert_eq!(shared_secret_len, shared_secret.len());
        shared_secret.truncate(shared_secret_len);

        Ok(SharedSecret(shared_secret.into_boxed_slice()))
    }
}

unsafe impl<Id> Send for DecapsulationKey<Id> where Id: AlgorithmIdentifier {}

unsafe impl<Id> Sync for DecapsulationKey<Id> where Id: AlgorithmIdentifier {}

impl<Id> Debug for DecapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

use paste::paste;
generated_encodings!(EncapsulationKeyBytes);

/// A serializable encapsulation key usable with KEM algorithms. Constructed
/// from either a `DecapsulationKey` or raw bytes.
pub struct EncapsulationKey<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    algorithm: &'static Algorithm<Id>,
    evp_pkey: LcPtr<EVP_PKEY>,
}

impl<Id> EncapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Return the algorithm associated with the given KEM encapsulation key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm<Id> {
        self.algorithm
    }

    /// Performs the encapsulate operation using this KEM encapsulation key, generating a ciphertext
    /// and associated shared secret.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn encapsulate(&self) -> Result<(Ciphertext<'static>, SharedSecret), Unspecified> {
        let mut ciphertext_len = self.algorithm.ciphertext_size();
        let mut shared_secret_len = self.algorithm.shared_secret_size();
        let mut ciphertext: Vec<u8> = vec![0u8; ciphertext_len];
        let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];

        let ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.evp_pkey, null_mut()) })?;

        if 1 != unsafe {
            EVP_PKEY_encapsulate(
                *ctx,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                shared_secret.as_mut_ptr(),
                &mut shared_secret_len,
            )
        } {
            return Err(Unspecified);
        }

        // The following two steps are currently pedantic but done for safety in-case the buffer allocation
        // sizes change in the future. `EVP_PKEY_encapsulate` updates `ciphertext_len` and `shared_secret_len` with
        // the length of the ciphertext and shared secret respectivly in the event the buffer provided for each was
        // larger then the actual values. Thus these two steps truncate the buffers to the proper length to match the
        // value lengths written.
        debug_assert_eq!(ciphertext_len, ciphertext.len());
        ciphertext.truncate(ciphertext_len);
        debug_assert_eq!(shared_secret_len, shared_secret.len());
        shared_secret.truncate(shared_secret_len);

        Ok((
            Ciphertext::new(ciphertext),
            SharedSecret::new(shared_secret.into_boxed_slice()),
        ))
    }

    /// Returns the `EnscapsulationKey` bytes.
    ///
    /// # Errors
    /// * `Unspecified`: Any failure to retrieve the `EnscapsulationKey` bytes.
    pub fn key_bytes(&self) -> Result<EncapsulationKeyBytes<'static>, Unspecified> {
        let mut encapsulate_key_size = self.algorithm.encapsulate_key_size();
        let mut encapsulate_bytes = vec![0u8; encapsulate_key_size];
        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(
                self.evp_pkey.as_const_ptr(),
                encapsulate_bytes.as_mut_ptr(),
                &mut encapsulate_key_size,
            )
        } {
            return Err(Unspecified);
        }

        // This is currently pedantic but done for safety in-case the encapsulation key
        // size changes in the future. `EVP_PKEY_get_raw_public_key` writes the total length
        // to `encapsulate_key_size` in the event that the buffer we provide is larger then
        // required.
        debug_assert_eq!(encapsulate_key_size, encapsulate_bytes.len());
        encapsulate_bytes.truncate(encapsulate_key_size);

        Ok(EncapsulationKeyBytes::new(encapsulate_bytes))
    }

    /// Creates a new KEM encapsulation key from raw bytes. This method MUST NOT be used to generate
    /// a new encapsulation key, rather it MUST be used to construct `EncapsulationKey` previously serialized
    /// to raw bytes.
    ///
    /// `alg` is the [`Algorithm`] to be associated with the generated `EncapsulationKey`.
    ///
    /// `bytes` is a slice of raw bytes representing a `EncapsulationKey`.
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    pub fn new(alg: &'static Algorithm<Id>, bytes: &[u8]) -> Result<Self, KeyRejected> {
        match bytes.len().cmp(&alg.encapsulate_key_size()) {
            Ordering::Less => Err(KeyRejected::too_small()),
            Ordering::Greater => Err(KeyRejected::too_large()),
            Ordering::Equal => Ok(()),
        }?;
        let pubkey = LcPtr::new(unsafe {
            EVP_PKEY_kem_new_raw_public_key(alg.id.nid(), bytes.as_ptr(), bytes.len())
        })?;
        Ok(EncapsulationKey {
            algorithm: alg,
            evp_pkey: pubkey,
        })
    }
}

unsafe impl<Id> Send for EncapsulationKey<Id> where Id: AlgorithmIdentifier {}

unsafe impl<Id> Sync for EncapsulationKey<Id> where Id: AlgorithmIdentifier {}

impl<Id> Debug for EncapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A set of encrypted bytes produced by [`EncapsulationKey::encapsulate`],
/// and used as an input to [`DecapsulationKey::decapsulate`].
pub struct Ciphertext<'a>(Cow<'a, [u8]>);

impl<'a> Ciphertext<'a> {
    fn new(value: Vec<u8>) -> Ciphertext<'a> {
        Self(Cow::Owned(value))
    }
}

impl<'a> Drop for Ciphertext<'a> {
    fn drop(&mut self) {
        if let Cow::Owned(ref mut v) = self.0 {
            v.zeroize();
        }
    }
}

impl<'a> AsRef<[u8]> for Ciphertext<'a> {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            Cow::Borrowed(v) => v,
            Cow::Owned(ref v) => v.as_ref(),
        }
    }
}

impl<'a> From<&'a [u8]> for Ciphertext<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(Cow::Borrowed(value))
    }
}

/// The cryptographic shared secret output from the KEM encapsulate / decapsulate process.
pub struct SharedSecret(Box<[u8]>);

impl SharedSecret {
    fn new(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// Returns an LcPtr to an EVP_PKEY
#[inline]
fn kem_key_generate(nid: i32) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut()) })?;
    if 1 != unsafe { EVP_PKEY_CTX_kem_set_params(*ctx, nid) }
        || 1 != unsafe { EVP_PKEY_keygen_init(*ctx) }
    {
        return Err(Unspecified);
    }

    let mut key_raw: *mut EVP_PKEY = null_mut();
    if 1 != unsafe { EVP_PKEY_keygen(*ctx, &mut key_raw) } {
        return Err(Unspecified);
    }
    Ok(LcPtr::new(key_raw)?)
}

#[cfg(test)]
mod tests {
    use super::{Ciphertext, SharedSecret};

    #[test]
    fn ciphertext() {
        let ciphertext_bytes = vec![42u8; 4];
        let ciphertext = Ciphertext::from(ciphertext_bytes.as_ref());
        assert_eq!(ciphertext.as_ref(), &[42, 42, 42, 42]);
        drop(ciphertext);

        let ciphertext_bytes = vec![42u8; 4];
        let ciphertext = Ciphertext::<'static>::new(ciphertext_bytes);
        assert_eq!(ciphertext.as_ref(), &[42, 42, 42, 42]);
    }

    #[test]
    fn shared_secret() {
        let secret_bytes = vec![42u8; 4];
        let shared_secret = SharedSecret::new(secret_bytes.into_boxed_slice());
        assert_eq!(shared_secret.as_ref(), &[42, 42, 42, 42]);
    }
}
