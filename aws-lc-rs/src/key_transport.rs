// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key Transport: KEMs, including support for Kyber.
//!
//! # Example
//!
//! Note that this example uses Kyber-512, but other algorithms can be used
//! in the exact same way by substituting
//! `key_transport::<desired_algorithm_here>` for `key_transport::KYBER512_R3`.
//!
//! ```
//! use aws_lc_rs::key_transport::{KemPrivateKey, KemPublicKey, KYBER512_R3};
//!
//! let priv_key = KemPrivateKey::generate(&KYBER512_R3)?;
//!
//! // Generate private key bytes to possibly save for later decapsulation
//! let privkey_raw_bytes = priv_key.as_ref();
//!
//! let pub_key = priv_key.compute_public_key()?;
//!
//! // Get the public key bytes to send to bob through some encoded
//! // protocol message.
//! let pub_key_bytes = pub_key.as_ref();
//!
//! let mut ciphertext: Vec<u8> = vec![];
//!
//! let retrieved_pub_key = KemPublicKey::new(&KYBER512_R3, pub_key_bytes)?;
//! let bob_result = retrieved_pub_key.encapsulate(|ct, ss| {
//!     ciphertext.extend_from_slice(ct);
//!     // In real applications, a KDF would be applied to derive
//!     // the session keys from the shared secret. We omit that here.
//!     Ok(())
//! });
//!
//! // Retrieve private key from stored raw bytes
//! let retrieved_priv_key = KemPrivateKey::new(&KYBER512_R3, privkey_raw_bytes)?;
//!
//! let alice_result = retrieved_priv_key.decapsulate(&mut ciphertext, |ss| {
//!     // In real applications, a KDF would be applied to derive
//!     // the session keys from the shared secret. We omit that here.
//!     Ok(())
//! });
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
use crate::{
    error::{KeyRejected, Unspecified},
    ptr::LcPtr,
    ptr::Pointer,
};
use aws_lc::{
    EVP_PKEY_CTX_kem_set_params, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id, EVP_PKEY_decapsulate,
    EVP_PKEY_encapsulate, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_kem_new_raw_public_key, EVP_PKEY_kem_new_raw_secret_key, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY, EVP_PKEY_KEM, NID_KYBER512_R3,
};
use std::os::raw::c_int;
use std::ptr::null_mut;
use zeroize::Zeroize;

// Key lengths defined as stated on the CRYSTALS website:
// https://pq-crystals.org/kyber/
//
const KYBER512_R3_SECRET_KEY_LENGTH: usize = 1632;
const KYBER512_R3_CIPHERTEXT_LENGTH: usize = 768;
const KYBER512_R3_PUBLIC_KEY_LENGTH: usize = 800;
const KYBER512_R3_SHARED_SECRET_LENGTH: usize = 32;

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq)]
enum KemAlgorithmID {
    Kyber512_R3,
}

/// A KEM algorithm
#[derive(Debug, PartialEq)]
pub struct KemAlgorithm {
    id: KemAlgorithmID,
    secret_key_size: usize,
    public_key_size: usize,
    ciphertext_size: usize,
    shared_secret_size: usize,
}

/// NIST Round 3 iteration of the Kyber-512 algorithm
pub static KYBER512_R3: KemAlgorithm = KemAlgorithm {
    id: KemAlgorithmID::Kyber512_R3,
    secret_key_size: KYBER512_R3_SECRET_KEY_LENGTH,
    public_key_size: KYBER512_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER512_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER512_R3_SHARED_SECRET_LENGTH,
};

impl KemAlgorithmID {
    #[inline]
    fn nid(&self) -> i32 {
        match self {
            KemAlgorithmID::Kyber512_R3 => NID_KYBER512_R3,
        }
    }
}

impl KemAlgorithm {
    #[inline]
    fn secret_key_size(&self) -> usize {
        self.secret_key_size
    }

    #[inline]
    fn public_key_size(&self) -> usize {
        self.public_key_size
    }

    #[inline]
    fn cipher_text_size(&self) -> usize {
        self.ciphertext_size
    }

    #[inline]
    fn shared_secret_size(&self) -> usize {
        self.shared_secret_size
    }
}

/// A serializable private key usable with KEMs. This can be randomly generated with KemPrivateKey::generate
/// or constructed from raw bytes.
#[derive(Debug)]
pub struct KemPrivateKey {
    algorithm: &'static KemAlgorithm,
    pkey: LcPtr<*mut EVP_PKEY>,
    priv_key: Box<[u8]>,
}

impl KemPrivateKey {
    /// Generate a new KEM private key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    ///
    pub fn generate(alg: &'static KemAlgorithm) -> Result<Self, Unspecified> {
        unsafe {
            let kyber_key = kem_key_generate(alg.id.nid())?;
            let mut secret_key_size = alg.secret_key_size();
            let mut priv_key_bytes = vec![0u8; secret_key_size];
            if 1 != EVP_PKEY_get_raw_private_key(
                kyber_key.as_const_ptr(),
                priv_key_bytes.as_mut_ptr(),
                &mut secret_key_size,
            ) {
                return Err(Unspecified);
            }
            Ok(KemPrivateKey {
                algorithm: alg,
                pkey: kyber_key,
                priv_key: priv_key_bytes.into(),
            })
        }
    }

    /// Return the algorithm associated with the given KEM private key.
    #[must_use]
    pub fn algorithm(&self) -> &'static KemAlgorithm {
        self.algorithm
    }

    /// Computes the KEM public key from the KEM private key
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    ///
    pub fn compute_public_key(&self) -> Result<KemPublicKey, Unspecified> {
        let mut pubkey_bytes = vec![0u8; self.algorithm.public_key_size()];
        unsafe {
            if 1 != EVP_PKEY_get_raw_public_key(
                self.pkey.as_const_ptr(),
                pubkey_bytes.as_mut_ptr(),
                &mut self.algorithm.public_key_size(),
            ) {
                return Err(Unspecified);
            }

            let pubkey = LcPtr::new(EVP_PKEY_kem_new_raw_public_key(
                self.algorithm.id.nid(),
                pubkey_bytes.as_ptr(),
                self.algorithm.public_key_size(),
            ))?;

            Ok(KemPublicKey {
                algorithm: self.algorithm,
                pkey: pubkey,
                pub_key: pubkey_bytes.into(),
            })
        }
    }

    /// Performs the decapsulate operation using the current KEM private key on the given ciphertext.
    ///
    /// `ciphertext` is the ciphertext generated by the encapsulate operation using the KEM public key
    /// associated with the current KEM private key.
    ///
    /// After the decapsulation is finished, `decapsulate` calls `kdf` with the raw shared secret
    /// from the operation and then returns what `kdf` returns.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    ///
    pub fn decapsulate<F, R>(&self, ciphertext: &mut [u8], kdf: F) -> Result<R, Unspecified>
    where
        F: FnOnce(&[u8]) -> Result<R, Unspecified>,
    {
        unsafe {
            let ctx = LcPtr::new(EVP_PKEY_CTX_new(*self.pkey, null_mut()))?;
            let mut shared_secret: Vec<u8> = vec![0u8; self.algorithm.shared_secret_size()];

            if 1 != EVP_PKEY_decapsulate(
                *ctx,
                shared_secret.as_mut_ptr(),
                &mut self.algorithm.secret_key_size(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
            ) {
                return Err(Unspecified);
            }
            kdf(&shared_secret)
        }
    }

    /// Creates a new KEM private key from raw bytes. This method is NOT meant to generate
    /// a new private key, rather it restores a `KemPrivateKey` that was previously converted
    /// to raw bytes.
    ///
    /// `alg` is the `KemAlgorithm` to be associated with the generated `KemPrivateKey`
    ///
    /// `bytes` is a slice of raw bytes representing a `KemPrivateKey`
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    ///
    pub fn new(alg: &'static KemAlgorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        if alg.secret_key_size() != bytes.len() {
            return Err(KeyRejected::unexpected_error());
        }
        unsafe {
            let privkey = LcPtr::new(EVP_PKEY_kem_new_raw_secret_key(
                alg.id.nid(),
                bytes.as_ptr(),
                bytes.len(),
            ))?;
            Ok(KemPrivateKey {
                algorithm: alg,
                pkey: privkey,
                priv_key: bytes.into(),
            })
        }
    }
}

impl Drop for KemPrivateKey {
    fn drop(&mut self) {
        self.priv_key.zeroize();
    }
}

impl AsRef<[u8]> for KemPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.priv_key
    }
}

/// A serializable public key usable with KEMS. This can be constructed
/// from a `KemPrivateKey` or constructed from raw bytes.
#[derive(Debug)]
pub struct KemPublicKey {
    algorithm: &'static KemAlgorithm,
    pkey: LcPtr<*mut EVP_PKEY>,
    pub_key: Box<[u8]>,
}

impl KemPublicKey {
    /// Return the algorithm associated with the given KEM public key.
    #[must_use]
    pub fn algorithm(&self) -> &'static KemAlgorithm {
        self.algorithm
    }

    /// Performs the encapsulate operation using the current KEM public key, generating a ciphertext
    /// and associated shared secret.
    ///
    /// After the encapsulation is finished, `encapsulate` calls `kdf` with the ciphertext and raw shared secret
    /// from the operation and then returns what `kdf` returns.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    ///
    pub fn encapsulate<F, R>(&self, kdf: F) -> Result<R, Unspecified>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<R, Unspecified>,
    {
        unsafe {
            let ctx = LcPtr::new(EVP_PKEY_CTX_new(*self.pkey, null_mut()))?;

            let mut ciphertext: Vec<u8> = vec![0u8; self.algorithm.cipher_text_size()];
            let mut shared_secret: Vec<u8> = vec![0u8; self.algorithm.shared_secret_size()];

            if EVP_PKEY_encapsulate(
                *ctx,
                ciphertext.as_mut_ptr(),
                &mut self.algorithm.cipher_text_size(),
                shared_secret.as_mut_ptr(),
                &mut self.algorithm.shared_secret_size(),
            ) != 1
            {
                return Err(Unspecified);
            }

            kdf(&ciphertext, &shared_secret)
        }
    }

    /// Creates a new KEM public key from raw bytes. This method is NOT meant to generate
    /// a new public key, rather it restores a `KemPublicKey` that was previously converted
    /// to raw bytes.
    ///
    /// `alg` is the `KemAlgorithm` to be associated with the generated `KemPublicKey`
    ///
    /// `bytes` is a slice of raw bytes representing a `KemPublicKey`
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    ///
    pub fn new(alg: &'static KemAlgorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        if alg.public_key_size() != bytes.len() {
            return Err(KeyRejected::unexpected_error());
        }
        unsafe {
            let pubkey = LcPtr::new(EVP_PKEY_kem_new_raw_public_key(
                alg.id.nid(),
                bytes.as_ptr(),
                bytes.len(),
            ))?;
            Ok(KemPublicKey {
                algorithm: alg,
                pkey: pubkey,
                pub_key: bytes.into(),
            })
        }
    }
}

impl Drop for KemPublicKey {
    fn drop(&mut self) {
        self.pub_key.zeroize();
    }
}

impl AsRef<[u8]> for KemPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.pub_key
    }
}

// Returns an LcPtr to an EVP_PKEY
#[inline]
unsafe fn kem_key_generate(nid: c_int) -> Result<LcPtr<*mut EVP_PKEY>, Unspecified> {
    let ctx = LcPtr::new(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut()))?;
    let mut key_raw: *mut EVP_PKEY = null_mut();
    if 1 != EVP_PKEY_keygen_init(*ctx)
        || 1 != EVP_PKEY_CTX_kem_set_params(*ctx, nid)
        || 1 != EVP_PKEY_keygen(*ctx, &mut key_raw)
    {
        // We don't have the key wrapped with LcPtr yet, so explicitly free it
        key_raw.free();
        return Err(Unspecified);
    }

    Ok(LcPtr::new(key_raw)?)
}

#[cfg(test)]
mod tests {
    use crate::key_transport::{KemPrivateKey, KemPublicKey, KYBER512_R3};

    #[test]
    fn test_kem_privkey_serialize() {
        let priv_key = KemPrivateKey::generate(&KYBER512_R3).unwrap();
        assert_eq!(priv_key.algorithm(), &KYBER512_R3);

        let privkey_raw_bytes = priv_key.as_ref();
        let priv_key_from_bytes = KemPrivateKey::new(&KYBER512_R3, privkey_raw_bytes).unwrap();

        assert_eq!(priv_key.as_ref(), priv_key_from_bytes.as_ref());
        assert_eq!(priv_key.algorithm(), priv_key_from_bytes.algorithm());
    }

    #[test]
    fn test_kem_pubkey_serialize() {
        let priv_key = KemPrivateKey::generate(&KYBER512_R3).unwrap();
        assert_eq!(priv_key.algorithm(), &KYBER512_R3);

        let pub_key = priv_key.compute_public_key().unwrap();

        let pubkey_raw_bytes = pub_key.as_ref();
        let pub_key_from_bytes = KemPublicKey::new(&KYBER512_R3, pubkey_raw_bytes).unwrap();

        assert_eq!(pub_key.as_ref(), pub_key_from_bytes.as_ref());
        assert_eq!(pub_key.algorithm(), pub_key_from_bytes.algorithm());
    }
}
