// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{error::{Unspecified, KeyRejected}, ptr::LcPtr, ptr::{DetachableLcPtr, Pointer}, cipher};
use std::{os::raw::c_int};
use std::ptr::null_mut;
use aws_lc::{
    EVP_PKEY, NID_KYBER512_R3, EVP_PKEY_keygen, EVP_PKEY_CTX_new_id, EVP_PKEY_keygen_init,
    EVP_PKEY_KEM, EVP_PKEY_kem_new_raw_secret_key, EVP_PKEY_CTX_kem_set_params, EVP_PKEY_CTX_new,
    EVP_PKEY_encapsulate, EVP_PKEY_decapsulate, EVP_PKEY_get_raw_public_key, EVP_PKEY_kem_new_raw_public_key, EVP_PKEY_get_raw_private_key
};
use zeroize::Zeroize;


const KYBER512_SECRETKEYBYTES: usize = 1632;
const KYBER512_PUBLICKEYBYTES: usize = 800;
const KYBER512_CIPHERTEXTBYTES: usize = 768;
const KYBER512_BYTES: usize = 32;

const PRIVATE_KEY_MAX_LEN: usize = KYBER512_SECRETKEYBYTES;
const PUBLIC_KEY_MAX_LEN: usize = KYBER512_PUBLICKEYBYTES;
const CIPHERTEXT_MAX_LEN: usize = KYBER512_CIPHERTEXTBYTES;
const SHARED_SECRET_MAX_LEN: usize = KYBER512_BYTES;


#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq)]
pub enum Algorithm {
    KYBER512_R3,
}

impl Algorithm {
    #[inline]
    fn nid(&self) -> i32 {
        match self {
            Algorithm::KYBER512_R3 => NID_KYBER512_R3,
        }
    }

    #[inline]
    fn get_pubkey_len(&self) -> usize {
        match self {
            Algorithm::KYBER512_R3 => KYBER512_PUBLICKEYBYTES,
        }
    }

    #[inline]
    fn get_privkey_len(&self) -> usize {
        match self {
            Algorithm::KYBER512_R3 => KYBER512_SECRETKEYBYTES,
        }
    }
}

// KemPrivateKey
#[derive(Debug)]
pub struct KemPrivateKey {
    algorithm: Algorithm,
    context: LcPtr<*mut EVP_PKEY>,
    priv_key: Vec<u8>
}

impl KemPrivateKey {
    pub fn generate(alg: Algorithm) -> Result<Self, Unspecified> {
        match alg {
            Algorithm::KYBER512_R3 => unsafe {
                let kyber_key = kem_key_generate(alg.nid())?;
                let mut priv_key_bytes = vec![0u8; alg.get_privkey_len()];
                if 1 != EVP_PKEY_get_raw_private_key(*kyber_key, priv_key_bytes.as_mut_ptr(), &mut alg.get_privkey_len()) {
                    return Err(Unspecified);
                }
                Ok(KemPrivateKey {
                    algorithm: alg,
                    context: LcPtr::from(kyber_key),
                    priv_key: priv_key_bytes
                })
            },
        }
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    pub fn compute_public_key(&self) -> Result<KemPublicKey, Unspecified> {
        // Could implement clone for LcPtr and call that here
        let mut pubkey_bytes = vec![0u8; self.algorithm.get_pubkey_len()];
        let mut pubkey_len;
        let pubkey_ctx_copy;
        match self.algorithm {
            Algorithm::KYBER512_R3 => {
                pubkey_len = KYBER512_PUBLICKEYBYTES;
            }
        }
        unsafe {
            if 1 != EVP_PKEY_get_raw_public_key(*self.context, pubkey_bytes.as_mut_ptr(), &mut pubkey_len) {
                return Err(Unspecified);
            }
            pubkey_ctx_copy = EVP_PKEY_kem_new_raw_public_key(self.algorithm.nid(), pubkey_bytes.as_mut_ptr(), pubkey_len);
            if pubkey_ctx_copy.is_null() {
                return Err(Unspecified);
            }
        }
        Ok(KemPublicKey{
            algorithm: self.algorithm.clone(),
            context: LcPtr::new(pubkey_ctx_copy)?,
            pub_key: pubkey_bytes
        })
    }

    pub fn decapsulate<F, R>(&self, ciphertext: &mut [u8], kdf: F) -> Result<R, Unspecified>
    where
        F: FnOnce(&[u8]) -> Result<R, Unspecified> {
        unsafe {
            let ctx = DetachableLcPtr::new(EVP_PKEY_CTX_new(*self.context, null_mut()))?;
            let mut shared_secret_len;
            match self.algorithm {
                Algorithm::KYBER512_R3 => {
                    shared_secret_len = KYBER512_BYTES;
                }
            }
            let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];
            if EVP_PKEY_decapsulate(*ctx, shared_secret.as_mut_ptr(), &mut shared_secret_len,
                                    ciphertext.as_mut_ptr(), ciphertext.len()) != 1 {
                shared_secret.zeroize()
            }
            kdf(&shared_secret)
        }
    }

    pub fn from_raw_bytes(alg: Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let pkey = DetachableLcPtr::new(EVP_PKEY_kem_new_raw_secret_key(alg.nid(), bytes.as_ptr(), bytes.len())).map_err(|_e| KeyRejected::unexpected_error())?;
            Ok(KemPrivateKey {
                algorithm: alg,
                context: LcPtr::from(pkey),
                priv_key: bytes.to_owned()
            })
        }
    }

    pub fn get_raw_bytes(&self) -> &[u8] {
        &self.priv_key
    }
}

#[cfg(test)]
impl PartialEq for KemPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        let mut self_privkey_bytes_from_ctx = vec![0u8; self.algorithm.get_privkey_len()];
        let mut other_privkey_bytes_from_ctx = vec![0u8; other.algorithm.get_privkey_len()];

        unsafe {
            if 1 != EVP_PKEY_get_raw_private_key(*self.context, self_privkey_bytes_from_ctx.as_mut_ptr(), &mut self.algorithm.get_privkey_len()) {
                panic!("Error getting private key from context");
            }
            if 1 != EVP_PKEY_get_raw_private_key(*other.context, other_privkey_bytes_from_ctx.as_mut_ptr(), &mut other.algorithm.get_privkey_len()) {
                panic!("Error getting private key from context");
            }
        }
        self.algorithm == other.algorithm &&
        self.priv_key == other.priv_key &&
        self_privkey_bytes_from_ctx == other_privkey_bytes_from_ctx
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
// #[derive(Clone)]
pub struct KemPublicKey {
    algorithm: Algorithm,
    context: LcPtr<*mut EVP_PKEY>,
    pub_key: Vec<u8>,
}

impl KemPublicKey {
    pub fn encapsulate<F, R>(&self, kdf: F) -> Result<R, Unspecified>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<R, Unspecified> {
        unsafe {
            let ctx = DetachableLcPtr::new(EVP_PKEY_CTX_new(*self.context, null_mut()))?;
            // get buffer lengths
            let mut ciphertext_len;
            let mut shared_secret_len;
            match self.algorithm {
                Algorithm::KYBER512_R3 => {
                    ciphertext_len = KYBER512_CIPHERTEXTBYTES;
                    shared_secret_len = KYBER512_BYTES;
                }
            }
            let mut ciphertext: Vec<u8> = vec![0u8; ciphertext_len];
            // println!("Shared secret length: {}", shared_secret_len);
            let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];
            // println!("Shared secret capacity: {}", shared_secret.capacity());
            if EVP_PKEY_encapsulate(*ctx, ciphertext.as_mut_ptr(), &mut ciphertext_len,
                                    shared_secret.as_mut_ptr(), &mut shared_secret_len) != 1 {
                ciphertext.zeroize();
                shared_secret.zeroize();
                return Err(Unspecified);
            }

            #[cfg(feature = "debug-kem")]
            {   
                println!("Ciphertext length: {}", ciphertext_len);
                println!("Shared secret length: {}", shared_secret_len);
                println!("Ciphertext: {:02x?}", ciphertext);
                println!("Shared Secret: {:02x?}", shared_secret);
            }

            kdf(&ciphertext, &shared_secret)
        }
    }

    pub fn from_raw_bytes(alg: Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let pubkey_ctx = EVP_PKEY_kem_new_raw_public_key(alg.nid(), bytes.as_ptr(), alg.get_pubkey_len());
            if pubkey_ctx.is_null() {
                return Err(KeyRejected::unexpected_error());
            }
            Ok(KemPublicKey { 
                algorithm: alg,
                context: LcPtr::new(pubkey_ctx)?,
                pub_key: bytes.to_owned()
                // pub_key: bytes.try_into().map_err(|_e|KeyRejected::unexpected_error())?
            })
        }
    }

    pub fn get_raw_bytes(&self) -> &[u8] {
        &self.pub_key
    }
}

// Returns a DetachableLcPtr to an EVP_PKEY
#[inline]
unsafe fn kem_key_generate(
    nid: c_int,
) -> Result<DetachableLcPtr<*mut EVP_PKEY>, Unspecified> {
    let ctx = DetachableLcPtr::new(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut()))?;
    let mut key_raw: *mut EVP_PKEY = null_mut();
    if 1 != EVP_PKEY_keygen_init(*ctx) ||
       1 != EVP_PKEY_CTX_kem_set_params(*ctx, nid) ||
       1 != EVP_PKEY_keygen(*ctx, &mut key_raw) {
        // We don't have the key wrapped with LcPtr yet, so explicitly free it
        key_raw.free();
        return Err(Unspecified);
    }
    
    Ok(DetachableLcPtr::new(key_raw)?)
}

#[cfg(test)]
mod tests {
    use crate::{key_transport::*, rand, test, test_file};
    use std::env;

    #[test]
    fn test_privkey_serialize() {
        let priv_key = KemPrivateKey::generate(Algorithm::KYBER512_R3).unwrap();
        assert_eq!(priv_key.algorithm(), &Algorithm::KYBER512_R3);

        let privkey_raw_bytes = priv_key.get_raw_bytes();
        let priv_key_from_bytes = KemPrivateKey::from_raw_bytes(Algorithm::KYBER512_R3, privkey_raw_bytes).unwrap();

        assert_eq!(priv_key, priv_key_from_bytes)
    }

    #[test]
    fn test_pubkey_serialize() {

    }
}
