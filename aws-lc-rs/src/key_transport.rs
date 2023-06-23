// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{error::{Unspecified, KeyRejected}, ptr::LcPtr, ptr::{DetachableLcPtr, Pointer}};
use std::{os::raw::c_int};
use std::ptr::null_mut;
use aws_lc::{
    EVP_PKEY, NID_KYBER512_R3, EVP_PKEY_keygen, EVP_PKEY_CTX_new_id, EVP_PKEY_keygen_init,
    EVP_PKEY_KEM, EVP_PKEY_kem_new_raw_secret_key, EVP_PKEY_CTX_kem_set_params
};

const KYBER512_SECRETKEYBYTES: usize = 1632;
const KYBER512_PUBLICKEYBYTES: usize = 800;
const KYBER512_CIPHERTEXTBYTES: usize = 768;
const KYBER512_BYTES: usize = 32;

const PRIVATE_KEY_MAX_LEN: usize = KYBER512_SECRETKEYBYTES;
const PUBLIC_KEY_MAX_LEN: usize = KYBER512_PUBLICKEYBYTES;
const CIPHERTEXT_MAX_LEN: usize = KYBER512_CIPHERTEXTBYTES;
const SHARED_SECRET_MAX_LEN: usize = KYBER512_BYTES;


#[allow(non_camel_case_types)]
#[derive(Clone)]
enum Algorithm {
    KYBER512_R3,
}

impl Algorithm {
    #[inline]
    fn nid(&self) -> i32 {
        match self {
            Algorithm::KYBER512_R3 => NID_KYBER512_R3,
        }
    }
}

// PrivateKey
pub struct PrivateKey {
    algorithm: &'static Algorithm,
    context: LcPtr<*mut EVP_PKEY>
}

impl PrivateKey {
    fn generate(alg: &'static Algorithm) -> Result<Self, Unspecified> {
        match alg {
            Algorithm::KYBER512_R3 => unsafe {
                let kyber_key = kem_key_generate(alg.nid())?;
                Ok(PrivateKey {
                    algorithm: alg,
                    context: LcPtr::from(kyber_key),
                })
            },
        }
    }

    unsafe fn from_raw_bytes(alg: &'static Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        let pkey = DetachableLcPtr::new(EVP_PKEY_kem_new_raw_secret_key(alg.nid(), bytes.as_ptr(), bytes.len()))?;
        Ok(PrivateKey {
            algorithm: alg,
            context: LcPtr::from(pkey),
        })
    }

    fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        Ok(PublicKey{ alg: &Algorithm::KYBER512_R3, bytes: [0u8; PUBLIC_KEY_MAX_LEN] })
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_MAX_LEN], Unspecified> {
        Ok([0u8; SHARED_SECRET_MAX_LEN])
    }
}

impl Into<[u8; PRIVATE_KEY_MAX_LEN]> for PrivateKey {
    fn into(self) -> [u8; PRIVATE_KEY_MAX_LEN] {
        [0u8; PRIVATE_KEY_MAX_LEN]
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
#[derive(Clone)]
pub struct PublicKey {
    alg: &'static Algorithm,
    bytes: [u8; PUBLIC_KEY_MAX_LEN],
}

impl PublicKey {
    fn from_raw_bytes(alg: Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        Ok(PublicKey{ alg: &Algorithm::KYBER512_R3, bytes: bytes.try_into().map_err(|_e| KeyRejected::unexpected_error())? })
    }

    fn encapsulate(&self) -> Result<([u8; CIPHERTEXT_MAX_LEN], [u8; SHARED_SECRET_MAX_LEN]), Unspecified> {
        Ok(([0u8; CIPHERTEXT_MAX_LEN], [0u8; SHARED_SECRET_MAX_LEN]))
    }
}

impl Into<[u8; PUBLIC_KEY_MAX_LEN]> for PublicKey {
    fn into(self) -> [u8; PUBLIC_KEY_MAX_LEN] {
        [0; PUBLIC_KEY_MAX_LEN]
    }
}

// Returns a DetachableLcPtr to an EVP_PKEY
#[inline]
unsafe fn kem_key_generate(
    nid: c_int,
) -> Result<DetachableLcPtr<*mut EVP_PKEY>, Unspecified> {
    let ctx = DetachableLcPtr::new(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut()))?;
    let mut key_raw = null_mut();
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
    use crate::error::Unspecified;
    use crate::{agreement, rand, test, test_file};

    #[test]
    fn key_transport_test() {

    }
}
