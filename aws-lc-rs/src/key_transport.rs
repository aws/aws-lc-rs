// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::{Unspecified, KeyRejected};
use aws_lc::{
    ECDH_compute_key, EC_GROUP_cmp, EC_GROUP_get_curve_name, EC_GROUP_get_degree,
    EC_KEY_get0_group, EC_KEY_get0_public_key, EC_KEY, NID_KYBER512_R3
};

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

// Structs
// PrivateKey
pub struct PrivateKey {

}

impl PrivateKey {
    fn generate(algorithm: Algorithm) -> Result<Self, Unspecified> {
        Ok(PrivateKey {})
    }

    fn from_raw_bytes(alg: Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        Ok(PrivateKey {})
    }

    fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        Ok(PublicKey{ alg: &Algorithm::KYBER512_R3, bytes: Vec::new() })
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, Unspecified> {
        Ok(SharedSecret {  })
    }
}

impl Into<[u8; 1]> for PrivateKey {
    fn into(self) -> [u8; 1] {
        [0]
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
#[derive(Clone)]
pub struct PublicKey {
    alg: &'static Algorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    fn from_raw_bytes(alg: Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        Ok(PublicKey{ alg: &Algorithm::KYBER512_R3, bytes: Vec::new() })
    }

    fn encapsulate(&self) -> Result<(&[u8], SharedSecret), Unspecified> {
        Ok((self.bytes.as_ref(), SharedSecret{}))
    }
}

impl Into<[u8; 1]> for PublicKey {
    fn into(self) -> [u8; 1] {
        [0]
    }
}

pub struct SharedSecret {
    
}
