// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::Unspecified;
use aws_lc::{
    ECDH_compute_key, EC_GROUP_cmp, EC_GROUP_get_curve_name, EC_GROUP_get_degree,
    EC_KEY_get0_group, EC_KEY_get0_public_key, EC_KEY, NID_KYBER512_R3
};

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

    fn compute_public_key(&self) -> Result<PublicKey<Vec<u8>>, Unspecified> {
        Ok(PublicKey{ alg: &Algorithm::KYBER512_R3, bytes: Vec::new() })
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
#[derive(Clone)]
pub struct PublicKey<B: AsRef<[u8]>> {
    alg: &'static Algorithm,
    bytes: B,
}

impl<B: AsRef<[u8]>> PublicKey<B> {
    // fn new()
}

pub struct SharedSecret {
    
}
// 