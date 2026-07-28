// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

pub(crate) mod key_pair;
pub(crate) mod signature;

use crate::aws_lc::{
    EVP_DigestFinalXOF, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_shake256, EVP_PKEY,
    EVP_PKEY_PQDSA, NID_MLDSA44, NID_MLDSA65, NID_MLDSA87,
};
use crate::digest::digest_ctx::DigestContext;
use crate::error::{KeyRejected, Unspecified};
use crate::ptr::LcPtr;
use core::ffi::c_int;
use core::ptr::null_mut;

/// The largest external message representative length across all PQDSA algorithms.
///
/// Mirrors the role of [`crate::digest::MAX_OUTPUT_LEN`]: it sizes the fixed buffer inside
/// the representative value type so one type can carry any algorithm's representative.
pub(crate) const MAX_EXTERNAL_REPRESENTATIVE_LEN: usize = 64;

/// The length in bytes of `tr = SHAKE256(public_key)` (`ML_DSA_TRBYTES`).
pub(crate) const TR_LEN: usize = 64;

#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub(crate) enum AlgorithmID {
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
}

impl AlgorithmID {
    #[allow(dead_code)]
    pub(crate) const fn from_nid(nid: c_int) -> Result<Self, Unspecified> {
        match nid {
            NID_MLDSA44 => Ok(Self::ML_DSA_44),
            NID_MLDSA65 => Ok(Self::ML_DSA_65),
            NID_MLDSA87 => Ok(Self::ML_DSA_87),
            _ => Err(Unspecified),
        }
    }

    pub(crate) const fn nid(&self) -> c_int {
        match self {
            Self::ML_DSA_44 => NID_MLDSA44,
            Self::ML_DSA_65 => NID_MLDSA65,
            Self::ML_DSA_87 => NID_MLDSA87,
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn priv_key_size_bytes(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 2560,
            Self::ML_DSA_65 => 4032,
            Self::ML_DSA_87 => 4896,
        }
    }

    pub(crate) const fn pub_key_size_bytes(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 1312,
            Self::ML_DSA_65 => 1952,
            Self::ML_DSA_87 => 2592,
        }
    }

    pub(crate) const fn seed_size_bytes(&self) -> usize {
        // All ML-DSA variants use 32-byte seeds per FIPS 204
        match self {
            Self::ML_DSA_44 | Self::ML_DSA_65 | Self::ML_DSA_87 => 32,
        }
    }

    pub(crate) const fn signature_size_bytes(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 2420,
            Self::ML_DSA_65 => 3309,
            Self::ML_DSA_87 => 4627,
        }
    }
}

pub(crate) fn validate_pqdsa_evp_key(
    evp_pkey: &LcPtr<EVP_PKEY>,
    id: &'static AlgorithmID,
) -> Result<(), KeyRejected> {
    if evp_pkey.as_const().key_size_bytes() == id.pub_key_size_bytes() {
        Ok(())
    } else {
        Err(KeyRejected::unspecified())
    }
}

pub(crate) fn parse_pqdsa_public_key(
    key_bytes: &[u8],
    id: &'static AlgorithmID,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(key_bytes, EVP_PKEY_PQDSA)
        .or(LcPtr::<EVP_PKEY>::parse_raw_public_key(
            key_bytes,
            EVP_PKEY_PQDSA,
        ))
        .and_then(|key| validate_pqdsa_evp_key(&key, id).map(|()| key))
}

/// Returns the length in bytes of the external message representative that `id` signs and
/// verifies, or `None` if `id` does not support signing a precomputed representative.
///
/// This mirrors AWS-LC's `PQDSA.digest_len`, which is a field on the family-level `PQDSA`
/// struct rather than on any one algorithm: the ability to sign a precomputed representative
/// is modelled as a per-algorithm capability that individual algorithms opt into.
///
/// For ML-DSA the representative is `mu`, of length `ML_DSA_CRHBYTES` (64) for every
/// parameter set. A future algorithm can only support this if its representative is a
/// deterministic function of public inputs alone -- that holds for ML-DSA, but not for
/// schemes that mix signer-chosen randomness into the message hash before signing (SLH-DSA
/// derives it through a secret-keyed PRF; FN-DSA draws a fresh salt).
//
// This is deliberately an exhaustive `match` with no wildcard arm. Every PQDSA algorithm
// supported today is an ML-DSA parameter set, so there is no reachable `None` case; writing
// it this way means adding an algorithm to `AlgorithmID` is a compile error here, forcing a
// deliberate decision instead of silently claiming or denying support for it. The `Option`
// is therefore always `Some` today, and is kept so that adding an algorithm that does not
// support this is not a breaking change to every caller.
#[allow(clippy::unnecessary_wraps)]
pub(crate) const fn external_representative_len(id: &AlgorithmID) -> Option<usize> {
    match id {
        AlgorithmID::ML_DSA_44 | AlgorithmID::ML_DSA_65 | AlgorithmID::ML_DSA_87 => Some(64),
    }
}

/// Computes `tr = SHAKE256(public_key, 64)`, the public key hash that binds `mu` to a
/// specific key. `raw_public_key` must be the raw (not X.509) public key encoding.
pub(crate) fn compute_tr(raw_public_key: &[u8]) -> Result<[u8; TR_LEN], Unspecified> {
    let mut tr = [0u8; TR_LEN];
    shake256(&[raw_public_key], &mut tr)?;
    Ok(tr)
}

/// Computes `mu`, the FIPS 204 "message representative", from a precomputed `tr`, squeezing
/// `mu.len()` bytes:
///
/// ```text
/// mu = SHAKE256(tr || 0x00 || len(context) || context || message, mu.len())
/// ```
///
/// The `0x00` octet is the domain separator selecting "pure" ML-DSA (as opposed to
/// HashML-DSA, which uses `0x01`).
pub(crate) fn compute_mu(
    tr: &[u8; TR_LEN],
    context: &[u8],
    message: &[u8],
    mu: &mut [u8],
) -> Result<(), Unspecified> {
    // FIPS 204 limits the context string to 255 bytes, which is also what the single
    // length octet below can encode.
    let context_len = u8::try_from(context.len()).map_err(|_| Unspecified)?;

    shake256(&[tr, &[0u8, context_len], context, message], mu)
}

/// Absorbs each element of `inputs` in order and squeezes `output.len()` bytes.
fn shake256(inputs: &[&[u8]], output: &mut [u8]) -> Result<(), Unspecified> {
    let mut md_ctx = DigestContext::new_uninit();
    if 1 != unsafe { EVP_DigestInit_ex(md_ctx.as_mut_ptr(), EVP_shake256(), null_mut()) } {
        return Err(Unspecified);
    }
    for input in inputs {
        if 1 != unsafe { EVP_DigestUpdate(md_ctx.as_mut_ptr(), input.as_ptr().cast(), input.len()) }
        {
            return Err(Unspecified);
        }
    }
    if 1 != unsafe { EVP_DigestFinalXOF(md_ctx.as_mut_ptr(), output.as_mut_ptr(), output.len()) } {
        return Err(Unspecified);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::aws_lc::{
        EVP_PKEY_cmp, EVP_PKEY, EVP_PKEY_PQDSA, NID_MLDSA44, NID_MLDSA65, NID_MLDSA87,
    };

    use crate::evp_pkey::*;

    use crate::pkcs8::Version;
    use crate::pqdsa::key_pair::evp_key_pqdsa_generate;
    use crate::pqdsa::AlgorithmID;
    use crate::ptr::LcPtr;

    #[test]
    fn test_keygen() {
        for nid in [NID_MLDSA44, NID_MLDSA65, NID_MLDSA87] {
            let key = evp_key_pqdsa_generate(nid).unwrap();
            println!("key size: {:?}", key.as_const().key_size_bytes());
            test_serialization_for(&key, &AlgorithmID::from_nid(nid).unwrap());
            test_signing_for(&key, &AlgorithmID::from_nid(nid).unwrap());
        }
    }

    fn test_serialization_for(evp_pkey: &LcPtr<EVP_PKEY>, id: &AlgorithmID) {
        let public_buffer = evp_pkey.as_const().marshal_rfc5280_public_key().unwrap();
        println!("public marshall: {public_buffer:?}");
        let key_public =
            LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(&public_buffer, EVP_PKEY_PQDSA).unwrap();

        let private_buffer = evp_pkey
            .as_const()
            .marshal_rfc5208_private_key(Version::V1)
            .unwrap();
        println!("private marshall: {private_buffer:?}");
        let key_private =
            LcPtr::<EVP_PKEY>::parse_rfc5208_private_key(&private_buffer, EVP_PKEY_PQDSA).unwrap();

        let raw_public_buffer = key_public.as_const().marshal_raw_public_key().unwrap();
        assert_eq!(raw_public_buffer.len(), id.pub_key_size_bytes());
        println!("raw public size: {}", raw_public_buffer.len());
        let key_public2 =
            LcPtr::<EVP_PKEY>::parse_raw_public_key(&raw_public_buffer, EVP_PKEY_PQDSA).unwrap();

        assert_eq!(1, unsafe {
            EVP_PKEY_cmp(key_public.as_const_ptr(), key_public2.as_const_ptr())
        });

        let raw_private_buffer = key_private.as_const().marshal_raw_private_key().unwrap();
        assert_eq!(raw_private_buffer.len(), id.priv_key_size_bytes());
        println!("raw private size: {}", raw_private_buffer.len());
        let key_private2 =
            LcPtr::<EVP_PKEY>::parse_raw_private_key(&raw_private_buffer, EVP_PKEY_PQDSA).unwrap();
        assert_eq!(1, unsafe {
            EVP_PKEY_cmp(key_private.as_const_ptr(), key_private2.as_const_ptr())
        });
    }

    fn test_signing_for(evp_pkey: &LcPtr<EVP_PKEY>, id: &AlgorithmID) {
        let message = b"hello world";
        let signature = evp_pkey
            .sign(message, None, No_EVP_PKEY_CTX_consumer)
            .unwrap();
        println!("signature size: {}", signature.len());
        assert_eq!(signature.len(), evp_pkey.as_const().signature_size_bytes());
        assert_eq!(signature.len(), id.signature_size_bytes());
        evp_pkey
            .verify(message, None, No_EVP_PKEY_CTX_consumer, &signature)
            .unwrap();
        println!("verified: {signature:?}");
    }
}
