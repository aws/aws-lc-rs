// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::digest::digest_ctx::DigestContext;
use crate::ec::{
    evp_key_generate, validate_evp_key, EcdsaSignatureFormat, EcdsaSigningAlgorithm, PublicKey,
};
use crate::error::{KeyRejected, Unspecified};
use crate::fips::indicator_check;
use crate::pkcs8::{Document, Version};
use crate::ptr::{DetachableLcPtr, LcPtr};
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature};
use crate::{digest, ec};
use aws_lc::{EVP_DigestSign, EVP_DigestSignInit, EVP_PKEY};
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};

use std::fmt::{Debug, Formatter};

/// An ECDSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct EcdsaKeyPair {
    algorithm: &'static EcdsaSigningAlgorithm,
    evp_pkey: LcPtr<EVP_PKEY>,
    pubkey: PublicKey,
}

impl Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("EcdsaKeyPair {{ public_key: {:?} }}", self.pubkey))
    }
}

unsafe impl Send for EcdsaKeyPair {}

unsafe impl Sync for EcdsaKeyPair {}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        &self.pubkey
    }
}

impl EcdsaKeyPair {
    #[allow(clippy::needless_pass_by_value)]
    unsafe fn new(
        algorithm: &'static EcdsaSigningAlgorithm,
        evp_pkey: LcPtr<EVP_PKEY>,
    ) -> Result<Self, ()> {
        let pubkey = ec::marshal_public_key(&evp_pkey.as_const())?;

        Ok(Self {
            algorithm,
            evp_pkey,
            pubkey,
        })
    }

    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an ECDSA key pair or if the key is otherwise not
    /// acceptable.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let evp_pkey = LcPtr::try_from(pkcs8)?;

            validate_evp_key(&evp_pkey.as_const(), alg.id.nid())?;

            let key_pair = Self::new(alg, evp_pkey)?;

            Ok(key_pair)
        }
    }

    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 v1 document.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        _rng: &dyn SecureRandom,
    ) -> Result<Document, Unspecified> {
        let evp_pkey = evp_key_generate(alg.0.id.nid())?;

        evp_pkey.marshall_private_key(Version::V1)
    }

    /// Serializes this `EcdsaKeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8(&self) -> Result<Document, Unspecified> {
        unsafe { self.evp_pkey.marshall_private_key(Version::V1) }
    }

    /// Constructs an ECDSA key pair from the private key and public key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// The public key is encoding in uncompressed form using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `EcdsaKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let ec_group = ec::ec_group_from_nid(alg.0.id.nid())?;
            let public_ec_point = ec::ec_point_from_bytes(&ec_group, public_key)
                .map_err(|_| KeyRejected::invalid_encoding())?;
            let private_bn = DetachableLcPtr::try_from(private_key)?;
            let evp_pkey =
                ec::evp_key_from_public_private(&ec_group, &public_ec_point, &private_bn)?;

            let key_pair = Self::new(alg, evp_pkey)?;
            Ok(key_pair)
        }
    }

    /// Returns the signature of the message using a random nonce.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    //
    // # FIPS
    // The following conditions must be met:
    // * NIST Elliptic Curves: P256, P384, P521
    // * Digest Algorithms: SHA256, SHA384, SHA512
    #[inline]
    pub fn sign(&self, _rng: &dyn SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        let mut md_ctx = DigestContext::new_uninit();

        let digest = digest::match_digest_type(&self.algorithm.digest.id);

        if 1 != unsafe {
            EVP_DigestSignInit(
                md_ctx.as_mut_ptr(),
                null_mut(),
                *digest,
                null_mut(),
                *self.evp_pkey,
            )
        } {
            return Err(Unspecified);
        }

        let mut out_sig = vec![0u8; get_signature_length(&mut md_ctx)?];

        let out_sig = compute_ecdsa_signature(&mut md_ctx, message, out_sig.as_mut_slice())?;

        Ok(match self.algorithm.sig_format {
            EcdsaSignatureFormat::ASN1 => Signature::new(|slice| {
                slice[..out_sig.len()].copy_from_slice(out_sig);
                out_sig.len()
            }),
            EcdsaSignatureFormat::Fixed => ec::ecdsa_asn1_to_fixed(self.algorithm.id, out_sig)?,
        })
    }
}

#[inline]
fn get_signature_length(ctx: &mut DigestContext) -> Result<usize, Unspecified> {
    let mut out_sig_len = MaybeUninit::<usize>::uninit();

    // determine signature size
    if 1 != unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            null_mut(),
            out_sig_len.as_mut_ptr(),
            null(),
            0,
        )
    } {
        return Err(Unspecified);
    }

    Ok(unsafe { out_sig_len.assume_init() })
}

#[inline]
fn compute_ecdsa_signature<'a>(
    ctx: &mut DigestContext,
    message: &[u8],
    signature: &'a mut [u8],
) -> Result<&'a mut [u8], Unspecified> {
    let mut out_sig_len = signature.len();

    if 1 != indicator_check!(unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut out_sig_len,
            message.as_ptr(),
            message.len(),
        )
    }) {
        return Err(Unspecified);
    }

    Ok(&mut signature[0..out_sig_len])
}

#[cfg(test)]
mod tests {
    use crate::rand::SystemRandom;
    use crate::signature::*;

    #[test]
    fn test_to_pkcs8() {
        for signing_alg in [
            &ECDSA_P521_SHA3_512_ASN1_SIGNING,
            &ECDSA_P521_SHA3_512_FIXED_SIGNING,
            &ECDSA_P521_SHA512_ASN1_SIGNING,
            &ECDSA_P521_SHA512_FIXED_SIGNING,
            &ECDSA_P384_SHA3_384_ASN1_SIGNING,
            &ECDSA_P384_SHA3_384_FIXED_SIGNING,
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &ECDSA_P256_SHA256_FIXED_SIGNING,
        ] {
            let rnd = SystemRandom::new();
            let key_pair_doc = EcdsaKeyPair::generate_pkcs8(signing_alg, &rnd).unwrap();
            let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, key_pair_doc.as_ref()).unwrap();

            let key_pair_export_doc = key_pair.to_pkcs8().unwrap();
            // Verify that the exported bytes match the original generated bytes
            assert_eq!(key_pair_doc.as_ref(), key_pair_export_doc.as_ref());
        }
    }
}
