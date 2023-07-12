// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::digest::digest_ctx::DigestContext;
use crate::ec::{validate_ec_key, EcdsaSignatureFormat, EcdsaSigningAlgorithm, PublicKey};
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::{Document, Version};
use crate::ptr::{DetachableLcPtr, LcPtr};
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature};
use crate::{digest, ec};
#[cfg(not(feature = "fips"))]
use aws_lc::EC_KEY_generate_key;
#[cfg(feature = "fips")]
use aws_lc::EC_KEY_generate_key_fips;
use aws_lc::{
    EC_KEY_new_by_curve_name, EVP_DigestSign, EVP_MD_CTX_set_pkey_ctx, EVP_PKEY_CTX_new,
    EVP_PKEY_assign_EC_KEY, EVP_PKEY_new, EVP_PKEY_set1_EC_KEY, EVP_PKEY_sign_init, EC_KEY,
    EVP_PKEY,
};
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};

use std::fmt::{Debug, Formatter};

/// An ECDSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct EcdsaKeyPair {
    algorithm: &'static EcdsaSigningAlgorithm,
    evp_pkey: LcPtr<*mut EVP_PKEY>,
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

pub(crate) unsafe fn generate_key(nid: i32) -> Result<LcPtr<*mut EVP_PKEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new_by_curve_name(nid))?;

    #[cfg(feature = "fips")]
    if 1 != EC_KEY_generate_key_fips(*ec_key) {
        return Err(Unspecified);
    }

    #[cfg(not(feature = "fips"))]
    if 1 != EC_KEY_generate_key(*ec_key) {
        return Err(Unspecified);
    }

    let evp_pkey = LcPtr::new(EVP_PKEY_new())?;
    if 1 != EVP_PKEY_assign_EC_KEY(*evp_pkey, *ec_key) {
        return Err(Unspecified);
    }
    ec_key.detach();

    Ok(evp_pkey)
}

impl EcdsaKeyPair {
    unsafe fn new(
        algorithm: &'static EcdsaSigningAlgorithm,
        ec_key: LcPtr<*mut EC_KEY>,
    ) -> Result<Self, ()> {
        let pubkey = ec::marshal_public_key(&ec_key.as_const())?;

        let evp_pkey = LcPtr::new(unsafe { EVP_PKEY_new() }).map_err(|_| Unspecified)?;
        if 1 != unsafe { EVP_PKEY_set1_EC_KEY(*evp_pkey, *ec_key) } {
            return Err(());
        }

        // Remove this reference since we took ownership by value, EVP_PKEY already incremented a reference to it
        // so this is safe, and would happen regardless.
        // Doing this in lieu of passing by reference or allowing the lint bypass.
        drop(ec_key);

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

            let ec_key = evp_pkey.get_ec_key()?;

            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;

            let key_pair = Self::new(alg, ec_key)?;

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
    ///
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        _rng: &dyn SecureRandom,
    ) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = generate_key(alg.0.id.nid())?;

            evp_pkey.marshall_private_key(Version::V1)
        }
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
            let ec_key = ec::ec_key_from_public_private(&ec_group, &public_ec_point, &private_bn)?;
            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;
            let key_pair = Self::new(alg, ec_key)?;
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
    ///
    #[inline]
    pub fn sign(&self, _rng: &dyn SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.evp_pkey, null_mut()) })
            .map_err(|_| Unspecified)?;

        if 1 != unsafe { EVP_PKEY_sign_init(*pkey_ctx) } {
            return Err(Unspecified);
        };

        let mut context = digest::digest_ctx::DigestContext::new(self.algorithm.digest)?;
        unsafe { EVP_MD_CTX_set_pkey_ctx(context.as_mut_ptr(), *pkey_ctx) };

        let mut out_sig = vec![0u8; get_signature_length(&mut context)?];

        let out_sig = compute_ecdsa_signature(&mut context, message, out_sig.as_mut_slice())?;

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
    let result = unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            null_mut(),
            out_sig_len.as_mut_ptr(),
            null(),
            0,
        )
    };
    if 1 != result {
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
    let mut out_sig_len = MaybeUninit::<usize>::new(signature.len());

    let result = unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            signature.as_mut_ptr(),
            out_sig_len.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
        )
    };
    if 1 != result {
        return Err(Unspecified);
    }

    let out_sig_len = unsafe { out_sig_len.assume_init() };

    Ok(&mut signature[0..out_sig_len])
}
