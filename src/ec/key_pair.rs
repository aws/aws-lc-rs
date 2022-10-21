/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 */

use crate::ec::{
    EcdsaPublicKey, EcdsaSignatureFormat, EcdsaSigningAlgorithm, PKCS8_DOCUMENT_MAX_LEN,
};
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::Document;
use crate::ptr::{DetachableLcPtr, LcPtr};
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature};
use crate::{cbb, cbs, digest, ec};
use aws_lc_sys::{ECDSA_do_sign, EVP_PKEY_get1_EC_KEY, EVP_parse_private_key, EC_KEY, EVP_PKEY};
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;

pub struct EcdsaKeyPair {
    algorithm: &'static EcdsaSigningAlgorithm,
    ec_key: LcPtr<*mut EC_KEY>,
    pubkey: EcdsaPublicKey,
}

impl Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("EcdsaKeyPair {{ public_key: {:?} }}", self.pubkey))
    }
}

unsafe impl Send for EcdsaKeyPair {}

unsafe impl Sync for EcdsaKeyPair {}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = EcdsaPublicKey;

    #[inline(always)]
    fn public_key(&self) -> &Self::PublicKey {
        &self.pubkey
    }
}

pub(crate) unsafe fn generate_key(nid: i32) -> Result<LcPtr<*mut EVP_PKEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(aws_lc_sys::EC_KEY_new_by_curve_name(nid))?;

    // TODO: There's a separate function for FIPS
    // aws_lc_sys::EC_KEY_generate_key_fips(ec_key)
    if 1 != aws_lc_sys::EC_KEY_generate_key(*ec_key) {
        return Err(Unspecified);
    }

    let evp_pkey = LcPtr::new(aws_lc_sys::EVP_PKEY_new())?;
    if 1 != aws_lc_sys::EVP_PKEY_assign_EC_KEY(*evp_pkey, *ec_key) {
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
        let pubkey = ec::marshal_public_key(&ec_key.as_non_null())?;

        Ok(Self {
            algorithm,
            ec_key,
            pubkey,
        })
    }

    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let mut cbs = cbs::build_CBS(pkcs8);

            let evp_pkey = LcPtr::new(EVP_parse_private_key(&mut cbs))
                .map_err(|_| KeyRejected::invalid_encoding())?;

            ec::validate_pkey(evp_pkey.as_non_null(), alg.bits)?;
            let ec_key = LcPtr::new(EVP_PKEY_get1_EC_KEY(*evp_pkey))?;

            ec::validate_ec_key(*ec_key)?;

            let key_pair = Self::new(alg, ec_key)?;

            Ok(key_pair)
        }
    }

    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        _rng: &dyn SecureRandom,
    ) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = generate_key(alg.0.id.nid())?;

            let mut cbb = cbb::build_CBB(PKCS8_DOCUMENT_MAX_LEN);
            if 1 != aws_lc_sys::EVP_marshal_private_key(&mut cbb, *evp_pkey) {
                aws_lc_sys::CBB_cleanup(&mut cbb);
                return Err(Unspecified);
            }

            let mut pkcs8_bytes_ptr = MaybeUninit::<*mut u8>::uninit();
            let mut out_len = MaybeUninit::<usize>::uninit();
            if 1 != aws_lc_sys::CBB_finish(
                &mut cbb,
                pkcs8_bytes_ptr.as_mut_ptr(),
                out_len.as_mut_ptr(),
            ) {
                aws_lc_sys::CBB_cleanup(&mut cbb);
                return Err(Unspecified);
            }
            let pkcs8_bytes_ptr = LcPtr::new(pkcs8_bytes_ptr.assume_init())?;
            let out_len = out_len.assume_init();

            let bytes_slice = std::slice::from_raw_parts(*pkcs8_bytes_ptr, out_len);
            let mut pkcs8_bytes = [0u8; PKCS8_DOCUMENT_MAX_LEN];
            pkcs8_bytes[0..out_len].copy_from_slice(bytes_slice);

            Ok(Document {
                bytes: pkcs8_bytes,
                len: out_len,
            })
        }
    }

    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let ec_group = ec::ec_group_from_nid(alg.0.id.nid())?;
            let public_ec_point = ec::ec_point_from_bytes(&ec_group, public_key)
                .map_err(|_| KeyRejected::invalid_encoding())?;
            let private_bn = ec::bignum_from_be_bytes(private_key)
                .map_err(|_| KeyRejected::invalid_encoding())?
                .into();

            let ec_key = ec::ec_key_from_public_private(&ec_group, &public_ec_point, &private_bn)?;
            let key_pair = Self::new(alg, ec_key)?;

            Ok(key_pair)
        }
    }

    #[inline]
    pub fn sign(&self, _rng: &dyn SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        unsafe {
            let digest = digest::digest(self.algorithm.digest, message);
            let digest = digest.as_ref();
            let ecdsa_sig = LcPtr::new(ECDSA_do_sign(digest.as_ptr(), digest.len(), *self.ec_key))?;
            match self.algorithm.sig_format {
                EcdsaSignatureFormat::ASN1 => ec::ecdsa_sig_to_asn1(&ecdsa_sig),
                EcdsaSignatureFormat::Fixed => {
                    ec::ecdsa_sig_to_fixed(self.algorithm.id, &ecdsa_sig)
                }
            }
        }
    }
}
