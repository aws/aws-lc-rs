// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ec::PKCS8_DOCUMENT_MAX_LEN;
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::{Document, Version};
use crate::ptr::LcPtr;
use crate::{cbb, cbs};
use aws_lc::{
    CBB_finish, EVP_PKEY_bits, EVP_PKEY_get1_EC_KEY, EVP_PKEY_get1_RSA, EVP_PKEY_id,
    EVP_marshal_private_key, EVP_marshal_private_key_v2, EVP_parse_private_key, EC_KEY, EVP_PKEY,
    RSA,
};
use std::mem::MaybeUninit;
use std::os::raw::c_int;

impl TryFrom<&[u8]> for LcPtr<*mut EVP_PKEY> {
    type Error = KeyRejected;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let mut cbs = cbs::build_CBS(bytes);

            LcPtr::new(EVP_parse_private_key(&mut cbs)).map_err(|_| KeyRejected::invalid_encoding())
        }
    }
}

impl LcPtr<*mut EVP_PKEY> {
    pub(crate) fn validate_as_ed25519(&self) -> Result<(), KeyRejected> {
        const ED25519_KEY_TYPE: c_int = aws_lc::EVP_PKEY_ED25519;
        const ED25519_MIN_BITS: c_int = 253;
        const ED25519_MAX_BITS: c_int = 256;

        let key_type = self.id();
        if key_type != ED25519_KEY_TYPE {
            return Err(KeyRejected::wrong_algorithm());
        }

        let bits = self.bits();
        if bits < ED25519_MIN_BITS {
            return Err(KeyRejected::too_small());
        }

        if bits > ED25519_MAX_BITS {
            return Err(KeyRejected::too_large());
        }
        Ok(())
    }

    // EVP_PKEY_NONE = 0;
    // EVP_PKEY_RSA = 6;
    // EVP_PKEY_RSA_PSS = 912;
    // EVP_PKEY_DSA = 116;
    // EVP_PKEY_EC = 408;
    // EVP_PKEY_ED25519 = 949;
    // EVP_PKEY_X25519 = 948;
    // EVP_PKEY_KYBER512 = 970;
    // EVP_PKEY_HKDF = 969;
    // EVP_PKEY_DH = 28;
    // EVP_PKEY_RSA2 = 19;
    // EVP_PKEY_X448 = 961;
    // EVP_PKEY_ED448 = 960;
    pub(crate) fn id(&self) -> i32 {
        unsafe { EVP_PKEY_id(**self) }
    }

    pub(crate) fn bits(&self) -> i32 {
        unsafe { EVP_PKEY_bits(**self) }
    }

    pub(crate) fn get_ec_key(&self) -> Result<LcPtr<*mut EC_KEY>, KeyRejected> {
        unsafe {
            LcPtr::new(EVP_PKEY_get1_EC_KEY(**self)).map_err(|_| KeyRejected::wrong_algorithm())
        }
    }

    pub(crate) fn get_rsa(&self) -> Result<LcPtr<*mut RSA>, KeyRejected> {
        unsafe { LcPtr::new(EVP_PKEY_get1_RSA(**self)).map_err(|_| KeyRejected::wrong_algorithm()) }
    }

    pub(crate) fn marshall_private_key(&self, version: Version) -> Result<Document, Unspecified> {
        unsafe {
            let mut cbb = cbb::build_CBB(PKCS8_DOCUMENT_MAX_LEN);

            match version {
                Version::V1 => {
                    if 1 != EVP_marshal_private_key(cbb.as_mut_ptr(), **self) {
                        return Err(Unspecified);
                    }
                }
                Version::V2 => {
                    if 1 != EVP_marshal_private_key_v2(cbb.as_mut_ptr(), **self) {
                        return Err(Unspecified);
                    }
                }
            }

            let mut pkcs8_bytes_ptr = MaybeUninit::<*mut u8>::uninit();
            let mut out_len = MaybeUninit::<usize>::uninit();
            if 1 != CBB_finish(
                cbb.as_mut_ptr(),
                pkcs8_bytes_ptr.as_mut_ptr(),
                out_len.as_mut_ptr(),
            ) {
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
}
