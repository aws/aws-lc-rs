// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cbb::LcCBB;
use crate::cbs;
use crate::ec::PKCS8_DOCUMENT_MAX_LEN;
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::Version;
use crate::ptr::LcPtr;
use aws_lc::{
    EVP_PKEY_CTX_new, EVP_PKEY_bits, EVP_PKEY_get1_EC_KEY, EVP_PKEY_get1_RSA, EVP_PKEY_id,
    EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_private_key_v2, EVP_parse_private_key,
    EC_KEY, EVP_PKEY, EVP_PKEY_CTX, RSA,
};
// TODO: Uncomment when MSRV >= 1.64
// use core::ffi::c_int;
use std::os::raw::c_int;
use std::ptr::null_mut;

impl TryFrom<&[u8]> for LcPtr<EVP_PKEY> {
    type Error = KeyRejected;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let mut cbs = cbs::build_CBS(bytes);
            // `EVP_parse_private_key` -> ... -> `eckey_priv_decode` -> ... -> `EC_KEY_check_key`
            LcPtr::new(EVP_parse_private_key(&mut cbs))
                .map_err(|()| KeyRejected::invalid_encoding())
        }
    }
}

impl LcPtr<EVP_PKEY> {
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
        unsafe { EVP_PKEY_id(*self.as_const()) }
    }

    pub(crate) fn bits(&self) -> i32 {
        unsafe { EVP_PKEY_bits(*self.as_const()) }
    }

    #[allow(dead_code)]
    pub(crate) fn get_ec_key(&self) -> Result<LcPtr<EC_KEY>, KeyRejected> {
        unsafe {
            LcPtr::new(EVP_PKEY_get1_EC_KEY(*self.as_const()))
                .map_err(|()| KeyRejected::wrong_algorithm())
        }
    }

    pub(crate) fn get_rsa(&self) -> Result<LcPtr<RSA>, KeyRejected> {
        unsafe {
            LcPtr::new(EVP_PKEY_get1_RSA(*self.as_const()))
                .map_err(|()| KeyRejected::wrong_algorithm())
        }
    }

    pub(crate) fn marshall_private_key(&self, version: Version) -> Result<Box<[u8]>, Unspecified> {
        let mut buffer = vec![0u8; PKCS8_DOCUMENT_MAX_LEN];

        let out_len = {
            let mut cbb = LcCBB::new_fixed(<&mut [u8; PKCS8_DOCUMENT_MAX_LEN]>::try_from(
                buffer.as_mut_slice(),
            )?);

            match version {
                Version::V1 => {
                    if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *self.as_const()) } {
                        return Err(Unspecified);
                    }
                }
                Version::V2 => {
                    if 1 != unsafe {
                        EVP_marshal_private_key_v2(cbb.as_mut_ptr(), *self.as_const())
                    } {
                        return Err(Unspecified);
                    }
                }
            }
            cbb.finish()?
        };

        buffer.truncate(out_len);

        Ok(buffer.into_boxed_slice())
    }

    #[allow(non_snake_case)]
    pub(crate) fn create_EVP_PKEY_CTX(&self) -> Result<LcPtr<EVP_PKEY_CTX>, ()> {
        // The only modification made by EVP_PKEY_CTX_new to `priv_key` is to increment its
        // refcount. The modification is made while holding a global lock:
        // https://github.com/aws/aws-lc/blob/61503f7fe72457e12d3446853a5452d175560c49/crypto/refcount_lock.c#L29
        LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.as_mut_unsafe(), null_mut()) })
    }
}

impl Clone for LcPtr<EVP_PKEY> {
    fn clone(&self) -> Self {
        // EVP_PKEY_up_ref increments the refcount while holding a global lock:
        // https://github.com/aws/aws-lc/blob/61503f7fe72457e12d3446853a5452d175560c49/crypto/refcount_lock.c#L29
        assert_eq!(
            1,
            unsafe { EVP_PKEY_up_ref(*self.as_mut_unsafe()) },
            "infallible AWS-LC function"
        );
        Self::new(unsafe { *self.as_mut_unsafe() }).expect("non-null AWS-LC EVP_PKEY pointer")
    }
}
