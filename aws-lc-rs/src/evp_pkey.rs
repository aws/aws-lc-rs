// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aws_lc::{
    EVP_PKEY_CTX_new, EVP_PKEY_bits, EVP_PKEY_get1_EC_KEY, EVP_PKEY_get1_RSA, EVP_PKEY_id,
    EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_private_key_v2, EVP_marshal_public_key,
    EVP_parse_private_key, EVP_parse_public_key, EC_KEY, EVP_PKEY, EVP_PKEY_CTX, RSA,
};
use crate::cbb::LcCBB;
use crate::cbs;
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::Version;
use crate::ptr::LcPtr;
// TODO: Uncomment when MSRV >= 1.64
// use core::ffi::c_int;
use std::os::raw::c_int;
use std::ptr::null_mut;

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

    pub(crate) fn marshall_rfc5280_public_key(&self) -> Result<Vec<u8>, Unspecified> {
        let key_size_bytes: usize = unsafe { EVP_PKEY_bits(*self.as_const()) / 8 }.try_into()?;
        // Data shows that the SubjectPublicKeyInfo is roughly 356% to 375% increase in size compared to the RSA key
        // size in bytes for keys ranging from 2048-bit to 4096-bit. So size the initial capacity to be roughly
        // 500% as a conservative estimate to avoid needing to reallocate for any key in that range.
        let mut cbb = LcCBB::new(key_size_bytes * 5);
        if 1 != unsafe { EVP_marshal_public_key(cbb.as_mut_ptr(), *self.as_const()) } {
            return Err(Unspecified);
        };
        cbb.into_vec()
    }

    pub(crate) fn parse_rfc5280_public_key(
        bytes: &[u8],
        evp_pkey_type: c_int,
    ) -> Result<Self, KeyRejected> {
        let mut cbs = cbs::build_CBS(bytes);
        // Also checks the validity of the key
        let evp_pkey = LcPtr::new(unsafe { EVP_parse_public_key(&mut cbs) })
            .map_err(|()| KeyRejected::invalid_encoding())?;
        unsafe { EVP_PKEY_id(*evp_pkey.as_const()) }
            .eq(&evp_pkey_type)
            .then_some(evp_pkey)
            .ok_or(KeyRejected::wrong_algorithm())
    }

    pub(crate) fn marshall_rfc5208_private_key(
        &self,
        version: Version,
    ) -> Result<Vec<u8>, Unspecified> {
        let key_size_bytes = TryInto::<usize>::try_into(unsafe { EVP_PKEY_bits(*self.as_const()) })
            .expect("fit in usize")
            / 8;
        let mut cbb = LcCBB::new(key_size_bytes * 5);
        match version {
            Version::V1 => {
                if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *self.as_const()) } {
                    return Err(Unspecified);
                }
            }
            Version::V2 => {
                if 1 != unsafe { EVP_marshal_private_key_v2(cbb.as_mut_ptr(), *self.as_const()) } {
                    return Err(Unspecified);
                }
            }
        }
        cbb.into_vec()
    }

    pub(crate) fn parse_rfc5208_private_key(
        bytes: &[u8],
        evp_pkey_type: c_int,
    ) -> Result<Self, KeyRejected> {
        let mut cbs = cbs::build_CBS(bytes);
        // Also checks the validity of the key
        let evp_pkey = LcPtr::new(unsafe { EVP_parse_private_key(&mut cbs) })
            .map_err(|()| KeyRejected::invalid_encoding())?;
        unsafe { EVP_PKEY_id(*evp_pkey.as_const()) }
            .eq(&evp_pkey_type)
            .then_some(evp_pkey)
            .ok_or(KeyRejected::wrong_algorithm())
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
