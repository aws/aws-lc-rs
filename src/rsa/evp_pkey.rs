/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 */

use crate::digest;
use crate::error::{KeyRejected, Unspecified};
use aws_lc_sys::{EVP_PKEY, EVP_PKEY_CTX};
use std::os::raw::{c_int, c_uint};
use std::ptr::null_mut;

use crate::ptr::{LcPtr, NonNullPtr};

#[inline]
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_CTX_verify(
    algorithm: &'static digest::Algorithm,
    rsa_padding: Option<i32>,
    msg: &[u8],
    signature: &[u8],
    evp_pkey_ctx: NonNullPtr<*mut EVP_PKEY_CTX>,
) -> Result<(), Unspecified> {
    if 1 != aws_lc_sys::EVP_PKEY_verify_init(*evp_pkey_ctx) {
        return Err(Unspecified);
    }

    let digest = digest::digest(algorithm, msg);
    let digest = digest.as_ref();

    if let Some(padding) = rsa_padding {
        if 1 != aws_lc_sys::EVP_PKEY_CTX_set_rsa_padding(*evp_pkey_ctx, padding) {
            return Err(Unspecified);
        }
    }

    let evp_md = digest::match_digest_type(&algorithm.id);
    if 1 != aws_lc_sys::EVP_PKEY_CTX_set_signature_md(*evp_pkey_ctx, evp_md) {
        return Err(Unspecified);
    }

    if 1 != aws_lc_sys::EVP_PKEY_verify(
        *evp_pkey_ctx,
        signature.as_ptr(),
        signature.len(),
        digest.as_ptr(),
        digest.len(),
    ) {
        return Err(Unspecified);
    }
    Ok(())
}

#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn build_EVP_PKEY_CTX(
    evp_pkey: NonNullPtr<*mut EVP_PKEY>,
) -> Result<LcPtr<*mut EVP_PKEY_CTX>, Unspecified> {
    let evp_pkey_ctx =
        LcPtr::new(aws_lc_sys::EVP_PKEY_CTX_new(*evp_pkey, null_mut())).map_err(|_| Unspecified)?;
    Ok(evp_pkey_ctx)
}

#[inline]
pub(crate) unsafe fn validate_pkey(
    evp_pkey: NonNullPtr<*mut EVP_PKEY>,
    expected_key_type: c_int,
    min_pkey_bits: c_uint,
    max_pkey_bits: c_uint,
) -> Result<(), KeyRejected> {
    let key_type = aws_lc_sys::EVP_PKEY_id(*evp_pkey);
    if key_type != expected_key_type {
        return Err(KeyRejected::wrong_algorithm());
    }

    let bits = aws_lc_sys::EVP_PKEY_bits(*evp_pkey);
    let bits = bits as c_uint;
    if bits < min_pkey_bits {
        return Err(KeyRejected::too_small());
    }

    if bits > max_pkey_bits {
        return Err(KeyRejected::too_large());
    }
    Ok(())
}
