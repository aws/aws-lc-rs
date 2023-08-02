// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::TAG_LEN;
use crate::cipher::chacha;

use crate::cipher::aes::{AES_128_KEY_LEN, AES_256_KEY_LEN};
use crate::error::Unspecified;
use aws_lc::{
    EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_init, EVP_AEAD_CTX_zero, EVP_aead_aes_128_gcm,
    EVP_aead_aes_256_gcm, EVP_aead_chacha20_poly1305, EVP_AEAD_CTX,
};
use std::mem::MaybeUninit;
use std::ptr::null_mut;

#[allow(
    clippy::large_enum_variant,
    variant_size_differences,
    non_camel_case_types
)]
pub(crate) enum AeadCtx {
    AES_128_GCM(EVP_AEAD_CTX),
    AES_256_GCM(EVP_AEAD_CTX),
    CHACHA20_POLY1305(EVP_AEAD_CTX),
}

unsafe impl Send for AeadCtx {}
unsafe impl Sync for AeadCtx {}

impl AeadCtx {
    pub(crate) fn aes_128_gcm(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if AES_128_KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        Ok(AeadCtx::AES_128_GCM(AeadCtx::build_context(
            EVP_aead_aes_128_gcm,
            key_bytes,
        )?))
    }

    pub(crate) fn aes_256_gcm(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if AES_256_KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        Ok(AeadCtx::AES_256_GCM(AeadCtx::build_context(
            EVP_aead_aes_256_gcm,
            key_bytes,
        )?))
    }

    pub(crate) fn chacha20(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if chacha::KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        Ok(AeadCtx::CHACHA20_POLY1305(AeadCtx::build_context(
            EVP_aead_chacha20_poly1305,
            key_bytes,
        )?))
    }

    fn build_context(
        aead_fn: unsafe extern "C" fn() -> *const aws_lc::evp_aead_st,
        key_bytes: &[u8],
    ) -> Result<EVP_AEAD_CTX, Unspecified> {
        let mut aead_ctx = MaybeUninit::<EVP_AEAD_CTX>::uninit();
        unsafe {
            let aead = aead_fn();

            if 1 != EVP_AEAD_CTX_init(
                aead_ctx.as_mut_ptr(),
                aead,
                key_bytes.as_ptr(),
                key_bytes.len(),
                TAG_LEN,
                null_mut(),
            ) {
                return Err(Unspecified);
            }
            Ok(aead_ctx.assume_init())
        }
    }
}

impl Drop for AeadCtx {
    fn drop(&mut self) {
        unsafe {
            let ctx = match self {
                AeadCtx::AES_128_GCM(ctx)
                | AeadCtx::AES_256_GCM(ctx)
                | AeadCtx::CHACHA20_POLY1305(ctx) => ctx,
            };
            EVP_AEAD_CTX_cleanup(ctx);
            EVP_AEAD_CTX_zero(ctx);
        }
    }
}
