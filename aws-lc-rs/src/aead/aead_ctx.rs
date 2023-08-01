// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::TAG_LEN;
use crate::cipher::chacha;

use crate::cipher::aes::{AES_128_KEY_LEN, AES_256_KEY_LEN};
use crate::error::Unspecified;
use crate::ptr::LcPtr;
use aws_lc::{
    EVP_AEAD_CTX_new, EVP_aead_aes_128_gcm, EVP_aead_aes_256_gcm, EVP_aead_aes_256_gcm_siv,
    EVP_aead_chacha20_poly1305, EVP_AEAD_CTX,
};

#[allow(
    clippy::large_enum_variant,
    variant_size_differences,
    non_camel_case_types
)]
pub(crate) enum AeadCtx {
    AES_128_GCM(LcPtr<EVP_AEAD_CTX>),
    AES_256_GCM(LcPtr<EVP_AEAD_CTX>),
    AES_256_GCM_SIV(LcPtr<EVP_AEAD_CTX>),
    CHACHA20_POLY1305(LcPtr<EVP_AEAD_CTX>),
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

    pub(crate) fn aes_256_gcm_siv(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if AES_256_KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        Ok(AeadCtx::AES_256_GCM_SIV(AeadCtx::build_context(
            EVP_aead_aes_256_gcm_siv,
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
    ) -> Result<LcPtr<EVP_AEAD_CTX>, Unspecified> {
        let aead = unsafe { aead_fn() };

        let aead_ctx = unsafe {
            LcPtr::new(EVP_AEAD_CTX_new(
                aead,
                key_bytes.as_ptr(),
                key_bytes.len(),
                TAG_LEN,
            ))?
        };

        Ok(aead_ctx)
    }
}
