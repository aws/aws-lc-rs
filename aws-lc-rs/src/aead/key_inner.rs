// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::TAG_LEN;
use crate::cipher::SymmetricCipherKey;
use crate::error;

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
pub(crate) enum KeyInner {
    AES_128_GCM(SymmetricCipherKey, EVP_AEAD_CTX),
    AES_256_GCM(SymmetricCipherKey, EVP_AEAD_CTX),
    CHACHA20_POLY1305(SymmetricCipherKey, EVP_AEAD_CTX),
}

unsafe impl Send for KeyInner {}
unsafe impl Sync for KeyInner {}

impl KeyInner {
    pub(crate) fn new(key: SymmetricCipherKey) -> Result<KeyInner, error::Unspecified> {
        unsafe {
            match key {
                SymmetricCipherKey::Aes128 { .. } => {
                    let aead = EVP_aead_aes_128_gcm();
                    let mut aead_ctx = MaybeUninit::<EVP_AEAD_CTX>::uninit();

                    if 1 != EVP_AEAD_CTX_init(
                        aead_ctx.as_mut_ptr(),
                        aead,
                        key.key_bytes().as_ptr().cast(),
                        key.key_bytes().len(),
                        TAG_LEN,
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    }
                    Ok(KeyInner::AES_128_GCM(key, aead_ctx.assume_init()))
                }
                SymmetricCipherKey::Aes256 { .. } => {
                    let aead = EVP_aead_aes_256_gcm();
                    let mut aead_ctx = MaybeUninit::<EVP_AEAD_CTX>::uninit();

                    if 1 != EVP_AEAD_CTX_init(
                        aead_ctx.as_mut_ptr(),
                        aead,
                        key.key_bytes().as_ptr().cast(),
                        key.key_bytes().len(),
                        TAG_LEN,
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    }
                    Ok(KeyInner::AES_256_GCM(key, aead_ctx.assume_init()))
                }
                SymmetricCipherKey::ChaCha20 { .. } => {
                    let aead = EVP_aead_chacha20_poly1305();
                    let mut aead_ctx = MaybeUninit::<EVP_AEAD_CTX>::uninit();

                    if 1 != EVP_AEAD_CTX_init(
                        aead_ctx.as_mut_ptr(),
                        aead,
                        key.key_bytes().as_ptr().cast(),
                        key.key_bytes().len(),
                        TAG_LEN,
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    }
                    Ok(KeyInner::CHACHA20_POLY1305(key, aead_ctx.assume_init()))
                }
            }
        }
    }

    #[inline]
    pub(crate) fn cipher_key(&self) -> &SymmetricCipherKey {
        match self {
            KeyInner::AES_128_GCM(cipher_key, ..)
            | KeyInner::AES_256_GCM(cipher_key, ..)
            | KeyInner::CHACHA20_POLY1305(cipher_key, ..) => cipher_key,
        }
    }
}

impl Drop for KeyInner {
    fn drop(&mut self) {
        unsafe {
            let ctx = match self {
                KeyInner::AES_128_GCM(.., ctx)
                | KeyInner::AES_256_GCM(.., ctx)
                | KeyInner::CHACHA20_POLY1305(.., ctx) => ctx,
            };
            EVP_AEAD_CTX_cleanup(ctx);
            EVP_AEAD_CTX_zero(ctx);
        }
    }
}
