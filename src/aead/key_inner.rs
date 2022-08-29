// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::TAG_LEN;
use crate::{error, init};

#[allow(
    clippy::large_enum_variant,
    variant_size_differences,
    non_camel_case_types
)]
pub(crate) enum KeyInner {
    AES_128_GCM(
        SymmetricCipherKey,
        *const aws_lc_sys::EVP_AEAD,
        *mut aws_lc_sys::EVP_AEAD_CTX,
    ),
    AES_256_GCM(
        SymmetricCipherKey,
        *const aws_lc_sys::EVP_AEAD,
        *mut aws_lc_sys::EVP_AEAD_CTX,
    ),
    CHACHA20_POLY1305(
        SymmetricCipherKey,
        *const aws_lc_sys::EVP_AEAD,
        *mut aws_lc_sys::EVP_AEAD_CTX,
    ),
}

impl KeyInner {
    pub(crate) fn new(key: SymmetricCipherKey) -> Result<KeyInner, error::Unspecified> {
        unsafe {
            init();
            match key {
                SymmetricCipherKey::Aes128(..) => {
                    let aead = aws_lc_sys::EVP_aead_aes_128_gcm();
                    let aead_ctx = aws_lc_sys::EVP_AEAD_CTX_new(
                        aead,
                        key.key_bytes().as_ptr().cast(),
                        key.key_bytes().len(),
                        TAG_LEN,
                    );
                    if aead_ctx.is_null() {
                        return Err(error::Unspecified);
                    }
                    Ok(KeyInner::AES_128_GCM(key, aead, aead_ctx))
                }
                SymmetricCipherKey::Aes256(..) => {
                    let aead = aws_lc_sys::EVP_aead_aes_256_gcm();
                    let aead_ctx = aws_lc_sys::EVP_AEAD_CTX_new(
                        aead,
                        key.key_bytes().as_ptr().cast(),
                        key.key_bytes().len(),
                        TAG_LEN,
                    );
                    if aead_ctx.is_null() {
                        return Err(error::Unspecified);
                    }
                    Ok(KeyInner::AES_256_GCM(key, aead, aead_ctx))
                }
                SymmetricCipherKey::ChaCha20(..) => {
                    let aead = aws_lc_sys::EVP_aead_chacha20_poly1305();
                    let aead_ctx = aws_lc_sys::EVP_AEAD_CTX_new(
                        aead,
                        key.key_bytes().as_ptr().cast(),
                        key.key_bytes().len(),
                        TAG_LEN,
                    );
                    if aead_ctx.is_null() {
                        return Err(error::Unspecified);
                    }
                    Ok(KeyInner::CHACHA20_POLY1305(key, aead, aead_ctx))
                }
            }
        }
    }

    pub(crate) fn cipher_key(&self) -> &SymmetricCipherKey {
        match self {
            KeyInner::AES_128_GCM(cipher_key, ..) => cipher_key,
            KeyInner::AES_256_GCM(cipher_key, ..) => cipher_key,
            KeyInner::CHACHA20_POLY1305(cipher_key, ..) => cipher_key,
        }
    }
}

impl Drop for KeyInner {
    fn drop(&mut self) {
        unsafe {
            match self {
                KeyInner::AES_128_GCM(.., ctx) => aws_lc_sys::EVP_AEAD_CTX_free(*ctx),
                KeyInner::AES_256_GCM(.., ctx) => aws_lc_sys::EVP_AEAD_CTX_free(*ctx),
                KeyInner::CHACHA20_POLY1305(.., ctx) => aws_lc_sys::EVP_AEAD_CTX_free(*ctx),
            }
        }
    }
}
