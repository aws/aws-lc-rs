// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::{error, Aad, Algorithm, AlgorithmID, Nonce, Tag, TAG_LEN};
use std::cmp::min;
use std::mem::MaybeUninit;
use std::os::raw::c_int;

use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::key_inner::KeyInner;
use std::ptr::{null, null_mut};

const CHUNK_SIZE: usize = 4096;

#[inline]
pub(crate) fn aes_gcm_seal_separate(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    unsafe {
        let gcm_ctx = match key.cipher_key() {
            SymmetricCipherKey::Aes128(.., gcm_ctx) => gcm_ctx,
            SymmetricCipherKey::Aes256(.., gcm_ctx) => gcm_ctx,
            _ => panic!("Unsupport algorithm"),
        };

        let nonce = nonce.as_ref();

        if 1 != aws_lc_sys::EVP_EncryptInit_ex(
            **gcm_ctx,
            null(),
            null_mut(),
            null(),
            nonce.as_ptr(),
        ) {
            return Err(error::Unspecified);
        }

        let aad_str = aad.0;
        let mut out_len = MaybeUninit::<c_int>::uninit();
        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            **gcm_ctx,
            null_mut(),
            out_len.as_mut_ptr(),
            aad_str.as_ptr(),
            aad_str.len() as c_int,
        ) {
            return Err(error::Unspecified);
        }

        let mut cipher_text = MaybeUninit::<[u8; CHUNK_SIZE]>::uninit();

        let mut pos = 0;
        let plaintext_len = in_out.len();
        while pos < plaintext_len {
            let in_len = min(plaintext_len - pos, CHUNK_SIZE);
            let next_plain_chunk = &in_out[pos..(pos + in_len)];
            if 1 != aws_lc_sys::EVP_EncryptUpdate(
                **gcm_ctx,
                cipher_text.as_mut_ptr().cast(),
                out_len.as_mut_ptr(),
                next_plain_chunk.as_ptr(),
                in_len as c_int,
            ) {
                return Err(error::Unspecified);
            }
            let olen = out_len.assume_init() as usize;
            let ctext = cipher_text.assume_init();
            let next_cipher_chunk = &mut in_out[pos..(pos + olen)];
            next_cipher_chunk.copy_from_slice(&ctext[0..olen]);
            pos += olen;
        }
        if 1 != aws_lc_sys::EVP_EncryptFinal_ex(**gcm_ctx, null_mut(), out_len.as_mut_ptr()) {
            return Err(error::Unspecified);
        }

        let mut inner_tag = MaybeUninit::<[u8; TAG_LEN]>::uninit();
        aws_lc_sys::EVP_CIPHER_CTX_ctrl(
            **gcm_ctx,
            aws_lc_sys::EVP_CTRL_GCM_GET_TAG,
            TAG_LEN as c_int,
            inner_tag.as_mut_ptr().cast(),
        );

        Ok(Tag(inner_tag.assume_init()))
    }
}
/*
#[inline]
pub(crate) fn aes_gcm_open_combined(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(), error::Unspecified> {
    let (aes_key, cipher, ctx) = match key {
        KeyInner::AES_128_GCM(aes_key, cipher, ctx, ..) => (aes_key, cipher, ctx),
        KeyInner::AES_256_GCM(aes_key, cipher, ctx, ..) => (aes_key, cipher, ctx),
        _ => panic!("Unsupported algorithm"),
    };
    debug_assert!(TAG_LEN <= in_out.len());
    unsafe {
        let tag_iv = Counter::one(nonce)
            .increment()
            .into_bytes_less_safe()
            .as_ptr();
        if 1 != aws_lc_sys::EVP_DecryptInit_ex(
            *ctx,
            *cipher,
            null_mut(),
            aes_key.key_bytes().as_ptr(),
            tag_iv,
        ) {
            return Err(error::Unspecified);
        }

        let aad_str = aad.0;
        let mut out_len = MaybeUninit::<c_int>::uninit();
        if 1 != aws_lc_sys::EVP_DecryptUpdate(
            *ctx,
            null_mut(),
            out_len.as_mut_ptr(),
            aad_str.as_ptr(),
            aad_str.len() as c_int,
        ) {
            return Err(error::Unspecified);
        }

        let mut plain_text = MaybeUninit::<[u8; CHUNK_SIZE]>::uninit();

        let mut pos = 0;
        let ciphertext_len = in_out.len() - TAG_LEN;
        while pos < ciphertext_len {
            let in_len = min(ciphertext_len - pos, CHUNK_SIZE);
            let next_cipher_chunk = &in_out[pos..(pos + in_len)];
            if 1 != aws_lc_sys::EVP_DecryptUpdate(
                *ctx,
                plain_text.as_mut_ptr().cast(),
                out_len.as_mut_ptr(),
                next_cipher_chunk.as_ptr(),
                in_len as c_int,
            ) {
                return Err(error::Unspecified);
            }
            let olen = out_len.assume_init() as usize;
            let ptext = plain_text.assume_init();
            let next_cipher_chunk = &mut in_out[pos..(pos + olen)];
            next_cipher_chunk.copy_from_slice(&ptext[0..olen]);
            pos += olen;
        }
        if 1 != aws_lc_sys::EVP_CIPHER_CTX_ctrl(
            *ctx,
            aws_lc_sys::EVP_CTRL_GCM_SET_TAG,
            TAG_LEN as c_int,
            in_out[ciphertext_len..].as_mut_ptr().cast(),
        ) {
            return Err(error::Unspecified);
        }
        let retval = aws_lc_sys::EVP_DecryptFinal_ex(*ctx, null_mut(), out_len.as_mut_ptr());
        if 1 != retval {
            eprintln!("EVP_DecryptFinal_ex Error: {}", retval);
            return Err(error::Unspecified);
        }
    }
    Ok(())
}
*/

pub static AES_128_GCM: Algorithm = Algorithm {
    init: init_128,
    key_len: 16,
    id: AlgorithmID::AES_128_GCM,
    max_input_len: u64::MAX,
};

pub static AES_256_GCM: Algorithm = Algorithm {
    init: init_256,
    key_len: 32,
    id: AlgorithmID::AES_256_GCM,
    max_input_len: u64::MAX,
};

fn init_128(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    init_aes_gcm(key, AlgorithmID::AES_128_GCM)
}

fn init_256(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    init_aes_gcm(key, AlgorithmID::AES_256_GCM)
}

fn init_aes_gcm(key: &[u8], id: AlgorithmID) -> Result<KeyInner, error::Unspecified> {
    match id {
        AlgorithmID::AES_128_GCM => KeyInner::new(SymmetricCipherKey::aes128(key)?),
        AlgorithmID::AES_256_GCM => KeyInner::new(SymmetricCipherKey::aes256(key)?),
        _ => panic!("Unrecognized algorithm: {:?}", id),
    }
}
