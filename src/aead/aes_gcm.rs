// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::{counter, error, Aad, Algorithm, AlgorithmID, KeyInner, Nonce, Tag, TAG_LEN};
use std::cmp::min;
use std::mem::MaybeUninit;
use std::os::raw::c_int;

use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::iv::IV_LEN;
use crate::endian::BigEndian;
use std::ptr::null_mut;

pub type Counter = counter::Counter<BigEndian<u32>>;

fn aes_gcm_seal(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    unsafe {
        let (aes_key, cipher, ctx) = match key {
            KeyInner::AES_128_GCM(aes_key, cipher, ctx) => (aes_key, cipher, ctx),
            KeyInner::AES_256_GCM(aes_key, cipher, ctx) => (aes_key, cipher, ctx),
        };

        if 1 != aws_lc_sys::EVP_EncryptInit_ex(*ctx, *cipher, null_mut(), null_mut(), null_mut()) {
            return Err(error::Unspecified);
        }

        if 1 != aws_lc_sys::EVP_CIPHER_CTX_ctrl(
            *ctx,
            aws_lc_sys::EVP_CTRL_GCM_SET_IVLEN,
            IV_LEN as c_int,
            null_mut(),
        ) {
            return Err(error::Unspecified);
        }

        let tag_iv = Counter::one(nonce)
            .increment()
            .into_bytes_less_safe()
            .as_ptr();
        if 1 != aws_lc_sys::EVP_EncryptInit_ex(
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
        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            *ctx,
            null_mut(),
            out_len.as_mut_ptr(),
            aad_str.as_ptr(),
            aad_str.len() as c_int,
        ) {
            return Err(error::Unspecified);
        }

        const CHUNK_SIZE: usize = 96;
        let mut cipher_text = MaybeUninit::<[u8; CHUNK_SIZE]>::uninit();

        let mut pos = 0;
        let plaintext_len = in_out.len();
        while pos < plaintext_len {
            let in_len = min(plaintext_len - pos, CHUNK_SIZE);
            let next_plain_chunk = &in_out[pos..(pos + in_len)];
            if 1 != aws_lc_sys::EVP_EncryptUpdate(
                *ctx,
                cipher_text.as_mut_ptr().cast(),
                out_len.as_mut_ptr(),
                next_plain_chunk.as_ptr(),
                in_len as c_int,
            ) {
                return Err(error::Unspecified);
            }
            let olen = out_len.assume_init() as usize;
            let ctext = cipher_text.assume_init();
            let mut next_cipher_chunk = &mut in_out[pos..(pos + olen)];
            next_cipher_chunk.copy_from_slice(&ctext[0..olen]);
            pos += olen;
        }
        if 1 != aws_lc_sys::EVP_EncryptFinal_ex(*ctx, null_mut(), out_len.as_mut_ptr()) {
            return Err(error::Unspecified);
        }

        let mut inner_tag = MaybeUninit::<[u8; TAG_LEN]>::uninit();
        aws_lc_sys::EVP_CIPHER_CTX_ctrl(
            *ctx,
            aws_lc_sys::EVP_CTRL_GCM_GET_TAG,
            TAG_LEN as c_int,
            inner_tag.as_mut_ptr().cast(),
        );

        Ok(Tag(inner_tag.assume_init()))
    }
}

fn aes_gcm_open(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    received_tag: &[u8],
) -> Result<(), error::Unspecified> {
    let (aes_key, cipher, ctx) = match key {
        KeyInner::AES_128_GCM(aes_key, cipher, ctx) => (aes_key, cipher, ctx),
        KeyInner::AES_256_GCM(aes_key, cipher, ctx) => (aes_key, cipher, ctx),
    };
    debug_assert_eq!(TAG_LEN, received_tag.len());
    unsafe {
        if 1 != aws_lc_sys::EVP_DecryptInit_ex(*ctx, *cipher, null_mut(), null_mut(), null_mut()) {
            return Err(error::Unspecified);
        }

        if 1 != aws_lc_sys::EVP_CIPHER_CTX_ctrl(
            *ctx,
            aws_lc_sys::EVP_CTRL_GCM_SET_IVLEN,
            IV_LEN as c_int,
            null_mut(),
        ) {
            return Err(error::Unspecified);
        }

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

        const CHUNK_SIZE: usize = 96;
        let mut plain_text = MaybeUninit::<[u8; CHUNK_SIZE]>::uninit();

        let mut pos = 0;
        let ciphertext_len = in_out.len();
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
        let mut inner_tag = [0u8; TAG_LEN];
        inner_tag.copy_from_slice(received_tag);
        if 1 != aws_lc_sys::EVP_CIPHER_CTX_ctrl(
            *ctx,
            aws_lc_sys::EVP_CTRL_GCM_SET_TAG,
            TAG_LEN as c_int,
            inner_tag.as_mut_ptr().cast(),
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

pub static AES_128_GCM: Algorithm = Algorithm {
    init: init_128,
    key_len: 16,
    id: AlgorithmID::AES_128_GCM,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    max_input_len: u64::MAX,
};

pub static AES_256_GCM: Algorithm = Algorithm {
    init: init_256,
    key_len: 32,
    id: AlgorithmID::AES_256_GCM,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    max_input_len: u64::MAX,
};

fn init_128(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    return init_aes_gcm(key, AlgorithmID::AES_128_GCM);
}

fn init_256(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    return init_aes_gcm(key, AlgorithmID::AES_256_GCM);
}

fn init_aes_gcm(key: &[u8], id: AlgorithmID) -> Result<KeyInner, error::Unspecified> {
    match id {
        AlgorithmID::AES_128_GCM => KeyInner::new(SymmetricCipherKey::aes128(key)?),
        AlgorithmID::AES_256_GCM => KeyInner::new(SymmetricCipherKey::aes256(key)?),
    }
}
