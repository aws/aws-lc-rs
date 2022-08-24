// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::block::BLOCK_LEN;
use crate::aead::{block::Block, counter, error, quic::Sample};
use aws_lc_sys::{EVP_CIPHER, EVP_CIPHER_CTX};
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::ptr;
use std::ptr::{null, null_mut};
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128(
        [u8; 16],
        *const aws_lc_sys::EVP_CIPHER,
        *const aws_lc_sys::EVP_CIPHER,
        *mut aws_lc_sys::EVP_CIPHER_CTX,
    ),
    Aes256(
        [u8; 32],
        *const aws_lc_sys::EVP_CIPHER,
        *const aws_lc_sys::EVP_CIPHER,
        *mut aws_lc_sys::EVP_CIPHER_CTX,
    ),
    ChaCha20([u8; 32]),
}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        match self {
            SymmetricCipherKey::Aes128(key_bytes, .., ctx) => {
                unsafe {
                    aws_lc_sys::EVP_CIPHER_CTX_free(*ctx);
                }
                key_bytes.zeroize();
            }
            SymmetricCipherKey::Aes256(key_bytes, .., ctx) => {
                unsafe {
                    aws_lc_sys::EVP_CIPHER_CTX_free(*ctx);
                }
                key_bytes.zeroize();
            }
            SymmetricCipherKey::ChaCha20(key_bytes) => {
                key_bytes.zeroize();
            }
        }
    }
}

impl SymmetricCipherKey {
    pub fn aes128(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        if key_bytes.len() != 16 {
            return Err(error::Unspecified);
        }

        let mut kb = MaybeUninit::<[u8; 16]>::uninit();
        unsafe {
            let ecb_cipher = aws_lc_sys::EVP_aes_128_ecb();
            let gcm_cipher = aws_lc_sys::EVP_aes_128_gcm();
            let gcm_cipher_ctx = aws_lc_sys::EVP_CIPHER_CTX_new();
            if gcm_cipher_ctx.is_null() {
                return Err(error::Unspecified);
            }
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes128(
                kb.assume_init(),
                ecb_cipher,
                gcm_cipher,
                gcm_cipher_ctx,
            ))
        }
    }

    pub fn aes256(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        if key_bytes.len() != 32 {
            return Err(error::Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            let ecb_cipher = aws_lc_sys::EVP_aes_256_ecb();
            let gcm_cipher = aws_lc_sys::EVP_aes_256_gcm();
            let cipher_ctx = aws_lc_sys::EVP_CIPHER_CTX_new();
            if cipher_ctx.is_null() {
                return Err(error::Unspecified);
            }
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256(
                kb.assume_init(),
                ecb_cipher,
                gcm_cipher,
                cipher_ctx,
            ))
        }
    }

    pub fn chacha20(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        if key_bytes.len() != 32 {
            return Err(error::Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::ChaCha20(kb.assume_init()))
        }
    }

    pub fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::Aes128(bytes, ..) => bytes,
            SymmetricCipherKey::Aes256(bytes, ..) => bytes,
            SymmetricCipherKey::ChaCha20(bytes) => bytes,
        }
    }

    pub fn key_size_bits(&self) -> usize {
        match self {
            SymmetricCipherKey::Aes128(..) => 128,
            SymmetricCipherKey::Aes256(..) => 256,
            SymmetricCipherKey::ChaCha20(..) => 256,
        }
    }

    pub fn new_mask(&self, sample: Sample) -> Result<[u8; 5], error::Unspecified> {
        let block = Block::from(&sample);

        let encrypted_block = match self {
            SymmetricCipherKey::Aes128(key_bytes, ecb_cipher, _, ctx) => {
                encrypt_block_aes_ecb(key_bytes.as_slice(), *ecb_cipher, *ctx, block)?
            }
            SymmetricCipherKey::Aes256(key_bytes, ecb_cipher, _, ctx) => {
                encrypt_block_aes_ecb(key_bytes.as_slice(), *ecb_cipher, *ctx, block)?
            }
            SymmetricCipherKey::ChaCha20(key_bytes) => {
                let plaintext = block.as_ref();
                let counter_bytes: &[u8; 4] = plaintext[0..=3].try_into()?;
                let nonce: &[u8; 12] = plaintext[4..=15].try_into()?;
                let input = Block::zero();
                unsafe {
                    let counter = std::mem::transmute::<[u8; 4], u32>(*counter_bytes).to_le();
                    encrypt_block_chacha20(key_bytes, input, nonce, counter)?
                }
            }
        };

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&encrypted_block.as_ref()[..5]);

        Ok(out)
    }

    pub fn encrypt_block(&self, block: Block) -> Result<Block, error::Unspecified> {
        match self {
            SymmetricCipherKey::Aes128(key_bytes, ecb_cipher, _, ctx) => {
                encrypt_block_aes_ecb(key_bytes.as_slice(), *ecb_cipher, *ctx, block)
            }
            SymmetricCipherKey::Aes256(key_bytes, ecb_cipher, _, ctx) => {
                encrypt_block_aes_ecb(key_bytes.as_slice(), *ecb_cipher, *ctx, block)
            }
            _ => panic!("Unsupported algorithm!"),
        }
    }
}

#[inline]
fn encrypt_block_aes_ecb(
    key_bytes: &[u8],
    cipher: *const EVP_CIPHER,
    ctx: *mut EVP_CIPHER_CTX,
    block: Block,
) -> Result<Block, error::Unspecified> {
    unsafe {
        if 1 != aws_lc_sys::EVP_EncryptInit_ex(ctx, cipher, null_mut(), key_bytes.as_ptr(), null())
        {
            return Err(error::Unspecified);
        }

        let mut out_len = MaybeUninit::<c_int>::uninit();
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit();
        let plain_bytes = block.as_ref();
        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            ctx,
            cipher_text.as_mut_ptr().cast(),
            out_len.as_mut_ptr(),
            plain_bytes.as_ptr(),
            BLOCK_LEN as c_int,
        ) {
            return Err(error::Unspecified);
        }
        let olen = out_len.assume_init() as usize;
        if olen != BLOCK_LEN {
            return Err(error::Unspecified);
        }

        let mut ctext = cipher_text.assume_init();
        if 1 != aws_lc_sys::EVP_EncryptFinal_ex(
            ctx,
            ctext[BLOCK_LEN..].as_mut_ptr(),
            out_len.as_mut_ptr(),
        ) {
            return Err(error::Unspecified);
        }

        Ok(Block::from(&ctext))
    }
}

#[inline]
fn encrypt_block_chacha20(
    key_bytes: &[u8],
    block: Block,
    nonce: &[u8; 12],
    counter: u32,
) -> Result<Block, error::Unspecified> {
    unsafe {
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit();
        let plaintext = block.as_ref();

        // This function can't fail?
        aws_lc_sys::CRYPTO_chacha_20(
            cipher_text.as_mut_ptr().cast(),
            plaintext.as_ptr(),
            BLOCK_LEN,
            key_bytes.as_ptr(),
            nonce.as_ptr(),
            counter,
        );

        Ok(Block::from(&cipher_text.assume_init()))
    }
}
