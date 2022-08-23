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
use crate::aead::{block::Block, error, quic::Sample, KeyInner};
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::ptr;
use std::ptr::{null, null_mut};
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
    ChaCha20([u8; 32]),
}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        match self {
            SymmetricCipherKey::Aes128(key_bytes) => {
                key_bytes.zeroize();
            }
            SymmetricCipherKey::Aes256(key_bytes) => {
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
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes128(kb.assume_init()))
        }
    }

    pub fn aes256(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        if key_bytes.len() != 32 {
            return Err(error::Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256(kb.assume_init()))
        }
    }

    pub fn chacha20poly1305(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
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
            SymmetricCipherKey::Aes128(bytes) => bytes,
            SymmetricCipherKey::Aes256(bytes) => bytes,
            SymmetricCipherKey::ChaCha20(bytes) => bytes,
        }
    }

    pub fn key_size_bits(&self) -> usize {
        match self {
            SymmetricCipherKey::Aes128(_) => 128,
            SymmetricCipherKey::Aes256(_) => 256,
            SymmetricCipherKey::ChaCha20(_) => 256,
        }
    }

    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let block = self.encrypt_block(Block::from(&sample));

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&block.as_ref()[..5]);

        out
    }

    pub fn encrypt_block(&self, block: Block) -> Block {
        Block::zero()
    }
}

#[inline]
pub(crate) fn encrypt_block_evp(key: &KeyInner, block: Block) -> Result<Block, error::Unspecified> {
    unsafe {
        let (aes_key, cipher, ctx) = match key {
            KeyInner::AES_128_GCM(aes_key, cipher, ctx, ..) => (aes_key, cipher, ctx),
            KeyInner::AES_256_GCM(aes_key, cipher, ctx, ..) => (aes_key, cipher, ctx),
            _ => panic!("Unsupport algorithm"),
        };

        if 1 != aws_lc_sys::EVP_EncryptInit_ex(
            *ctx,
            *cipher,
            null_mut(),
            aes_key.key_bytes().as_ptr(),
            null(),
        ) {
            return Err(error::Unspecified);
        }

        let mut out_len = MaybeUninit::<c_int>::uninit();
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit();
        let plain_bytes = block.as_ref();

        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            *ctx,
            cipher_text.as_mut_ptr().cast(),
            out_len.as_mut_ptr(),
            plain_bytes.as_ptr(),
            BLOCK_LEN as c_int,
        ) {
            return Err(error::Unspecified);
        }
        let olen = out_len.assume_init() as usize;
        if olen.ne(&BLOCK_LEN) {
            return Err(error::Unspecified);
        }

        if 1 != aws_lc_sys::EVP_EncryptFinal_ex(*ctx, null_mut(), out_len.as_mut_ptr()) {
            return Err(error::Unspecified);
        }

        let ctext = cipher_text.assume_init();
        Ok(Block::from(&ctext))
    }
}
