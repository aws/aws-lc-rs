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
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::aes::{encrypt_block_aes_ecb, Aes128Key, Aes256Key};
use crate::aead::chacha::{encrypt_block_chacha20, ChaCha20Key};
use crate::aead::{block::Block, error, quic::Sample, Nonce};
use crate::error::Unspecified;
use aws_lc_sys::AES_KEY;
use core::ffi::c_uint;
use std::mem::{size_of, transmute, MaybeUninit};
use std::ptr;
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128(Aes128Key, AES_KEY),
    Aes256(Aes256Key, AES_KEY),
    ChaCha20(ChaCha20Key),
}

unsafe impl Send for SymmetricCipherKey {}
// The AES_KEY value is only used as a `*const AES_KEY` in calls to `AES_ecb_encrypt`.
unsafe impl Sync for SymmetricCipherKey {}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        // Aes128Key, Aes256Key and ChaCha20Key implement Drop separately.
        match self {
            SymmetricCipherKey::Aes128(_, aes_key) | SymmetricCipherKey::Aes256(_, aes_key) => unsafe {
                #[allow(clippy::transmute_ptr_to_ptr)]
                let value: &mut [u8; size_of::<AES_KEY>()] = transmute(aes_key);
                value.zeroize();
            },
            SymmetricCipherKey::ChaCha20(_) => {}
        }
    }
}

impl SymmetricCipherKey {
    pub(crate) fn aes128(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 16 {
            return Err(Unspecified);
        }

        unsafe {
            let mut aes_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != aws_lc_sys::AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                aes_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let aes_key = aes_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 16]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 16);
            Ok(SymmetricCipherKey::Aes128(
                Aes128Key(kb.assume_init()),
                aes_key,
            ))
        }
    }

    pub(crate) fn aes256(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        unsafe {
            let mut aes_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != aws_lc_sys::AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                aes_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let aes_key = aes_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 32]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256(
                Aes256Key(kb.assume_init()),
                aes_key,
            ))
        }
    }

    pub(crate) fn chacha20(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        if key_bytes.len() != 32 {
            return Err(error::Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::ChaCha20(ChaCha20Key(kb.assume_init())))
        }
    }

    #[inline]
    pub(super) fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::Aes128(bytes, ..) => &bytes.0,
            SymmetricCipherKey::Aes256(bytes, ..) => &bytes.0,
            SymmetricCipherKey::ChaCha20(bytes) => &bytes.0,
        }
    }

    #[inline]
    pub(super) fn new_mask(&self, sample: Sample) -> Result<[u8; 5], error::Unspecified> {
        let block = Block::from(&sample);

        let encrypted_block = match self {
            SymmetricCipherKey::Aes128(.., aes_key) | SymmetricCipherKey::Aes256(.., aes_key) => {
                encrypt_block_aes_ecb(aes_key, block)
            }
            SymmetricCipherKey::ChaCha20(key_bytes) => {
                let plaintext = block.as_ref();
                let counter_bytes: &[u8; 4] = plaintext[0..=3].try_into()?;
                let nonce: &[u8; 12] = plaintext[4..=15].try_into()?;
                let input = Block::zero();
                unsafe {
                    let counter = std::mem::transmute::<[u8; 4], u32>(*counter_bytes).to_le();
                    encrypt_block_chacha20(key_bytes, input, Nonce::from(nonce), counter)?
                }
            }
        };

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&encrypted_block.as_ref()[..5]);

        Ok(out)
    }

    #[allow(dead_code)]
    #[inline]
    pub fn encrypt_block(&self, block: Block) -> Result<Block, Unspecified> {
        match self {
            SymmetricCipherKey::Aes128(.., aes_key) | SymmetricCipherKey::Aes256(.., aes_key) => {
                Ok(encrypt_block_aes_ecb(aes_key, block))
            }
            SymmetricCipherKey::ChaCha20(..) => panic!("Unsupported algorithm!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::block::BLOCK_LEN;
    use crate::test::from_hex;

    #[test]
    fn test_encrypt_block_aes_128() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let input = from_hex("00112233445566778899aabbccddeeff").unwrap();
        let expected_result = from_hex("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let input_block: [u8; BLOCK_LEN] = <[u8; BLOCK_LEN]>::try_from(input).unwrap();

        let aes128 = SymmetricCipherKey::aes128(key.as_slice()).unwrap();
        let result = aes128.encrypt_block(Block::from(&input_block)).unwrap();

        assert_eq!(expected_result.as_slice(), result.as_ref());
    }

    #[test]
    fn test_encrypt_block_aes_256() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let input = from_hex("00112233445566778899aabbccddeeff").unwrap();
        let expected_result = from_hex("8ea2b7ca516745bfeafc49904b496089").unwrap();
        let input_block: [u8; BLOCK_LEN] = <[u8; BLOCK_LEN]>::try_from(input).unwrap();

        let aes128 = SymmetricCipherKey::aes256(key.as_slice()).unwrap();
        let result = aes128.encrypt_block(Block::from(&input_block)).unwrap();

        assert_eq!(expected_result.as_slice(), result.as_ref());
    }
}
