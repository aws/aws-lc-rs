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

use std::mem::{MaybeUninit, size_of};
use std::ptr;
use crate::aead::error;
use zeroize::Zeroize;


pub(crate) enum SymmetricCipherKey {
    AES_128([u8; 16]),
    AES_256([u8; 32]),
}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        unsafe {
            match self {
                SymmetricCipherKey::AES_128(key_bytes) => {
                    key_bytes.zeroize();
                },
                SymmetricCipherKey::AES_256(key_bytes) => {
                    key_bytes.zeroize();
                }
            }
        }
    }
}

impl SymmetricCipherKey {
    pub fn aes128(
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        assert_eq!(key_bytes.len(), 16);
        let mut kb= MaybeUninit::<[u8;16]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::AES_128(kb.assume_init()))
        }
    }

    pub fn aes256(
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        assert_eq!(key_bytes.len(), 32);
        let mut kb= MaybeUninit::<[u8;32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::AES_256(kb.assume_init()))
        }
    }

    pub fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::AES_128(bytes) => bytes,
            SymmetricCipherKey::AES_256(bytes) => bytes
        }
    }

    fn key_size_bits(&self) -> usize {
        match self {
            SymmetricCipherKey::AES_128(_) => 128,
            SymmetricCipherKey::AES_256(_) => 256
        }
    }
}


