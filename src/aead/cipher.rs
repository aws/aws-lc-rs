// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::error;
use std::mem::MaybeUninit;
use std::ptr;
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
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
        }
    }
}

impl SymmetricCipherKey {
    pub fn aes128(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        assert_eq!(key_bytes.len(), 16);
        let mut kb = MaybeUninit::<[u8; 16]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes128(kb.assume_init()))
        }
    }

    pub fn aes256(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        assert_eq!(key_bytes.len(), 32);
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256(kb.assume_init()))
        }
    }

    pub fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::Aes128(bytes) => bytes,
            SymmetricCipherKey::Aes256(bytes) => bytes,
        }
    }

    fn key_size_bits(&self) -> usize {
        match self {
            SymmetricCipherKey::Aes128(_) => 128,
            SymmetricCipherKey::Aes256(_) => 256,
        }
    }
}
