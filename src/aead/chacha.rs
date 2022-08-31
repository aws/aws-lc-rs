// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::block::{Block, BLOCK_LEN};
use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::iv::Iv;
use crate::aead::key_inner::KeyInner;
use crate::aead::{Algorithm, AlgorithmID, Nonce, NONCE_LEN};
use std::mem::MaybeUninit;
use std::ops::Deref;
use zeroize::Zeroize;

use crate::error;

pub(crate) const KEY_LEN: usize = 32usize;

pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    init: init_chacha,
    key_len: KEY_LEN,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: u64::MAX,
};

fn init_chacha(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    KeyInner::new(SymmetricCipherKey::chacha20(key)?)
}

pub(crate) struct ChaCha20Key(pub(super) [u8; KEY_LEN]);
impl Deref for ChaCha20Key {
    type Target = [u8; KEY_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; KEY_LEN]> for ChaCha20Key {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        ChaCha20Key(bytes)
    }
}

impl Drop for ChaCha20Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ChaCha20Key {
    #[inline]
    pub(super) fn encrypt_in_place(
        &self,
        nonce: Nonce,
        in_out: &mut [u8],
        counter: u32,
    ) -> Result<(), error::Unspecified> {
        encrypt_in_place_chacha20(self, nonce.as_ref(), in_out, counter)
    }
}

#[inline]
pub(super) fn encrypt_block_chacha20(
    key: &ChaCha20Key,
    block: Block,
    nonce: Nonce,
    counter: u32,
) -> Result<Block, error::Unspecified> {
    unsafe {
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit().assume_init();
        encrypt_chacha20(
            key,
            block.as_ref().as_slice(),
            cipher_text.as_mut_slice(),
            nonce.as_ref(),
            counter,
        );

        Ok(Block::from(&cipher_text))
    }
}

#[inline]
pub(super) fn encrypt_chacha20(
    key: &ChaCha20Key,
    plaintext: &[u8],
    ciphertext: &mut [u8],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
) -> Result<(), error::Unspecified> {
    if ciphertext.len() < plaintext.len() {
        return Err(error::Unspecified);
    }
    let key_bytes = &key.0;
    unsafe {
        aws_lc_sys::CRYPTO_chacha_20(
            ciphertext.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            key_bytes.as_ptr(),
            nonce.as_ptr(),
            counter,
        );
    }
    Ok(())
}

#[inline]
pub(super) fn encrypt_in_place_chacha20(
    key: &ChaCha20Key,
    nonce: &[u8; NONCE_LEN],
    in_out: &mut [u8],
    counter: u32,
) -> Result<(), error::Unspecified> {
    unsafe {
        let key_bytes = &key.0;
        unsafe {
            aws_lc_sys::CRYPTO_chacha_20(
                in_out.as_mut_ptr(),
                in_out.as_ptr(),
                in_out.len(),
                key_bytes.as_ptr(),
                nonce.as_ptr(),
                counter,
            );
        }
        Ok(())
    }
}
