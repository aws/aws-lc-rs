// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::block::BLOCK_LEN;
use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::iv::Iv;
use crate::aead::key_inner::KeyInner;
use crate::aead::{poly1305, Algorithm, AlgorithmID};

use crate::error;

pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    init: init_chacha,
    key_len: 32,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: u64::MAX,
};

fn init_chacha(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    KeyInner::new(SymmetricCipherKey::chacha20(key)?)
}
/*
// Also used by chacha20_poly1305_openssh.
pub(super) fn derive_poly1305_key(
    chacha_key: &SymmetricCipherKey::ChaCha20,
    iv: Iv,
) -> poly1305::Key {
    let mut key_bytes = [0u8; 2 * BLOCK_LEN];
    chacha_key.encrypt_iv_xor_blocks_in_place(iv, &mut key_bytes);
    poly1305::Key::new(key_bytes, cpu_features)
}
*/
