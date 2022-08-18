// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::{Algorithm, AlgorithmID, KeyInner};

use crate::error;

pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    init: init_chacha,
    key_len: 32,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: u64::MAX,
};

fn init_chacha(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    KeyInner::new(SymmetricCipherKey::chacha20poly1305(key)?)
}
