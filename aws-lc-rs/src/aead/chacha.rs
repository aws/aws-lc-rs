// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::key_inner::KeyInner;
use crate::aead::{Algorithm, AlgorithmID};
use crate::cipher::chacha::KEY_LEN;
use crate::cipher::key::SymmetricCipherKey;

use crate::error;

/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    init: init_chacha,
    key_len: KEY_LEN,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: u64::MAX,
};

#[inline]
fn init_chacha(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    KeyInner::new(SymmetricCipherKey::chacha20(key)?)
}
