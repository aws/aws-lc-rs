// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 or ISC

use crate::aead::block::Block;
use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::{Nonce, NonceSequence, NONCE_LEN};
use crate::error::Unspecified;
use crate::rand;
use crate::rand::SystemRandom;

/// `PredictableNonceSequence`
#[allow(clippy::module_name_repetitions)]
pub struct PredictableNonceSequence {
    position: u64,
}

impl Default for PredictableNonceSequence {
    /// default
    fn default() -> Self {
        Self::new()
    }
}

impl PredictableNonceSequence {
    /// new
    #[must_use]
    pub fn new() -> PredictableNonceSequence {
        PredictableNonceSequence::starting_from(0)
    }

    /// `starting_from`
    #[must_use]
    pub fn starting_from(position: u64) -> PredictableNonceSequence {
        PredictableNonceSequence { position }
    }
}

impl NonceSequence for PredictableNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.position = self.position.wrapping_add(1);
        let bytes: [u8; 8] = self.position.to_be_bytes();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&bytes);
        Ok(Nonce(nonce_bytes))
    }
}

/// `UnpredictableNonceSequence`
#[allow(clippy::module_name_repetitions)]
pub struct UnpredictableNonceSequence {
    aes_key: SymmetricCipherKey,
    position: u64,
}

impl UnpredictableNonceSequence {
    /// new
    /// # Panics
    #[must_use]
    pub fn new() -> ([u8; 16], UnpredictableNonceSequence) {
        let rand = SystemRandom::new();
        let key: [u8; 16] = rand::generate(&rand).unwrap().expose();
        (key, UnpredictableNonceSequence::using_key(key))
    }

    /// `starting_from`
    ///
    /// # Panics
    #[must_use]
    pub fn starting_from(position: u64) -> ([u8; 16], UnpredictableNonceSequence) {
        let rand = SystemRandom::new();
        let key: [u8; 16] = rand::generate(&rand).unwrap().expose();
        (
            key,
            UnpredictableNonceSequence::using_key_and_position(key, position),
        )
    }

    /// `using_key`
    #[must_use]
    pub fn using_key(key: [u8; 16]) -> UnpredictableNonceSequence {
        UnpredictableNonceSequence::using_key_and_position(key, 0)
    }

    /// `using_key_and_position`
    /// # Panics
    #[must_use]
    pub fn using_key_and_position(key: [u8; 16], position: u64) -> UnpredictableNonceSequence {
        UnpredictableNonceSequence {
            aes_key: SymmetricCipherKey::aes128(&key).unwrap(),
            position,
        }
    }
}

impl NonceSequence for UnpredictableNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.position = self.position.wrapping_add(1);
        let mut block_bytes = [0u8; 16];
        block_bytes[4..12].copy_from_slice(&self.position.to_be_bytes());
        let encrypted_block = self.aes_key.encrypt_block(Block::from(&block_bytes))?;
        let encrypted_bytes = encrypted_block.as_ref();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&encrypted_bytes[0..NONCE_LEN]);
        Ok(Nonce(nonce_bytes))
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::nonce_sequence::{PredictableNonceSequence, UnpredictableNonceSequence};
    use crate::aead::NonceSequence;

    #[test]
    fn test_predictable() {
        let value = 0x0002_4CB0_16EA_u64; // 9_876_543_210
        let mut predicatable_ns = PredictableNonceSequence::starting_from(value);
        let nonce = predicatable_ns.advance().unwrap().0;
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0x02, 0x4C, 0xB0, 0x16, 0xEB]);
    }

    #[test]
    fn test_predictable_new() {
        let mut predictable_ns = PredictableNonceSequence::new();
        let nonce = predictable_ns.advance().unwrap().0;
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_unpredictable() {
        const STARTING_POS: u64 = 9_876_543_210u64;
        let (key, mut uns1) = UnpredictableNonceSequence::starting_from(STARTING_POS);
        let mut uns2 = UnpredictableNonceSequence::using_key_and_position(key, STARTING_POS);

        for _ in 0..100 {
            assert_eq!(uns1.advance().unwrap().0, uns2.advance().unwrap().0);
        }
    }

    #[test]
    fn test_unpredictable_new() {
        let (key, mut uns1) = UnpredictableNonceSequence::new();
        let mut uns2 = UnpredictableNonceSequence::using_key(key);

        for _ in 0..100 {
            assert_eq!(uns1.advance().unwrap().0, uns2.advance().unwrap().0);
        }
    }
}
