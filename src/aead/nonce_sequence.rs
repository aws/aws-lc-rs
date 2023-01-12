// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 or ISC

use crate::aead::aes::AES128_KEY_LENGTH;
use crate::aead::block::Block;
use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::{Nonce, NonceSequence, BLOCK_LEN, NONCE_LEN};
use crate::error::Unspecified;
use crate::rand;
use crate::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

/// `PredictableNonceSequence` is an implementation of the `NonceSequence` trait.
/// As its name indicates, the next nonce is the sequence is predictable by observing the
/// previous nonces produced.
/// The internal state of a `PredictableNonceSequence` is a 64-bit unsigned position that
/// increments on each call to `advance` and an optional 4-byte "context". The position and context
/// values are used to construct the nonce.
/// A limit can be set on the number of nonces allowed to be generate, by default this limit is
/// `u64::MAX`.
#[allow(clippy::module_name_repetitions)]
pub struct PredictableNonceSequence {
    limit: u64,
    counter: u64,
    context: [u8; 4],
    position: u64,
}

/// `NonceSequenceBuilder` facilitates the building of a `PredictableNonceSequence` or
/// `UnpredictableNonceSequence`.
pub struct PredictableNonceSequenceBuilder {
    limit: u64,
    context: [u8; 4],
    position: u64,
}

impl Default for PredictableNonceSequenceBuilder {
    fn default() -> Self {
        PredictableNonceSequenceBuilder::new()
    }
}

impl PredictableNonceSequenceBuilder {
    /// Constructs a `PredictableNonceSequenceBuilder` with all default values.
    #[must_use]
    pub fn new() -> PredictableNonceSequenceBuilder {
        PredictableNonceSequenceBuilder {
            limit: u64::MAX,
            context: [0u8; 4],
            position: 0,
        }
    }

    /// Constructs a `PredictableNonceSequenceBuilder` with a random context and position.
    /// #  Panics
    /// Panics if unable to obtain random bytes
    #[must_use]
    pub fn random(rng: &dyn SecureRandom) -> PredictableNonceSequenceBuilder {
        let context: [u8; 4] = rand::generate(rng).unwrap().expose();
        let position: [u8; 8] = rand::generate(rng).unwrap().expose();
        PredictableNonceSequenceBuilder {
            limit: u64::MAX,
            context,
            position: u64::from_be_bytes(position),
        }
    }

    /// Generates a random value for the context.
    /// # Panics
    /// Panics if unable to obtain random bytes.
    #[must_use]
    pub fn random_context(mut self, rng: &dyn SecureRandom) -> PredictableNonceSequenceBuilder {
        self.context = rand::generate(rng).unwrap().expose();
        self
    }

    /// The context for the `PredictableNonceSequence` - this value helps differentiate nonce
    /// sequences.
    #[must_use]
    pub fn context(mut self, context: [u8; 4]) -> PredictableNonceSequenceBuilder {
        self.context = context;
        self
    }

    /// The starting position for the `PredictableNonceSequence`.
    #[must_use]
    pub fn position(mut self, position: u64) -> PredictableNonceSequenceBuilder {
        self.position = position;
        self
    }

    /// The limit for the number of nonces the `PredictableNonceSequence` can produce.
    #[must_use]
    pub fn limit(mut self, limit: u64) -> PredictableNonceSequenceBuilder {
        self.limit = limit;
        self
    }

    /// Constructs a new `PredictableNonceSequence` with internal context and position set to the
    /// values provided by this struct.
    #[must_use]
    pub fn build(self) -> PredictableNonceSequence {
        PredictableNonceSequence {
            limit: self.limit,
            counter: 0,
            context: self.context,
            position: self.position,
        }
    }
}

impl PredictableNonceSequence {
    /// Provides the internal context.
    #[must_use]
    pub fn context(&self) -> [u8; 4] {
        self.context
    }

    /// Provides the current internal position value.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Provides the current counter indicating how many nonces have been generated.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Provides the limit on the number of nonces allowed to be generate.
    #[must_use]
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

impl NonceSequence for PredictableNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.counter = self.counter.checked_add(1).ok_or(Unspecified)?;
        if self.counter > self.limit {
            return Err(Unspecified);
        }
        self.position = self.position.wrapping_add(1);
        let bytes: [u8; 8] = self.position.to_be_bytes();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&self.context);
        nonce_bytes[4..].copy_from_slice(&bytes);
        Ok(Nonce(nonce_bytes))
    }
}

#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
/// `NonceSequenceKey` wraps a `[u8; AES128_KEY_LENGTH]`. The value is zero'd when dropped.
pub struct NonceSequenceKey([u8; AES128_KEY_LENGTH]);

impl NonceSequenceKey {
    fn random(rng: &dyn SecureRandom) -> Self {
        let key: [u8; AES128_KEY_LENGTH] = rand::generate(rng).unwrap().expose();
        Self(key)
    }
}

impl From<&[u8; AES128_KEY_LENGTH]> for NonceSequenceKey {
    fn from(value: &[u8; AES128_KEY_LENGTH]) -> Self {
        let mut key = [0u8; AES128_KEY_LENGTH];
        key.copy_from_slice(value);
        Self(key)
    }
}

impl From<NonceSequenceKey> for [u8; AES128_KEY_LENGTH] {
    fn from(value: NonceSequenceKey) -> Self {
        value.0
    }
}

impl Drop for NonceSequenceKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `UnpredictableNonceSequence` is an implementation of the `NonceSequence` trait.
/// The nonces in the sequence this produces appear random to an outside observer w/o
/// knowledge of the key being used.
/// The internal state of an `UnpredictableNonceSequence` is a unsigned 32-bit position, an 8-byte
/// "context" and an AES128 key. The key is determined at construction and is immutable.
/// The position increments on each call to `advance`.
/// Each nonce is generated by encrypting the context and counter using the AES128 key.
/// A limit can be set on the number of nonces allowed to be generate, by default this limit is
/// `u16::MAX`.
#[allow(clippy::module_name_repetitions)]
pub struct UnpredictableNonceSequence {
    limit: u32,
    counter: u32,
    key: SymmetricCipherKey,
    context: [u8; 12],
    position: u32,
}

/// Facilitates the construction of an `UnpredictableNonceSequence`
pub struct UnpredictableNonceSequenceBuilder {
    limit: u32,
    context: [u8; 12],
    position: u32,
}

impl Default for UnpredictableNonceSequenceBuilder {
    fn default() -> Self {
        UnpredictableNonceSequenceBuilder::new()
    }
}

impl UnpredictableNonceSequenceBuilder {
    /// Constructs a `UnpredictableNonceSequenceBuilder` with all default values.
    #[must_use]
    pub fn new() -> UnpredictableNonceSequenceBuilder {
        UnpredictableNonceSequenceBuilder {
            limit: u32::from(u16::MAX),
            context: [0u8; 12],
            position: 0,
        }
    }

    /// Constructs a `UnpredictableNonceSequenceBuilder` with randome values for context and
    /// position.
    /// # Panics
    /// Panics is unable to obtain random bytes.
    #[must_use]
    pub fn random(rng: &dyn SecureRandom) -> UnpredictableNonceSequenceBuilder {
        let context: [u8; 12] = rand::generate(rng).unwrap().expose();
        let position: [u8; 4] = rand::generate(rng).unwrap().expose();

        UnpredictableNonceSequenceBuilder {
            limit: u32::from(u16::MAX),
            context,
            position: u32::from_be_bytes(position),
        }
    }

    /// Generates a random value for the context.
    /// # Panics
    /// Panics if unable to obtain random bytes.
    #[must_use]
    pub fn random_context(mut self, rng: &dyn SecureRandom) -> UnpredictableNonceSequenceBuilder {
        self.context = rand::generate(rng).unwrap().expose();
        self
    }

    /// Sets the "context" for the `UnpredictableNonceSequence` - this value helps differentiate
    /// nonce sequences that are using the same key.
    #[must_use]
    pub fn context(mut self, context: [u8; 12]) -> UnpredictableNonceSequenceBuilder {
        self.context = context;
        self
    }

    /// Sets the position for the `UnpredictableNonceSequence`.
    #[must_use]
    pub fn position(mut self, position: u32) -> UnpredictableNonceSequenceBuilder {
        self.position = position;
        self
    }

    /// Sets the limit on the number of nonces the `UnpredictableNonceSequence` is allowed to
    /// generate.
    #[must_use]
    pub fn limit(mut self, limit: u32) -> UnpredictableNonceSequenceBuilder {
        self.limit = limit;
        self
    }

    /// Constructs an `UnpredictableNonceSequence` using the key provided.
    /// # Panics
    /// Panics if unable to construct cipher key.
    #[must_use]
    pub fn build_with_key(self, key: &NonceSequenceKey) -> UnpredictableNonceSequence {
        UnpredictableNonceSequence {
            limit: self.limit,
            counter: 0,
            key: SymmetricCipherKey::aes128(&key.0).unwrap(),
            context: self.context,
            position: self.position,
        }
    }

    /// Constructs an `UnpredictableNonceSequence` using a randomly generated `NonceSequenceKey`.
    /// # Panics
    /// Panics is unable to construct cipher key.
    #[must_use]
    pub fn build(self) -> (NonceSequenceKey, UnpredictableNonceSequence) {
        let key = NonceSequenceKey::random(&SystemRandom::new());
        let result = UnpredictableNonceSequence {
            limit: self.limit,
            counter: 0,
            key: SymmetricCipherKey::aes128(&key.0).unwrap(),
            context: self.context,
            position: self.position,
        };
        (key, result)
    }
}

impl UnpredictableNonceSequence {
    /// Provides the current internal position value.
    #[must_use]
    pub fn position(&self) -> u32 {
        self.position
    }

    /// Provides the current counter indicating how many nonces have been generated.
    #[must_use]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Provides the context for this sequence.
    #[must_use]
    pub fn context(&self) -> [u8; 12] {
        self.context
    }

    /// Provides the limit on the number of nonces allowed to be generate.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

impl NonceSequence for UnpredictableNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.counter = self.counter.checked_add(1).ok_or(Unspecified)?;
        if self.counter > self.limit {
            return Err(Unspecified);
        }
        self.position = self.position.wrapping_add(1);
        let mut block_bytes = [0u8; BLOCK_LEN];
        block_bytes[..12].copy_from_slice(&self.context);
        block_bytes[12..].copy_from_slice(&self.position.to_be_bytes());
        let encrypted_block = self.key.encrypt_block(Block::from(&block_bytes))?;
        let encrypted_bytes = encrypted_block.as_ref();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&encrypted_bytes[0..NONCE_LEN]);
        Ok(Nonce(nonce_bytes))
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::nonce_sequence::{
        PredictableNonceSequenceBuilder, UnpredictableNonceSequenceBuilder,
    };
    use crate::aead::NonceSequence;
    use crate::rand::SystemRandom;

    #[test]
    fn test_predictable_context() {
        let mut predicatable_ns = PredictableNonceSequenceBuilder::new()
            .context([0xA1, 0xB2, 0xC3, 0xD4])
            .position(7)
            .build();
        let nonce = predicatable_ns.advance().unwrap().0;
        assert_eq!(nonce, [0xA1, 0xB2, 0xC3, 0xD4, 0, 0, 0, 0, 0, 0, 0, 8]);
    }

    #[test]
    fn test_predictable() {
        let mut predicatable_ns = PredictableNonceSequenceBuilder::new()
            .position(0x0002_4CB0_16EA_u64)
            .build();
        let nonce = predicatable_ns.advance().unwrap().0;
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0x02, 0x4C, 0xB0, 0x16, 0xEB]);
    }

    #[test]
    fn test_predictable_limit() {
        let mut predicatable_ns = PredictableNonceSequenceBuilder::new().limit(1).build();
        let _nonce = predicatable_ns.advance().unwrap().0;
        assert!(predicatable_ns.advance().is_err());
    }

    #[test]
    fn test_predictable_random() {
        let rng = SystemRandom::new();
        let mut predictable_ns1 = PredictableNonceSequenceBuilder::random(&rng)
            .random_context(&rng)
            .build();
        let mut predictable_ns2 = PredictableNonceSequenceBuilder::new()
            .position(predictable_ns1.position())
            .context(predictable_ns1.context())
            .build();
        for _ in 1..100 {
            assert_eq!(
                predictable_ns1.advance().unwrap().0,
                predictable_ns2.advance().unwrap().0
            );
        }
    }

    #[test]
    fn test_unpredictable() {
        const CONTEXT: [u8; 12] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xFF, 0xCC, 0x11, 0x55,
        ];
        const STARTING_POS: u32 = 543_210u32;
        let (key, mut uns1) = UnpredictableNonceSequenceBuilder::new()
            .context(CONTEXT)
            .position(STARTING_POS)
            .build();
        let mut uns2 = UnpredictableNonceSequenceBuilder::new()
            .context(CONTEXT)
            .position(STARTING_POS)
            .build_with_key(&key);

        for _ in 0..100 {
            assert_eq!(uns1.advance().unwrap().0, uns2.advance().unwrap().0);
        }
    }

    #[test]
    fn test_unpredictable_random() {
        let rng = SystemRandom::new();
        let (key, mut uns1) = UnpredictableNonceSequenceBuilder::random(&rng)
            .random_context(&rng)
            .build();
        let mut uns2 = UnpredictableNonceSequenceBuilder::new()
            .context(uns1.context())
            .position(uns1.position())
            .build_with_key(&key);

        for _ in 0..100 {
            assert_eq!(uns1.advance().unwrap().0, uns2.advance().unwrap().0);
        }
    }

    #[test]
    fn test_unpredictable_limit() {
        let (_, mut uns) = UnpredictableNonceSequenceBuilder::new().limit(1).build();
        let _nonce = uns.advance().unwrap().0;
        assert!(uns.advance().is_err());
    }
}
