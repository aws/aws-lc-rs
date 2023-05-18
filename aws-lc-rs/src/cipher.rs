// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Block and Stream Cipher for Encryption and Decryption.
//!
//! # 🛑 Read Before Using
//!
//! This module provides access to block and stream cipher algorithms.
//! The modes provided here only provide confidentiality, but **do not**
//! provide integrity or authentication verification of ciphertext.
//!
//! These algorithms are provided solely for applications requring them
//! in order to maintain backwards compatability in legacy applications.
//!
//! If you are developing new applications requring data encryption see
//! the algorithms provided in [`aead`](crate::aead).
//!
//! # Examples
//! ```
//! use aws_lc_rs::cipher::{CipherKey, DecryptingKey, EncryptingKey, AES_128_CTR};
//!
//! let mut plaintext = Vec::from("This is a secret message!");
//!
//! let key_bytes: &[u8] = &[
//!     0xff, 0x0b, 0xe5, 0x84, 0x64, 0x0b, 0x00, 0xc8, 0x90, 0x7a, 0x4b, 0xbf, 0x82, 0x7c, 0xb6,
//!     0xd1,
//! ];
//!
//! let key = CipherKey::new(&AES_128_CTR, key_bytes).unwrap();
//! let encrypting_key = EncryptingKey::new(key).unwrap();
//! let iv = encrypting_key.encrypt(&mut plaintext).unwrap();
//!
//! let key = CipherKey::new(&AES_128_CTR, key_bytes).unwrap();
//! let decrypting_key = DecryptingKey::new(key, iv);
//! let plaintext = decrypting_key.decrypt(&mut plaintext).unwrap();
//! ```
//!

#![allow(clippy::module_name_repetitions)]

pub(crate) mod aes;
pub(crate) mod block;
pub(crate) mod chacha;

use crate::cipher::aes::{encrypt_block_aes, Aes128Key, Aes256Key};
use crate::cipher::block::Block;
use crate::cipher::chacha::ChaCha20Key;
use crate::error::Unspecified;
use crate::iv::IV;
use crate::rand;
use aws_lc::{
    AES_cbc_encrypt, AES_ctr128_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AES_DECRYPT,
    AES_ENCRYPT, AES_KEY,
};
use std::mem::{size_of, transmute, MaybeUninit};
use std::os::raw::c_uint;
use std::ptr;
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128 {
        raw_key: Aes128Key,
        enc_key: AES_KEY,
        dec_key: AES_KEY,
    },
    Aes256 {
        raw_key: Aes256Key,
        enc_key: AES_KEY,
        dec_key: AES_KEY,
    },
    ChaCha20 {
        raw_key: ChaCha20Key,
    },
}

unsafe impl Send for SymmetricCipherKey {}
// The AES_KEY value is only used as a `*const AES_KEY` in calls to `AES_encrypt`.
unsafe impl Sync for SymmetricCipherKey {}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        // Aes128Key, Aes256Key and ChaCha20Key implement Drop separately.
        match self {
            SymmetricCipherKey::Aes128 {
                enc_key, dec_key, ..
            }
            | SymmetricCipherKey::Aes256 {
                enc_key, dec_key, ..
            } => unsafe {
                #[allow(clippy::transmute_ptr_to_ptr)]
                let enc_bytes: &mut [u8; size_of::<AES_KEY>()] = transmute(enc_key);
                enc_bytes.zeroize();
                #[allow(clippy::transmute_ptr_to_ptr)]
                let dec_bytes: &mut [u8; size_of::<AES_KEY>()] = transmute(dec_key);
                dec_bytes.zeroize();
            },
            SymmetricCipherKey::ChaCha20 { .. } => {}
        }
    }
}

#[derive(Clone, Copy)]
enum AlgorithmId {
    Aes128ctr,
    Aes128cbc,
    Aes256ctr,
    Aes256cbc,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum PaddingStrategy {
    Unpadded,
    PKCS7,
}

#[derive(Clone, Copy)]
enum OperatingMode {
    Block(PaddingStrategy),
    Stream,
}

/// A Block or Stream Cipher Algorithm
///
/// # Supported Algorithms
///
/// ## Counter (CTR) Modes
///
/// * [`AES_128_CTR`]
/// * [`AES_256_CTR`]
///
/// ## Cipher block chaining (CBC) Modes
///
/// * [`AES_128_CBC_PKCS7_PADDING`]
/// * [`AES_256_CBC_PKCS7_PADDING`]
///
pub struct Algorithm<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>(
    AlgorithmId,
    OperatingMode,
);

/// The number of bytes in an AES 128-bit key
pub const AES_128_KEY_LEN: usize = 16;

/// The number of bytes in an AES 256-bit key
pub const AES_256_KEY_LEN: usize = 32;

/// The number of bytes for an AES initalization vector (IV)
pub const AES_IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

/// AES-128 Counter (CTR) Mode
pub const AES_128_CTR: Algorithm<AES_128_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(AlgorithmId::Aes128ctr, OperatingMode::Stream);

/// AES-128 Cipher block chaining (CBC) Mode using PKCS#7 padding.
pub const AES_128_CBC_PKCS7_PADDING: Algorithm<AES_128_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(
        AlgorithmId::Aes128cbc,
        OperatingMode::Block(PaddingStrategy::PKCS7),
    );

/// AES-256 Counter (CTR) Mode
pub const AES_256_CTR: Algorithm<AES_256_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(AlgorithmId::Aes256ctr, OperatingMode::Stream);

/// AES-256 Cipher block chaining (CBC) Mode using PKCS#7 padding.
pub const AES_256_CBC_PKCS7_PADDING: Algorithm<AES_256_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(
        AlgorithmId::Aes256cbc,
        OperatingMode::Block(PaddingStrategy::PKCS7),
    );

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    Algorithm<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    #[inline]
    fn get_id(&self) -> &AlgorithmId {
        &self.0
    }

    #[inline]
    fn get_operating_mode(&self) -> &OperatingMode {
        &self.1
    }
}

/// A key bound to a particular cipher algorithm.
pub struct CipherKey<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize> {
    algorithm: &'static Algorithm<KEY_LEN, IV_LEN, BLOCK_LEN>,
    key: SymmetricCipherKey,
}

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    #[inline]
    fn get_algorithm(&self) -> &'static Algorithm<KEY_LEN, IV_LEN, BLOCK_LEN> {
        self.algorithm
    }
}

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    /// Constructs a [`CipherKey`].
    ///
    /// # Errors
    ///
    /// * [`Unspecified`] if `key_bytes.len()` does not match the
    /// length required by `algorithm`.
    ///
    pub fn new(
        algorithm: &'static Algorithm<KEY_LEN, IV_LEN, BLOCK_LEN>,
        key_bytes: &[u8],
    ) -> Result<Self, Unspecified> {
        let key: &[u8; KEY_LEN] = key_bytes.try_into()?;
        let key = match algorithm.get_id() {
            AlgorithmId::Aes128ctr | AlgorithmId::Aes128cbc => SymmetricCipherKey::aes128(key),
            AlgorithmId::Aes256ctr | AlgorithmId::Aes256cbc => SymmetricCipherKey::aes256(key),
        }?;
        Ok(CipherKey { algorithm, key })
    }
}

/// An encryting cipher key.
pub struct EncryptingKey<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize> {
    cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
    iv: IV<IV_LEN>,
}

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    EncryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    #[cfg(test)]
    fn new_with_iv(
        cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
        iv_bytes: [u8; IV_LEN],
    ) -> EncryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN> {
        EncryptingKey {
            cipher_key,
            iv: IV::assume_unique_for_key(iv_bytes),
        }
    }

    /// Constructs a new [`EncryptingKey`].
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if a randomized IV fails to be generated.
    ///
    pub fn new(
        cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
    ) -> Result<EncryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN>, Unspecified> {
        let mut iv_bytes = [0u8; IV_LEN];
        rand::fill(&mut iv_bytes)?;
        Ok(EncryptingKey {
            cipher_key,
            iv: IV::assume_unique_for_key(iv_bytes),
        })
    }

    /// Encrypts the data `in_out` in-place. If the algorithm bound to this key uses padding
    /// then the `in_out` will be extended to add the necessary padding.
    ///
    /// Returns the initalization vector necessary to later decrypt the data.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if the data fails to be encrypted.
    ///
    pub fn encrypt<InOut>(self, in_out: &mut InOut) -> Result<IV<IV_LEN>, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let alg = self.cipher_key.get_algorithm();

        match alg.get_operating_mode() {
            OperatingMode::Block(strategy) => match strategy {
                PaddingStrategy::PKCS7 => {
                    let in_out_len = in_out.as_mut().len();
                    // This implements PKCS#7 padding scheme, used by aws-lc if we were using EVP_CIPHER API's
                    let remainder = in_out_len % BLOCK_LEN;
                    if remainder == 0 {
                        let block_size: u8 = BLOCK_LEN.try_into().map_err(|_| Unspecified)?;
                        in_out.extend(vec![block_size; BLOCK_LEN].iter());
                    } else {
                        let padding_size = BLOCK_LEN - remainder;
                        let v: u8 = padding_size.try_into().map_err(|_| Unspecified)?;
                        // Heap allocation :(
                        in_out.extend(vec![v; padding_size].iter());
                    }
                }
                PaddingStrategy::Unpadded => {}
            },
            OperatingMode::Stream => {}
        }

        let in_out = in_out.as_mut();

        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(self.iv.as_ref());

        match alg.get_id() {
            AlgorithmId::Aes128ctr | AlgorithmId::Aes256ctr => {
                let mut num = MaybeUninit::<u32>::new(0);
                let key = match &self.cipher_key.key {
                    SymmetricCipherKey::Aes128 { enc_key, .. }
                    | SymmetricCipherKey::Aes256 { enc_key, .. } => enc_key,
                    SymmetricCipherKey::ChaCha20 { .. } => return Err(Unspecified),
                };

                let mut buf = [0u8; BLOCK_LEN];

                unsafe {
                    AES_ctr128_encrypt(
                        in_out.as_ptr(),
                        in_out.as_mut_ptr(),
                        in_out.len(),
                        key,
                        iv.as_mut_ptr(),
                        buf.as_mut_slice().as_mut_ptr(),
                        num.as_mut_ptr(),
                    );
                };

                Zeroize::zeroize(buf.as_mut_slice());
            }
            AlgorithmId::Aes128cbc | AlgorithmId::Aes256cbc => {
                let key = match &self.cipher_key.key {
                    SymmetricCipherKey::Aes128 { enc_key, .. }
                    | SymmetricCipherKey::Aes256 { enc_key, .. } => enc_key,
                    SymmetricCipherKey::ChaCha20 { .. } => return Err(Unspecified),
                };
                unsafe {
                    AES_cbc_encrypt(
                        in_out.as_ptr(),
                        in_out.as_mut_ptr(),
                        in_out.len(),
                        key,
                        iv.as_mut_ptr(),
                        AES_ENCRYPT,
                    );
                }
            }
        }
        Ok(self.iv)
    }
}

/// An decrypting cipher key.
pub struct DecryptingKey<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize> {
    cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
    iv: IV<IV_LEN>,
}

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    DecryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    /// Constructs a new [`DecryptingKey`].
    #[must_use]
    pub fn new(
        cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
        iv: IV<IV_LEN>,
    ) -> DecryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN> {
        DecryptingKey { cipher_key, iv }
    }

    /// Decrypts the data `in_out` in-place.
    ///
    /// Returns a reference to the decrypted data. If the algorithm bound to this key uses padding,
    /// then the returned slice reference will have it's length adjusted to remove the padding bytes.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if the data fails to be decrypted.
    ///
    pub fn decrypt(mut self, in_out: &mut [u8]) -> Result<&mut [u8], Unspecified> {
        let alg = self.cipher_key.get_algorithm();

        let mut final_len = in_out.len();

        let iv = self.iv.as_mut();

        match alg.get_id() {
            AlgorithmId::Aes128ctr | AlgorithmId::Aes256ctr => {
                let mut num = MaybeUninit::<u32>::new(0);
                let key = match &self.cipher_key.key {
                    SymmetricCipherKey::Aes128 { enc_key, .. }
                    | SymmetricCipherKey::Aes256 { enc_key, .. } => enc_key,
                    SymmetricCipherKey::ChaCha20 { .. } => return Err(Unspecified),
                };
                let mut buf = [0u8; BLOCK_LEN];
                unsafe {
                    AES_ctr128_encrypt(
                        in_out.as_ptr(),
                        in_out.as_mut_ptr(),
                        in_out.len(),
                        key,
                        iv.as_mut_ptr(),
                        buf.as_mut_slice().as_mut_ptr(),
                        num.as_mut_ptr(),
                    );
                };
                Zeroize::zeroize(buf.as_mut_slice());
            }
            AlgorithmId::Aes128cbc | AlgorithmId::Aes256cbc => {
                let key = match &self.cipher_key.key {
                    SymmetricCipherKey::Aes128 { dec_key, .. }
                    | SymmetricCipherKey::Aes256 { dec_key, .. } => dec_key,
                    SymmetricCipherKey::ChaCha20 { .. } => return Err(Unspecified),
                };
                unsafe {
                    AES_cbc_encrypt(
                        in_out.as_ptr(),
                        in_out.as_mut_ptr(),
                        in_out.len(),
                        key,
                        iv.as_mut_ptr(),
                        AES_DECRYPT,
                    );
                }
            }
        }

        match alg.get_operating_mode() {
            OperatingMode::Block(strategy) => match strategy {
                PaddingStrategy::PKCS7 => {
                    let block_size: u8 = BLOCK_LEN.try_into().map_err(|_| Unspecified)?;

                    if in_out.is_empty() || in_out.len() < BLOCK_LEN {
                        return Err(Unspecified);
                    }
                    let padding: u8 = in_out[in_out.len() - 1];
                    if padding == 0 || padding > block_size {
                        return Err(Unspecified);
                    }

                    for item in in_out.iter().skip(in_out.len() - padding as usize) {
                        if *item != padding {
                            return Err(Unspecified);
                        }
                    }

                    final_len = in_out.len() - padding as usize;
                }
                PaddingStrategy::Unpadded => {}
            },
            OperatingMode::Stream => {}
        }

        Ok(&mut in_out[0..final_len])
    }
}

impl SymmetricCipherKey {
    pub(crate) fn aes128(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 16 {
            return Err(Unspecified);
        }

        unsafe {
            let mut enc_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                enc_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let enc_key = enc_key.assume_init();

            let mut dec_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_decrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                dec_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let dec_key = dec_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 16]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 16);
            Ok(SymmetricCipherKey::Aes128 {
                raw_key: Aes128Key(kb.assume_init()),
                enc_key,
                dec_key,
            })
        }
    }

    pub(crate) fn aes256(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        unsafe {
            let mut enc_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                enc_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let enc_key = enc_key.assume_init();

            let mut dec_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_decrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                dec_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let dec_key = dec_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 32]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256 {
                raw_key: Aes256Key(kb.assume_init()),
                enc_key,
                dec_key,
            })
        }
    }

    pub(crate) fn chacha20(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::ChaCha20 {
                raw_key: ChaCha20Key(kb.assume_init()),
            })
        }
    }

    #[inline]
    pub(super) fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::Aes128 { raw_key, .. } => &raw_key.0,
            SymmetricCipherKey::Aes256 { raw_key, .. } => &raw_key.0,
            SymmetricCipherKey::ChaCha20 { raw_key, .. } => &raw_key.0,
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn encrypt_block(&self, block: Block) -> Block {
        match self {
            SymmetricCipherKey::Aes128 { enc_key, .. }
            | SymmetricCipherKey::Aes256 { enc_key, .. } => encrypt_block_aes(enc_key, block),
            SymmetricCipherKey::ChaCha20 { .. } => panic!("Unsupported algorithm!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::block::BLOCK_LEN;
    use crate::test::from_hex;

    #[test]
    fn test_encrypt_block_aes_128() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let input = from_hex("00112233445566778899aabbccddeeff").unwrap();
        let expected_result = from_hex("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let input_block: [u8; BLOCK_LEN] = <[u8; BLOCK_LEN]>::try_from(input).unwrap();

        let aes128 = SymmetricCipherKey::aes128(key.as_slice()).unwrap();
        let result = aes128.encrypt_block(Block::from(&input_block));

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
        let result = aes128.encrypt_block(Block::from(&input_block));

        assert_eq!(expected_result.as_slice(), result.as_ref());
    }

    fn helper_test_cipher_n_bytes<
        const KEY_LEN: usize,
        const IV_LEN: usize,
        const BLOCK_LEN: usize,
    >(
        key: &[u8],
        alg: &'static Algorithm<KEY_LEN, IV_LEN, BLOCK_LEN>,
        n: usize,
    ) {
        let mut input: Vec<u8> = Vec::with_capacity(n);
        for i in 0..n {
            let byte: u8 = i.try_into().unwrap();
            input.push(byte);
        }

        let cipher_key = CipherKey::new(alg, key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut ciphertext = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut ciphertext).unwrap();

        assert_ne!(input.as_slice(), ciphertext);

        let cipher_key2 = CipherKey::new(alg, key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        let plaintext = decrypting_key.decrypt(&mut ciphertext).unwrap();
        assert_eq!(input.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_128_cbc() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_128_CBC_PKCS7_PADDING, i);
        }
    }

    #[test]
    fn test_aes_256_cbc() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_256_CBC_PKCS7_PADDING, i);
        }
    }

    #[test]
    fn test_aes_128_ctr() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        // TODO: test 0 bytes.
        for i in 1..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_128_CTR, i);
        }
    }

    #[test]
    fn test_aes_256_ctr() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        // TODO: test 0 bytes.
        for i in 1..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_256_CTR, i);
        }
    }

    macro_rules! cipher_test_vector {
        ($name:ident, $cipher:expr, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
            #[test]
            fn $name() {
                let key = from_hex($key).unwrap();
                let input = from_hex($plaintext).unwrap();
                let expected_ciphertext = from_hex($ciphertext).unwrap();
                let mut iv = from_hex($iv).unwrap();
                let iv = {
                    let slice = iv.as_mut_slice();
                    let mut iv = [0u8; 16];
                    {
                        let x = iv.as_mut_slice();
                        x.copy_from_slice(slice);
                    }
                    iv
                };

                let alg = $cipher;
                let cipher_key = CipherKey::new(alg, &key).unwrap();
                let encrypting_key = EncryptingKey::new_with_iv(cipher_key, iv.try_into().unwrap());

                let mut ciphertext = input.clone();
                let decrypt_iv = encrypting_key.encrypt(&mut ciphertext).unwrap();
                assert_eq!(expected_ciphertext, ciphertext);

                let cipher_key2 = CipherKey::new(alg, &key).unwrap();
                let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

                let plaintext = decrypting_key.decrypt(&mut ciphertext).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        };
    }

    cipher_test_vector!(
        test_iv_aes_128_cbc_16_bytes,
        &AES_128_CBC_PKCS7_PADDING,
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a9e978e6d16b086570ef794ef97984232"
    );

    cipher_test_vector!(
        test_iv_aes_256_cbc_15_bytes,
        &AES_256_CBC_PKCS7_PADDING,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddee",
        "2ddfb635a651a43f582997966840ca0c"
    );

    cipher_test_vector!(
        test_iv_aes_128_ctr_16_bytes,
        &AES_128_CTR,
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "c6b01904c3da3df5e7d62bd96d153686"
    );

    cipher_test_vector!(
        test_iv_aes_256_ctr_15_bytes,
        &AES_256_CTR,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddee",
        "f28122856e1cf9a7216a30d111f399"
    );

    cipher_test_vector!(
        test_openssl_aes_128_ctr_15_bytes,
        &AES_128_CTR,
        "244828580821c1652582c76e34d299f5",
        "093145d5af233f46072a5eb5adc11aa1",
        "3ee38cec171e6cf466bf0df98aa0e1",
        "bd7d928f60e3422d96b3f8cd614eb2"
    );

    cipher_test_vector!(
        test_openssl_aes_256_ctr_15_bytes,
        &AES_256_CTR,
        "0857db8240ea459bdf660b4cced66d1f2d3734ff2de7b81e92740e65e7cc6a1d",
        "f028ecb053f801102d11fccc9d303a27",
        "eca7285d19f3c20e295378460e8729",
        "b5098e5e788de6ac2f2098eb2fc6f8"
    );

    cipher_test_vector!(
        test_openssl_aes_128_cbc_15_bytes,
        &AES_128_CBC_PKCS7_PADDING,
        "053304bb3899e1d99db9d29343ea782d",
        "b5313560244a4822c46c2a0c9d0cf7fd",
        "a3e4c990356c01f320043c3d8d6f43",
        "ad96993f248bd6a29760ec7ccda95ee1"
    );

    cipher_test_vector!(
        test_openssl_aes_128_cbc_16_bytes,
        &AES_128_CBC_PKCS7_PADDING,
        "95af71f1c63e4a1d0b0b1a27fb978283",
        "89e40797dca70197ff87d3dbb0ef2802",
        "aece7b5e3c3df1ffc9802d2dfe296dc7",
        "301b5dab49fb11e919d0d39970d06739301919743304f23f3cbc67d28564b25b"
    );

    cipher_test_vector!(
        test_openssl_aes_256_cbc_15_bytes,
        &AES_256_CBC_PKCS7_PADDING,
        "d369e03e9752784917cc7bac1db7399598d9555e691861d9dd7b3292a693ef57",
        "1399bb66b2f6ad99a7f064140eaaa885",
        "7385f5784b85bf0a97768ddd896d6d",
        "4351082bac9b4593ae8848cc9dfb5a01"
    );

    cipher_test_vector!(
        test_openssl_aes_256_cbc_16_bytes,
        &AES_256_CBC_PKCS7_PADDING,
        "d4a8206dcae01242f9db79a4ecfe277d0f7bb8ccbafd8f9809adb39f35aa9b41",
        "24f6076548fb9d93c8f7ed9f6e661ef9",
        "a39c1fdf77ea3e1f18178c0ec237c70a",
        "f1af484830a149ee0387b854d65fe87ca0e62efc1c8e6909d4b9ab8666470453"
    );
}
