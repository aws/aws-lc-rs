// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(dead_code, clippy::module_name_repetitions)]

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

pub struct Algorithm<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>(
    AlgorithmId,
    OperatingMode,
);

pub const AES_128_KEY_LEN: usize = 16;
pub const AES_256_KEY_LEN: usize = 32;
pub const AES_IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

pub const AES_128_CTR: Algorithm<AES_128_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(AlgorithmId::Aes128ctr, OperatingMode::Stream);
pub const AES_128_CBC_PKCS7_PADDING: Algorithm<AES_128_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(
        AlgorithmId::Aes128cbc,
        OperatingMode::Block(PaddingStrategy::PKCS7),
    );
pub const AES_256_CTR: Algorithm<AES_256_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN> =
    Algorithm(AlgorithmId::Aes256ctr, OperatingMode::Stream);
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
        return &self.1;
    }
}

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

pub struct DecryptingKey<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize> {
    cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
    iv: IV<IV_LEN>,
}

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    DecryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    pub fn new(
        cipher_key: CipherKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
        iv: IV<IV_LEN>,
    ) -> DecryptingKey<KEY_LEN, IV_LEN, BLOCK_LEN> {
        DecryptingKey { cipher_key, iv }
    }

    pub fn decrypt(mut self, in_out: &mut [u8]) -> Result<usize, Unspecified> {
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

        Ok(final_len)
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

    #[test]
    fn test_aes_128_ctr() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let input = from_hex("00112233445566778899aabbccddeeff").unwrap();

        let cipher_key = CipherKey::new(&AES_128_CTR, &key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut ciphertext = input.clone();

        let decrypt_iv = encrypting_key.encrypt(&mut ciphertext).unwrap();

        let cipher_key2 = CipherKey::new(&AES_128_CTR, &key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        decrypting_key.decrypt(&mut ciphertext).unwrap();

        assert_eq!(input.as_slice(), ciphertext.as_slice());
    }

    #[test]
    fn test_aes_128_cbc_15_bytes() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let input = from_hex("00112233445566778899aabbccddee").unwrap();

        let cipher_key = CipherKey::new(&AES_128_CBC_PKCS7_PADDING, &key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut ciphertext = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut ciphertext).unwrap();

        let cipher_key2 = CipherKey::new(&AES_128_CBC_PKCS7_PADDING, &key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        let plaintext_len = decrypting_key.decrypt(&mut ciphertext).unwrap();
        let plaintext = ciphertext.as_slice();
        let plaintext = &plaintext[..plaintext_len];
        assert_eq!(input.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_128_cbc_16_bytes() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let input = from_hex("00112233445566778899aabbccddeeff").unwrap();

        let cipher_key = CipherKey::new(&AES_128_CBC_PKCS7_PADDING, &key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut ciphertext = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut ciphertext).unwrap();

        let cipher_key2 = CipherKey::new(&AES_128_CBC_PKCS7_PADDING, &key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        let plaintext_len = decrypting_key.decrypt(&mut ciphertext).unwrap();
        let plaintext = ciphertext.as_slice();
        let plaintext = &plaintext[..plaintext_len];
        assert_eq!(input.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_128_cbc_17_bytes() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let input = from_hex("00112233445566778899aabbccddeeff00").unwrap();

        let cipher_key = CipherKey::new(&AES_128_CBC_PKCS7_PADDING, &key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut ciphertext = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut ciphertext).unwrap();

        let cipher_key2 = CipherKey::new(&AES_128_CBC_PKCS7_PADDING, &key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        let plaintext_len = decrypting_key.decrypt(&mut ciphertext).unwrap();
        let plaintext = ciphertext.as_slice();
        let plaintext = &plaintext[..plaintext_len];
        assert_eq!(input.as_slice(), plaintext);
    }
}
