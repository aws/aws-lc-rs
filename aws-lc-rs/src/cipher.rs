// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(dead_code, unused_variables)]

pub(crate) mod aes;
pub(crate) mod block;
pub(crate) mod chacha;

use crate::cipher::aes::{encrypt_block_aes, Aes128Key, Aes256Key};
use crate::cipher::block::Block;
use crate::cipher::chacha::ChaCha20Key;
use crate::error::Unspecified;
use crate::iv::IV;
use crate::rand;
use aws_lc::{AES_set_encrypt_key, AES_KEY};
use std::mem::{size_of, transmute, MaybeUninit};
use std::os::raw::c_uint;
use std::ptr;
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128(Aes128Key, AES_KEY),
    Aes256(Aes256Key, AES_KEY),
    ChaCha20(ChaCha20Key),
}

unsafe impl Send for SymmetricCipherKey {}
// The AES_KEY value is only used as a `*const AES_KEY` in calls to `AES_encrypt`.
unsafe impl Sync for SymmetricCipherKey {}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        // Aes128Key, Aes256Key and ChaCha20Key implement Drop separately.
        match self {
            SymmetricCipherKey::Aes128(_, aes_key) | SymmetricCipherKey::Aes256(_, aes_key) => unsafe {
                #[allow(clippy::transmute_ptr_to_ptr)]
                let value: &mut [u8; size_of::<AES_KEY>()] = transmute(aes_key);
                value.zeroize();
            },
            SymmetricCipherKey::ChaCha20(_) => {}
        }
    }
}

enum AlgorithmId {
    Aes128ctr,
    Aes128cbc,
    Aes256ctr,
    Aes256cbc,
    Chacha20,
}
pub struct Algorithm<const KEYSIZE: usize, const IVSIZE: usize>(AlgorithmId);

pub const AES128_CTR: Algorithm<16, 16> = Algorithm(AlgorithmId::Aes128ctr);
pub const AES128_CBC: Algorithm<16, 16> = Algorithm(AlgorithmId::Aes128cbc);
pub const AES256_CTR: Algorithm<32, 16> = Algorithm(AlgorithmId::Aes256ctr);
pub const AES256_CBC: Algorithm<32, 16> = Algorithm(AlgorithmId::Aes256cbc);
pub const CHACHA20: Algorithm<32, 12> = Algorithm(AlgorithmId::Chacha20);

pub struct CipherKey<const KEYSIZE: usize, const IVSIZE: usize> {
    algorithm: &'static Algorithm<KEYSIZE, IVSIZE>,
    key: [u8; KEYSIZE],
}

impl<const KEYSIZE: usize, const IVSIZE: usize> CipherKey<KEYSIZE, IVSIZE> {
    fn new(
        algorithm: &'static Algorithm<KEYSIZE, IVSIZE>,
        key_bytes: &[u8],
    ) -> Result<Self, Unspecified> {
        let key = key_bytes.try_into()?;
        Ok(CipherKey { algorithm, key })
    }
}

pub struct EncryptingKey<const KEYSIZE: usize, const IVSIZE: usize> {
    cipher_key: CipherKey<KEYSIZE, IVSIZE>,
    iv: IV<IVSIZE>,
}

impl<const KEYSIZE: usize, const IVSIZE: usize> EncryptingKey<KEYSIZE, IVSIZE> {
    fn new(
        cipher_key: CipherKey<KEYSIZE, IVSIZE>,
    ) -> Result<EncryptingKey<KEYSIZE, IVSIZE>, Unspecified> {
        let mut iv_bytes = [0u8; IVSIZE];
        rand::fill(&mut iv_bytes)?;
        Ok(EncryptingKey {
            cipher_key,
            iv: IV::assume_unique_for_key(iv_bytes),
        })
    }

    #[must_use]
    fn encrypt_in_place(self, in_out: &mut [u8]) -> Result<IV<IVSIZE>, Unspecified> {
        // TODO: THIS IS A PROOF OF CONCEPT
        // do nothing
        Ok(self.iv)
    }

    fn encrypt_append_padding<INOUT>(self, in_out: INOUT) -> Result<IV<IVSIZE>, Unspecified>
    where
        INOUT: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        todo!()
    }
}

pub struct DecryptingKey<const KEYSIZE: usize, const IVSIZE: usize> {
    cipher_key: CipherKey<KEYSIZE, IVSIZE>,
    iv: IV<IVSIZE>,
}

impl<const KEYSIZE: usize, const IVSIZE: usize> DecryptingKey<KEYSIZE, IVSIZE> {
    fn new(
        cipher_key: CipherKey<KEYSIZE, IVSIZE>,
        iv: IV<IVSIZE>,
    ) -> DecryptingKey<KEYSIZE, IVSIZE> {
        DecryptingKey { cipher_key, iv }
    }

    fn decrypt_in_place(&self, in_out: &mut [u8]) -> Result<(), Unspecified> {
        // TODO: THIS IS A PROOF OF CONCEPT
        // do nothing
        Ok(())
    }
}

impl SymmetricCipherKey {
    pub(crate) fn aes128(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 16 {
            return Err(Unspecified);
        }

        unsafe {
            let mut aes_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                aes_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let aes_key = aes_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 16]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 16);
            Ok(SymmetricCipherKey::Aes128(
                Aes128Key(kb.assume_init()),
                aes_key,
            ))
        }
    }

    pub(crate) fn aes256(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        unsafe {
            let mut aes_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                aes_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let aes_key = aes_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 32]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256(
                Aes256Key(kb.assume_init()),
                aes_key,
            ))
        }
    }

    pub(crate) fn chacha20(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::ChaCha20(ChaCha20Key(kb.assume_init())))
        }
    }

    #[inline]
    pub(super) fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::Aes128(bytes, ..) => &bytes.0,
            SymmetricCipherKey::Aes256(bytes, ..) => &bytes.0,
            SymmetricCipherKey::ChaCha20(bytes) => &bytes.0,
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn encrypt_block(&self, block: Block) -> Block {
        match self {
            SymmetricCipherKey::Aes128(.., aes_key) | SymmetricCipherKey::Aes256(.., aes_key) => {
                encrypt_block_aes(aes_key, block)
            }
            SymmetricCipherKey::ChaCha20(..) => panic!("Unsupported algorithm!"),
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
        let mut input = from_hex("00112233445566778899aabbccddeeff").unwrap();

        let cipher_key = CipherKey::new(&AES128_CTR, &key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut inout = input.as_mut_slice();

        let decrypt_iv = encrypting_key.encrypt_in_place(inout).unwrap();

        let cipher_key2 = CipherKey::new(&AES128_CTR, &key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        decrypting_key.decrypt_in_place(inout);
    }

    #[test]
    fn test_aes_128_cbc() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut input = from_hex("00112233445566778899aabbccddeeff").unwrap();

        let cipher_key = CipherKey::new(&AES128_CBC, &key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut inout = input.as_mut_slice();
        let decrypt_iv = encrypting_key.encrypt_in_place(inout).unwrap();

        let cipher_key2 = CipherKey::new(&AES128_CBC, &key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        decrypting_key.decrypt_in_place(inout);
    }
}
