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
//! use aws_lc_rs::cipher::{UnboundCipherKey, DecryptingKey, EncryptingKey, AES_128_CTR};
//!
//! let mut plaintext = Vec::from("This is a secret message!");
//!
//! let key_bytes: &[u8] = &[
//!     0xff, 0x0b, 0xe5, 0x84, 0x64, 0x0b, 0x00, 0xc8, 0x90, 0x7a, 0x4b, 0xbf, 0x82, 0x7c, 0xb6,
//!     0xd1,
//! ];
//!
//! let key = UnboundCipherKey::new(&AES_128_CTR, key_bytes).unwrap();
//! let encrypting_key = EncryptingKey::new(key).unwrap();
//! let iv = encrypting_key.encrypt(&mut plaintext).unwrap();
//!
//! let key = UnboundCipherKey::new(&AES_128_CTR, key_bytes).unwrap();
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
use crate::iv::{FixedLength, NonceIV};
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

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum PaddingStrategy {
    NoPadding,
    PKCS7,
}

impl OperatingMode {
    fn add_padding<InOut>(self, block_len: usize, in_out: &mut InOut) -> Result<(), Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        match self {
            OperatingMode::Block(strategy) => match strategy {
                PaddingStrategy::PKCS7 => {
                    let in_out_len = in_out.as_mut().len();
                    // This implements PKCS#7 padding scheme, used by aws-lc if we were using EVP_CIPHER API's
                    let remainder = in_out_len % block_len;
                    if remainder == 0 {
                        let block_size: u8 = block_len.try_into().map_err(|_| Unspecified)?;
                        in_out.extend(vec![block_size; block_len].iter());
                    } else {
                        let padding_size = block_len - remainder;
                        let v: u8 = padding_size.try_into().map_err(|_| Unspecified)?;
                        // Heap allocation :(
                        in_out.extend(vec![v; padding_size].iter());
                    }
                }
                PaddingStrategy::NoPadding => {}
            },
            OperatingMode::Stream => {}
        }
        Ok(())
    }

    fn remove_padding(self, block_len: usize, in_out: &mut [u8]) -> Result<&mut [u8], Unspecified> {
        match self {
            OperatingMode::Block(strategy) => match strategy {
                PaddingStrategy::PKCS7 => {
                    let block_size: u8 = block_len.try_into().map_err(|_| Unspecified)?;

                    if in_out.is_empty() || in_out.len() < block_len {
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

                    let final_len = in_out.len() - padding as usize;
                    Ok(&mut in_out[0..final_len])
                }
                PaddingStrategy::NoPadding => Ok(in_out),
            },
            OperatingMode::Stream => Ok(in_out),
        }
    }
}

#[derive(Clone, Copy)]
enum OperatingMode {
    Block(PaddingStrategy),
    Stream,
}

/// A cipher configuration description.
pub struct CipherConfig<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>(
    OperatingMode,
);

/// The number of bytes in an AES 128-bit key
pub const AES_128_KEY_LEN: usize = 16;

/// The number of bytes in an AES 256-bit key
pub const AES_256_KEY_LEN: usize = 32;

/// The number of bytes for an AES initalization vector (IV)
pub const AES_IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

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
///l
pub enum Algorithm {
    /// AES-128 Counter (CTR) Mode
    Aes128Ctr(CipherConfig<AES_128_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN>),

    /// AES-256 Counter (CTR) Mode
    Aes256Ctr(CipherConfig<AES_256_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN>),

    /// AES-128 Cipher block chaining (CBC) Mode
    Aes128CbcPkcs7Padding(CipherConfig<AES_128_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN>),

    /// AES-256 Cipher block chaining (CBC) Mode
    Aes256CbcPkcs7Padding(CipherConfig<AES_256_KEY_LEN, AES_IV_LEN, AES_BLOCK_LEN>),
}

impl Algorithm {
    fn get_operating_mode(&self) -> &OperatingMode {
        match self {
            Algorithm::Aes128Ctr(v) | Algorithm::Aes128CbcPkcs7Padding(v) => v.get_operating_mode(),
            Algorithm::Aes256Ctr(v) | Algorithm::Aes256CbcPkcs7Padding(v) => v.get_operating_mode(),
        }
    }

    fn get_block_len(&self) -> usize {
        match self {
            Algorithm::Aes128Ctr(v) | Algorithm::Aes128CbcPkcs7Padding(v) => v.get_block_len(),
            Algorithm::Aes256Ctr(v) | Algorithm::Aes256CbcPkcs7Padding(v) => v.get_block_len(),
        }
    }

    #[allow(clippy::unused_self)]
    fn new_randomized_nonce(&self) -> Result<NonceIV, Unspecified> {
        Ok(NonceIV::Size128(FixedLength::<16>::new()?))
    }

    fn new_symmetric_cipher_key(
        &self,
        key_bytes: &[u8],
    ) -> Result<SymmetricCipherKey, Unspecified> {
        match self {
            Algorithm::Aes128Ctr(v) | Algorithm::Aes128CbcPkcs7Padding(v) => {
                let key = v.try_into_key(key_bytes)?;
                SymmetricCipherKey::aes128(key)
            }
            Algorithm::Aes256Ctr(v) | Algorithm::Aes256CbcPkcs7Padding(v) => {
                let key = v.try_into_key(key_bytes)?;
                SymmetricCipherKey::aes256(key)
            }
        }
    }

    fn prepare_for_encrypt<InOut>(&self, in_out: &mut InOut) -> Result<(), Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.get_operating_mode()
            .add_padding(self.get_block_len(), in_out)?;
        Ok(())
    }

    fn finalalize_decryption<'a>(&self, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Unspecified> {
        let in_out = self
            .get_operating_mode()
            .remove_padding(self.get_block_len(), in_out.as_mut())?;
        Ok(in_out)
    }

    const fn max_block_len() -> usize {
        16
    }

    const fn max_iv_len() -> usize {
        16
    }
}

/// AES-128 Counter (CTR) Mode
pub const AES_128_CTR: Algorithm = Algorithm::Aes128Ctr(CipherConfig(OperatingMode::Stream));

/// AES-128 Cipher block chaining (CBC) Mode using PKCS#7 padding.
pub const AES_128_CBC_PKCS7_PADDING: Algorithm =
    Algorithm::Aes128CbcPkcs7Padding(CipherConfig(OperatingMode::Block(PaddingStrategy::PKCS7)));

/// AES-256 Counter (CTR) Mode
pub const AES_256_CTR: Algorithm = Algorithm::Aes256Ctr(CipherConfig(OperatingMode::Stream));

/// AES-256 Cipher block chaining (CBC) Mode using PKCS#7 padding.
pub const AES_256_CBC_PKCS7_PADDING: Algorithm =
    Algorithm::Aes256CbcPkcs7Padding(CipherConfig(OperatingMode::Block(PaddingStrategy::PKCS7)));

const MAX_BLOCK_LEN: usize = 16;

impl<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>
    CipherConfig<KEY_LEN, IV_LEN, BLOCK_LEN>
{
    #[inline]
    fn get_operating_mode(&self) -> &OperatingMode {
        &self.0
    }

    #[allow(clippy::unused_self)]
    fn try_into_key<'a>(&self, key: &'a [u8]) -> Result<&'a [u8; KEY_LEN], Unspecified> {
        let key: &'a [u8; KEY_LEN] = key.try_into()?;
        Ok(key)
    }

    #[allow(clippy::unused_self)]
    fn get_block_len(&self) -> usize {
        BLOCK_LEN
    }
}

/// A key bound to a particular cipher algorithm.
pub struct UnboundCipherKey {
    algorithm: &'static Algorithm,
    key: SymmetricCipherKey,
}

impl UnboundCipherKey {
    /// Constructs a [`UnboundCipherKey`].
    ///
    /// # Errors
    ///
    /// * [`Unspecified`] if `key_bytes.len()` does not match the
    /// length required by `algorithm`.
    ///
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let key = algorithm.new_symmetric_cipher_key(key_bytes)?;
        Ok(UnboundCipherKey { algorithm, key })
    }

    #[inline]
    fn get_algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// An encryting cipher key.
pub struct EncryptingKey {
    cipher_key: UnboundCipherKey,
    iv: NonceIV,
}

impl EncryptingKey {
    /// Constructs a new [`EncryptingKey`].
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if a randomized IV fails to be generated.
    ///
    pub fn new(key: UnboundCipherKey) -> Result<EncryptingKey, Unspecified> {
        let iv = key.get_algorithm().new_randomized_nonce()?;
        Ok(EncryptingKey {
            cipher_key: key,
            iv,
        })
    }

    /// Encrypts the data `in_out` in-place. If the algorithm bound to this key uses padding
    /// then the `in_out` will be extended to add the necessary padding.
    ///
    /// Returns the initialization vector necessary to later decrypt the data.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if the data fails to be encrypted.
    ///
    pub fn encrypt<InOut>(self, in_out: &mut InOut) -> Result<NonceIV, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        encrypt(
            self.cipher_key.get_algorithm(),
            &self.cipher_key.key,
            self.iv,
            in_out,
        )
    }
}

/// An decrypting cipher key.
pub struct DecryptingKey {
    cipher_key: UnboundCipherKey,
    iv: NonceIV,
}

impl DecryptingKey {
    /// Constructs a new [`DecryptingKey`].
    #[must_use]
    pub fn new(cipher_key: UnboundCipherKey, iv: NonceIV) -> DecryptingKey {
        DecryptingKey { cipher_key, iv }
    }

    /// Decrypts the data `in_out` in-place.
    ///
    /// Returns a slice reference to the decrypted data within `in_out`. If the algorithm bound to
    /// this key uses padding then the returned slice reference is length adjusted to exclude
    /// the padding bytes.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if the data fails to be decrypted.
    ///
    #[allow(unused_mut)]
    pub fn decrypt(mut self, in_out: &mut [u8]) -> Result<&mut [u8], Unspecified> {
        decrypt(
            self.cipher_key.algorithm,
            &self.cipher_key.key,
            self.iv,
            in_out,
        )
    }
}

/// Less safe cipher key that allows for specifying a user provided [`NonceIV`].
pub struct LessSafeCipherKey {
    algorithm: &'static Algorithm,
    key: SymmetricCipherKey,
}

impl LessSafeCipherKey {
    /// Constructs a new [`LessSafeCipherKey`].
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if `key_bytes` is not the proper byte length for the selected algorithm.
    ///
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let key = algorithm.new_symmetric_cipher_key(key_bytes)?;
        Ok(LessSafeCipherKey { algorithm, key })
    }

    /// Encrypts the data `in_out` in-place. If the algorithm bound to this key uses padding
    /// then the `in_out` will be extended to add the necessary padding.
    ///
    /// Returns the initialization vector necessary to later decrypt the data.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if the data fails to be encrypted.
    ///
    pub fn encrypt<InOut>(&self, iv: NonceIV, in_out: &mut InOut) -> Result<NonceIV, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        encrypt(self.algorithm, &self.key, iv, in_out)
    }

    /// Decrypts the data `in_out` in-place.
    ///
    /// Returns a slice reference to the decrypted data within `in_out`. If the algorithm bound to
    /// this key uses padding then the returned slice reference is length adjusted to exclude
    /// the padding bytes.
    ///
    /// # Errors
    ///
    /// * [`Unspecified`]: Returned if the data fails to be decrypted.
    ///
    #[allow(unused_mut)]
    pub fn decrypt<'a>(
        &self,
        iv: NonceIV,
        in_out: &'a mut [u8],
    ) -> Result<&'a mut [u8], Unspecified> {
        decrypt(self.algorithm, &self.key, iv, in_out)
    }
}

fn encrypt<InOut>(
    algorithm: &'static Algorithm,
    key: &SymmetricCipherKey,
    iv: NonceIV,
    in_out: &mut InOut,
) -> Result<NonceIV, Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    algorithm.prepare_for_encrypt(in_out)?;

    let in_out = in_out.as_mut();

    let mut ivec = [0u8; Algorithm::max_iv_len()];
    ivec.copy_from_slice(iv.as_ref());

    let mut buf = [0u8; Algorithm::max_block_len()];

    // This works b/c we currently only support AES keys
    let aes_key = match key {
        SymmetricCipherKey::Aes128 { enc_key, .. } | SymmetricCipherKey::Aes256 { enc_key, .. } => {
            Ok(enc_key)
        }
        SymmetricCipherKey::ChaCha20 { .. } => Err(Unspecified),
    }?;

    match algorithm {
        Algorithm::Aes128Ctr(..) | Algorithm::Aes256Ctr(..) => {
            aes_ctr128_encrypt(aes_key, &mut ivec, &mut buf, in_out);
        }
        Algorithm::Aes128CbcPkcs7Padding(..) | Algorithm::Aes256CbcPkcs7Padding(..) => {
            aes_cbc_encrypt(aes_key, &mut ivec, in_out);
        }
    }
    Ok(iv)
}

fn aes_ctr128_encrypt(key: &AES_KEY, iv: &mut [u8], block_buffer: &mut [u8], in_out: &mut [u8]) {
    let mut num = MaybeUninit::<u32>::new(0);

    unsafe {
        AES_ctr128_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            block_buffer.as_mut_ptr(),
            num.as_mut_ptr(),
        );
    };

    Zeroize::zeroize(block_buffer);
}

fn aes_cbc_encrypt(key: &AES_KEY, iv: &mut [u8], in_out: &mut [u8]) {
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

fn aes_cbc_decrypt(key: &AES_KEY, iv: &mut [u8], in_out: &mut [u8]) {
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

fn decrypt<'a>(
    algorithm: &'static Algorithm,
    key: &SymmetricCipherKey,
    mut iv: NonceIV,
    in_out: &'a mut [u8],
) -> Result<&'a mut [u8], Unspecified> {
    let iv = iv.as_mut();

    match algorithm {
        Algorithm::Aes128Ctr(v) => {
            let key = match key {
                SymmetricCipherKey::Aes128 { enc_key, .. } => enc_key,
                _ => return Err(Unspecified),
            };

            let mut buf = [0u8; MAX_BLOCK_LEN];

            assert!(buf.len() >= v.get_block_len());

            aes_ctr128_encrypt(key, iv, &mut buf, in_out);
        }
        Algorithm::Aes256Ctr(v) => {
            let key = match key {
                SymmetricCipherKey::Aes256 { enc_key, .. } => enc_key,
                _ => return Err(Unspecified),
            };

            let mut buf = [0u8; MAX_BLOCK_LEN];

            assert!(buf.len() >= v.get_block_len());

            aes_ctr128_encrypt(key, iv, &mut buf, in_out);
        }
        Algorithm::Aes128CbcPkcs7Padding(_) => {
            let key = match key {
                SymmetricCipherKey::Aes128 { dec_key, .. } => dec_key,
                _ => return Err(Unspecified),
            };

            aes_cbc_decrypt(key, iv, in_out);
        }
        Algorithm::Aes256CbcPkcs7Padding(_) => {
            let key = match key {
                SymmetricCipherKey::Aes256 { dec_key, .. } => dec_key,
                _ => return Err(Unspecified),
            };
            aes_cbc_decrypt(key, iv, in_out);
        }
    }

    let in_out = algorithm.finalalize_decryption(in_out)?;

    Ok(in_out)
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

    fn helper_test_cipher_n_bytes(key: &[u8], alg: &'static Algorithm, n: usize) {
        let mut input: Vec<u8> = Vec::with_capacity(n);
        for i in 0..n {
            let byte: u8 = i.try_into().unwrap();
            input.push(byte);
        }

        let cipher_key = UnboundCipherKey::new(alg, key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key).unwrap();

        let mut in_out = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut in_out).unwrap();

        if n > 5 {
            // There's no more than a 1 in 2^48 chance that this will fail randomly
            assert_ne!(input.as_slice(), in_out);
        }

        let cipher_key2 = UnboundCipherKey::new(alg, key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

        let plaintext = decrypting_key.decrypt(&mut in_out).unwrap();
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
        for i in 0..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_128_CTR, i);
        }
    }

    #[test]
    fn test_aes_256_ctr() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
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
                    let mut iv = [0u8; $iv.len() / 2];
                    {
                        let x = iv.as_mut_slice();
                        x.copy_from_slice(slice);
                    }
                    iv
                };

                let alg = $cipher;
                let encrypting_key = LessSafeCipherKey::new(alg, &key).unwrap();

                let mut in_out = input.clone();
                let decrypt_iv = encrypting_key
                    .encrypt(NonceIV::try_from(iv).unwrap(), &mut in_out)
                    .unwrap();
                assert_eq!(expected_ciphertext, in_out);

                let cipher_key2 = UnboundCipherKey::new(alg, &key).unwrap();
                let decrypting_key = DecryptingKey::new(cipher_key2, decrypt_iv);

                let plaintext = decrypting_key.decrypt(&mut in_out).unwrap();
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
