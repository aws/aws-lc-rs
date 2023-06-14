// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Block and Stream Ciphers for Encryption and Decryption.
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
//!
//! ## AES-128 CBC Mode Encryption
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use std::io::Read;
//! use aws_lc_rs::cipher::{
//!     PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey, AES_128,
//! };
//!
//! let original_message = "This is a secret message!".as_bytes();
//! let mut in_out_buffer = Vec::from(original_message);
//!
//! let key_bytes: &[u8] = &[
//!     0xff, 0x0b, 0xe5, 0x84, 0x64, 0x0b, 0x00, 0xc8, 0x90, 0x7a, 0x4b, 0xbf, 0x82, 0x7c, 0xb6,
//!     0xd1,
//! ];
//!
//! let key = UnboundCipherKey::new(&AES_128, key_bytes)?;
//! let mut encrypting_key = PaddedBlockEncryptingKey::cbc_pkcs7(key)?;
//! let context = encrypting_key.encrypt(&mut in_out_buffer)?;
//!
//! let key = UnboundCipherKey::new(&AES_128, key_bytes)?;
//! let mut decrypting_key = PaddedBlockDecryptingKey::cbc_pkcs7(key)?;
//! let plaintext = decrypting_key.decrypt(&mut in_out_buffer, context)?;
//! assert_eq!(original_message, plaintext);
//! #
//! #
//! # Ok(())
//! # }
//! ```
//!
//! ## AES-128 CTR Mode Encryption
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::cipher::{DecryptingKey, EncryptingKey, UnboundCipherKey, AES_128};
//!
//! let original_message = "This is a secret message!".as_bytes();
//! let mut in_out_buffer = Vec::from(original_message);
//!
//! let key_bytes: &[u8] = &[
//!     0xff, 0x0b, 0xe5, 0x84, 0x64, 0x0b, 0x00, 0xc8, 0x90, 0x7a, 0x4b, 0xbf, 0x82, 0x7c, 0xb6,
//!     0xd1,
//! ];
//!
//! let key = UnboundCipherKey::new(&AES_128, key_bytes)?;
//! let mut encrypting_key = EncryptingKey::ctr(key)?;
//! let context = encrypting_key.encrypt(&mut in_out_buffer)?;
//!
//! let key = UnboundCipherKey::new(&AES_128, key_bytes)?;
//! let mut decrypting_key = DecryptingKey::ctr(key)?;
//! let plaintext = decrypting_key.decrypt(&mut in_out_buffer, context)?;
//! assert_eq!(original_message, plaintext);
//! #
//! # Ok(())
//! # }
//! ```
//!

#![allow(clippy::module_name_repetitions)]

pub(crate) mod aes;
pub(crate) mod block;
pub(crate) mod chacha;
pub(crate) mod key;

use crate::error::Unspecified;
use crate::hkdf;
use crate::hkdf::KeyType;
use crate::iv::FixedLength;
use aws_lc::{AES_cbc_encrypt, AES_ctr128_encrypt, AES_DECRYPT, AES_ENCRYPT, AES_KEY};
use key::SymmetricCipherKey;
use std::fmt::Debug;
use std::mem::MaybeUninit;
use zeroize::Zeroize;

/// The cipher block padding strategy.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum PaddingStrategy {
    /// PKCS#7 Padding. ([See RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652#section-6.3))
    PKCS7,
}

impl PaddingStrategy {
    fn add_padding<InOut>(self, block_len: usize, in_out: &mut InOut) -> Result<(), Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        match self {
            PaddingStrategy::PKCS7 => {
                let mut padding_buffer = [0u8; MAX_CIPHER_BLOCK_LEN];

                let in_out_len = in_out.as_mut().len();
                // This implements PKCS#7 padding scheme, used by aws-lc if we were using EVP_CIPHER API's
                let remainder = in_out_len % block_len;
                let padding_size = block_len - remainder;
                let v: u8 = padding_size.try_into().map_err(|_| Unspecified)?;
                padding_buffer.fill(v);
                // Possible heap allocation here :(
                in_out.extend(padding_buffer[0..padding_size].iter());
            }
        }
        Ok(())
    }

    fn remove_padding(self, block_len: usize, in_out: &mut [u8]) -> Result<&mut [u8], Unspecified> {
        match self {
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
        }
    }
}

/// The number of bytes in an AES 128-bit key
pub const AES_128_KEY_LEN: usize = 16;

/// The number of bytes in an AES 256-bit key
pub const AES_256_KEY_LEN: usize = 32;

const MAX_CIPHER_KEY_LEN: usize = AES_256_KEY_LEN;

/// The number of bytes for an AES-CBC initialization vector (IV)
pub const AES_CBC_IV_LEN: usize = 16;

/// The number of bytes for an AES-CTR initialization vector (IV)
pub const AES_CTR_IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

const MAX_CIPHER_BLOCK_LEN: usize = AES_BLOCK_LEN;

const IV_LEN_128_BIT: usize = 16;

/// The cipher operating mode.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OperatingMode {
    /// Cipher block chaining (CBC) mode.
    CBC,

    /// Counter (CTR) mode.
    CTR,
}

/// The contextual data used to encrypted/decrypt data.
///
/// # Examples
///
/// ## Constructing a `CipherContext` for decryption.
///
/// ```rust
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use aws_lc_rs::cipher::{CipherContext, DecryptingKey, UnboundCipherKey, AES_128};
/// use aws_lc_rs::iv::FixedLength;
///
/// let context = CipherContext::Iv128(FixedLength::<16>::from(&[
///     0x8d, 0xdb, 0x7d, 0xf1, 0x56, 0xf5, 0x1c, 0xde, 0x63, 0xe3, 0x4a, 0x34, 0xb0, 0xdf, 0x28,
///     0xf0,
/// ]));
///
/// let ciphertext: &[u8] = &[
///     0x79, 0x8c, 0x04, 0x58, 0xcf, 0x98, 0xb1, 0xe9, 0x97, 0x6b, 0xa1, 0xce,
/// ];
///
/// let mut in_out_buffer = Vec::from(ciphertext);
///
/// let key = UnboundCipherKey::new(
///     &AES_128,
///     &[
///         0x5b, 0xfc, 0xe7, 0x5e, 0x57, 0xc5, 0x4d, 0xda, 0x2d, 0xd4, 0x7e, 0x07, 0x0a, 0xef,
///         0x43, 0x29,
///     ],
/// )?;
/// let mut decrypting_key = DecryptingKey::ctr(key)?;
/// let plaintext = decrypting_key.decrypt(&mut in_out_buffer, context)?;
/// assert_eq!("Hello World!".as_bytes(), plaintext);
///
///     # Ok(())
/// # }
/// ```
///
/// ## Getting an immutable reference to an IV slice.
///
/// `CipherContext` implements `TryFrom<&CipherContext>` for `&[u8]` allowing immutable references
/// to IV bytes returned from cipher encryption operations.
///
/// ```rust
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use aws_lc_rs::cipher::CipherContext;
/// # use aws_lc_rs::cipher::{EncryptingKey, UnboundCipherKey, AES_128};
/// # let original_message = "Hello World!".as_bytes();
/// # let mut in_out_buffer = Vec::from(original_message);
/// # let key_bytes: &[u8] = &[
/// #    0x68, 0xf9, 0x46, 0x1a, 0xde, 0x8d, 0x35, 0x38, 0x7b, 0x50, 0xcc, 0x9a, 0x36, 0x64, 0xf8,
/// #    0x9d,
/// # ];
/// # let key = UnboundCipherKey::new(&AES_128, key_bytes)?;
/// # let mut encrypting_key = EncryptingKey::ctr(key)?;
/// #
/// let context: CipherContext = encrypting_key.encrypt(&mut in_out_buffer)?;
/// let iv_bytes: &[u8] = (&context).try_into()?;
/// assert_eq!(16, iv_bytes.len());
/// #
/// #    Ok(())
/// # }
/// ```
///
///
#[non_exhaustive]
pub enum CipherContext {
    /// A 128-bit Initialization Vector.
    Iv128(FixedLength<IV_LEN_128_BIT>),

    /// No input to the cipher mode.
    None,
}

impl<'a> TryFrom<&'a CipherContext> for &'a [u8] {
    type Error = Unspecified;

    fn try_from(value: &'a CipherContext) -> Result<Self, Unspecified> {
        match value {
            CipherContext::Iv128(iv) => Ok(iv.as_ref()),
            CipherContext::None => Err(Unspecified),
        }
    }
}

impl Debug for CipherContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iv128(_) => write!(f, "Iv128"),
            Self::None => write!(f, "None"),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Cipher algorithm identifier.
pub enum AlgorithmId {
    /// AES 128-bit
    Aes128,

    /// AES 256-bit
    Aes256,
}

/// A cipher algorithm.
#[derive(Debug, PartialEq, Eq)]
pub struct Algorithm {
    id: AlgorithmId,
    key_len: usize,
    block_len: usize,
}

/// AES 128-bit cipher
pub static AES_128: Algorithm = Algorithm {
    id: AlgorithmId::Aes128,
    key_len: AES_128_KEY_LEN,
    block_len: AES_BLOCK_LEN,
};

/// AES 256-bit cipher
pub static AES_256: Algorithm = Algorithm {
    id: AlgorithmId::Aes256,
    key_len: AES_256_KEY_LEN,
    block_len: AES_BLOCK_LEN,
};

impl Algorithm {
    fn id(&self) -> &AlgorithmId {
        &self.id
    }

    const fn block_len(&self) -> usize {
        self.block_len
    }

    fn new_cipher_context(&self, mode: OperatingMode) -> Result<CipherContext, Unspecified> {
        match self.id {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => match mode {
                OperatingMode::CBC | OperatingMode::CTR => {
                    Ok(CipherContext::Iv128(FixedLength::new()?))
                }
            },
        }
    }

    fn is_valid_cipher_context(&self, mode: OperatingMode, input: &CipherContext) -> bool {
        match self.id {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => match mode {
                OperatingMode::CBC | OperatingMode::CTR => {
                    matches!(input, CipherContext::Iv128(_))
                }
            },
        }
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for UnboundCipherKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundCipherKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundCipherKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_CIPHER_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}

impl KeyType for &'static Algorithm {
    fn len(&self) -> usize {
        self.key_len
    }
}

/// A key bound to a particular cipher algorithm.
pub struct UnboundCipherKey {
    algorithm: &'static Algorithm,
    key: SymmetricCipherKey,
}

impl UnboundCipherKey {
    /// Constructs an [`UnboundCipherKey`].
    ///
    /// # Errors
    ///
    /// * [`Unspecified`] if `key_bytes.len()` does not match the
    /// length required by `algorithm`.
    ///
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let key = match algorithm.id() {
            AlgorithmId::Aes128 => SymmetricCipherKey::aes128(key_bytes),
            AlgorithmId::Aes256 => SymmetricCipherKey::aes256(key_bytes),
        }?;
        Ok(UnboundCipherKey { algorithm, key })
    }

    #[inline]
    #[must_use]
    /// Returns the algorithm associated with this key.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// A cipher encryption key that performs block padding.
pub struct PaddedBlockEncryptingKey {
    key: UnboundCipherKey,
    mode: OperatingMode,
    padding: PaddingStrategy,
}

impl PaddedBlockEncryptingKey {
    /// Constructs a new `PaddedBlockEncryptingKey` cipher with chaining block cipher (CBC) mode.
    /// Plaintext data is padded following the PKCS#7 scheme.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if there is an error cosntructing a `PaddedBlockEncryptingKey`.
    ///
    pub fn cbc_pkcs7(key: UnboundCipherKey) -> Result<PaddedBlockEncryptingKey, Unspecified> {
        PaddedBlockEncryptingKey::new(key, OperatingMode::CBC, PaddingStrategy::PKCS7)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new(
        key: UnboundCipherKey,
        mode: OperatingMode,
        padding: PaddingStrategy,
    ) -> Result<PaddedBlockEncryptingKey, Unspecified> {
        Ok(PaddedBlockEncryptingKey { key, mode, padding })
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &Algorithm {
        self.key.algorithm()
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Pads and encrypts data provided in `in_out` in-place.
    /// Returns a references to the encryted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if encryption fails.
    ///
    pub fn encrypt<InOut>(&self, in_out: &mut InOut) -> Result<CipherContext, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'a> Extend<&'a u8>,
    {
        let context = self.key.algorithm.new_cipher_context(self.mode)?;
        self.less_safe_encrypt(in_out, context)
    }

    /// Pads and encrypts data provided in `in_out` in-place.
    /// Returns a references to the encryted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if encryption fails.
    ///
    pub fn less_safe_encrypt<InOut>(
        &self,
        in_out: &mut InOut,
        context: CipherContext,
    ) -> Result<CipherContext, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'a> Extend<&'a u8>,
    {
        if !self
            .key
            .algorithm()
            .is_valid_cipher_context(self.mode, &context)
        {
            return Err(Unspecified);
        }

        self.padding
            .add_padding(self.algorithm().block_len(), in_out)?;
        encrypt(&self.key, self.mode, in_out.as_mut(), context)
    }
}

impl Debug for PaddedBlockEncryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaddedBlockEncryptingKey")
            .field("key", &self.key)
            .field("mode", &self.mode)
            .field("padding", &self.padding)
            .finish()
    }
}

/// A cipher decryption key that performs block padding.
pub struct PaddedBlockDecryptingKey {
    key: UnboundCipherKey,
    mode: OperatingMode,
    padding: PaddingStrategy,
}

impl PaddedBlockDecryptingKey {
    /// Constructs a new `PaddedBlockDecryptingKey` cipher with chaining block cipher (CBC) mode.
    /// Decrypted data is unpadded following the PKCS#7 scheme.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if there is an error constructing the `PaddedBlockDecryptingKey`.
    ///
    pub fn cbc_pkcs7(key: UnboundCipherKey) -> Result<PaddedBlockDecryptingKey, Unspecified> {
        PaddedBlockDecryptingKey::new(key, OperatingMode::CBC, PaddingStrategy::PKCS7)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new(
        key: UnboundCipherKey,
        mode: OperatingMode,
        padding: PaddingStrategy,
    ) -> Result<PaddedBlockDecryptingKey, Unspecified> {
        Ok(PaddedBlockDecryptingKey { key, mode, padding })
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &Algorithm {
        self.key.algorithm()
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Decrypts and unpads data provided in `in_out` in-place.
    /// Returns a references to the decrypted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if decryption fails.
    ///
    pub fn decrypt<'in_out>(
        &self,
        in_out: &'in_out mut [u8],
        context: CipherContext,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        if !self
            .key
            .algorithm()
            .is_valid_cipher_context(self.mode, &context)
        {
            return Err(Unspecified);
        }

        let block_len = self.algorithm().block_len();
        let padding = self.padding;
        let mut in_out = decrypt(&self.key, self.mode, in_out, context)?;
        in_out = padding.remove_padding(block_len, in_out)?;
        Ok(in_out)
    }
}

impl Debug for PaddedBlockDecryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaddedBlockDecryptingKey")
            .field("key", &self.key)
            .field("mode", &self.mode)
            .field("padding", &self.padding)
            .finish()
    }
}

/// A cipher encryption key that does not perform block padding.
pub struct EncryptingKey {
    key: UnboundCipherKey,
    mode: OperatingMode,
}

impl EncryptingKey {
    /// Constructs an `EncryptingKey` operating in counter (CTR) mode using the provided key.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if there is an error constructing the `EncryptingKey`.
    ///
    pub fn ctr(key: UnboundCipherKey) -> Result<EncryptingKey, Unspecified> {
        EncryptingKey::new(key, OperatingMode::CTR)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new(key: UnboundCipherKey, mode: OperatingMode) -> Result<EncryptingKey, Unspecified> {
        Ok(EncryptingKey { key, mode })
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &Algorithm {
        self.key.algorithm()
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Encrypts the data provided in `in_out` in-place.
    /// Returns a references to the decrypted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if cipher mode requires input to be a multiple of the block length,
    /// and `in_out.len()` is not. Otherwise returned if encryption fails.
    ///
    pub fn encrypt(&self, in_out: &mut [u8]) -> Result<CipherContext, Unspecified> {
        let context = self.key.algorithm.new_cipher_context(self.mode)?;
        self.less_safe_encrypt(in_out, context)
    }

    /// Encrypts the data provided in `in_out` in-place using the provided `CipherContext`.
    /// Returns a references to the decrypted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if cipher mode requires input to be a multiple of the block length,
    /// and `in_out.len()` is not. Otherwise returned if encryption fails.
    ///
    pub fn less_safe_encrypt(
        &self,
        in_out: &mut [u8],
        context: CipherContext,
    ) -> Result<CipherContext, Unspecified> {
        if !self
            .key
            .algorithm()
            .is_valid_cipher_context(self.mode, &context)
        {
            return Err(Unspecified);
        }
        encrypt(&self.key, self.mode, in_out, context)
    }
}

impl Debug for EncryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingKey")
            .field("key", &self.key)
            .field("mode", &self.mode)
            .finish()
    }
}

/// A cipher decryption key that does not perform block padding.
pub struct DecryptingKey {
    key: UnboundCipherKey,
    mode: OperatingMode,
}

impl DecryptingKey {
    /// Constructs a cipher decrypting key operating in counter (CTR) mode using the provided key and context.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if there is an error during decryption.
    ///
    pub fn ctr(key: UnboundCipherKey) -> Result<DecryptingKey, Unspecified> {
        DecryptingKey::new(key, OperatingMode::CTR)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new(key: UnboundCipherKey, mode: OperatingMode) -> Result<DecryptingKey, Unspecified> {
        Ok(DecryptingKey { key, mode })
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &Algorithm {
        self.key.algorithm()
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Decrypts the data provided in `in_out` in-place.
    /// Returns a references to the decrypted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if cipher mode requires input to be a multiple of the block length,
    /// and `in_out.len()` is not. Also returned if decryption fails.
    ///
    pub fn decrypt<'in_out>(
        &self,
        in_out: &'in_out mut [u8],
        context: CipherContext,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        decrypt(&self.key, self.mode, in_out, context)
    }
}

impl Debug for DecryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptingKey")
            .field("key", &self.key)
            .field("mode", &self.mode)
            .finish()
    }
}

fn encrypt(
    key: &UnboundCipherKey,
    mode: OperatingMode,
    in_out: &mut [u8],
    context: CipherContext,
) -> Result<CipherContext, Unspecified> {
    let block_len = key.algorithm().block_len();

    match mode {
        OperatingMode::CTR => {}
        _ => {
            if (in_out.len() % block_len) != 0 {
                return Err(Unspecified);
            }
        }
    }

    match mode {
        OperatingMode::CBC => match key.algorithm().id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => encrypt_aes_cbc_mode(key, context, in_out),
        },
        OperatingMode::CTR => match key.algorithm().id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => encrypt_aes_ctr_mode(key, context, in_out),
        },
    }
}

fn decrypt<'in_out>(
    key: &UnboundCipherKey,
    mode: OperatingMode,
    in_out: &'in_out mut [u8],
    context: CipherContext,
) -> Result<&'in_out mut [u8], Unspecified> {
    let block_len = key.algorithm().block_len();

    match mode {
        OperatingMode::CTR => {}
        _ => {
            if (in_out.len() % block_len) != 0 {
                return Err(Unspecified);
            }
        }
    }

    match mode {
        OperatingMode::CBC => match key.algorithm().id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => {
                decrypt_aes_cbc_mode(key, context, in_out).map(|_| in_out)
            }
        },
        OperatingMode::CTR => match key.algorithm().id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => {
                decrypt_aes_ctr_mode(key, context, in_out).map(|_| in_out)
            }
        },
    }
}

fn encrypt_aes_ctr_mode(
    key: &UnboundCipherKey,
    context: CipherContext,
    in_out: &mut [u8],
) -> Result<CipherContext, Unspecified> {
    #[allow(clippy::match_wildcard_for_single_variants)]
    let key = match &key.key {
        SymmetricCipherKey::Aes128 { enc_key, .. } | SymmetricCipherKey::Aes256 { enc_key, .. } => {
            enc_key
        }
        _ => return Err(Unspecified),
    };

    let mut iv = {
        let mut iv = [0u8; AES_CTR_IV_LEN];
        iv.copy_from_slice((&context).try_into()?);
        iv
    };

    let mut buffer = [0u8; AES_BLOCK_LEN];

    aes_ctr128_encrypt(key, &mut iv, &mut buffer, in_out);
    iv.zeroize();

    Ok(context)
}

fn decrypt_aes_ctr_mode(
    key: &UnboundCipherKey,
    context: CipherContext,
    in_out: &mut [u8],
) -> Result<CipherContext, Unspecified> {
    // it's the same in CTR, just providing a nice named wrapper to match
    encrypt_aes_ctr_mode(key, context, in_out)
}

fn encrypt_aes_cbc_mode(
    key: &UnboundCipherKey,
    context: CipherContext,
    in_out: &mut [u8],
) -> Result<CipherContext, Unspecified> {
    #[allow(clippy::match_wildcard_for_single_variants)]
    let key = match &key.key {
        SymmetricCipherKey::Aes128 { enc_key, .. } | SymmetricCipherKey::Aes256 { enc_key, .. } => {
            enc_key
        }
        _ => return Err(Unspecified),
    };

    let mut iv = {
        let mut iv = [0u8; AES_CBC_IV_LEN];
        iv.copy_from_slice((&context).try_into()?);
        iv
    };

    aes_cbc_encrypt(key, &mut iv, in_out);
    iv.zeroize();

    Ok(context)
}

fn decrypt_aes_cbc_mode(
    key: &UnboundCipherKey,
    context: CipherContext,
    in_out: &mut [u8],
) -> Result<CipherContext, Unspecified> {
    #[allow(clippy::match_wildcard_for_single_variants)]
    let key = match &key.key {
        SymmetricCipherKey::Aes128 { dec_key, .. } | SymmetricCipherKey::Aes256 { dec_key, .. } => {
            dec_key
        }
        _ => return Err(Unspecified),
    };

    let mut iv = {
        let mut iv = [0u8; AES_CBC_IV_LEN];
        iv.copy_from_slice((&context).try_into()?);
        iv
    };

    aes_cbc_decrypt(key, &mut iv, in_out);
    iv.zeroize();

    Ok(context)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::from_hex;

    #[test]
    fn test_debug() {
        {
            let aes_128_key_bytes = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
            let cipher_key = UnboundCipherKey::new(&AES_128, aes_128_key_bytes.as_slice()).unwrap();
            assert_eq!("UnboundCipherKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 } }", format!("{cipher_key:?}"));
        }

        {
            let aes_256_key_bytes =
                from_hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
                    .unwrap();
            let cipher_key = UnboundCipherKey::new(&AES_256, aes_256_key_bytes.as_slice()).unwrap();
            assert_eq!("UnboundCipherKey { algorithm: Algorithm { id: Aes256, key_len: 32, block_len: 16 } }", format!("{cipher_key:?}"));
        }

        {
            let key_bytes = &[0u8; 16];
            let key = PaddedBlockEncryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(&AES_128, key_bytes).unwrap(),
            )
            .unwrap();
            assert_eq!("PaddedBlockEncryptingKey { key: UnboundCipherKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 } }, mode: CBC, padding: PKCS7 }", format!("{key:?}"));
            let mut data = vec![0u8; 16];
            let context = key.encrypt(&mut data).unwrap();
            assert_eq!("Iv128", format!("{context:?}"));
            let key = PaddedBlockDecryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(&AES_128, key_bytes).unwrap(),
            )
            .unwrap();
            assert_eq!("PaddedBlockDecryptingKey { key: UnboundCipherKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 } }, mode: CBC, padding: PKCS7 }", format!("{key:?}"));
        }

        {
            let key_bytes = &[0u8; 16];
            let key =
                EncryptingKey::ctr(UnboundCipherKey::new(&AES_128, key_bytes).unwrap()).unwrap();
            assert_eq!("EncryptingKey { key: UnboundCipherKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 } }, mode: CTR }", format!("{key:?}"));
            let mut data = vec![0u8; 16];
            let context = key.encrypt(&mut data).unwrap();
            assert_eq!("Iv128", format!("{context:?}"));
            let key =
                DecryptingKey::ctr(UnboundCipherKey::new(&AES_128, key_bytes).unwrap()).unwrap();
            assert_eq!("DecryptingKey { key: UnboundCipherKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 } }, mode: CTR }", format!("{key:?}"));
        }
    }

    fn helper_test_cipher_n_bytes(
        key: &[u8],
        alg: &'static Algorithm,
        mode: OperatingMode,
        n: usize,
    ) {
        let mut input: Vec<u8> = Vec::with_capacity(n);
        for i in 0..n {
            let byte: u8 = i.try_into().unwrap();
            input.push(byte);
        }

        let cipher_key = UnboundCipherKey::new(alg, key).unwrap();
        let encrypting_key = EncryptingKey::new(cipher_key, mode).unwrap();

        let mut in_out = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut in_out).unwrap();

        if n > 5 {
            // There's no more than a 1 in 2^48 chance that this will fail randomly
            assert_ne!(input.as_slice(), in_out);
        }

        let cipher_key2 = UnboundCipherKey::new(alg, key).unwrap();
        let decrypting_key = DecryptingKey::new(cipher_key2, mode).unwrap();

        let plaintext = decrypting_key.decrypt(&mut in_out, decrypt_iv).unwrap();
        assert_eq!(input.as_slice(), plaintext);
    }

    fn helper_test_padded_cipher_n_bytes(
        key: &[u8],
        alg: &'static Algorithm,
        mode: OperatingMode,
        padding: PaddingStrategy,
        n: usize,
    ) {
        let mut input: Vec<u8> = Vec::with_capacity(n);
        for i in 0..n {
            let byte: u8 = i.try_into().unwrap();
            input.push(byte);
        }

        let cipher_key = UnboundCipherKey::new(alg, key).unwrap();
        let encrypting_key = PaddedBlockEncryptingKey::new(cipher_key, mode, padding).unwrap();

        let mut in_out = input.clone();
        let decrypt_iv = encrypting_key.encrypt(&mut in_out).unwrap();

        if n > 5 {
            // There's no more than a 1 in 2^48 chance that this will fail randomly
            assert_ne!(input.as_slice(), in_out);
        }

        let cipher_key2 = UnboundCipherKey::new(alg, key).unwrap();
        let decrypting_key = PaddedBlockDecryptingKey::new(cipher_key2, mode, padding).unwrap();

        let plaintext = decrypting_key.decrypt(&mut in_out, decrypt_iv).unwrap();
        assert_eq!(input.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_128_cbc() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
            helper_test_padded_cipher_n_bytes(
                key.as_slice(),
                &AES_128,
                OperatingMode::CBC,
                PaddingStrategy::PKCS7,
                i,
            );
        }
    }

    #[test]
    fn test_aes_256_cbc() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
            helper_test_padded_cipher_n_bytes(
                key.as_slice(),
                &AES_256,
                OperatingMode::CBC,
                PaddingStrategy::PKCS7,
                i,
            );
        }
    }

    #[test]
    fn test_aes_128_ctr() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_128, OperatingMode::CTR, i);
        }
    }

    #[test]
    fn test_aes_256_ctr() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        for i in 0..=50 {
            helper_test_cipher_n_bytes(key.as_slice(), &AES_256, OperatingMode::CTR, i);
        }
    }

    macro_rules! padded_cipher_kat {
        ($name:ident, $alg:expr, $mode:expr, $padding:expr, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
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

                let dc = CipherContext::Iv128(FixedLength::from(iv));

                let alg = $alg;

                let unbound_key = UnboundCipherKey::new(alg, &key).unwrap();

                let encrypting_key =
                    PaddedBlockEncryptingKey::new(unbound_key, $mode, $padding).unwrap();

                let mut in_out = input.clone();

                let context = encrypting_key.less_safe_encrypt(&mut in_out, dc).unwrap();

                assert_eq!(expected_ciphertext, in_out);

                let unbound_key2 = UnboundCipherKey::new(alg, &key).unwrap();
                let decrypting_key =
                    PaddedBlockDecryptingKey::new(unbound_key2, $mode, $padding).unwrap();

                let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        };
    }

    macro_rules! cipher_kat {
        ($name:ident, $alg:expr, $mode:expr, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
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

                let dc = CipherContext::Iv128(FixedLength::from(iv));

                let alg = $alg;

                let unbound_key = UnboundCipherKey::new(alg, &key).unwrap();

                let encrypting_key = EncryptingKey::new(unbound_key, $mode).unwrap();

                let mut in_out = input.clone();

                let context = encrypting_key.less_safe_encrypt(&mut in_out, dc).unwrap();

                assert_eq!(expected_ciphertext, in_out);

                let unbound_key2 = UnboundCipherKey::new(alg, &key).unwrap();
                let decrypting_key = DecryptingKey::new(unbound_key2, $mode).unwrap();

                let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        };
    }

    padded_cipher_kat!(
        test_iv_aes_128_cbc_16_bytes,
        &AES_128,
        OperatingMode::CBC,
        PaddingStrategy::PKCS7,
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a9e978e6d16b086570ef794ef97984232"
    );

    padded_cipher_kat!(
        test_iv_aes_256_cbc_15_bytes,
        &AES_256,
        OperatingMode::CBC,
        PaddingStrategy::PKCS7,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddee",
        "2ddfb635a651a43f582997966840ca0c"
    );

    cipher_kat!(
        test_iv_aes_128_ctr_16_bytes,
        &AES_128,
        OperatingMode::CTR,
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "c6b01904c3da3df5e7d62bd96d153686"
    );

    cipher_kat!(
        test_iv_aes_256_ctr_15_bytes,
        &AES_256,
        OperatingMode::CTR,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddee",
        "f28122856e1cf9a7216a30d111f399"
    );

    cipher_kat!(
        test_openssl_aes_128_ctr_15_bytes,
        &AES_128,
        OperatingMode::CTR,
        "244828580821c1652582c76e34d299f5",
        "093145d5af233f46072a5eb5adc11aa1",
        "3ee38cec171e6cf466bf0df98aa0e1",
        "bd7d928f60e3422d96b3f8cd614eb2"
    );

    cipher_kat!(
        test_openssl_aes_256_ctr_15_bytes,
        &AES_256,
        OperatingMode::CTR,
        "0857db8240ea459bdf660b4cced66d1f2d3734ff2de7b81e92740e65e7cc6a1d",
        "f028ecb053f801102d11fccc9d303a27",
        "eca7285d19f3c20e295378460e8729",
        "b5098e5e788de6ac2f2098eb2fc6f8"
    );

    padded_cipher_kat!(
        test_openssl_aes_128_cbc_15_bytes,
        &AES_128,
        OperatingMode::CBC,
        PaddingStrategy::PKCS7,
        "053304bb3899e1d99db9d29343ea782d",
        "b5313560244a4822c46c2a0c9d0cf7fd",
        "a3e4c990356c01f320043c3d8d6f43",
        "ad96993f248bd6a29760ec7ccda95ee1"
    );

    padded_cipher_kat!(
        test_openssl_aes_128_cbc_16_bytes,
        &AES_128,
        OperatingMode::CBC,
        PaddingStrategy::PKCS7,
        "95af71f1c63e4a1d0b0b1a27fb978283",
        "89e40797dca70197ff87d3dbb0ef2802",
        "aece7b5e3c3df1ffc9802d2dfe296dc7",
        "301b5dab49fb11e919d0d39970d06739301919743304f23f3cbc67d28564b25b"
    );

    padded_cipher_kat!(
        test_openssl_aes_256_cbc_15_bytes,
        &AES_256,
        OperatingMode::CBC,
        PaddingStrategy::PKCS7,
        "d369e03e9752784917cc7bac1db7399598d9555e691861d9dd7b3292a693ef57",
        "1399bb66b2f6ad99a7f064140eaaa885",
        "7385f5784b85bf0a97768ddd896d6d",
        "4351082bac9b4593ae8848cc9dfb5a01"
    );

    padded_cipher_kat!(
        test_openssl_aes_256_cbc_16_bytes,
        &AES_256,
        OperatingMode::CBC,
        PaddingStrategy::PKCS7,
        "d4a8206dcae01242f9db79a4ecfe277d0f7bb8ccbafd8f9809adb39f35aa9b41",
        "24f6076548fb9d93c8f7ed9f6e661ef9",
        "a39c1fdf77ea3e1f18178c0ec237c70a",
        "f1af484830a149ee0387b854d65fe87ca0e62efc1c8e6909d4b9ab8666470453"
    );
}
