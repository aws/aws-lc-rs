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
//! ## Encryption Modes
//!
//! ### AES-128 CBC
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::cipher::{
//!     PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey, AES_128,
//! };
//! use std::io::Read;
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
//! ### AES-128 CTR
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
//! ### AES-128 CBC Streaming Cipher
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::cipher::{
//!     StreamingDecryptingKey, StreamingEncryptingKey, UnboundCipherKey, AES_128,
//! };
//! let original_message = "This is a secret message!".as_bytes();
//! let key_bytes: &[u8] = &[
//!     0xff, 0x0b, 0xe5, 0x84, 0x64, 0x0b, 0x00, 0xc8, 0x90, 0x7a, 0x4b, 0xbf, 0x82, 0x7c,
//!     0xb6, 0xd1,
//! ];
//! // Prepare ciphertext buffer
//! let mut ciphertext_buffer = vec![0u8; original_message.len() + AES_128.block_len()];
//! let ciphertext_slice = ciphertext_buffer.as_mut_slice();
//!
//! // Create StreamingEncryptingKey
//! let key = UnboundCipherKey::new(&AES_128, key_bytes).unwrap();
//! let mut encrypting_key = StreamingEncryptingKey::cbc_pkcs7(key).unwrap();
//!
//! // Encrypt
//! let mut first_update = encrypting_key
//!                            .update(original_message, ciphertext_slice)
//!                            .unwrap();
//! let first_update_len = first_update.written().len();
//! let (context, final_update) = encrypting_key.finish(first_update.remainder_mut()).unwrap();
//! let ciphertext_len = first_update_len + final_update.written().len();
//! let ciphertext = &ciphertext_slice[0..ciphertext_len];
//!
//! // Prepare plaintext buffer
//! let mut plaintext_buffer = vec![0u8; ciphertext_len + AES_128.block_len()];
//! let plaintext_slice = plaintext_buffer.as_mut_slice();
//!
//! // Create StreamingDecryptingKey
//! let key = UnboundCipherKey::new(&AES_128, key_bytes).unwrap();
//! let mut decrypting_key = StreamingDecryptingKey::cbc_pkcs7(key, context).unwrap();
//!
//! // Decrypt
//! let mut first_update = decrypting_key.update(ciphertext, plaintext_slice).unwrap();
//! let first_update_len = first_update.written().len();
//! let final_update = decrypting_key.finish(first_update.remainder_mut()).unwrap();
//! let plaintext_len = first_update_len + final_update.written().len();
//! let plaintext = &plaintext_slice[0..plaintext_len];
//!
//! assert_eq!(original_message, plaintext);
//! #
//! # Ok(())
//! # }
//! ```
//!
//! ## Constructing a `DecryptionContext` for decryption.
//!
//! ```rust
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::cipher::{DecryptingKey, DecryptionContext, UnboundCipherKey, AES_128};
//! use aws_lc_rs::iv::{FixedLength, IV_LEN_128_BIT};
//!
//! let context = DecryptionContext::Iv128(FixedLength::<IV_LEN_128_BIT>::from(&[
//!     0x8d, 0xdb, 0x7d, 0xf1, 0x56, 0xf5, 0x1c, 0xde, 0x63, 0xe3, 0x4a, 0x34, 0xb0, 0xdf, 0x28,
//!     0xf0,
//! ]));
//!
//! let ciphertext: &[u8] = &[
//!     0x79, 0x8c, 0x04, 0x58, 0xcf, 0x98, 0xb1, 0xe9, 0x97, 0x6b, 0xa1, 0xce,
//! ];
//!
//! let mut in_out_buffer = Vec::from(ciphertext);
//!
//! let key = UnboundCipherKey::new(
//!     &AES_128,
//!     &[
//!         0x5b, 0xfc, 0xe7, 0x5e, 0x57, 0xc5, 0x4d, 0xda, 0x2d, 0xd4, 0x7e, 0x07, 0x0a, 0xef,
//!         0x43, 0x29,
//!     ],
//! )?;
//! let mut decrypting_key = DecryptingKey::ctr(key)?;
//! let plaintext = decrypting_key.decrypt(&mut in_out_buffer, context)?;
//! assert_eq!("Hello World!".as_bytes(), plaintext);
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting an immutable reference to the IV slice.
//!
//! `TryFrom<&DecryptionContext>` is implemented for `&[u8]` allowing immutable references
//! to IV bytes returned from cipher encryption operations. Note this is implemented as a `TryFrom` as it
//! may fail for future enum variants that aren't representable as a single slice.
//!
//! ```rust
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! # use aws_lc_rs::cipher::DecryptionContext;
//! # use aws_lc_rs::iv::FixedLength;
//! # let x: DecryptionContext = DecryptionContext::Iv128(FixedLength::from([0u8; 16]));
//! // x is type `DecryptionContext`
//! let iv: &[u8] = (&x).try_into()?;
//! # Ok(())
//! # }
//! ```

#![allow(clippy::module_name_repetitions)]

pub(crate) mod aes;
pub(crate) mod block;
pub(crate) mod chacha;
pub(crate) mod key;
mod padded;
mod streaming;

pub use padded::{PaddedBlockDecryptingKey, PaddedBlockEncryptingKey};
pub use streaming::{BufferUpdate, StreamingDecryptingKey, StreamingEncryptingKey};

use crate::buffer::Buffer;
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::hkdf;
use crate::hkdf::KeyType;
use crate::iv::{FixedLength, IV_LEN_128_BIT};
use crate::ptr::ConstPointer;
use aws_lc::{
    AES_cbc_encrypt, AES_ctr128_encrypt, EVP_aes_128_cbc, EVP_aes_128_ctr, EVP_aes_256_cbc,
    EVP_aes_256_ctr, AES_DECRYPT, AES_ENCRYPT, AES_KEY, EVP_CIPHER,
};
use core::fmt::Debug;
use core::mem::MaybeUninit;
use key::SymmetricCipherKey;
use zeroize::Zeroize;

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

/// The cipher operating mode.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OperatingMode {
    /// Cipher block chaining (CBC) mode.
    CBC,

    /// Counter (CTR) mode.
    CTR,
}

impl OperatingMode {
    #[allow(dead_code)]
    fn evp_cipher(&self, algorithm: &Algorithm) -> ConstPointer<EVP_CIPHER> {
        ConstPointer::new(match (self, algorithm.id) {
            (OperatingMode::CBC, AlgorithmId::Aes128) => unsafe { EVP_aes_128_cbc() },
            (OperatingMode::CTR, AlgorithmId::Aes128) => unsafe { EVP_aes_128_ctr() },
            (OperatingMode::CBC, AlgorithmId::Aes256) => unsafe { EVP_aes_256_cbc() },
            (OperatingMode::CTR, AlgorithmId::Aes256) => unsafe { EVP_aes_256_ctr() },
        })
        .unwrap()
    }
}

macro_rules! define_cipher_context {
    ($name:ident, $other:ident) => {
        /// The contextual data used to encrypt or decrypt data.
        #[non_exhaustive]
        pub enum $name {
            /// A 128-bit Initialization Vector.
            Iv128(FixedLength<IV_LEN_128_BIT>),
        }

        impl<'a> TryFrom<&'a $name> for &'a [u8] {
            type Error = Unspecified;

            fn try_from(value: &'a $name) -> Result<Self, Unspecified> {
                match value {
                    $name::Iv128(iv) => Ok(iv.as_ref()),
                }
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self::Iv128(_) => write!(f, "Iv128"),
                }
            }
        }

        impl From<$other> for $name {
            fn from(value: $other) -> Self {
                match value {
                    $other::Iv128(iv) => $name::Iv128(iv),
                }
            }
        }
    };
}

define_cipher_context!(EncryptionContext, DecryptionContext);
define_cipher_context!(DecryptionContext, EncryptionContext);

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

    /// The block length of this cipher algorithm.
    #[must_use]
    pub const fn block_len(&self) -> usize {
        self.block_len
    }

    fn new_encryption_context(
        &self,
        mode: OperatingMode,
    ) -> Result<EncryptionContext, Unspecified> {
        match self.id {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => match mode {
                OperatingMode::CBC | OperatingMode::CTR => {
                    Ok(EncryptionContext::Iv128(FixedLength::new()?))
                }
            },
        }
    }

    fn is_valid_encryption_context(&self, mode: OperatingMode, input: &EncryptionContext) -> bool {
        match self.id {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => match mode {
                OperatingMode::CBC | OperatingMode::CTR => {
                    matches!(input, EncryptionContext::Iv128(_))
                }
            },
        }
    }

    fn is_valid_decryption_context(&self, mode: OperatingMode, input: &DecryptionContext) -> bool {
        match self.id {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => match mode {
                OperatingMode::CBC | OperatingMode::CTR => {
                    matches!(input, DecryptionContext::Iv128(_))
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
    key_bytes: Buffer<'static, &'static [u8]>,
}

impl UnboundCipherKey {
    /// Constructs an [`UnboundCipherKey`].
    ///
    /// # Errors
    ///
    /// * [`Unspecified`] if `key_bytes.len()` does not match the length required by `algorithm`.
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let key_bytes = Buffer::new(key_bytes.to_vec());
        Ok(UnboundCipherKey {
            algorithm,
            key_bytes,
        })
    }

    #[inline]
    #[must_use]
    /// Returns the algorithm associated with this key.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl TryInto<SymmetricCipherKey> for UnboundCipherKey {
    type Error = Unspecified;

    fn try_into(self) -> Result<SymmetricCipherKey, Self::Error> {
        match self.algorithm.id() {
            AlgorithmId::Aes128 => SymmetricCipherKey::aes128(self.key_bytes.as_ref()),
            AlgorithmId::Aes256 => SymmetricCipherKey::aes256(self.key_bytes.as_ref()),
        }
    }
}

/// A cipher encryption key that does not perform block padding.
pub struct EncryptingKey {
    algorithm: &'static Algorithm,
    key: SymmetricCipherKey,
    mode: OperatingMode,
}

impl EncryptingKey {
    /// Constructs an `EncryptingKey` operating in counter (CTR) mode using the provided key.
    ///
    // # FIPS
    // Use this function with an `UnboundCipherKey` constructed with one of the following algorithms:
    // * `AES_128`
    // * `AES_256`
    //
    /// # Errors
    /// * [`Unspecified`]: Returned if there is an error constructing the `EncryptingKey`.
    pub fn ctr(key: UnboundCipherKey) -> Result<EncryptingKey, Unspecified> {
        EncryptingKey::new(key, OperatingMode::CTR)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new(key: UnboundCipherKey, mode: OperatingMode) -> Result<EncryptingKey, Unspecified> {
        let algorithm = key.algorithm();
        let key = key.try_into()?;
        Ok(EncryptingKey {
            algorithm,
            key,
            mode,
        })
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &Algorithm {
        self.algorithm
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Encrypts the data provided in `in_out` in-place.
    /// Returns a references to the encrypted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if cipher mode requires input to be a multiple of the block length,
    ///   and `in_out.len()` is not. Otherwise, returned if encryption fails.
    pub fn encrypt(&self, in_out: &mut [u8]) -> Result<DecryptionContext, Unspecified> {
        let context = self.algorithm.new_encryption_context(self.mode)?;
        self.less_safe_encrypt(in_out, context)
    }

    /// Encrypts the data provided in `in_out` in-place using the provided `EncryptionContext`.
    /// This is considered "less safe" because the caller could potentially construct
    /// a `EncryptionContext` from a previously used IV (initialization vector).
    /// Returns a references to the decrypted data.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if cipher mode requires input to be a multiple of the block length,
    ///   and `in_out.len()` is not. Otherwise returned if encryption fails.
    pub fn less_safe_encrypt(
        &self,
        in_out: &mut [u8],
        context: EncryptionContext,
    ) -> Result<DecryptionContext, Unspecified> {
        if !self
            .algorithm()
            .is_valid_encryption_context(self.mode, &context)
        {
            return Err(Unspecified);
        }
        encrypt(self.algorithm(), &self.key, self.mode, in_out, context)
    }
}

impl Debug for EncryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptingKey")
            .field("algorithm", self.algorithm)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// A cipher decryption key that does not perform block padding.
pub struct DecryptingKey {
    algorithm: &'static Algorithm,
    key: SymmetricCipherKey,
    mode: OperatingMode,
}

impl DecryptingKey {
    /// Constructs a cipher decrypting key operating in counter (CTR) mode using the provided key and context.
    ///
    // # FIPS
    // Use this function with an `UnboundCipherKey` constructed with one of the following algorithms:
    // * `AES_128`
    // * `AES_256`
    //
    /// # Errors
    /// * [`Unspecified`]: Returned if there is an error during decryption.
    pub fn ctr(key: UnboundCipherKey) -> Result<DecryptingKey, Unspecified> {
        DecryptingKey::new(key, OperatingMode::CTR)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new(key: UnboundCipherKey, mode: OperatingMode) -> Result<DecryptingKey, Unspecified> {
        let algorithm = key.algorithm();
        let key = key.try_into()?;
        Ok(DecryptingKey {
            algorithm,
            key,
            mode,
        })
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &Algorithm {
        self.algorithm
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
    ///   and `in_out.len()` is not. Also returned if decryption fails.
    pub fn decrypt<'in_out>(
        &self,
        in_out: &'in_out mut [u8],
        context: DecryptionContext,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        decrypt(self.algorithm, &self.key, self.mode, in_out, context)
    }
}

impl Debug for DecryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptingKey")
            .field("algorithm", &self.algorithm)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

fn encrypt(
    algorithm: &Algorithm,
    key: &SymmetricCipherKey,
    mode: OperatingMode,
    in_out: &mut [u8],
    context: EncryptionContext,
) -> Result<DecryptionContext, Unspecified> {
    let block_len = algorithm.block_len();

    match mode {
        OperatingMode::CTR => {}
        _ => {
            if (in_out.len() % block_len) != 0 {
                return Err(Unspecified);
            }
        }
    }

    match mode {
        OperatingMode::CBC => match algorithm.id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => encrypt_aes_cbc_mode(key, context, in_out),
        },
        OperatingMode::CTR => match algorithm.id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => encrypt_aes_ctr_mode(key, context, in_out),
        },
    }
}

fn decrypt<'in_out>(
    algorithm: &'static Algorithm,
    key: &SymmetricCipherKey,
    mode: OperatingMode,
    in_out: &'in_out mut [u8],
    context: DecryptionContext,
) -> Result<&'in_out mut [u8], Unspecified> {
    let block_len = algorithm.block_len();

    match mode {
        OperatingMode::CTR => {}
        _ => {
            if (in_out.len() % block_len) != 0 {
                return Err(Unspecified);
            }
        }
    }

    match mode {
        OperatingMode::CBC => match algorithm.id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => decrypt_aes_cbc_mode(key, context, in_out),
        },
        OperatingMode::CTR => match algorithm.id() {
            AlgorithmId::Aes128 | AlgorithmId::Aes256 => decrypt_aes_ctr_mode(key, context, in_out),
        },
    }
}

fn encrypt_aes_ctr_mode(
    key: &SymmetricCipherKey,
    context: EncryptionContext,
    in_out: &mut [u8],
) -> Result<DecryptionContext, Unspecified> {
    #[allow(clippy::match_wildcard_for_single_variants)]
    let key = match &key {
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

    Ok(context.into())
}

fn decrypt_aes_ctr_mode<'in_out>(
    key: &SymmetricCipherKey,
    context: DecryptionContext,
    in_out: &'in_out mut [u8],
) -> Result<&'in_out mut [u8], Unspecified> {
    // it's the same in CTR, just providing a nice named wrapper to match
    encrypt_aes_ctr_mode(key, context.into(), in_out).map(|_| in_out)
}

fn encrypt_aes_cbc_mode(
    key: &SymmetricCipherKey,
    context: EncryptionContext,
    in_out: &mut [u8],
) -> Result<DecryptionContext, Unspecified> {
    #[allow(clippy::match_wildcard_for_single_variants)]
    let key = match &key {
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

    Ok(context.into())
}

#[allow(clippy::needless_pass_by_value)]
fn decrypt_aes_cbc_mode<'in_out>(
    key: &SymmetricCipherKey,
    context: DecryptionContext,
    in_out: &'in_out mut [u8],
) -> Result<&'in_out mut [u8], Unspecified> {
    #[allow(clippy::match_wildcard_for_single_variants)]
    let key = match &key {
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

    Ok(in_out)
}

fn aes_ctr128_encrypt(key: &AES_KEY, iv: &mut [u8], block_buffer: &mut [u8], in_out: &mut [u8]) {
    let mut num = MaybeUninit::<u32>::new(0);

    indicator_check!(unsafe {
        AES_ctr128_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            block_buffer.as_mut_ptr(),
            num.as_mut_ptr(),
        );
    });

    Zeroize::zeroize(block_buffer);
}

fn aes_cbc_encrypt(key: &AES_KEY, iv: &mut [u8], in_out: &mut [u8]) {
    indicator_check!(unsafe {
        AES_cbc_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            AES_ENCRYPT,
        );
    });
}

fn aes_cbc_decrypt(key: &AES_KEY, iv: &mut [u8], in_out: &mut [u8]) {
    indicator_check!(unsafe {
        AES_cbc_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            AES_DECRYPT,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::from_hex;

    #[cfg(feature = "fips")]
    mod fips;

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
            assert_eq!("PaddedBlockEncryptingKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 }, mode: CBC, padding: PKCS7, .. }", format!("{key:?}"));
            let mut data = vec![0u8; 16];
            let context = key.encrypt(&mut data).unwrap();
            assert_eq!("Iv128", format!("{context:?}"));
            let key = PaddedBlockDecryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(&AES_128, key_bytes).unwrap(),
            )
            .unwrap();
            assert_eq!("PaddedBlockDecryptingKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 }, mode: CBC, padding: PKCS7, .. }", format!("{key:?}"));
        }

        {
            let key_bytes = &[0u8; 16];
            let key =
                EncryptingKey::ctr(UnboundCipherKey::new(&AES_128, key_bytes).unwrap()).unwrap();
            assert_eq!("EncryptingKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 }, mode: CTR, .. }", format!("{key:?}"));
            let mut data = vec![0u8; 16];
            let context = key.encrypt(&mut data).unwrap();
            assert_eq!("Iv128", format!("{context:?}"));
            let key =
                DecryptingKey::ctr(UnboundCipherKey::new(&AES_128, key_bytes).unwrap()).unwrap();
            assert_eq!("DecryptingKey { algorithm: Algorithm { id: Aes128, key_len: 16, block_len: 16 }, mode: CTR, .. }", format!("{key:?}"));
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

                let ec = EncryptionContext::Iv128(FixedLength::from(iv));

                let alg = $alg;

                let unbound_key = UnboundCipherKey::new(alg, &key).unwrap();

                let encrypting_key = EncryptingKey::new(unbound_key, $mode).unwrap();

                let mut in_out = input.clone();

                let context = encrypting_key.less_safe_encrypt(&mut in_out, ec).unwrap();

                assert_eq!(expected_ciphertext, in_out);

                let unbound_key2 = UnboundCipherKey::new(alg, &key).unwrap();
                let decrypting_key = DecryptingKey::new(unbound_key2, $mode).unwrap();

                let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        };
    }

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
}
