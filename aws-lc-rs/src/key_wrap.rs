// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key Wrap Algorithm [NIST SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf)
//!
//! # Examples
//! ```rust
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::key_wrap::{KeyEncryptionKey, WrappingMode, AES_128};
//!
//! const KEY: &[u8] = &[
//!     0xa8, 0xe0, 0x6d, 0xa6, 0x25, 0xa6, 0x5b, 0x25, 0xcf, 0x50, 0x30, 0x82, 0x68, 0x30, 0xb6,
//!     0x61,
//! ];
//! const PLAINTEXT: &[u8] = &[0x43, 0xac, 0xff, 0x29, 0x31, 0x20, 0xdd, 0x5d];
//!
//! let kek = KeyEncryptionKey::new(&AES_128, KEY, WrappingMode::Padded)?;
//!
//! let mut output = vec![0u8; PLAINTEXT.len() + 15];
//!
//! let ciphertext = kek.wrap(PLAINTEXT, &mut output)?;
//!
//! let kek = KeyEncryptionKey::new(&AES_128, KEY, WrappingMode::Padded)?;
//!
//! let mut output = vec![0u8; ciphertext.len()];
//!
//! let plaintext = kek.unwrap(&*ciphertext, &mut output)?;
//!
//! assert_eq!(PLAINTEXT, plaintext);
//!
//! Ok(())
//! # }
//! ```
use std::{fmt::Debug, mem::MaybeUninit, ptr::null};

use aws_lc::{
    AES_set_decrypt_key, AES_set_encrypt_key, AES_unwrap_key, AES_unwrap_key_padded, AES_wrap_key,
    AES_wrap_key_padded, AES_KEY,
};

use crate::{error::Unspecified, fips::indicator_check};

mod tests;

/// The Key Wrapping Algorithm
pub struct Algorithm {
    id: AlgorithmId,
    key_len: usize,
}

impl Algorithm {
    /// Returns the algorithm identifier.
    #[inline]
    #[must_use]
    pub fn id(&self) -> AlgorithmId {
        self.id
    }

    /// Returns the algorithm key length.
    #[inline]
    #[must_use]
    fn key_len(&self) -> usize {
        self.key_len
    }
}

impl Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// The Key Wrapping Algorithm Identifier
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AlgorithmId {
    /// AES-128 Key Wrap
    Aes128,

    /// AES-256 Key Wrap
    Aes256,
}

/// AES-128 Key Wrapping
pub const AES_128: Algorithm = Algorithm {
    id: AlgorithmId::Aes128,
    key_len: 16,
};

/// AES-256 Key Wrapping
pub const AES_256: Algorithm = Algorithm {
    id: AlgorithmId::Aes256,
    key_len: 32,
};

/// The mode of operation for the wrapping algorithm.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WrappingMode {
    /// Key Wrap with Padding
    Padded,

    /// Key Wrap
    Unpadded,
}

impl WrappingMode {
    fn wrap<'output>(
        self,
        key: &[u8],
        input: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        // For most checks we can count on AWS-LC, but in this instance
        // it expects that output is sufficiently sized. So we must check it here.
        if self == WrappingMode::Unpadded && output.len() < input.len() + 8 {
            return Err(Unspecified);
        }

        let mut aes_key = MaybeUninit::<AES_KEY>::uninit();

        let key_bits: u32 = (key.len() * 8).try_into().map_err(|_| Unspecified)?;

        if 0 != unsafe { AES_set_encrypt_key(key.as_ptr(), key_bits, aes_key.as_mut_ptr()) } {
            return Err(Unspecified);
        }

        let aes_key = unsafe { aes_key.assume_init() };

        let out_len = match self {
            WrappingMode::Padded => {
                let mut out_len: usize = 0;

                // AWS-LC validates the following:
                // * in_len != 0
                // * in_len <= INT_MAX
                // * max_out >= required_padding + 8
                if 1 != indicator_check!(unsafe {
                    AES_wrap_key_padded(
                        &aes_key,
                        output.as_mut_ptr(),
                        &mut out_len,
                        output.len(),
                        input.as_ptr(),
                        input.len(),
                    )
                }) {
                    return Err(Unspecified);
                }

                out_len
            }
            WrappingMode::Unpadded => {
                // AWS-LC validates the following:
                // * in_len <= INT_MAX - 8
                // * in_len >= 16
                // * in_len % 8 == 0
                let out_len = indicator_check!(unsafe {
                    AES_wrap_key(
                        &aes_key,
                        null(),
                        output.as_mut_ptr(),
                        input.as_ptr(),
                        input.len(),
                    )
                });

                if out_len == -1 {
                    return Err(Unspecified);
                }

                let out_len: usize = out_len.try_into().map_err(|_| Unspecified)?;

                debug_assert_eq!(out_len, input.len() + 8);

                out_len
            }
        };

        Ok(&mut output[..out_len])
    }

    fn unwrap<'output>(
        self,
        key: &[u8],
        input: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        if self == WrappingMode::Unpadded && output.len() < input.len() - 8 {
            return Err(Unspecified);
        }

        let mut aes_key = MaybeUninit::<AES_KEY>::uninit();

        if 0 != unsafe {
            AES_set_decrypt_key(
                key.as_ptr(),
                (key.len() * 8).try_into().map_err(|_| Unspecified)?,
                aes_key.as_mut_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        let aes_key = unsafe { aes_key.assume_init() };

        let out_len = match self {
            WrappingMode::Padded => {
                let mut out_len: usize = 0;

                // AWS-LC validates the following:
                // * in_len >= AES_BLOCK_SIZE
                // * max_out >= in_len - 8
                if 1 != indicator_check!(unsafe {
                    AES_unwrap_key_padded(
                        &aes_key,
                        output.as_mut_ptr(),
                        &mut out_len,
                        output.len(),
                        input.as_ptr(),
                        input.len(),
                    )
                }) {
                    return Err(Unspecified);
                };

                out_len
            }
            WrappingMode::Unpadded => {
                // AWS-LC validates the following:
                // * in_len < INT_MAX
                // * in_len > 24
                // * in_len % 8 == 0
                let out_len = indicator_check!(unsafe {
                    AES_unwrap_key(
                        &aes_key,
                        null(),
                        output.as_mut_ptr(),
                        input.as_ptr(),
                        input.len(),
                    )
                });

                if out_len == -1 {
                    return Err(Unspecified);
                }

                let out_len: usize = out_len.try_into().map_err(|_| Unspecified)?;

                debug_assert_eq!(out_len, input.len() - 8);

                out_len
            }
        };

        Ok(&mut output[..out_len])
    }
}

/// The key-encryption key used with the selected cipher algorithn to wrap or unwrap a key.
pub struct KeyEncryptionKey {
    algorithm: &'static Algorithm,
    key: Box<[u8]>,
    mode: WrappingMode,
}

impl KeyEncryptionKey {
    /// Creates a new `KeyEncryptionKey` using the provider cipher algorithm, key bytes, and wrapping mode.
    ///
    /// # Errors
    /// * [`Unspecified`]: Returned if `key_bytes.len()` does not match the size expected for the provided algorithm.
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
        mode: WrappingMode,
    ) -> Result<Self, Unspecified> {
        if algorithm.key_len() != key_bytes.len() {
            return Err(Unspecified);
        }

        let key = Vec::from(key_bytes).into_boxed_slice();

        Ok(Self {
            algorithm,
            key,
            mode,
        })
    }

    /// Peforms the key wrap encryption algorithm using `KeyEncryptionKey`'s configured cipher algorithm
    /// and wrapping operation mode. It wraps the provided `input` plaintext and writes the
    /// ciphertext to `output`.
    ///
    /// If `WrappingMode::Unpadded` is the configured mode, then `input.len()` must be a multiple of 8 and non-zero.
    ///
    /// # Sizing `output`
    /// `output` must be sized appropriately depending on the configured [`WrappingMode`].
    /// * [`WrappingMode::Padded`]: `output.len() >= (input.len() + 15)`
    /// * [`WrappingMode::Unpadded`]: `output.len() >= (input.len() + 8)`
    ///
    /// # Errors
    /// * [`Unspecified`]: An error occurred either due to `output` being insufficiently sized, `input` exceeding
    /// the allowed input size, or for other unspecified reasons.
    pub fn wrap<'output>(
        self,
        input: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        self.mode.wrap(&self.key, input, output)
    }

    /// Peforms the key wrap decryption algorithm using `KeyEncryptionKey`'s configured cipher algorithm
    /// and wrapping operation mode. It unwraps the provided `input` ciphertext and writes the
    /// plaintext to `output`.
    ///
    /// If `WrappingMode::Unpadded` is the configured mode, then `input.len()` must be a multiple of 8.
    ///
    /// # Sizing `output`
    /// `output` must be sized appropriately depending on the configured [`WrappingMode`].
    /// * [`WrappingMode::Padded`]: `output.len() >= input.len()`
    /// * [`WrappingMode::Unpadded`]: `output.len() >= (input.len() - 8)`
    ///
    /// # Errors
    /// * [`Unspecified`]: An error occurred either due to `output` being insufficiently sized, `input` exceeding
    /// the allowed input size, or for other unspecified reasons.
    pub fn unwrap<'output>(
        self,
        input: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        self.mode.unwrap(&self.key, input, output)
    }

    /// Returns the configured `Algorithm`.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// Returns the configured `WrappingMode`.
    #[must_use]
    pub fn wrapping_mode(&self) -> WrappingMode {
        self.mode
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEncryptionKey")
            .field("algorithm", &self.algorithm)
            .field("mode", &self.mode)
            .finish()
    }
}
