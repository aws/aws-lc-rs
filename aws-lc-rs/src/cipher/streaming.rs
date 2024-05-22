// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cipher::{
    Algorithm, DecryptionContext, EncryptionContext, OperatingMode, UnboundCipherKey,
};
use crate::error::Unspecified;
use crate::ptr::{LcPtr, Pointer};
use aws_lc::{
    EVP_CIPHER_CTX_new, EVP_CIPHER_iv_length, EVP_CIPHER_key_length, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate, EVP_CIPHER_CTX,
};
use std::ptr::null_mut;

/// A key for streaming encryption operations.
pub struct StreamingEncryptingKey {
    algorithm: &'static Algorithm,
    mode: OperatingMode,
    cipher_ctx: LcPtr<EVP_CIPHER_CTX>,
    context: EncryptionContext,
}

/// A struct indicating the portion of a buffer written to, and/or not written to, during an
/// encryption/decryption operation.
pub struct BufferUpdate<'a> {
    written: &'a [u8],
    remainder: &'a mut [u8],
}

impl<'a> BufferUpdate<'a> {
    fn new(out_buffer: &'a mut [u8], written_len: usize) -> Self {
        let (written, remainder) = out_buffer.split_at_mut(written_len);
        Self { written, remainder }
    }
}

impl BufferUpdate<'_> {
    /// Returns the slice from the buffer that was modified by the operation.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        self.written
    }

    /// Returns the slice of the buffer that was not modified by the operation.
    #[must_use]
    pub fn remainder(&self) -> &[u8] {
        self.remainder
    }

    /// Returns a mutable slice of the buffer that was not modified by the operation.
    #[must_use]
    pub fn remainder_mut(&mut self) -> &mut [u8] {
        self.remainder
    }
}

impl StreamingEncryptingKey {
    #[allow(clippy::needless_pass_by_value)]
    fn new(
        key: UnboundCipherKey,
        mode: OperatingMode,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        let algorithm = key.algorithm();
        let cipher_ctx = LcPtr::new(unsafe { EVP_CIPHER_CTX_new() })?;
        let cipher = mode.evp_cipher(key.algorithm);
        let key_bytes = key.key_bytes.as_ref();
        debug_assert_eq!(
            key_bytes.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_key_length(*cipher) }).unwrap()
        );
        let iv = <&[u8]>::try_from(&context)?;
        debug_assert_eq!(
            iv.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_iv_length(*cipher) }).unwrap()
        );

        if 1 != unsafe {
            EVP_EncryptInit_ex(
                cipher_ctx.as_mut_ptr(),
                *cipher,
                null_mut(),
                key_bytes.as_ptr(),
                iv.as_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        Ok(Self {
            algorithm,
            mode,
            cipher_ctx,
            context,
        })
    }

    /// Updates the internal state of the key with the provided ciphertext `input`,
    /// potentially writing bytes of ciphertext to `output`.
    ///
    /// The number of bytes written to `output` can be up to `input.len()`
    /// plus the block length of the algorithm (e.g., 16 bytes for AES).
    ///
    /// # Errors
    /// * May return an error if the `output` buffer is smaller than the length of
    ///   the `input` plus the algorithm's block length. Certain cipher modes
    ///   (such as CTR) may allow the output buffer to be as small as the size
    ///   of the input in certain circumstances.
    /// * Returns an error if the length of either `input` or `output` is larger
    ///   than `i32::MAX`.
    pub fn update<'a>(
        &mut self,
        input: &[u8],
        output: &'a mut [u8],
    ) -> Result<BufferUpdate<'a>, Unspecified> {
        let mut outlen: i32 = output.len().try_into()?;
        let inlen: i32 = input.len().try_into()?;
        if 1 != unsafe {
            EVP_EncryptUpdate(
                self.cipher_ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                inlen,
            )
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok(BufferUpdate::new(output, outlen))
    }

    /// Finishes the encryption operation, writing any remaining ciphertext to
    /// `output`.
    ///
    /// The number of bytes written to `output` can be up to the block length of
    /// the algorithm (e.g., 16 bytes for AES).
    ///
    /// # Errors
    /// * May return an error if the `output` buffer is smaller than the algorithm's
    ///   block length. Certain cipher mode (such as CTR) may allow the output
    ///   buffer to only be large enough to fit the remainder of the ciphertext.
    /// * Returns an error if the length of `output` is larger than `i32::MAX`.
    pub fn finish(
        self,
        output: &mut [u8],
    ) -> Result<(DecryptionContext, BufferUpdate), Unspecified> {
        let mut outlen: i32 = output.len().try_into()?;
        if 1 != unsafe {
            EVP_EncryptFinal_ex(
                self.cipher_ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
            )
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok((self.context.into(), BufferUpdate::new(output, outlen)))
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Returns the cipher algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// Constructs a `StreamingEncryptingKey` for encrypting data using the CTR cipher mode.
    /// The resulting ciphertext will be the same length as the plaintext.
    ///
    /// # Errors
    /// Returns and error on an internal failure.
    pub fn ctr(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        let context = key.algorithm().new_encryption_context(OperatingMode::CTR)?;
        Self::less_safe_ctr(key, context)
    }

    /// Constructs a `StreamingEncryptingKey` for encrypting data using the CTR cipher mode.
    /// The resulting ciphertext will be the same length as the plaintext.
    ///
    /// This is considered less safe because the caller could potentially construct
    /// an `EncryptionContext` from a previously used initialization vector (IV).
    ///
    /// # Errors
    /// Returns an error on an internal failure.
    pub fn less_safe_ctr(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CTR, context)
    }

    /// Constructs a `StreamingEncryptingKey` for encrypting data using the CBC cipher mode
    /// with pkcs7 padding.
    /// The resulting ciphertext will be longer than the plaintext; padding is added
    /// to fill the next block of ciphertext.
    ///
    /// # Errors
    /// Returns an error on an internal failure.
    pub fn cbc_pkcs7(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        let context = key.algorithm().new_encryption_context(OperatingMode::CBC)?;
        Self::less_safe_cbc_pkcs7(key, context)
    }

    /// Constructs a `StreamingEncryptingKey` for encrypting data using the CBC cipher mode
    /// with pkcs7 padding.
    /// The resulting ciphertext will be longer than the plaintext; padding is added
    /// to fill the next block of ciphertext.
    ///
    /// This is considered less safe because the caller could potentially construct
    /// an `EncryptionContext` from a previously used initialization vector (IV).
    ///
    /// # Errors
    /// Returns an error on an internal failure.
    pub fn less_safe_cbc_pkcs7(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CBC, context)
    }
}

/// A key for streaming decryption operations.
pub struct StreamingDecryptingKey {
    algorithm: &'static Algorithm,
    mode: OperatingMode,
    cipher_ctx: LcPtr<EVP_CIPHER_CTX>,
}
impl StreamingDecryptingKey {
    #[allow(clippy::needless_pass_by_value)]
    fn new(
        key: UnboundCipherKey,
        mode: OperatingMode,
        context: DecryptionContext,
    ) -> Result<Self, Unspecified> {
        let cipher_ctx = LcPtr::new(unsafe { EVP_CIPHER_CTX_new() })?;
        let algorithm = key.algorithm();
        let cipher = mode.evp_cipher(key.algorithm);
        let key_bytes = key.key_bytes.as_ref();
        debug_assert_eq!(
            key_bytes.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_key_length(*cipher) }).unwrap()
        );
        let iv = <&[u8]>::try_from(&context)?;
        debug_assert_eq!(
            iv.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_iv_length(*cipher) }).unwrap()
        );

        if 1 != unsafe {
            EVP_DecryptInit_ex(
                cipher_ctx.as_mut_ptr(),
                *cipher,
                null_mut(),
                key_bytes.as_ptr(),
                iv.as_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        Ok(Self {
            algorithm,
            mode,
            cipher_ctx,
        })
    }

    /// Updates the internal state of the key with the provided ciphertext `input`,
    /// potentially also writing bytes of plaintext to `output`.
    /// The number of bytes written to `output` can be up to `input.len()`
    /// plus the block length of the cipher algorithm (e.g., 16 bytes for AES).
    ///
    /// # Errors
    /// * May return an error if the `output` buffer is smaller than the length of
    ///   the `input` plus the algorithm's block length. Certain cipher modes
    ///   (such as CTR) may allow the output buffer to be as small as the size of
    ///   the input in certain circumstances.
    /// * Returns an error if the length of either `input` or `output` is larger
    ///   than `i32::MAX`.
    pub fn update<'a>(
        &mut self,
        input: &[u8],
        output: &'a mut [u8],
    ) -> Result<BufferUpdate<'a>, Unspecified> {
        let mut outlen: i32 = output.len().try_into()?;
        let inlen: i32 = input.len().try_into()?;
        if 1 != unsafe {
            EVP_DecryptUpdate(
                self.cipher_ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                inlen,
            )
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok(BufferUpdate::new(output, outlen))
    }

    /// Finishes the decryption operation, writing the remaining plaintext to
    /// `output`.
    /// The number of bytes written to `output` can be up to the block length of
    /// the cipher algorithm (e.g., 16 bytes for AES).
    ///
    /// # Errors
    /// * May return an error if the `output` buffer is smaller than the algorithm's
    ///   block length. Certain cipher modes (such as CTR) may allow the output buffer
    ///   to only be large enough to fit the remaining plaintext.
    /// * Returns an error if the length of `output` is larger than `i32::MAX`.
    pub fn finish(self, output: &mut [u8]) -> Result<BufferUpdate, Unspecified> {
        let mut outlen: i32 = output.len().try_into()?;
        if 1 != unsafe { EVP_DecryptFinal_ex(*self.cipher_ctx, output.as_mut_ptr(), &mut outlen) } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok(BufferUpdate::new(output, outlen))
    }

    /// Returns the cipher operating mode.
    #[must_use]
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Returns the cipher algorithm
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// Constructs a `StreamingDecryptingKey` for decrypting using the CTR cipher mode.
    /// The resulting plaintext will be the same length as the ciphertext.
    ///
    /// # Errors
    /// Returns an error on an internal failure.
    pub fn ctr(key: UnboundCipherKey, context: DecryptionContext) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CTR, context)
    }

    /// Constructs a `StreamingDecryptingKey` for decrypting using the CBC cipher mode.
    /// The resulting plaintext will be shorter than the ciphertext.
    ///
    /// # Errors
    /// Returns an error on an internal failure.
    pub fn cbc_pkcs7(
        key: UnboundCipherKey,
        context: DecryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CBC, context)
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher::{
        DecryptionContext, OperatingMode, StreamingDecryptingKey, StreamingEncryptingKey,
        UnboundCipherKey, AES_256, AES_256_KEY_LEN,
    };
    use crate::rand::{SecureRandom, SystemRandom};
    use paste::*;

    fn step_encrypt(
        mut encrypting_key: StreamingEncryptingKey,
        plaintext: &[u8],
        step: usize,
    ) -> (Box<[u8]>, DecryptionContext) {
        let alg = encrypting_key.algorithm();
        let mode = encrypting_key.mode();
        let n = plaintext.len();
        let mut ciphertext = vec![0u8; n + alg.block_len()];

        let mut in_idx: usize = 0;
        let mut out_idx: usize = 0;
        loop {
            let mut in_end = in_idx + step;
            if in_end > n {
                in_end = n;
            }
            let out_end = out_idx + (in_end - in_idx) + alg.block_len();
            let output = encrypting_key
                .update(
                    &plaintext[in_idx..in_end],
                    &mut ciphertext[out_idx..out_end],
                )
                .unwrap();
            in_idx += step;
            out_idx += output.written().len();
            if in_idx >= n {
                break;
            }
        }
        let out_end = out_idx + alg.block_len();
        let (decrypt_iv, output) = encrypting_key
            .finish(&mut ciphertext[out_idx..out_end])
            .unwrap();
        let outlen = output.written().len();
        ciphertext.truncate(out_idx + outlen);
        match mode {
            OperatingMode::CBC => {
                assert!(ciphertext.len() > plaintext.len());
                assert!(ciphertext.len() <= plaintext.len() + alg.block_len());
            }
            OperatingMode::CTR => {
                assert_eq!(ciphertext.len(), plaintext.len());
            }
        }

        (ciphertext.into_boxed_slice(), decrypt_iv)
    }

    fn step_decrypt(
        mut decrypting_key: StreamingDecryptingKey,
        ciphertext: &[u8],
        step: usize,
    ) -> Box<[u8]> {
        let alg = decrypting_key.algorithm;
        let mode = decrypting_key.mode;
        let n = ciphertext.len();
        let mut plaintext = vec![0u8; n + alg.block_len()];

        let mut in_idx: usize = 0;
        let mut out_idx: usize = 0;
        loop {
            let mut in_end = in_idx + step;
            if in_end > n {
                in_end = n;
            }
            let out_end = out_idx + (in_end - in_idx) + alg.block_len();
            let output = decrypting_key
                .update(
                    &ciphertext[in_idx..in_end],
                    &mut plaintext[out_idx..out_end],
                )
                .unwrap();
            in_idx += step;
            out_idx += output.written().len();
            if in_idx >= n {
                break;
            }
        }
        let out_end = out_idx + alg.block_len();
        let output = decrypting_key
            .finish(&mut plaintext[out_idx..out_end])
            .unwrap();
        let outlen = output.written().len();
        plaintext.truncate(out_idx + outlen);
        match mode {
            OperatingMode::CBC => {
                assert!(ciphertext.len() > plaintext.len());
                assert!(ciphertext.len() <= plaintext.len() + alg.block_len());
            }
            OperatingMode::CTR => {
                assert_eq!(ciphertext.len(), plaintext.len());
            }
        }
        plaintext.into_boxed_slice()
    }

    macro_rules! helper_stream_step_encrypt_test {
        ($mode:ident) => {
            paste! {
                fn [<helper_test_ $mode _stream_encrypt_step_n_bytes>](
                    encrypting_key_creator: impl Fn() -> StreamingEncryptingKey,
                    decrypting_key_creator: impl Fn(DecryptionContext) -> StreamingDecryptingKey,
                    n: usize,
                    step: usize,
                ) {
                    let mut input = vec![0u8; n];
                    let random = SystemRandom::new();
                    random.fill(&mut input).unwrap();

                    let encrypting_key = encrypting_key_creator();

                    let (ciphertext, decrypt_iv) = step_encrypt(encrypting_key, &input, step);

                    let decrypting_key = decrypting_key_creator(decrypt_iv);

                    let plaintext = step_decrypt(decrypting_key, &ciphertext, step);

                    assert_eq!(input.as_slice(), &*plaintext);
                }
            }
        };
    }

    helper_stream_step_encrypt_test!(cbc_pkcs7);
    helper_stream_step_encrypt_test!(ctr);

    #[test]
    fn test_step_cbc() {
        let random = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_LEN];
        random.fill(&mut key).unwrap();
        let key = key;

        let encrypting_key_creator = || {
            let key = UnboundCipherKey::new(&AES_256, &key.clone()).unwrap();
            StreamingEncryptingKey::cbc_pkcs7(key).unwrap()
        };
        let decrypting_key_creator = |decryption_ctx: DecryptionContext| {
            let key = UnboundCipherKey::new(&AES_256, &key.clone()).unwrap();
            StreamingDecryptingKey::cbc_pkcs7(key, decryption_ctx).unwrap()
        };

        for i in 13..=21 {
            for j in 124..=131 {
                helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(
                    encrypting_key_creator,
                    decrypting_key_creator,
                    j,
                    i,
                );
            }
            for j in 124..=131 {
                helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(
                    encrypting_key_creator,
                    decrypting_key_creator,
                    j,
                    j - i,
                );
            }
        }
        for j in 124..=131 {
            helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(
                encrypting_key_creator,
                decrypting_key_creator,
                j,
                j,
            );
            helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(
                encrypting_key_creator,
                decrypting_key_creator,
                j,
                256,
            );
            helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(
                encrypting_key_creator,
                decrypting_key_creator,
                j,
                1,
            );
        }
    }

    #[test]
    fn test_step_ctr() {
        let random = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_LEN];
        random.fill(&mut key).unwrap();

        let encrypting_key_creator = || {
            let key = UnboundCipherKey::new(&AES_256, &key.clone()).unwrap();
            StreamingEncryptingKey::ctr(key).unwrap()
        };
        let decrypting_key_creator = |decryption_ctx: DecryptionContext| {
            let key = UnboundCipherKey::new(&AES_256, &key.clone()).unwrap();
            StreamingDecryptingKey::ctr(key, decryption_ctx).unwrap()
        };

        for i in 13..=21 {
            for j in 124..=131 {
                helper_test_ctr_stream_encrypt_step_n_bytes(
                    encrypting_key_creator,
                    decrypting_key_creator,
                    j,
                    i,
                );
            }
            for j in 124..=131 {
                helper_test_ctr_stream_encrypt_step_n_bytes(
                    encrypting_key_creator,
                    decrypting_key_creator,
                    j,
                    j - i,
                );
            }
        }
        for j in 124..=131 {
            helper_test_ctr_stream_encrypt_step_n_bytes(
                encrypting_key_creator,
                decrypting_key_creator,
                j,
                j,
            );
            helper_test_ctr_stream_encrypt_step_n_bytes(
                encrypting_key_creator,
                decrypting_key_creator,
                j,
                256,
            );
            helper_test_ctr_stream_encrypt_step_n_bytes(
                encrypting_key_creator,
                decrypting_key_creator,
                j,
                1,
            );
        }
    }
}
