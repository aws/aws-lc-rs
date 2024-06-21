// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cipher::{
    Algorithm, DecryptionContext, EncryptionContext, OperatingMode, UnboundCipherKey,
};
use crate::error::Unspecified;
use crate::fips::indicator_check;
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
        let mut cipher_ctx = LcPtr::new(unsafe { EVP_CIPHER_CTX_new() })?;
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

        // AWS-LC copies the key and iv values into the EVP_CIPHER_CTX, and thus can be dropped after this.
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
    /// plus the block length of the algorithm (e.g., [`Algorithm::block_len`]).
    ///
    /// # Errors
    /// * Returns an error if the `output` buffer is smaller than the length of
    ///   the `input` plus the algorithm's block length (e.g. [`Algorithm::block_len`]) minus one.
    /// * May return an error if the length of `input` plus the algorithm's block length is larger than `i32::MAX`.
    pub fn update<'a>(
        &mut self,
        input: &[u8],
        output: &'a mut [u8],
    ) -> Result<BufferUpdate<'a>, Unspecified> {
        let min_outsize = input
            .len()
            .checked_add(self.algorithm().block_len())
            .ok_or(Unspecified)?
            - 1;
        if output.len() < min_outsize {
            return Err(Unspecified);
        }
        let mut outlen: i32 = 0;
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
        debug_assert!(outlen <= min_outsize);
        Ok(BufferUpdate::new(output, outlen))
    }

    /// Finishes the encryption operation, writing any remaining ciphertext to
    /// `output`.
    ///
    /// The number of bytes written to `output` can be up to the block length of
    /// [`Algorithm::block_len`].
    ///
    /// # Errors
    /// * Returns an error if the `output` buffer is smaller than the algorithm's
    ///   block length.
    pub fn finish(
        mut self,
        output: &mut [u8],
    ) -> Result<(DecryptionContext, BufferUpdate), Unspecified> {
        if output.len() < self.algorithm().block_len() {
            return Err(Unspecified);
        }
        let mut outlen: i32 = 0;

        if 1 != indicator_check!(unsafe {
            EVP_EncryptFinal_ex(
                self.cipher_ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
            )
        }) {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        debug_assert!(outlen <= self.algorithm().block_len());
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
        let mut cipher_ctx = LcPtr::new(unsafe { EVP_CIPHER_CTX_new() })?;
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

        // AWS-LC copies the key and iv values into the EVP_CIPHER_CTX, and thus can be dropped after this.
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
    /// plus the block length of the cipher algorithm (e.g., [`Algorithm::block_len`]).
    ///
    /// # Errors
    /// * Returns an error if the `output` buffer is smaller than the length of
    ///   the `input` plus the algorithm's block length.
    /// * May return an error if the length of `input` plus the algorithm's block length is larger
    ///   than `i32::MAX`.
    pub fn update<'a>(
        &mut self,
        input: &[u8],
        output: &'a mut [u8],
    ) -> Result<BufferUpdate<'a>, Unspecified> {
        let mut outlen: i32 = 0;
        let inlen: i32 = input.len().try_into()?;

        let min_outsize = input
            .len()
            .checked_add(self.algorithm().block_len())
            .ok_or(Unspecified)?;
        if output.len() < min_outsize {
            return Err(Unspecified);
        }

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
        debug_assert!(outlen <= min_outsize);
        Ok(BufferUpdate::new(output, outlen))
    }

    /// Finishes the decryption operation, writing the remaining plaintext to
    /// `output`.
    /// The number of bytes written to `output` can be up to the block length of
    /// the cipher algorithm (e.g., [`Algorithm::block_len`]).
    ///
    /// # Errors
    /// * Returns an error if the `output` buffer is smaller than the algorithm's
    ///   block length.
    pub fn finish(self, output: &mut [u8]) -> Result<BufferUpdate, Unspecified> {
        if output.len() < self.algorithm().block_len() {
            return Err(Unspecified);
        }
        let mut outlen: i32 = 0;

        if 1 != indicator_check!(unsafe {
            EVP_DecryptFinal_ex(*self.cipher_ctx, output.as_mut_ptr(), &mut outlen)
        }) {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        debug_assert!(outlen <= self.algorithm().block_len());
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
        DecryptionContext, EncryptionContext, OperatingMode, StreamingDecryptingKey,
        StreamingEncryptingKey, UnboundCipherKey, AES_128, AES_256, AES_256_KEY_LEN,
    };
    use crate::iv::{FixedLength, IV_LEN_128_BIT};
    use crate::rand::{SecureRandom, SystemRandom};
    use crate::test::from_hex;
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
        let alg = decrypting_key.algorithm();
        let mode = decrypting_key.mode();
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

    macro_rules! streaming_cipher_kat {
        ($name:ident, $alg:expr, $mode:expr, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
            #[test]
            fn $name() {
                let key = from_hex($key).unwrap();
                let input = from_hex($plaintext).unwrap();
                let expected_ciphertext = from_hex($ciphertext).unwrap();
                let iv = from_hex($iv).unwrap();

                for step in ($from_step..=$to_step) {
                    let ec = EncryptionContext::Iv128(
                        FixedLength::<IV_LEN_128_BIT>::try_from(iv.as_slice()).unwrap(),
                    );

                    let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

                    let encrypting_key =
                        StreamingEncryptingKey::new(unbound_key, $mode, ec).unwrap();

                    let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                    assert_eq!(expected_ciphertext.as_slice(), ciphertext.as_ref());

                    let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                    let decrypting_key =
                        StreamingDecryptingKey::new(unbound_key2, $mode, decrypt_ctx).unwrap();

                    let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                    assert_eq!(input.as_slice(), plaintext.as_ref());
                }
            }
        };
    }

    streaming_cipher_kat!(
        test_iv_aes_128_ctr_16_bytes,
        &AES_128,
        OperatingMode::CTR,
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "c6b01904c3da3df5e7d62bd96d153686",
        2,
        9
    );
    streaming_cipher_kat!(
        test_iv_aes_256_ctr_15_bytes,
        &AES_256,
        OperatingMode::CTR,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddee",
        "f28122856e1cf9a7216a30d111f399",
        2,
        9
    );

    streaming_cipher_kat!(
        test_openssl_aes_128_ctr_15_bytes,
        &AES_128,
        OperatingMode::CTR,
        "244828580821c1652582c76e34d299f5",
        "093145d5af233f46072a5eb5adc11aa1",
        "3ee38cec171e6cf466bf0df98aa0e1",
        "bd7d928f60e3422d96b3f8cd614eb2",
        2,
        9
    );

    streaming_cipher_kat!(
        test_openssl_aes_256_ctr_15_bytes,
        &AES_256,
        OperatingMode::CTR,
        "0857db8240ea459bdf660b4cced66d1f2d3734ff2de7b81e92740e65e7cc6a1d",
        "f028ecb053f801102d11fccc9d303a27",
        "eca7285d19f3c20e295378460e8729",
        "b5098e5e788de6ac2f2098eb2fc6f8",
        2,
        9
    );

    streaming_cipher_kat!(
        test_iv_aes_128_cbc_16_bytes,
        &AES_128,
        OperatingMode::CBC,
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a9e978e6d16b086570ef794ef97984232",
        2,
        9
    );

    streaming_cipher_kat!(
        test_iv_aes_256_cbc_15_bytes,
        &AES_256,
        OperatingMode::CBC,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00000000000000000000000000000000",
        "00112233445566778899aabbccddee",
        "2ddfb635a651a43f582997966840ca0c",
        2,
        9
    );

    streaming_cipher_kat!(
        test_openssl_aes_128_cbc_15_bytes,
        &AES_128,
        OperatingMode::CBC,
        "053304bb3899e1d99db9d29343ea782d",
        "b5313560244a4822c46c2a0c9d0cf7fd",
        "a3e4c990356c01f320043c3d8d6f43",
        "ad96993f248bd6a29760ec7ccda95ee1",
        2,
        9
    );

    streaming_cipher_kat!(
        test_openssl_aes_128_cbc_16_bytes,
        &AES_128,
        OperatingMode::CBC,
        "95af71f1c63e4a1d0b0b1a27fb978283",
        "89e40797dca70197ff87d3dbb0ef2802",
        "aece7b5e3c3df1ffc9802d2dfe296dc7",
        "301b5dab49fb11e919d0d39970d06739301919743304f23f3cbc67d28564b25b",
        2,
        9
    );

    streaming_cipher_kat!(
        test_openssl_aes_256_cbc_15_bytes,
        &AES_256,
        OperatingMode::CBC,
        "d369e03e9752784917cc7bac1db7399598d9555e691861d9dd7b3292a693ef57",
        "1399bb66b2f6ad99a7f064140eaaa885",
        "7385f5784b85bf0a97768ddd896d6d",
        "4351082bac9b4593ae8848cc9dfb5a01",
        2,
        9
    );

    streaming_cipher_kat!(
        test_openssl_aes_256_cbc_16_bytes,
        &AES_256,
        OperatingMode::CBC,
        "d4a8206dcae01242f9db79a4ecfe277d0f7bb8ccbafd8f9809adb39f35aa9b41",
        "24f6076548fb9d93c8f7ed9f6e661ef9",
        "a39c1fdf77ea3e1f18178c0ec237c70a",
        "f1af484830a149ee0387b854d65fe87ca0e62efc1c8e6909d4b9ab8666470453",
        2,
        9
    );
}
