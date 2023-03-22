// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::block::{Block, BLOCK_LEN};
use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::key_inner::KeyInner;
use crate::aead::{Algorithm, AlgorithmID, Nonce, NONCE_LEN};
use aws_lc::CRYPTO_chacha_20;
use zeroize::Zeroize;

use crate::error;

pub(crate) const KEY_LEN: usize = 32usize;

/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    init: init_chacha,
    key_len: KEY_LEN,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: u64::MAX,
};

#[inline]
fn init_chacha(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    KeyInner::new(SymmetricCipherKey::chacha20(key)?)
}

pub(crate) struct ChaCha20Key(pub(super) [u8; KEY_LEN]);

impl From<[u8; KEY_LEN]> for ChaCha20Key {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        ChaCha20Key(bytes)
    }
}

impl Drop for ChaCha20Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[allow(clippy::needless_pass_by_value)]
impl ChaCha20Key {
    #[inline]
    pub(super) fn encrypt_in_place(&self, nonce: Nonce, in_out: &mut [u8], ctr: u32) {
        encrypt_in_place_chacha20(self, nonce.as_ref(), in_out, ctr);
    }
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(super) fn encrypt_block_chacha20(
    key: &ChaCha20Key,
    block: Block,
    nonce: Nonce,
    counter: u32,
) -> Result<Block, error::Unspecified> {
    let mut cipher_text = [0u8; BLOCK_LEN];
    encrypt_chacha20(
        key,
        block.as_ref().as_slice(),
        &mut cipher_text,
        nonce.as_ref(),
        counter,
    )?;

    Ok(Block::from(&cipher_text))
}

#[inline]
pub(super) fn encrypt_chacha20(
    key: &ChaCha20Key,
    plaintext: &[u8],
    ciphertext: &mut [u8],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
) -> Result<(), error::Unspecified> {
    if ciphertext.len() < plaintext.len() {
        return Err(error::Unspecified);
    }
    let key_bytes = &key.0;
    unsafe {
        CRYPTO_chacha_20(
            ciphertext.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            key_bytes.as_ptr(),
            nonce.as_ptr(),
            counter,
        );
    }
    Ok(())
}

#[inline]
pub(super) fn encrypt_in_place_chacha20(
    key: &ChaCha20Key,
    nonce: &[u8; NONCE_LEN],
    in_out: &mut [u8],
    counter: u32,
) {
    let key_bytes = &key.0;
    unsafe {
        CRYPTO_chacha_20(
            in_out.as_mut_ptr(),
            in_out.as_ptr(),
            in_out.len(),
            key_bytes.as_ptr(),
            nonce.as_ptr(),
            counter,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test, test_file};
    use core::convert::TryInto;

    const MAX_ALIGNMENT: usize = 15;

    // Verifies the encryption is successful when done on overlapping buffers.
    //
    // On some branches of the 32-bit x86 and ARM assembly code the in-place
    // operation fails in some situations where the input/output buffers are
    // not exactly overlapping. Such failures are dependent not only on the
    // degree of overlapping but also the length of the data. `encrypt_within`
    // works around that.
    #[test]
    fn chacha20_test() {
        // Reuse a buffer to avoid slowing down the tests with allocations.
        let mut buf = vec![0u8; 1300];

        test::run(
            test_file!("data/chacha_tests.txt"),
            move |section, test_case| {
                assert_eq!(section, "");

                let key = test_case.consume_bytes("Key");
                let key: &[u8; KEY_LEN] = key.as_slice().try_into()?;
                let key = ChaCha20Key::from(*key);

                #[allow(clippy::cast_possible_truncation)]
                let ctr = test_case.consume_usize("Ctr") as u32;
                let nonce: [u8; NONCE_LEN] = test_case.consume_bytes("Nonce").try_into().unwrap();
                let input = test_case.consume_bytes("Input");
                let output = test_case.consume_bytes("Output");

                // Run the test case over all prefixes of the input because the
                // behavior of ChaCha20 implementation changes dependent on the
                // length of the input.
                for len in 0..=input.len() {
                    chacha20_test_case_inner(
                        &key,
                        nonce,
                        ctr,
                        &input[..len],
                        &output[..len],
                        &mut buf,
                    );
                }

                Ok(())
            },
        );
    }

    fn chacha20_test_case_inner(
        key: &ChaCha20Key,
        nonce: [u8; NONCE_LEN],
        ctr: u32,
        input: &[u8],
        expected: &[u8],
        buf: &mut [u8],
    ) {
        // Straightforward encryption into disjoint buffers is computed
        // correctly.
        const ARBITRARY: u8 = 123;

        for alignment in 0..=MAX_ALIGNMENT {
            buf[..alignment].fill(ARBITRARY);
            let buf = &mut buf[..(input.len())];
            buf.copy_from_slice(input);
            let nonce = Nonce(nonce);

            key.encrypt_in_place(nonce, buf, ctr);
            assert_eq!(
                &buf[..input.len()],
                expected,
                "Failed on alignment: {alignment}",
            );
        }
    }
}
