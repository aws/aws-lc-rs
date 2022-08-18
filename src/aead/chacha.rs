// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::{counter, Aad, Algorithm, AlgorithmID, KeyInner, Nonce, NONCE_LEN, TAG_LEN};
use crate::endian::BigEndian;
use crate::error;
use std::mem::MaybeUninit;

pub type Counter = counter::Counter<BigEndian<u32>>;

pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    init: init_chacha,
    key_len: 32,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: u64::MAX,
};

pub(crate) fn aead_seal_combined<InOut>(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut InOut,
) -> Result<(), error::Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    unsafe {
        let ctx = match key {
            KeyInner::CHACHA20_POLY1305(_, _, ctx) => *ctx,
            _ => panic!("Unsupport algorithm"),
        };
        let tag_iv = Counter::one(nonce)
            .increment()
            .into_bytes_less_safe()
            .as_ptr();

        let plaintext_len = in_out.as_mut().len();

        in_out.extend(&vec![0u8; TAG_LEN]);

        let mut out_len = MaybeUninit::<usize>::uninit();
        let mut mut_in_out = in_out.as_mut();
        let add_str = aad.0;

        if 1 != aws_lc_sys::EVP_AEAD_CTX_seal(
            ctx,
            mut_in_out.as_mut_ptr(),
            out_len.as_mut_ptr(),
            plaintext_len + TAG_LEN,
            tag_iv,
            NONCE_LEN,
            mut_in_out.as_ptr(),
            plaintext_len,
            add_str.as_ptr(),
            add_str.len(),
        ) {
            return Err(error::Unspecified);
        }

        Ok(())
    }
}

pub(crate) fn aead_open_combined(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(), error::Unspecified> {
    unsafe {
        let ctx = match key {
            KeyInner::CHACHA20_POLY1305(_, _, ctx) => *ctx,
            _ => panic!("Unsupport algorithm"),
        };
        let tag_iv = Counter::one(nonce)
            .increment()
            .into_bytes_less_safe()
            .as_ptr();

        let plaintext_len = in_out.as_mut().len() - TAG_LEN;

        let aad_str = aad.0;
        let mut out_len = MaybeUninit::<usize>::uninit();
        if 1 != aws_lc_sys::EVP_AEAD_CTX_open(
            ctx,
            in_out.as_mut_ptr(),
            out_len.as_mut_ptr(),
            plaintext_len,
            tag_iv,
            NONCE_LEN,
            in_out.as_ptr(),
            plaintext_len + TAG_LEN,
            aad_str.as_ptr(),
            aad_str.len(),
        ) {
            return Err(error::Unspecified);
        }

        Ok(())
    }
}

fn init_chacha(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    Ok(KeyInner::new(SymmetricCipherKey::chacha20poly1305(key)?)?)
}
