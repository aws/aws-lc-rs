// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::{counter, Aad, Algorithm, AlgorithmID, KeyInner, Nonce, TAG_LEN};
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

pub(crate) fn seal_combined<InOut>(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut InOut,
    plaintext_len: usize,
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

        let mut overhead_size: usize;
        unsafe {
            overhead_size =
                aws_lc_sys::EVP_AEAD_max_overhead(aws_lc_sys::EVP_aead_xchacha20_poly1305());
        }

        in_out.extend(&vec![0u8; overhead_size]);

        let mut out_len = MaybeUninit::<usize>::uninit();
        let mut mut_in_out = in_out.as_mut();
        let mut out_ptr = mut_in_out.as_mut_ptr();
        let mut in_ptr = mut_in_out.as_ptr();
        let aad_str_ptr = aad.0.as_ptr();
        let aad_len = aad.0.len();

        if 1 != aws_lc_sys::EVP_AEAD_CTX_seal(
            ctx,
            out_ptr,
            out_len.as_mut_ptr(),
            plaintext_len + overhead_size,
            tag_iv,
            TAG_LEN,
            in_ptr,
            plaintext_len,
            aad_str_ptr,
            aad_len,
        ) {
            return Err(error::Unspecified);
        }

        Ok(())
    }
}

fn chacha_open_combined(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(), error::Unspecified> {
    unsafe {
        let ctx = match key {
            KeyInner::CHACHA20_POLY1305(_, _, ctx) => ctx,
            _ => panic!("Unsupport algorithm"),
        };
        let tag_iv = Counter::one(nonce)
            .increment()
            .into_bytes_less_safe()
            .as_ptr();

        let aad_str = aad.0;
        let mut out_len = MaybeUninit::<usize>::uninit();
        if 1 != aws_lc_sys::EVP_AEAD_CTX_open(
            *ctx,
            in_out.as_mut_ptr().cast(),
            out_len.as_mut_ptr(),
            usize::MAX,
            tag_iv,
            TAG_LEN,
            in_out.as_ptr(),
            in_out.as_mut().len(),
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
