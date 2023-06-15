// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::{Aad, Algorithm, AlgorithmID, Nonce, Tag, MAX_TAG_LEN};
use std::mem::MaybeUninit;

use crate::aead::aead_ctx::AeadCtx;
use crate::cipher::aes::{AES_128_KEY_LEN, AES_256_KEY_LEN};
use crate::error::Unspecified;
use aws_lc::EVP_AEAD_CTX_seal_scatter;
use std::ptr::null;

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_separate(
    key: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, Unspecified> {
    unsafe {
        let aead_ctx = match key {
            AeadCtx::CHACHA20_POLY1305(aead_ctx)
            | AeadCtx::AES_128_GCM(aead_ctx)
            | AeadCtx::AES_256_GCM(aead_ctx) => aead_ctx,
        };

        let aad_slice = aad.as_ref();
        let nonce = nonce.as_ref();
        let mut tag = MaybeUninit::<[u8; MAX_TAG_LEN]>::uninit();
        let mut out_tag_len = MaybeUninit::<usize>::uninit();

        if 1 != EVP_AEAD_CTX_seal_scatter(
            aead_ctx,
            in_out.as_mut_ptr(),
            tag.as_mut_ptr().cast(),
            out_tag_len.as_mut_ptr(),
            MAX_TAG_LEN,
            nonce.as_ptr(),
            nonce.len(),
            in_out.as_ptr(),
            in_out.len(),
            null(),
            0usize,
            aad_slice.as_ptr(),
            aad_slice.len(),
        ) {
            return Err(Unspecified);
        }
        Ok(Tag(tag.assume_init()))
    }
}

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM: Algorithm = Algorithm {
    init: init_128_aead,
    key_len: AES_128_KEY_LEN,
    id: AlgorithmID::AES_128_GCM,
    max_input_len: u64::MAX,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM: Algorithm = Algorithm {
    init: init_256_aead,
    key_len: AES_256_KEY_LEN,
    id: AlgorithmID::AES_256_GCM,
    max_input_len: u64::MAX,
};

#[inline]
fn init_128_aead(key: &[u8]) -> Result<AeadCtx, Unspecified> {
    AeadCtx::aes_128_gcm(key)
}

#[inline]
fn init_256_aead(key: &[u8]) -> Result<AeadCtx, Unspecified> {
    AeadCtx::aes_256_gcm(key)
}
