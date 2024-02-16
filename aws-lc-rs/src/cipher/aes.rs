// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{
    cipher::block::{Block, BLOCK_LEN},
    fips::indicator_check,
};
use aws_lc::{AES_ecb_encrypt, AES_ENCRYPT, AES_KEY};
use core::mem::MaybeUninit;

/// Length of an AES-128 key in bytes.
pub const AES_128_KEY_LEN: usize = 16;

/// Length of an AES-256 key in bytes.
pub const AES_256_KEY_LEN: usize = 32;

#[inline]
pub(crate) fn encrypt_block_aes(aes_key: &AES_KEY, block: Block) -> Block {
    unsafe {
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit();
        let plain_bytes = block.as_ref();

        indicator_check!(AES_ecb_encrypt(
            plain_bytes.as_ptr(),
            cipher_text.as_mut_ptr().cast(),
            aes_key,
            AES_ENCRYPT,
        ));

        Block::from(&cipher_text.assume_init())
    }
}
