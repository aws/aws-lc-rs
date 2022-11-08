// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::block::{Block, BLOCK_LEN};
use crate::error;
use aws_lc_sys::EVP_CIPHER_CTX;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::raw::c_int;
use zeroize::Zeroize;

pub(crate) struct Aes128Key(pub(super) [u8; 16]);
impl Deref for Aes128Key {
    type Target = [u8; 16];
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Aes128Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct Aes256Key(pub(super) [u8; 32]);
impl Deref for Aes256Key {
    type Target = [u8; 32];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Aes256Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[inline]
pub(super) fn encrypt_block_aes_ecb(
    ctx: *mut EVP_CIPHER_CTX,
    block: Block,
) -> Result<Block, error::Unspecified> {
    unsafe {
        let mut out_len = MaybeUninit::<c_int>::uninit();
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit();
        let plain_bytes = block.as_ref();
        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            ctx,
            cipher_text.as_mut_ptr().cast(),
            out_len.as_mut_ptr(),
            plain_bytes.as_ptr(),
            BLOCK_LEN as c_int,
        ) {
            return Err(error::Unspecified);
        }
        #[allow(clippy::cast_sign_loss)]
        let olen = out_len.assume_init() as usize;
        if olen != BLOCK_LEN {
            return Err(error::Unspecified);
        }

        Ok(Block::from(&cipher_text.assume_init()))
    }
}

#[cfg(test)]
mod test {
    use crate::aead::aes::{Aes128Key, Aes256Key};
    use crate::test;

    #[test]
    fn test_key_type_header_protection_key() {
        let aes128_key_bytes = test::from_dirty_hex(r#"d480429666d48b400633921c5407d1d1"#);
        let aes256_key_bytes = test::from_dirty_hex(
            r#"d480429666d48b400633921c5407d1d1d480429666d48b400633921c5407d1d1"#,
        );

        let aes128 = Aes128Key(aes128_key_bytes.clone().try_into().unwrap());
        let aes256 = Aes256Key(aes256_key_bytes.clone().try_into().unwrap());

        assert_eq!(aes128.as_slice(), aes128_key_bytes.as_slice());
        assert_eq!(aes256.as_slice(), aes256_key_bytes.as_slice());
    }
}
