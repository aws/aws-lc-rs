// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cipher::block::{Block, BLOCK_LEN};
use aws_lc::{AES_ecb_encrypt, AES_ENCRYPT, AES_KEY};
use std::mem::MaybeUninit;
use std::ops::Deref;
use zeroize::Zeroize;

pub(crate) struct Aes128Key(pub(crate) [u8; 16]);
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

pub(crate) struct Aes256Key(pub(crate) [u8; 32]);
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
pub(crate) fn encrypt_block_aes_ecb(aes_key: &AES_KEY, block: Block) -> Block {
    unsafe {
        let mut cipher_text = MaybeUninit::<[u8; BLOCK_LEN]>::uninit();
        let plain_bytes = block.as_ref();
        AES_ecb_encrypt(
            plain_bytes.as_ptr(),
            cipher_text.as_mut_ptr().cast(),
            aes_key,
            AES_ENCRYPT,
        );

        Block::from(&cipher_text.assume_init())
    }
}

#[cfg(test)]
mod test {
    use crate::cipher::aes::{Aes128Key, Aes256Key};
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
