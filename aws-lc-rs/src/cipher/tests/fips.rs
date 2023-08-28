// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(debug_assertions)]

use crate::{
    cipher::{
        DecryptingKey, EncryptingKey, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey,
        UnboundCipherKey, AES_128, AES_256,
    },
    fips::{assert_fips_status_indicator, FipsServiceStatus},
};

const TEST_KEY_128_BIT: [u8; 16] = [
    0x9f, 0xd9, 0x41, 0xc3, 0xa6, 0xfe, 0xb9, 0x26, 0x2a, 0x35, 0xa7, 0x44, 0xbb, 0xc0, 0x3a, 0x6a,
];

const TEST_KEY_256_BIT: [u8; 32] = [
    0xd8, 0x32, 0x58, 0xa9, 0x5a, 0x62, 0x6c, 0x99, 0xc4, 0xe6, 0xb5, 0x3f, 0x97, 0x90, 0x62, 0xbe,
    0x71, 0x0f, 0xd5, 0xe1, 0xd4, 0xfe, 0x95, 0xb3, 0x03, 0x46, 0xa5, 0x8e, 0x36, 0xad, 0x18, 0xe3,
];

const TEST_MESSAGE: &str = "test message";

macro_rules! block_api {
    ($name:ident, $alg:expr, $encrypt_mode:path, $decrypt_mode:path, $key:expr) => {
        #[test]
        fn $name() {
            let key = $encrypt_mode(UnboundCipherKey::new($alg, $key).unwrap()).unwrap();

            let mut in_out = Vec::from(TEST_MESSAGE);

            let context = assert_fips_status_indicator!(
                key.encrypt(&mut in_out),
                FipsServiceStatus::ApprovedMode
            )
            .unwrap();

            let key = $decrypt_mode(UnboundCipherKey::new($alg, $key).unwrap()).unwrap();

            let in_out = assert_fips_status_indicator!(
                key.decrypt(&mut in_out, context),
                FipsServiceStatus::ApprovedMode
            )
            .unwrap();

            assert_eq!(TEST_MESSAGE.as_bytes(), in_out);
        }
    };
}

block_api!(
    aes_126_cbc_pkcs7,
    &AES_128,
    PaddedBlockEncryptingKey::cbc_pkcs7,
    PaddedBlockDecryptingKey::cbc_pkcs7,
    &TEST_KEY_128_BIT
);
block_api!(
    aes_126_ctr,
    &AES_128,
    EncryptingKey::ctr,
    DecryptingKey::ctr,
    &TEST_KEY_128_BIT
);

block_api!(
    aes_256_cbc_pkcs7,
    &AES_256,
    PaddedBlockEncryptingKey::cbc_pkcs7,
    PaddedBlockDecryptingKey::cbc_pkcs7,
    &TEST_KEY_256_BIT
);
block_api!(
    aes_256_ctr,
    &AES_256,
    EncryptingKey::ctr,
    DecryptingKey::ctr,
    &TEST_KEY_256_BIT
);
