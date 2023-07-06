// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    cipher::{
        DecryptingKey, EncryptingKey, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey,
        UnboundCipherKey, AES_128, AES_256,
    },
    FipsServiceStatus,
};

use crate::common::{
    assert_fips_status_indicator, TEST_KEY_128_BIT, TEST_KEY_256_BIT, TEST_MESSAGE,
};

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
