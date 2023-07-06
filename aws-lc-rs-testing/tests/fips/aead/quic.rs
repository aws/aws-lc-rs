// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20},
    FipsServiceStatus,
};

use crate::common::{assert_fips_status_indicator, TEST_KEY_128_BIT, TEST_KEY_256_BIT};

macro_rules! quic_api {
    ($name:ident, $alg:expr, $key:expr, $expect:path) => {
        #[test]
        fn $name() {
            let key = HeaderProtectionKey::new($alg, $key).unwrap();

            assert_fips_status_indicator!(key.new_mask(&[42u8; 16]), $expect).unwrap();
        }
    };
}

quic_api!(
    aes_128,
    &AES_128,
    &TEST_KEY_128_BIT,
    FipsServiceStatus::NonApprovedMode
);
quic_api!(
    aes_256,
    &AES_256,
    &TEST_KEY_256_BIT,
    FipsServiceStatus::NonApprovedMode
);
quic_api!(
    chacha20,
    &CHACHA20,
    &TEST_KEY_256_BIT,
    FipsServiceStatus::NonApprovedMode
);
