// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    hkdf::{
        KeyType, Prk, Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, HKDF_SHA256, HKDF_SHA384, HKDF_SHA512,
    },
    FipsServiceStatus,
};

use crate::common::{assert_fips_status_indicator, TEST_KEY_128_BIT};

macro_rules! hkdf_extract_expand_api {
    ($name:ident, $alg:expr, $expect:path, $salt_len:literal, $info_len:literal) => {
        #[test]
        fn $name() {
            let salt = vec![42u8; $salt_len];

            // Will not set indicator function
            let salt = assert_fips_status_indicator!(
                Salt::new($alg, &salt[..]),
                FipsServiceStatus::ApprovedMode
            );

            // Will not set the indicator function
            let prk = assert_fips_status_indicator!(
                salt.extract(&[5, 6, 7, 8]),
                FipsServiceStatus::ApprovedMode
            );

            let info: Vec<u8> = vec![42u8; $info_len];
            let info_slices: Vec<&[u8]> = vec![info.as_ref()];

            // Will not set the inidcator function
            let okm = assert_fips_status_indicator!(
                prk.expand(info_slices.as_ref(), $alg),
                FipsServiceStatus::ApprovedMode
            )
            .unwrap();

            let mut out = vec![0u8; $alg.len()];

            // Will set the indicator function
            assert_fips_status_indicator!(okm.fill(&mut out), $expect).unwrap();
        }
    };
}

hkdf_extract_expand_api!(
    test_sha1_hkdf_extract_expand_api,
    HKDF_SHA1_FOR_LEGACY_USE_ONLY,
    FipsServiceStatus::ApprovedMode,
    16,
    16
);
hkdf_extract_expand_api!(
    test_sha256_hkdf_extract_expand_api_api,
    HKDF_SHA256,
    FipsServiceStatus::ApprovedMode,
    16,
    16
);
hkdf_extract_expand_api!(
    test_sha384_hkdf_extract_expand_api,
    HKDF_SHA384,
    FipsServiceStatus::ApprovedMode,
    16,
    16
);
hkdf_extract_expand_api!(
    test_sha512_hkdf_extract_expand_api,
    HKDF_SHA512,
    FipsServiceStatus::ApprovedMode,
    16,
    16
);
hkdf_extract_expand_api!(
    test_sha1_hkdf_extract_expand_api_invalid_nonce,
    HKDF_SHA1_FOR_LEGACY_USE_ONLY,
    FipsServiceStatus::NonApprovedMode,
    0,
    16
);
hkdf_extract_expand_api!(
    test_sha256_hkdf_extract_expand_api_invalid_nonce,
    HKDF_SHA256,
    FipsServiceStatus::NonApprovedMode,
    0,
    16
);
hkdf_extract_expand_api!(
    test_sha384_hkdf_extract_expand_api_invalid_nonce,
    HKDF_SHA384,
    FipsServiceStatus::NonApprovedMode,
    0,
    16
);
hkdf_extract_expand_api!(
    test_sha512_hkdf_extract_expand_api_invalid_nonce,
    HKDF_SHA512,
    FipsServiceStatus::NonApprovedMode,
    0,
    16
);

macro_rules! hkdf_expand_api {
    ($name:ident, $alg:expr, $key:expr, $expect:path, $info_len:literal) => {
        #[test]
        fn $name() {
            let prk = Prk::new_less_safe($alg, $key);

            let info: Vec<u8> = vec![42u8; $info_len];
            let info_slices: Vec<&[u8]> = vec![info.as_ref()];

            // Will not set the inidcator function
            let okm = assert_fips_status_indicator!(
                prk.expand(info_slices.as_ref(), $alg),
                FipsServiceStatus::ApprovedMode
            )
            .unwrap();

            let mut out = vec![0u8; $alg.len()];

            // Will set the indicator function
            assert_fips_status_indicator!(okm.fill(&mut out), $expect).unwrap();
        }
    };
}

hkdf_expand_api!(
    sha1,
    HKDF_SHA1_FOR_LEGACY_USE_ONLY,
    &TEST_KEY_128_BIT[..],
    FipsServiceStatus::ApprovedMode,
    16
);
hkdf_expand_api!(
    sha256,
    HKDF_SHA256,
    &TEST_KEY_128_BIT[..],
    FipsServiceStatus::ApprovedMode,
    16
);
hkdf_expand_api!(
    sha384,
    HKDF_SHA384,
    &TEST_KEY_128_BIT[..],
    FipsServiceStatus::ApprovedMode,
    16
);
hkdf_expand_api!(
    sha512,
    HKDF_SHA512,
    &TEST_KEY_128_BIT[..],
    FipsServiceStatus::ApprovedMode,
    16
);
