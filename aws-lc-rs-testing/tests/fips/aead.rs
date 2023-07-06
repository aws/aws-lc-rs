// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

mod chacha20_poly1305_openssh;
mod quic;

use aws_lc_rs::aead::{
    nonce_sequence::Counter64Builder, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey,
    AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use aws_lc_rs::aead::{
    Nonce, RandomizedNonceKey, TLSProtocolId, TLSRecordOpeningKey, TLSRecordSealingKey,
};

use aws_lc_rs::FipsServiceStatus;

use crate::common::{
    assert_fips_status_indicator, TEST_KEY_128_BIT, TEST_KEY_256_BIT, TEST_MESSAGE,
    TEST_NONCE_96_BIT,
};

macro_rules! nonce_sequence_api {
    ($name:ident, $alg:expr, $key:expr, $seal_expect:path, $open_expect:path) => {
        #[test]
        fn $name() {
            {
                let mut key = SealingKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let mut in_out = Vec::from(TEST_MESSAGE);

                assert_fips_status_indicator!(
                    key.seal_in_place_append_tag(Aad::empty(), &mut in_out),
                    $seal_expect
                )
                .unwrap();

                let mut key = OpeningKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let result = assert_fips_status_indicator!(
                    key.open_in_place(Aad::empty(), &mut in_out),
                    $open_expect
                )
                .unwrap();

                assert_eq!(TEST_MESSAGE.as_bytes(), result);
            }

            {
                let mut key = SealingKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let mut in_out = Vec::from(TEST_MESSAGE);

                let tag = assert_fips_status_indicator!(
                    key.seal_in_place_separate_tag(Aad::empty(), &mut in_out),
                    $seal_expect
                )
                .unwrap();

                in_out.extend(tag.as_ref().iter());

                let mut key = OpeningKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let result = assert_fips_status_indicator!(
                    key.open_in_place(Aad::empty(), &mut in_out),
                    $open_expect
                )
                .unwrap();

                assert_eq!(TEST_MESSAGE.as_bytes(), result);
            }
        }
    };
}

nonce_sequence_api!(
    aes_gcm_128_nonce_sequence_api,
    &AES_128_GCM,
    &TEST_KEY_128_BIT[..],
    FipsServiceStatus::NonApprovedMode,
    FipsServiceStatus::ApprovedMode
);
nonce_sequence_api!(
    aes_gcm_256_nonce_sequence_api,
    &AES_256_GCM,
    &TEST_KEY_256_BIT[..],
    FipsServiceStatus::NonApprovedMode,
    FipsServiceStatus::ApprovedMode
);
nonce_sequence_api!(
    chacha20_poly1305_nonce_sequence_api,
    &CHACHA20_POLY1305,
    &TEST_KEY_256_BIT[..],
    FipsServiceStatus::NonApprovedMode,
    FipsServiceStatus::NonApprovedMode
);

macro_rules! randnonce_api {
    ($name:ident, $alg:expr, $key:expr) => {
        #[test]
        fn $name() {
            let key = RandomizedNonceKey::new($alg, $key).unwrap();

            {
                let mut in_out = Vec::from(TEST_MESSAGE);
                let nonce = assert_fips_status_indicator!(
                    key.seal_in_place_append_tag(Aad::empty(), &mut in_out),
                    FipsServiceStatus::ApprovedMode
                )
                .unwrap();

                let in_out = assert_fips_status_indicator!(
                    key.open_in_place(nonce, Aad::empty(), &mut in_out),
                    FipsServiceStatus::ApprovedMode
                )
                .unwrap();

                assert_eq!(TEST_MESSAGE.as_bytes(), in_out);
            }

            {
                let mut in_out = Vec::from(TEST_MESSAGE);

                let (nonce, tag) = assert_fips_status_indicator!(
                    key.seal_in_place_separate_tag(Aad::empty(), &mut in_out),
                    FipsServiceStatus::ApprovedMode
                )
                .unwrap();

                in_out.extend(tag.as_ref().iter());

                let in_out = assert_fips_status_indicator!(
                    key.open_in_place(nonce, Aad::empty(), &mut in_out),
                    FipsServiceStatus::ApprovedMode
                )
                .unwrap();

                assert_eq!(TEST_MESSAGE.as_bytes(), in_out);
            }
        }
    };
    // Match for unsupported variants
    ($name:ident, $alg:expr, $key:expr, false) => {
        #[test]
        fn $name() {
            assert!(RandomizedNonceKey::new($alg, $key).is_err());
        }
    };
}

randnonce_api!(
    aes_gcm_128_randnonce_api,
    &AES_128_GCM,
    &TEST_KEY_128_BIT[..]
);
randnonce_api!(
    aes_gcm_256_randnonce_api,
    &AES_256_GCM,
    &TEST_KEY_256_BIT[..]
);
randnonce_api!(
    chacha20_poly1305_randnonce_api,
    &CHACHA20_POLY1305,
    &TEST_KEY_256_BIT[..],
    false
);

macro_rules! tls_nonce_api {
    ($name:ident, $alg:expr, $proto:expr, $key:expr) => {
        #[test]
        fn $name() {
            let key = TLSRecordSealingKey::new($alg, $proto, $key).unwrap();

            let mut in_out = Vec::from(TEST_MESSAGE);

            assert_fips_status_indicator!(
                key.seal_in_place_append_tag(
                    Nonce::from(&TEST_NONCE_96_BIT),
                    Aad::empty(),
                    &mut in_out,
                ),
                FipsServiceStatus::ApprovedMode
            )
            .unwrap();

            let key = TLSRecordOpeningKey::new($alg, $proto, $key).unwrap();

            let in_out = assert_fips_status_indicator!(
                key.open_in_place(Nonce::from(&TEST_NONCE_96_BIT), Aad::empty(), &mut in_out),
                FipsServiceStatus::ApprovedMode
            )
            .unwrap();

            assert_eq!(in_out, TEST_MESSAGE.as_bytes());
        }
    };
    // Match for unsupported variants
    ($name:ident, $alg:expr, $proto:expr, $key:expr, false) => {
        #[test]
        fn $name() {
            assert!(TLSRecordSealingKey::new($alg, $proto, $key).is_err());
            assert!(TLSRecordOpeningKey::new($alg, $proto, $key).is_err());
        }
    };
}

tls_nonce_api!(
    aes_128_tls12_nonce_api,
    &AES_128_GCM,
    TLSProtocolId::TLS12,
    &TEST_KEY_128_BIT
);
tls_nonce_api!(
    aes_256_tls12_nonce_api,
    &AES_256_GCM,
    TLSProtocolId::TLS12,
    &TEST_KEY_256_BIT
);
tls_nonce_api!(
    aes_128_tls13_nonce_api,
    &AES_128_GCM,
    TLSProtocolId::TLS13,
    &TEST_KEY_128_BIT
);
tls_nonce_api!(
    aes_256_tls13_nonce_api,
    &AES_256_GCM,
    TLSProtocolId::TLS13,
    &TEST_KEY_256_BIT
);
tls_nonce_api!(
    chaca20_poly1305_tls12_nonce_api,
    &CHACHA20_POLY1305,
    TLSProtocolId::TLS12,
    &TEST_KEY_256_BIT,
    false
);
tls_nonce_api!(
    chaca20_poly1305_tls13_nonce_api,
    &CHACHA20_POLY1305,
    TLSProtocolId::TLS13,
    &TEST_KEY_256_BIT,
    false
);
