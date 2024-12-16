// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{digest, error, pbkdf2, test, test_file};
use core::num::NonZeroU32;

/// Test vectors from `BoringSSL`, Go, and other sources.
#[test]
fn pbkdf2_tests() {
    test::run(test_file!("data/pbkdf2_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let algorithm = {
            let digest_alg = test_case.consume_digest_alg("Hash").unwrap();
            if digest_alg == &digest::SHA1_FOR_LEGACY_USE_ONLY {
                pbkdf2::PBKDF2_HMAC_SHA1
            } else if digest_alg == &digest::SHA256 {
                pbkdf2::PBKDF2_HMAC_SHA256
            } else if digest_alg == &digest::SHA384 {
                pbkdf2::PBKDF2_HMAC_SHA384
            } else if digest_alg == &digest::SHA512 {
                pbkdf2::PBKDF2_HMAC_SHA512
            } else {
                unreachable!()
            }
        };
        #[allow(clippy::cast_possible_truncation)]
        let iterations = test_case.consume_usize("c") as u32;
        let iterations = NonZeroU32::new(iterations).unwrap();
        let secret = test_case.consume_bytes("P");
        let salt = test_case.consume_bytes("S");
        let dk = test_case.consume_bytes("DK");
        let verify_expected_result = test_case.consume_string("Verify");
        let verify_expected_result = match verify_expected_result.as_str() {
            "OK" => Ok(()),
            "Err" => Err(error::Unspecified),
            _ => panic!("Unsupported value of \"Verify\""),
        };

        {
            let mut out = vec![0u8; dk.len()];
            pbkdf2::derive(algorithm, iterations, &salt, &secret, &mut out);
            assert_eq!(dk == out, verify_expected_result.is_ok() || dk.is_empty());
        }

        assert_eq!(
            pbkdf2::verify(algorithm, iterations, &salt, &secret, &dk),
            verify_expected_result
        );

        Ok(())
    });
}
