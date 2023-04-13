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

/// The API documentation specifies that derive/verify should panic, if the designated output length
/// is too long. Ring checks for an output array length while pbkdf2 is being ran, while we check
/// the array length before everything is processed.
/// Most platforms will fail to allocate this much memory, so we only test on platforms which can.
#[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
#[cfg(test)]
mod tests {
    use aws_lc_rs::{digest, pbkdf2};
    use core::num::NonZeroU32;
    use mirai_annotations::assume;

    #[test]
    #[should_panic(expected = "derived key too long")]
    fn pbkdf2_derive_too_long() {
        let iterations = NonZeroU32::new(1_u32).unwrap();
        let max_usize32 = u32::MAX as usize;
        for &alg in &[
            pbkdf2::PBKDF2_HMAC_SHA1,
            pbkdf2::PBKDF2_HMAC_SHA256,
            pbkdf2::PBKDF2_HMAC_SHA384,
            pbkdf2::PBKDF2_HMAC_SHA512,
        ] {
            let output_len = match_pbkdf2_digest(&alg).output_len;
            assume!(output_len < 2048);
            let mut out = vec![0u8; max_usize32 * output_len + 1];
            pbkdf2::derive(alg, iterations, b"salt", b"password", &mut out);
        }
    }

    #[test]
    #[should_panic(expected = "derived key too long")]
    fn pbkdf2_verify_too_long() {
        let iterations = NonZeroU32::new(1_u32).unwrap();
        let max_usize32 = u32::MAX as usize;
        for &alg in &[
            pbkdf2::PBKDF2_HMAC_SHA1,
            pbkdf2::PBKDF2_HMAC_SHA256,
            pbkdf2::PBKDF2_HMAC_SHA384,
            pbkdf2::PBKDF2_HMAC_SHA512,
        ] {
            let out = vec![0u8; max_usize32 * match_pbkdf2_digest(&alg).output_len + 1];
            pbkdf2::verify(alg, iterations, b"salt", b"password", &out).unwrap();
        }
    }

    fn match_pbkdf2_digest(&algorithm: &pbkdf2::Algorithm) -> &digest::Algorithm {
        if algorithm == pbkdf2::PBKDF2_HMAC_SHA1 {
            &digest::SHA1_FOR_LEGACY_USE_ONLY
        } else if algorithm == pbkdf2::PBKDF2_HMAC_SHA256 {
            &digest::SHA256
        } else if algorithm == pbkdf2::PBKDF2_HMAC_SHA384 {
            &digest::SHA384
        } else if algorithm == pbkdf2::PBKDF2_HMAC_SHA512 {
            &digest::SHA512
        } else {
            unreachable!()
        }
    }
}
