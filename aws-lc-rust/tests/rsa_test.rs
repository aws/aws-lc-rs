// Copyright 2017 Brian Smith.
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

use aws_lc_rust::signature::{KeyPair, RsaParameters};
use aws_lc_rust::test::to_hex_upper;
use aws_lc_rust::{rand, signature, signature::RsaKeyPair, test, test_file};

#[test]
fn rsa_traits() {
    test::compile_time_assert_send::<RsaKeyPair>();
    test::compile_time_assert_sync::<RsaKeyPair>();
    test::compile_time_assert_send::<signature::RsaSubjectPublicKey>();
    test::compile_time_assert_sync::<signature::RsaSubjectPublicKey>();
    test::compile_time_assert_send::<signature::RsaPublicKeyComponents<&[u8]>>();
    test::compile_time_assert_sync::<signature::RsaPublicKeyComponents<&[u8]>>();
    test::compile_time_assert_send::<signature::RsaPublicKeyComponents<Vec<u8>>>();
    test::compile_time_assert_sync::<signature::RsaPublicKeyComponents<Vec<u8>>>();
}

#[test]
fn rsa_from_pkcs8_test() {
    test::run(
        test_file!("data/rsa_from_pkcs8_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let input = test_case.consume_bytes("Input");
            let error = test_case.consume_optional_string("Error");

            match (RsaKeyPair::from_pkcs8(&input), error) {
                (Ok(_), None) => (),
                (Err(e), None) => panic!("Failed with error \"{e}\", but expected to succeed"),
                (Ok(_), Some(e)) => panic!("Succeeded, but expected error \"{e}\""),
                (Err(actual), Some(expected)) => assert_eq!(
                    format!("{actual}"),
                    expected,
                    "Input: {}",
                    test::to_hex(input.as_slice())
                ),
            };

            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pkcs1_sign() {
    let rng = rand::SystemRandom::new();
    test::run(
        test_file!("data/rsa_pkcs1_sign_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PKCS1_SHA256,
                "SHA384" => &signature::RSA_PKCS1_SHA384,
                "SHA512" => &signature::RSA_PKCS1_SHA512,
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let private_key = test_case.consume_bytes("Key");
            let debug_msg = format!("Key = {}", test::to_hex(&private_key));
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let key_pair = RsaKeyPair::from_der(&private_key);
            if result == "Fail-Invalid-Key" {
                assert!(key_pair.is_err(), "{}", &debug_msg);
                return Ok(());
            }
            let key_pair = key_pair.expect(&debug_msg);

            // XXX: This test is too slow on Android ARM Travis CI builds.
            // TODO: re-enable these tests on Android ARM.
            let mut actual = vec![0u8; key_pair.public_modulus_len()];
            key_pair
                .sign(alg, &rng, &msg, actual.as_mut_slice())
                .expect(&debug_msg);
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pss_sign() {
    test::run(
        test_file!("data/rsa_pss_sign_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_SHA256,
                "SHA384" => &signature::RSA_PSS_SHA384,
                "SHA512" => &signature::RSA_PSS_SHA512,
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let result = test_case.consume_string("Result");
            let private_key = test_case.consume_bytes("Key");
            let key_pair = RsaKeyPair::from_der(&private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let msg = test_case.consume_bytes("Msg");
            let salt = test_case.consume_bytes("Salt");
            let _expected = test_case.consume_bytes("Sig");

            let rng = test::rand::FixedSliceRandom { bytes: &salt };

            let mut actual = vec![0u8; key_pair.public_modulus_len()];

            key_pair.sign(alg, &rng, &msg, actual.as_mut_slice())?;
            // TODO: *AWS-LC* does not allow the salt to be specified for PSS
            //assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pkcs1_verify() {
    let sha1_params = &[
        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    ];
    let sha256_params = &[
        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA256,
    ];
    let sha384_params = &[
        &signature::RSA_PKCS1_2048_8192_SHA384,
        &signature::RSA_PKCS1_3072_8192_SHA384,
    ];
    let sha512_params = &[
        &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA512,
    ];
    test::run(
        test_file!("data/rsa_pkcs1_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let params: &[_] = match digest_name.as_ref() {
                "SHA1" => sha1_params,
                "SHA256" => sha256_params,
                "SHA384" => sha384_params,
                "SHA512" => sha512_params,
                _ => panic!("Unsupported digest: {digest_name}"),
            };
            let public_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let is_valid = test_case.consume_string("Result") == "P";

            let key_bits = RsaParameters::public_modulus_len(&public_key);
            if key_bits.is_err() {
                assert!(!is_valid);
                return Ok(());
            }
            let key_bits = key_bits.unwrap();

            for &alg in params {
                let width_ok = key_bits >= alg.min_modulus_len();
                let width_ok = width_ok && key_bits <= alg.max_modulus_len();
                let actual_result =
                    signature::UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
                assert_eq!(actual_result.is_ok(), is_valid && width_ok);
            }

            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pss_verify() {
    test::run(
        test_file!("data/rsa_pss_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_2048_8192_SHA256,
                "SHA384" => &signature::RSA_PSS_2048_8192_SHA384,
                "SHA512" => &signature::RSA_PSS_2048_8192_SHA512,
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let public_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let is_valid = test_case.consume_string("Result") == "P";

            let actual_result =
                signature::UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
            assert_eq!(actual_result.is_ok(), is_valid);

            Ok(())
        },
    );
}

// Test for `primitive::verify()`. Read public key parts from a file
// and use them to verify a signature.
#[test]
fn test_signature_rsa_primitive_verification() {
    test::run(
        test_file!("data/rsa_primitive_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let n = test_case.consume_bytes("n");
            let e = test_case.consume_bytes("e");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let expected = test_case.consume_string("Result");
            let public_key = signature::RsaPublicKeyComponents { n: &n, e: &e };
            let result = public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, &msg, &sig);
            assert_eq!(
                result.is_ok(),
                expected == "Pass",
                "N = {}",
                to_hex_upper(n)
            );
            Ok(())
        },
    );
}

#[test]
fn rsa_test_public_key_coverage() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_2048.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_2048.der");
    const PUBLIC_KEY_DEBUG: &str = include_str!("data/rsa_test_public_key_2048_debug.txt");

    let key_pair = RsaKeyPair::from_pkcs8(PRIVATE_KEY).unwrap();

    let pubkey = key_pair.public_key();
    // Test `AsRef<[u8]>`
    assert_eq!(pubkey.as_ref(), PUBLIC_KEY);

    // Test `Clone`.
    #[allow(let_underscore_drop)]
    let _ = pubkey.clone();

    #[cfg(feature = "ring-io")]
    assert_eq!(
        &[0x01, 0x00, 0x01],
        key_pair
            .public_key()
            .exponent()
            .big_endian_without_leading_zero()
    );

    // Test `Debug`
    assert_eq!(PUBLIC_KEY_DEBUG, format!("{:?}", key_pair.public_key()));
    assert_eq!(
        format!("RsaKeyPair {{ public_key: {:?} }}", key_pair.public_key()),
        format!("{key_pair:?}")
    );
}
