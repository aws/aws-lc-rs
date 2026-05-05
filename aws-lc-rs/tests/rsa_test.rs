// Copyright 2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::digest::{Digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{
    EncryptionAlgorithmId, KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    Pkcs1PrivateDecryptingKey, Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
};
use aws_lc_rs::signature::{
    KeyPair, ParsedPublicKey, RsaKeyPair, RsaParameters, RsaPublicKeyComponents,
    RsaSubjectPublicKey, UnparsedPublicKey, VerificationAlgorithm,
};
use aws_lc_rs::test::to_hex_upper;
use aws_lc_rs::{digest, rand, signature, test, test_file};

#[test]
fn rsa_traits() {
    test::compile_time_assert_send::<RsaKeyPair>();
    test::compile_time_assert_sync::<RsaKeyPair>();
    test::compile_time_assert_send::<RsaSubjectPublicKey>();
    test::compile_time_assert_sync::<RsaSubjectPublicKey>();
    test::compile_time_assert_send::<RsaPublicKeyComponents<&[u8]>>();
    test::compile_time_assert_sync::<RsaPublicKeyComponents<&[u8]>>();
    test::compile_time_assert_send::<RsaPublicKeyComponents<Vec<u8>>>();
    test::compile_time_assert_sync::<RsaPublicKeyComponents<Vec<u8>>>();
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
            }

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
            let (alg, verification_alg, digest_alg) = match digest_name.as_ref() {
                "SHA256" => (
                    &signature::RSA_PKCS1_SHA256,
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                    &SHA256,
                ),
                "SHA384" => (
                    &signature::RSA_PKCS1_SHA384,
                    &signature::RSA_PKCS1_2048_8192_SHA384,
                    &SHA384,
                ),
                "SHA512" => (
                    &signature::RSA_PKCS1_SHA512,
                    &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                    &SHA512,
                ),
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
            let public_key = key_pair.public_key();
            {
                let upk = UnparsedPublicKey::new(verification_alg, public_key.as_ref());
                assert_eq!(public_key.as_ref(), upk.as_ref());

                let mut actual = vec![0u8; key_pair.public_modulus_len()];
                key_pair
                    .sign(alg, &rng, &msg, actual.as_mut_slice())
                    .expect(&debug_msg);
                assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
                assert!(upk.verify(&msg, actual.as_slice()).is_ok());

                let og_digest = digest::digest(digest_alg, &msg);
                let digest = Digest::import_less_safe(og_digest.as_ref(), digest_alg).unwrap();
                key_pair.sign_digest(alg, &digest, actual.as_mut_slice())?;
                assert!(upk.verify_digest(&digest, actual.as_slice()).is_ok());
            }

            {
                let ppk = ParsedPublicKey::new(verification_alg, public_key.as_ref()).unwrap();
                assert_eq!(public_key.as_ref(), ppk.as_ref());

                let mut actual = vec![0u8; key_pair.public_modulus_len()];
                key_pair
                    .sign(alg, &rng, &msg, actual.as_mut_slice())
                    .expect(&debug_msg);
                assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
                assert!(ppk.verify_sig(&msg, actual.as_slice()).is_ok());

                let og_digest = digest::digest(digest_alg, &msg);
                let digest = Digest::import_less_safe(og_digest.as_ref(), digest_alg).unwrap();
                key_pair.sign_digest(alg, &digest, actual.as_mut_slice())?;
                assert!(ppk.verify_digest_sig(&digest, actual.as_slice()).is_ok());

                let x509_bytes = ppk.as_der().unwrap();
                let actual_x509_result = verification_alg.verify_digest_sig(
                    x509_bytes.as_ref(),
                    &digest,
                    actual.as_slice(),
                );
                assert!(actual_x509_result.is_ok());
            }

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
            let (encoding, verification_alg, digest_alg) = match digest_name.as_ref() {
                "SHA256" => (
                    &signature::RSA_PSS_SHA256,
                    &signature::RSA_PSS_2048_8192_SHA256,
                    &SHA256,
                ),
                "SHA384" => (
                    &signature::RSA_PSS_SHA384,
                    &signature::RSA_PSS_2048_8192_SHA384,
                    &SHA384,
                ),
                "SHA512" => (
                    &signature::RSA_PSS_SHA512,
                    &signature::RSA_PSS_2048_8192_SHA512,
                    &SHA512,
                ),
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let result = test_case.consume_string("Result");
            let private_key = test_case.consume_bytes("Key");
            let key_pair = RsaKeyPair::from_der(&private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let public_key = key_pair.public_key();
            let rng = SystemRandom::new();
            let msg = test_case.consume_bytes("Msg");

            {
                let upk = UnparsedPublicKey::new(verification_alg, public_key.as_ref());
                let mut actual = vec![0u8; key_pair.public_modulus_len()];

                key_pair.sign(encoding, &rng, &msg, actual.as_mut_slice())?;
                upk.verify(&msg, actual.as_slice())?;

                let digest = digest::digest(digest_alg, &msg);
                key_pair.sign_digest(encoding, &digest, actual.as_mut_slice())?;
                upk.verify_digest(&digest, actual.as_slice())?;
            }

            {
                let ppk = ParsedPublicKey::new(verification_alg, public_key.as_ref()).unwrap();
                let mut actual = vec![0u8; key_pair.public_modulus_len()];

                key_pair.sign(encoding, &rng, &msg, actual.as_mut_slice())?;
                ppk.verify_sig(&msg, actual.as_slice())?;

                let digest = digest::digest(digest_alg, &msg);
                key_pair.sign_digest(encoding, &digest, actual.as_mut_slice())?;
                ppk.verify_digest_sig(&digest, actual.as_slice())?;
            }

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
            let (params, digest_alg) = match digest_name.as_ref() {
                "SHA1" => (sha1_params, &SHA1_FOR_LEGACY_USE_ONLY),
                "SHA256" => (sha256_params, &SHA256),
                "SHA384" => (sha384_params, &SHA384),
                "SHA512" => (sha512_params, &SHA512),
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
                let upk = UnparsedPublicKey::new(alg, &public_key);
                let actual_result = upk.verify(&msg, &sig);
                assert_eq!(actual_result.is_ok(), is_valid && width_ok);

                let digest = digest::digest(digest_alg, &msg);
                let actual_digest_result = upk.verify_digest(&digest, &sig);
                assert_eq!(actual_digest_result, actual_result);
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
            let (alg, digest_alg) = match digest_name.as_ref() {
                "SHA256" => (&signature::RSA_PSS_2048_8192_SHA256, &SHA256),
                "SHA384" => (&signature::RSA_PSS_2048_8192_SHA384, &SHA384),
                "SHA512" => (&signature::RSA_PSS_2048_8192_SHA512, &SHA512),
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let public_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let is_valid = test_case.consume_string("Result") == "P";

            let upk = UnparsedPublicKey::new(alg, &public_key);

            let actual_result = upk.verify(&msg, &sig);
            assert_eq!(actual_result.is_ok(), is_valid);

            let digest = digest::digest(digest_alg, &msg);
            let actual_digest_result = upk.verify_digest(&digest, &sig);
            assert_eq!(actual_digest_result, actual_result);

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
            let public_key = RsaPublicKeyComponents { n: &n, e: &e };
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

// Exercises `RsaPublicKeyComponents::to_parsed_public_key` across the same
// vectors as `test_signature_rsa_primitive_verification`.  The
// `ParsedPublicKey` produced from the components must accept the same
// signatures that `RsaPublicKeyComponents::verify` accepts on the same inputs.
#[test]
fn test_rsa_public_key_components_to_parsed_public_key() {
    test::run(
        test_file!("data/rsa_primitive_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let n = test_case.consume_bytes("n");
            let e = test_case.consume_bytes("e");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let expected = test_case.consume_string("Result");
            let components = RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            };
            let built = components.to_parsed_public_key(&signature::RSA_PKCS1_2048_8192_SHA256);
            if let Ok(parsed) = built {
                let result = parsed.verify_sig(&msg, &sig);
                assert_eq!(
                    result.is_ok(),
                    expected == "Pass",
                    "N = {}",
                    to_hex_upper(n)
                );
            } else {
                assert_ne!(
                    expected,
                    "Pass",
                    "to_parsed_public_key rejected a Pass vector: N = {}",
                    to_hex_upper(n)
                );
            }
            Ok(())
        },
    );
}

// Zero or empty modulus/exponent are invalid RSA components and must be
// rejected before any DER parsing happens. The error must describe the
// problem as inconsistent components rather than invalid encoding.
#[test]
fn test_rsa_public_key_components_to_parsed_public_key_rejects_empty_modulus() {
    let n: [u8; 0] = [];
    let e: [u8; 3] = [0x01, 0x00, 0x01];
    let components = RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    let err = components
        .to_parsed_public_key(&signature::RSA_PKCS1_2048_8192_SHA256)
        .expect_err("empty modulus should be rejected");
    assert_eq!(err.description_(), "InconsistentComponents");
}

// `AsDer<PublicKeyX509Der>` must also reject invalid components.
#[test]
fn test_rsa_public_key_components_as_der_rejects_empty_modulus() {
    let n: [u8; 0] = [];
    let e: [u8; 3] = [0x01, 0x00, 0x01];
    let components = RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    let result: Result<PublicKeyX509Der<'_>, _> = components.as_der();
    assert!(result.is_err(), "as_der should reject empty modulus");
}

// Empty exponents (and exponents with a leading zero byte, since big-endian
// components are expected without leading zeros) are invalid RSA components
// and must be rejected on both the `to_parsed_public_key` and `as_der` paths.
// This is the symmetric case of the empty-modulus tests above: `build_rsa`
// applies the same validation to `e` as it does to `n`, so both surfaces are
// exercised here.
#[test]
fn test_rsa_public_key_components_rejects_invalid_exponent() {
    // 2048-bit modulus of `data/rsa_test_private_key_2048.p8`.
    const N_HEX: &str = concat!(
        "c8a78500a5a250db8ed36c85b8dcf83c4be1953114faaac7616e0ea24922fa6b",
        "7ab01f85582c815cc3bdeb5ed46762bc536accaa8b72705b00cef316b2ec508f",
        "b9697241b9e34238419cccf7339eeb8b062147af4f5932f613d9bc0ae70bf6d5",
        "6d4432e83e13767587531bfa9dd56531741244be75e8bc9226b9fa44b4b8a101",
        "358d7e8bb75d0c724a4f11ece77776263faefe79612eb1d71646e77e8982866b",
        "e1400eafc3580d3139b41aaa7380187372f22e35bd55b288496165c881ed154d",
        "5811245c52d56cc09d4916d4f2a50bcf5ae0a2637f4cfa6bf9daafc113dba838",
        "3b6dd7da6dd8db22d8510a8d3115983308909a1a0332517aa55e896e154249b3",
    );
    let n = aws_lc_rs::test::from_hex(N_HEX).unwrap();

    for bad_e in [&[][..], &[0x00, 0x01, 0x00, 0x01][..]] {
        let components = RsaPublicKeyComponents {
            n: n.as_slice(),
            e: bad_e,
        };
        let err = components
            .to_parsed_public_key(&signature::RSA_PKCS1_2048_8192_SHA256)
            .expect_err("invalid exponent should be rejected by to_parsed_public_key");
        assert_eq!(err.description_(), "InconsistentComponents");
        let der_result: Result<PublicKeyX509Der<'_>, _> = components.as_der();
        assert!(
            der_result.is_err(),
            "invalid exponent should be rejected by as_der"
        );
    }
}

// A 1024-bit RSA key is below the algorithm's accepted range
// (`RSA_PKCS1_2048_8192_SHA256` accepts 2048..=8192). Note that the
// bit-range check happens at verification time, not at construction: this
// mirrors the behavior of `ParsedPublicKey::new`, which also defers the
// range check to `verify_sig`. This test pins down that contract.
#[test]
fn test_rsa_public_key_components_to_parsed_public_key_small_key_fails_at_verify() {
    // 1024-bit modulus taken from a valid RSA key.
    const N_HEX: &str = concat!(
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab",
        "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72",
        "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514",
        "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
    );
    let n = aws_lc_rs::test::from_hex(N_HEX).unwrap();
    let e: [u8; 3] = [0x01, 0x00, 0x01];
    let components = RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    // Construction succeeds: RSA SPKI parsing does not enforce the
    // algorithm's bit-size range.
    let parsed = components
        .to_parsed_public_key(&signature::RSA_PKCS1_2048_8192_SHA256)
        .expect("construction should succeed; bit-range check is deferred to verify");
    // Verification fails because 1024 is outside `RSA_PKCS1_2048_8192_SHA256`'s
    // 2048..=8192 range. The signature bytes are irrelevant -- the bit-range
    // check short-circuits before any cryptographic work is attempted.
    let fake_sig = vec![0u8; n.len()];
    assert!(parsed.verify_sig(b"anything", &fake_sig).is_err());
}

// `AsDer<PublicKeyX509Der>` on `RsaPublicKeyComponents` must produce X.509
// SubjectPublicKeyInfo DER that re-parses as the same RSA key. This test
// does not rely on the `ring-io`-gated `From<&PublicKey>` conversion, so it
// exercises the `AsDer` impl in the default feature configuration.
#[test]
fn test_rsa_public_key_components_as_der_round_trip_no_ring_io() {
    // 2048-bit modulus of `data/rsa_test_private_key_2048.p8`, taken from
    // `data/rsa_test_public_key_2048_debug.txt`.
    const N_HEX: &str = concat!(
        "c8a78500a5a250db8ed36c85b8dcf83c4be1953114faaac7616e0ea24922fa6b",
        "7ab01f85582c815cc3bdeb5ed46762bc536accaa8b72705b00cef316b2ec508f",
        "b9697241b9e34238419cccf7339eeb8b062147af4f5932f613d9bc0ae70bf6d5",
        "6d4432e83e13767587531bfa9dd56531741244be75e8bc9226b9fa44b4b8a101",
        "358d7e8bb75d0c724a4f11ece77776263faefe79612eb1d71646e77e8982866b",
        "e1400eafc3580d3139b41aaa7380187372f22e35bd55b288496165c881ed154d",
        "5811245c52d56cc09d4916d4f2a50bcf5ae0a2637f4cfa6bf9daafc113dba838",
        "3b6dd7da6dd8db22d8510a8d3115983308909a1a0332517aa55e896e154249b3",
    );
    let n = aws_lc_rs::test::from_hex(N_HEX).unwrap();
    let e: [u8; 3] = [0x01, 0x00, 0x01];
    let components = RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    // The `AsDer` output must be parseable as an X.509 SubjectPublicKeyInfo.
    let der: PublicKeyX509Der<'_> = components.as_der().unwrap();
    let parsed_from_der =
        ParsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der.as_ref()).unwrap();
    let parsed_from_components = components
        .to_parsed_public_key(&signature::RSA_PKCS1_2048_8192_SHA256)
        .unwrap();
    // Both paths must produce byte-for-byte identical canonical DER.
    assert_eq!(der.as_ref(), parsed_from_components.as_ref());
    // Both constructors must accept a signature produced by the matching
    // private key.
    let key_pair =
        RsaKeyPair::from_pkcs8(include_bytes!("data/rsa_test_private_key_2048.p8")).unwrap();
    let message = b"hello, world";
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
        .unwrap();
    parsed_from_der.verify_sig(message, &signature).unwrap();
    parsed_from_components
        .verify_sig(message, &signature)
        .unwrap();
}

// PSS coverage for `to_parsed_public_key`: the rustdoc example cites
// `RSA_PSS_2048_8192_SHA256`, so the path must actually work for PSS too.
#[test]
fn test_rsa_public_key_components_to_parsed_public_key_pss() {
    const N_HEX: &str = concat!(
        "c8a78500a5a250db8ed36c85b8dcf83c4be1953114faaac7616e0ea24922fa6b",
        "7ab01f85582c815cc3bdeb5ed46762bc536accaa8b72705b00cef316b2ec508f",
        "b9697241b9e34238419cccf7339eeb8b062147af4f5932f613d9bc0ae70bf6d5",
        "6d4432e83e13767587531bfa9dd56531741244be75e8bc9226b9fa44b4b8a101",
        "358d7e8bb75d0c724a4f11ece77776263faefe79612eb1d71646e77e8982866b",
        "e1400eafc3580d3139b41aaa7380187372f22e35bd55b288496165c881ed154d",
        "5811245c52d56cc09d4916d4f2a50bcf5ae0a2637f4cfa6bf9daafc113dba838",
        "3b6dd7da6dd8db22d8510a8d3115983308909a1a0332517aa55e896e154249b3",
    );
    let n = aws_lc_rs::test::from_hex(N_HEX).unwrap();
    let e: [u8; 3] = [0x01, 0x00, 0x01];
    let components = RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    let parsed = components
        .to_parsed_public_key(&signature::RSA_PSS_2048_8192_SHA256)
        .unwrap();
    // The `algorithm` stored on the resulting `ParsedPublicKey` must be the
    // `RsaParameters` instance passed in, not e.g. a silently-substituted
    // PKCS#1 default. Compare via `Debug` output because `VerificationAlgorithm`
    // is a trait object and does not implement `PartialEq`; `RsaParameters`'s
    // `Debug` impl uses its `RsaVerificationAlgorithmId`, which is unique per
    // algorithm constant.
    assert_eq!(
        format!("{:?}", parsed.algorithm()),
        format!("{:?}", &signature::RSA_PSS_2048_8192_SHA256),
    );
    let key_pair =
        RsaKeyPair::from_pkcs8(include_bytes!("data/rsa_test_private_key_2048.p8")).unwrap();
    let message = b"hello, world";
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(&signature::RSA_PSS_SHA256, &rng, message, &mut signature)
        .unwrap();
    parsed.verify_sig(message, &signature).unwrap();
    // A tampered message must not verify.
    assert!(parsed.verify_sig(b"goodbye, world", &signature).is_err());
    // And a PKCS#1-produced signature must not verify against a PSS-parsed
    // key: this pins down that the `RsaParameters` passed at construction is
    // actually what drives verification.
    let mut pkcs1_sig = vec![0u8; key_pair.public_modulus_len()];
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut pkcs1_sig)
        .unwrap();
    assert!(parsed.verify_sig(message, &pkcs1_sig).is_err());
}

// `AsDer<PublicKeyX509Der>` on `RsaPublicKeyComponents` must round-trip when
// paired with the `ring-io`-gated `From<&PublicKey>` accessor: deconstruct a
// real RSA public key into components, re-encode them as X.509, and confirm
// both the re-parsed DER and the direct `to_parsed_public_key` path accept a
// signature produced by the matching private key. The default-feature (no
// `ring-io`) `AsDer` path is covered by
// `test_rsa_public_key_components_as_der_round_trip_no_ring_io`.
#[cfg(feature = "ring-io")]
#[test]
fn test_rsa_public_key_components_as_der_round_trip() {
    let key_pair =
        RsaKeyPair::from_pkcs8(include_bytes!("data/rsa_test_private_key_2048.p8")).unwrap();
    let pubkey = key_pair.public_key();
    let components: RsaPublicKeyComponents<Vec<u8>> = pubkey.into();
    let der: PublicKeyX509Der<'_> = components.as_der().unwrap();
    let parsed_from_der =
        ParsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der.as_ref()).unwrap();
    let parsed_from_components = components
        .to_parsed_public_key(&signature::RSA_PKCS1_2048_8192_SHA256)
        .unwrap();
    // Both constructors should accept the same signature.
    let message = b"hello, world";
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
        .unwrap();
    parsed_from_der.verify_sig(message, &signature).unwrap();
    parsed_from_components
        .verify_sig(message, &signature)
        .unwrap();
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
    let _: RsaSubjectPublicKey = pubkey.clone();

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

#[test]
fn keysize_len() {
    assert_eq!(KeySize::Rsa2048.len(), 256);
    assert_eq!(KeySize::Rsa3072.len(), 384);
    assert_eq!(KeySize::Rsa4096.len(), 512);
    assert_eq!(KeySize::Rsa8192.len(), 1024);
}

macro_rules! generate_encode_decode {
    ($name:ident, $size:expr) => {
        #[test]
        fn $name() {
            let private_key = RsaKeyPair::generate($size).expect("generation");

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = RsaKeyPair::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = crate::signature::KeyPair::public_key(&private_key);

            let _ = public_key.as_ref();
        }
    };
}

generate_encode_decode!(rsa2048_generate_encode_decode, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_encode_decode!(rsa3072_generate_encode_decode, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_encode_decode!(rsa4096_generate_encode_decode, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_encode_decode!(rsa8192_generate_encode_decode, KeySize::Rsa8192);

macro_rules! generate_fips_encode_decode {
    ($name:ident, $size:expr) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let private_key = RsaKeyPair::generate($size).expect("generation");

            assert_eq!(true, private_key.is_valid_fips_key());

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = RsaKeyPair::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = crate::signature::KeyPair::public_key(&private_key);

            let _ = public_key.as_ref();
        }
    };
    ($name:ident, $size:expr, false) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let _ = RsaKeyPair::generate_fips($size).expect_err("should fail for key size");
        }
    };
}

generate_fips_encode_decode!(rsa2048_generate_fips_encode_decode, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_fips_encode_decode!(rsa3072_generate_fips_encode_decode, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_fips_encode_decode!(rsa4096_generate_fips_encode_decode, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_fips_encode_decode!(rsa8192_generate_fips_encode_decode, KeySize::Rsa8192);

macro_rules! encryption_generate_encode_decode {
    ($name:ident, $size:expr) => {
        #[test]
        fn $name() {
            let private_key = PrivateDecryptingKey::generate($size).expect("generation");

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = private_key.public_key();

            drop(private_key);

            let public_key_der = public_key.as_der().expect("encoded");

            let _public_key =
                PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
        }
    };
}

encryption_generate_encode_decode!(rsa2048_encryption_generate_encode_decode, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_encode_decode!(rsa3072_encryption_generate_encode_decode, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_encode_decode!(rsa4096_encryption_generate_encode_decode, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_encode_decode!(rsa8192_encryption_generate_encode_decode, KeySize::Rsa8192);

macro_rules! encryption_generate_fips_encode_decode {
    ($name:ident, $size:expr) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let private_key = PrivateDecryptingKey::generate($size).expect("generation");

            assert_eq!(true, private_key.is_valid_fips_key());

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = private_key.public_key();

            drop(private_key);

            let public_key_der = public_key.as_der().expect("encoded");

            let _public_key =
                PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
        }
    };
    ($name:ident, $size:expr, false) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let _ =
                PrivateDecryptingKey::generate_fips($size).expect_err("should fail for key size");
        }
    };
}

encryption_generate_fips_encode_decode!(
    rsa2048_encryption_generate_fips_encode_decode,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_fips_encode_decode!(
    rsa3072_encryption_generate_fips_encode_decode,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_fips_encode_decode!(
    rsa4096_encryption_generate_fips_encode_decode,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_fips_encode_decode!(
    rsa8192_encryption_generate_fips_encode_decode,
    KeySize::Rsa8192
);

#[test]
fn public_key_components_clone_debug() {
    let pkc = RsaPublicKeyComponents::<&[u8]> {
        n: &[0x63, 0x61, 0x6d, 0x65, 0x6c, 0x6f, 0x74],
        e: &[0x61, 0x76, 0x61, 0x6c, 0x6f, 0x6e],
    };
    assert_eq!("RsaPublicKeyComponents { n: [99, 97, 109, 101, 108, 111, 116], e: [97, 118, 97, 108, 111, 110] }", format!("{pkc:?}"));
}

#[test]
fn encryption_algorithm_id() {
    assert_eq!(
        OAEP_SHA1_MGF1SHA1.id(),
        EncryptionAlgorithmId::OaepSha1Mgf1sha1
    );
    assert_eq!(
        OAEP_SHA256_MGF1SHA256.id(),
        EncryptionAlgorithmId::OaepSha256Mgf1sha256
    );
    assert_eq!(
        OAEP_SHA384_MGF1SHA384.id(),
        EncryptionAlgorithmId::OaepSha384Mgf1sha384
    );
    assert_eq!(
        OAEP_SHA512_MGF1SHA512.id(),
        EncryptionAlgorithmId::OaepSha512Mgf1sha512
    );
}

#[test]
fn encryption_algorithm_debug() {
    assert_eq!("OaepSha1Mgf1sha1", format!("{OAEP_SHA1_MGF1SHA1:?}"));
}

macro_rules! round_trip_oaep_algorithm {
    ($name:ident, $alg:expr, $keysize:expr) => {
        #[test]
        fn $name() {
            const MESSAGE: &[u8] = b"Hello World!";

            let private_key = PrivateDecryptingKey::generate($keysize).expect("generation");
            let public_key = private_key.public_key();

            let (byte_len, bit_len) = match $keysize {
                KeySize::Rsa2048 => (256, 2048),
                KeySize::Rsa3072 => (384, 3072),
                KeySize::Rsa4096 => (512, 4096),
                KeySize::Rsa8192 => (1024, 8192),
                _ => panic!("missing KeySize match arm"),
            };

            assert_eq!(private_key.key_size_bytes(), byte_len);
            assert_eq!(public_key.key_size_bytes(), byte_len);
            assert_eq!(private_key.key_size_bits(), bit_len);
            assert_eq!(public_key.key_size_bits(), bit_len);

            let public_key = OaepPublicEncryptingKey::new(public_key)
                .expect("RSA-OAEP public key from public key");
            let private_key = OaepPrivateDecryptingKey::new(private_key)
                .expect("RSA-OAEP private key from private key");

            assert_eq!(private_key.key_size_bytes(), byte_len);
            assert_eq!(public_key.key_size_bytes(), byte_len);
            assert_eq!(private_key.key_size_bits(), bit_len);
            assert_eq!(public_key.key_size_bits(), bit_len);

            // fixed message, None (empty label)
            {
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut(), None)
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, None)
                    .expect("decrypted");

                assert_eq!(MESSAGE, plaintext);
            }

            // fixed message, Some(&[0u8; 0])
            {
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut(), Some(&[0u8; 0]))
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, Some(&[0u8; 0]))
                    .expect("decrypted");

                assert_eq!(MESSAGE, plaintext);
            }

            // fixed message, Some(label)
            {
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let label: &[u8] = br"Testing Data Label";

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut(), Some(label))
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, Some(label))
                    .expect("decrypted");

                assert_eq!(MESSAGE, plaintext);
            }

            // zero-length message
            {
                let message: &[u8] = &[1u8; 0];
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, message, ciphertext.as_mut(), None)
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, None)
                    .expect("decrypted");

                assert_eq!(message, plaintext);
            }

            // max_plaintext_size message
            {
                let message = vec![1u8; public_key.max_plaintext_size($alg)];
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, &message, ciphertext.as_mut(), None)
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, None)
                    .expect("decrypted");

                assert_eq!(message, plaintext);
            }

            // max_plaintext_size+1 message
            {
                let message = vec![1u8; public_key.max_plaintext_size($alg) + 1];
                let mut ciphertext = vec![0u8; private_key.min_output_size()];

                public_key
                    .encrypt($alg, &message, ciphertext.as_mut(), None)
                    .expect_err("plaintext too large");
            }
        }
    };
}

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa8192
);

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa8192
);

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa8192
);

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa8192
);

#[test]
fn encrypting_keypair_debug() {
    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");

    assert_eq!("PrivateDecryptingKey", format!("{:?}", &private_key));

    let public_key = private_key.public_key();

    assert_eq!("PublicEncryptingKey", format!("{:?}", &public_key));

    let oaep_private_key =
        OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");

    assert_eq!(
        "OaepPrivateDecryptingKey { .. }",
        format!("{:?}", &oaep_private_key)
    );

    let oaep_public_key =
        OaepPublicEncryptingKey::new(public_key.clone()).expect("oaep public key");

    assert_eq!(
        "OaepPublicEncryptingKey { .. }",
        format!("{:?}", &oaep_public_key)
    );

    let pkcs1_private_key =
        Pkcs1PrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");

    assert_eq!(
        "Pkcs1PrivateDecryptingKey { .. }",
        format!("{:?}", &pkcs1_private_key)
    );

    let pkcs1_public_key =
        Pkcs1PublicEncryptingKey::new(public_key.clone()).expect("oaep public key");

    assert_eq!(
        "Pkcs1PublicEncryptingKey { .. }",
        format!("{:?}", &pkcs1_public_key)
    );
}

#[test]
fn clone_then_drop() {
    const MESSAGE: &[u8] = b"Hello World!";

    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");
    let public_key = private_key.public_key();

    let oaep_priv_key =
        OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");
    let oaep_pub_key = OaepPublicEncryptingKey::new(public_key.clone()).expect("oaep public key");

    drop(private_key);
    drop(public_key);

    let mut ciphertext = vec![0u8; oaep_pub_key.ciphertext_size()];

    let ciphertext = oaep_pub_key
        .encrypt(&OAEP_SHA256_MGF1SHA256, MESSAGE, ciphertext.as_mut(), None)
        .expect("encrypted");

    let mut plaintext = vec![0u8; oaep_priv_key.key_size_bytes()];

    let plaintext = oaep_priv_key
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .expect("decrypted");

    assert_eq!(MESSAGE, plaintext);
}

#[test]
fn encrypt_decrypt_key_size() {
    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");
    let public_key = private_key.public_key();
    assert_eq!(private_key.key_size_bytes(), public_key.key_size_bytes());
    assert_eq!(private_key.key_size_bits(), public_key.key_size_bits());

    let oaep_priv_key =
        OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");
    let oaep_pub_key = OaepPublicEncryptingKey::new(public_key.clone()).expect("oaep public key");
    assert_eq!(
        oaep_priv_key.key_size_bytes(),
        oaep_pub_key.key_size_bytes()
    );
    assert_eq!(oaep_priv_key.key_size_bits(), oaep_pub_key.key_size_bits());

    assert_eq!(private_key.key_size_bytes(), oaep_priv_key.key_size_bytes());
    assert_eq!(private_key.key_size_bits(), oaep_priv_key.key_size_bits());
}

#[test]
fn too_small_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_1024.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_1024.x509");
    PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect_err("private key too small");
    PublicEncryptingKey::from_der(PUBLIC_KEY).expect_err("public key too small");
}

#[test]
fn min_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_2048.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_2048.x509");

    let parsed_private_key = PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect("key supported");
    let signing_priv_key = RsaKeyPair::from_pkcs8(PRIVATE_KEY).expect("key supported");
    let parsed_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("key supported");
    let parsed_signing_public_key =
        RsaSubjectPublicKey::from_der(PUBLIC_KEY).expect("key supported");

    let derived_public_key = parsed_private_key.public_key();
    let derived_signing_public_key = signing_priv_key.public_key();

    let private_key_bytes =
        AsDer::<Pkcs8V1Der>::as_der(&parsed_private_key).expect("serializeable");
    let signing_private_key_bytes =
        AsDer::<Pkcs8V1Der>::as_der(&signing_priv_key).expect("serializeable");
    let parsed_public_key_bytes =
        AsDer::<PublicKeyX509Der>::as_der(&parsed_public_key).expect("serializeable");
    let parsed_signing_public_key_bytes =
        AsDer::<PublicKeyX509Der>::as_der(&parsed_signing_public_key).expect("serializeable");
    let derived_public_key_bytes =
        AsDer::<PublicKeyX509Der>::as_der(&derived_public_key).expect("serializeable");
    let derived_signing_public_key_bytes =
        AsDer::<PublicKeyX509Der>::as_der(derived_signing_public_key).expect("serializeable");

    assert_eq!(PRIVATE_KEY, private_key_bytes.as_ref());
    assert_eq!(PRIVATE_KEY, signing_private_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, parsed_public_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, parsed_signing_public_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, derived_public_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, derived_signing_public_key_bytes.as_ref());

    let oaep_parsed_private =
        OaepPrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let oaep_parsed_public =
        OaepPublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; oaep_parsed_public.max_plaintext_size(&OAEP_SHA256_MGF1SHA256)];

    let mut ciphertext = vec![0u8; oaep_parsed_public.ciphertext_size()];
    let ciphertext = oaep_parsed_public
        .encrypt(&OAEP_SHA256_MGF1SHA256, &message, &mut ciphertext, None)
        .expect("encrypted");

    let mut plaintext = vec![0u8; oaep_parsed_private.min_output_size()];
    let plaintext = oaep_parsed_private
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .expect("decrypted");

    assert_eq!(message, plaintext);

    let pkcs1_parsed_private =
        Pkcs1PrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let pkcs1_parsed_public =
        Pkcs1PublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; pkcs1_parsed_public.max_plaintext_size()];

    let mut ciphertext = vec![0u8; pkcs1_parsed_public.ciphertext_size()];
    let ciphertext = pkcs1_parsed_public
        .encrypt(&message, &mut ciphertext)
        .expect("encrypted");

    let mut plaintext = vec![0u8; pkcs1_parsed_private.min_output_size()];
    let plaintext = pkcs1_parsed_private
        .decrypt(ciphertext, &mut plaintext)
        .expect("decrypted");

    assert_eq!(message, plaintext);
}

#[test]
fn max_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_8192.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_8192.x509");

    let parsed_private_key = PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect("key supported");
    let parsed_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("key supported");

    let public_key = parsed_private_key.public_key();

    let private_key_bytes =
        AsDer::<Pkcs8V1Der>::as_der(&parsed_private_key).expect("serializeable");
    let public_key_bytes = AsDer::<PublicKeyX509Der>::as_der(&public_key).expect("serializeable");

    assert_eq!(PRIVATE_KEY, private_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, public_key_bytes.as_ref());

    let oaep_parsed_private =
        OaepPrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let oaep_parsed_public =
        OaepPublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; oaep_parsed_public.max_plaintext_size(&OAEP_SHA256_MGF1SHA256)];

    let mut ciphertext = vec![0u8; oaep_parsed_public.ciphertext_size()];
    let ciphertext = oaep_parsed_public
        .encrypt(&OAEP_SHA256_MGF1SHA256, &message, &mut ciphertext, None)
        .expect("encrypted");

    let mut plaintext = vec![0u8; oaep_parsed_private.key_size_bytes()];
    let plaintext = oaep_parsed_private
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .expect("decrypted");

    assert_eq!(message, plaintext);

    let pkcs1_parsed_private =
        Pkcs1PrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let pkcs1_parsed_public =
        Pkcs1PublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; pkcs1_parsed_public.max_plaintext_size()];

    let mut ciphertext = vec![0u8; pkcs1_parsed_public.ciphertext_size()];
    let ciphertext = pkcs1_parsed_public
        .encrypt(&message, &mut ciphertext)
        .expect("encrypted");

    let mut plaintext = vec![0u8; pkcs1_parsed_private.min_output_size()];
    let plaintext = pkcs1_parsed_private
        .decrypt(ciphertext, &mut plaintext)
        .expect("decrypted");

    assert_eq!(message, plaintext);
}

#[test]
fn errors_on_larger_than_max_plaintext() {
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_2048.x509");

    let parsed_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("key supported");

    let oaep_parsed_public =
        OaepPublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; oaep_parsed_public.max_plaintext_size(&OAEP_SHA256_MGF1SHA256) + 1];

    let mut ciphertext = vec![0u8; oaep_parsed_public.ciphertext_size()];
    oaep_parsed_public
        .encrypt(&OAEP_SHA256_MGF1SHA256, &message, &mut ciphertext, None)
        .expect_err("plaintext too large");

    let pkcs1_parsed_public =
        Pkcs1PublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; pkcs1_parsed_public.max_plaintext_size() + 1];

    let mut ciphertext = vec![0u8; pkcs1_parsed_public.ciphertext_size()];
    pkcs1_parsed_public
        .encrypt(&message, &mut ciphertext)
        .expect_err("plaintext too large");
}

#[test]
fn too_big_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_16384.p8");
    PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect_err("key too big");
}

macro_rules! round_trip_pkcs1_encryption {
    ($name:ident, $keysize:expr) => {
        #[test]
        fn $name() {
            const MESSAGE: &[u8] = b"Hello World";

            let priv_key = PrivateDecryptingKey::generate($keysize).expect("key generated");
            let pub_key = priv_key.public_key();

            let priv_key =
                Pkcs1PrivateDecryptingKey::new(priv_key).expect("construct PKCS1 private key");

            let pub_key =
                Pkcs1PublicEncryptingKey::new(pub_key).expect("construct PKCS1 private key");

            let (byte_len, bit_len) = match $keysize {
                KeySize::Rsa2048 => (256, 2048),
                KeySize::Rsa3072 => (384, 3072),
                KeySize::Rsa4096 => (512, 4096),
                KeySize::Rsa8192 => (1024, 8192),
                _ => panic!("missing KeySize match arm"),
            };

            assert_eq!(priv_key.key_size_bytes(), byte_len);
            assert_eq!(pub_key.key_size_bytes(), byte_len);
            assert_eq!(priv_key.key_size_bits(), bit_len);
            assert_eq!(pub_key.key_size_bits(), bit_len);

            let mut ciphertext = vec![0u8; pub_key.ciphertext_size()];

            let ciphertext: &[u8] = pub_key
                .encrypt(MESSAGE, &mut ciphertext)
                .expect("encrypted");

            let mut plaintext = vec![0u8; priv_key.min_output_size()];

            let plaintext: &[u8] = priv_key
                .decrypt(ciphertext, &mut plaintext)
                .expect("decrypt");

            assert_eq!(MESSAGE, plaintext);
        }
    };
}

round_trip_pkcs1_encryption!(rsa2048_pkcs1_encryption, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_pkcs1_encryption!(rsa3072_pkcs1_encryption, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_pkcs1_encryption!(rsa4096_pkcs1_encryption, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_pkcs1_encryption!(rsa8192_pkcs1_encryption, KeySize::Rsa8192);

// Generated by `echo -n "OpenSSL KAT" | openssl pkeyutl -inkey rsa_test_public_key_2048.x509 -pubin -encrypt -pkeyopt rsa_padding_mode:pkcs1 | xxd -i`
#[test]
fn rsa2048_pkcs1_openssl_kat() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_2048.p8");

    const EXPECTED_MESSAGE: &[u8] = b"OpenSSL KAT";
    const CIPHERTEXT: &[u8] = &[
        0x79, 0xc3, 0xf1, 0x0a, 0x69, 0xc7, 0x0b, 0x19, 0xc1, 0xfd, 0x62, 0xbe, 0x24, 0x85, 0x31,
        0xc1, 0x1d, 0x6c, 0x85, 0x34, 0x03, 0x78, 0x4a, 0x7e, 0xbe, 0xb8, 0xa2, 0xe5, 0xac, 0x79,
        0xaf, 0x1c, 0x6a, 0xff, 0x2f, 0xa5, 0xff, 0xaa, 0x5b, 0xb9, 0x6f, 0xa1, 0xaa, 0x42, 0x72,
        0xa5, 0x87, 0x92, 0x05, 0x97, 0xb4, 0xef, 0x42, 0x02, 0xd3, 0xc4, 0x9f, 0x6e, 0xe3, 0xed,
        0x51, 0xba, 0x52, 0xcf, 0x44, 0x14, 0xf8, 0x47, 0x53, 0x8c, 0xfc, 0x12, 0x0d, 0x53, 0x13,
        0x11, 0x00, 0x7f, 0x87, 0xf7, 0xb5, 0x56, 0xdc, 0xd7, 0xe9, 0xf4, 0xc5, 0xb0, 0x34, 0x85,
        0x10, 0x8a, 0x04, 0xe4, 0x62, 0x38, 0x91, 0xa4, 0xb3, 0x5e, 0x98, 0x15, 0x89, 0x98, 0xf2,
        0xf7, 0x4f, 0xb1, 0x30, 0xa2, 0x09, 0x23, 0x38, 0x43, 0x22, 0x58, 0xec, 0x3c, 0xeb, 0x8d,
        0x62, 0x75, 0x9f, 0xa9, 0x83, 0x0d, 0xe0, 0x43, 0x5a, 0x1c, 0xd5, 0xdb, 0xc6, 0x2c, 0x97,
        0x19, 0xfd, 0xa7, 0xb5, 0x71, 0x1b, 0x87, 0xab, 0x3d, 0xf2, 0x3c, 0x42, 0xc2, 0xea, 0xd8,
        0x57, 0x2a, 0x80, 0xdc, 0xc1, 0x00, 0x66, 0xa5, 0xf0, 0x95, 0x51, 0x56, 0xe8, 0x66, 0x8e,
        0xe9, 0x8e, 0x2a, 0xa6, 0x37, 0x16, 0xeb, 0xbf, 0xe5, 0x12, 0x25, 0x67, 0x0e, 0xc0, 0x3d,
        0x3c, 0x58, 0x15, 0x16, 0x54, 0x15, 0x04, 0xa2, 0xa2, 0x26, 0x46, 0x81, 0x36, 0x64, 0xc0,
        0x7f, 0x6a, 0x04, 0x10, 0x2a, 0x7f, 0x08, 0x6d, 0x4b, 0x23, 0x12, 0x30, 0x9b, 0x0c, 0xb4,
        0xa5, 0x10, 0x80, 0xaa, 0xf0, 0xe3, 0xf3, 0x1e, 0x3b, 0x59, 0x1d, 0x52, 0x68, 0x8e, 0xb9,
        0x9c, 0x89, 0x97, 0x46, 0xfb, 0x06, 0x32, 0xd6, 0xc2, 0x1c, 0x81, 0x8c, 0xa6, 0xf4, 0xa7,
        0xf8, 0xda, 0xb4, 0x4b, 0xd2, 0x49, 0x17, 0xd6, 0x6c, 0x19, 0xe3, 0xa1, 0xbd, 0xe3, 0x5a,
        0x99,
    ];

    let private_key = PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect("private key");
    let private_key = Pkcs1PrivateDecryptingKey::new(private_key).expect("private key");

    let mut plaintext = vec![0u8; private_key.min_output_size()];

    let plaintext = private_key
        .decrypt(CIPHERTEXT, &mut plaintext)
        .expect("decrypt");

    assert_eq!(EXPECTED_MESSAGE, plaintext);
}

#[test]
// For code coverage
fn test_wrong_digest() {
    let keypair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let msg = "Hello World!";
    let digest_sha256 = digest::digest(&SHA256, msg.as_bytes());
    let digest_sha384 = digest::digest(&SHA384, msg.as_bytes());

    let mut signature = vec![0u8; keypair.public_modulus_len()];
    keypair
        .sign_digest(&signature::RSA_PSS_SHA256, &digest_sha256, &mut signature)
        .unwrap();
    assert!(keypair
        .sign_digest(&signature::RSA_PSS_SHA256, &digest_sha384, &mut signature)
        .is_err());

    let public_key = keypair.public_key();
    let upk = UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, &public_key);
    upk.verify_digest(&digest_sha256, &signature).unwrap();
    assert!(upk.verify_digest(&digest_sha384, &signature).is_err());
}
