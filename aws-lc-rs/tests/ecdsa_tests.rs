// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::digest::{
    Digest, SHA1_FOR_LEGACY_USE_ONLY, SHA224, SHA256, SHA384, SHA3_256, SHA3_384, SHA3_512, SHA512,
    SHA512_256,
};
use aws_lc_rs::encoding::{AsBigEndian, AsDer, EcPrivateKeyRfc5915Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, EcdsaCurve, EcdsaKeyPair, EcdsaSignatureFormat, EcdsaSigningAlgorithm,
    EcdsaVerificationAlgorithm, KeyPair, ParsedPublicKey, Signature, UnparsedPublicKey,
    VerificationAlgorithm,
};
use aws_lc_rs::{digest, test, test_file};

const ECDSA_CURVES: [EcdsaCurve; 4] = [
    EcdsaCurve::P256,
    EcdsaCurve::P384,
    EcdsaCurve::P521,
    EcdsaCurve::P256K1,
];
const ECDSA_SIGNATURE_FORMATS: [EcdsaSignatureFormat; 2] =
    [EcdsaSignatureFormat::Asn1, EcdsaSignatureFormat::Fixed];
const ECDSA_SIGNING_DIGESTS: [&digest::Algorithm; 8] = [
    &SHA224,
    &SHA256,
    &SHA384,
    &SHA512,
    &SHA512_256,
    &SHA3_256,
    &SHA3_384,
    &SHA3_512,
];

// (curve, digest) pairs that have NIST CAVP vectors but no predefined signing constant.
macro_rules! ecdsa_asn1_algorithms {
    ($($signing:ident, $verifying:ident = ($curve:ident, $digest:ident);)+) => {
        $(
            static $signing: EcdsaSigningAlgorithm =
                EcdsaSigningAlgorithm::new(EcdsaCurve::$curve, &$digest, EcdsaSignatureFormat::Asn1);
            static $verifying: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm::new(
                EcdsaCurve::$curve,
                &$digest,
                EcdsaSignatureFormat::Asn1,
            );
        )+
    };
}
ecdsa_asn1_algorithms! {
    ECDSA_P256_SHA224_ASN1_SIGNING, ECDSA_P256_SHA224_ASN1 = (P256, SHA224);
    ECDSA_P256_SHA384_ASN1_SIGNING, ECDSA_P256_SHA384_ASN1 = (P256, SHA384);
    ECDSA_P256_SHA512_ASN1_SIGNING, ECDSA_P256_SHA512_ASN1 = (P256, SHA512);
    ECDSA_P384_SHA224_ASN1_SIGNING, ECDSA_P384_SHA224_ASN1 = (P384, SHA224);
    ECDSA_P384_SHA256_ASN1_SIGNING, ECDSA_P384_SHA256_ASN1 = (P384, SHA256);
    ECDSA_P384_SHA512_ASN1_SIGNING, ECDSA_P384_SHA512_ASN1 = (P384, SHA512);
}

#[test]
fn ecdsa_traits() {
    test::compile_time_assert_send::<EcdsaKeyPair>();
    test::compile_time_assert_sync::<EcdsaKeyPair>();
    test::compile_time_assert_clone::<EcdsaKeyPair>();
    test::compile_time_assert_send::<Signature>();
    test::compile_time_assert_sync::<Signature>();

    test::compile_time_assert_eq::<EcdsaVerificationAlgorithm>();
    test::compile_time_assert_copy::<EcdsaVerificationAlgorithm>();
    test::compile_time_assert_eq::<EcdsaSigningAlgorithm>();
    test::compile_time_assert_copy::<EcdsaSigningAlgorithm>();
    test::compile_time_assert_eq::<EcdsaCurve>();
    test::compile_time_assert_copy::<EcdsaCurve>();
    test::compile_time_assert_eq::<EcdsaSignatureFormat>();
    test::compile_time_assert_copy::<EcdsaSignatureFormat>();
}

/// The `const fn` constructors reproduce every predefined ECDSA constant, so a constructed
/// algorithm is interchangeable with the constant for the same (curve, digest, format).
#[test]
fn ecdsa_algorithm_constructors_match_constants() {
    macro_rules! assert_constructs {
        ($ty:ident: $($constant:ident = ($curve:ident, $digest:ident, $format:ident);)+) => {
            $(
                assert_eq!(
                    $ty::new(EcdsaCurve::$curve, &$digest, EcdsaSignatureFormat::$format),
                    signature::$constant,
                    stringify!($constant)
                );
            )+
        };
    }

    assert_constructs! { EcdsaVerificationAlgorithm:
        ECDSA_P256_SHA256_FIXED = (P256, SHA256, Fixed);
        ECDSA_P384_SHA384_FIXED = (P384, SHA384, Fixed);
        ECDSA_P384_SHA3_384_FIXED = (P384, SHA3_384, Fixed);
        ECDSA_P521_SHA1_FIXED = (P521, SHA1_FOR_LEGACY_USE_ONLY, Fixed);
        ECDSA_P521_SHA224_FIXED = (P521, SHA224, Fixed);
        ECDSA_P521_SHA256_FIXED = (P521, SHA256, Fixed);
        ECDSA_P521_SHA384_FIXED = (P521, SHA384, Fixed);
        ECDSA_P521_SHA512_FIXED = (P521, SHA512, Fixed);
        ECDSA_P521_SHA3_512_FIXED = (P521, SHA3_512, Fixed);
        ECDSA_P256K1_SHA256_FIXED = (P256K1, SHA256, Fixed);
        ECDSA_P256K1_SHA3_256_FIXED = (P256K1, SHA3_256, Fixed);
        ECDSA_P256_SHA1_ASN1 = (P256, SHA1_FOR_LEGACY_USE_ONLY, Asn1);
        ECDSA_P256_SHA256_ASN1 = (P256, SHA256, Asn1);
        ECDSA_P256_SHA384_ASN1 = (P256, SHA384, Asn1);
        ECDSA_P256_SHA512_ASN1 = (P256, SHA512, Asn1);
        ECDSA_P384_SHA256_ASN1 = (P384, SHA256, Asn1);
        ECDSA_P384_SHA384_ASN1 = (P384, SHA384, Asn1);
        ECDSA_P384_SHA512_ASN1 = (P384, SHA512, Asn1);
        ECDSA_P384_SHA3_384_ASN1 = (P384, SHA3_384, Asn1);
        ECDSA_P521_SHA1_ASN1 = (P521, SHA1_FOR_LEGACY_USE_ONLY, Asn1);
        ECDSA_P521_SHA224_ASN1 = (P521, SHA224, Asn1);
        ECDSA_P521_SHA256_ASN1 = (P521, SHA256, Asn1);
        ECDSA_P521_SHA384_ASN1 = (P521, SHA384, Asn1);
        ECDSA_P521_SHA512_ASN1 = (P521, SHA512, Asn1);
        ECDSA_P521_SHA3_512_ASN1 = (P521, SHA3_512, Asn1);
        ECDSA_P256K1_SHA256_ASN1 = (P256K1, SHA256, Asn1);
        ECDSA_P256K1_SHA3_256_ASN1 = (P256K1, SHA3_256, Asn1);
    }

    assert_constructs! { EcdsaSigningAlgorithm:
        ECDSA_P256_SHA256_FIXED_SIGNING = (P256, SHA256, Fixed);
        ECDSA_P384_SHA384_FIXED_SIGNING = (P384, SHA384, Fixed);
        ECDSA_P384_SHA3_384_FIXED_SIGNING = (P384, SHA3_384, Fixed);
        ECDSA_P521_SHA224_FIXED_SIGNING = (P521, SHA224, Fixed);
        ECDSA_P521_SHA256_FIXED_SIGNING = (P521, SHA256, Fixed);
        ECDSA_P521_SHA384_FIXED_SIGNING = (P521, SHA384, Fixed);
        ECDSA_P521_SHA512_FIXED_SIGNING = (P521, SHA512, Fixed);
        ECDSA_P521_SHA3_512_FIXED_SIGNING = (P521, SHA3_512, Fixed);
        ECDSA_P256K1_SHA256_FIXED_SIGNING = (P256K1, SHA256, Fixed);
        ECDSA_P256K1_SHA3_256_FIXED_SIGNING = (P256K1, SHA3_256, Fixed);
        ECDSA_P256_SHA256_ASN1_SIGNING = (P256, SHA256, Asn1);
        ECDSA_P384_SHA384_ASN1_SIGNING = (P384, SHA384, Asn1);
        ECDSA_P384_SHA3_384_ASN1_SIGNING = (P384, SHA3_384, Asn1);
        ECDSA_P521_SHA224_ASN1_SIGNING = (P521, SHA224, Asn1);
        ECDSA_P521_SHA256_ASN1_SIGNING = (P521, SHA256, Asn1);
        ECDSA_P521_SHA384_ASN1_SIGNING = (P521, SHA384, Asn1);
        ECDSA_P521_SHA512_ASN1_SIGNING = (P521, SHA512, Asn1);
        ECDSA_P521_SHA3_512_ASN1_SIGNING = (P521, SHA3_512, Asn1);
        ECDSA_P256K1_SHA256_ASN1_SIGNING = (P256K1, SHA256, Asn1);
        ECDSA_P256K1_SHA3_256_ASN1_SIGNING = (P256K1, SHA3_256, Asn1);
    }
}

/// The constructors and accessors are usable in `const` contexts.
#[test]
fn ecdsa_algorithm_const_accessors() {
    const SIGNING: EcdsaSigningAlgorithm =
        EcdsaSigningAlgorithm::new(EcdsaCurve::P384, &SHA256, EcdsaSignatureFormat::Fixed);
    const VERIFYING: &EcdsaVerificationAlgorithm = SIGNING.verification_algorithm();
    const CURVE: EcdsaCurve = VERIFYING.curve();
    const DIGEST: &digest::Algorithm = VERIFYING.digest_algorithm();
    const FORMAT: EcdsaSignatureFormat = VERIFYING.signature_format();
    const SCALAR_LEN: usize = CURVE.private_key_size();

    assert_eq!(CURVE, EcdsaCurve::P384);
    assert_eq!(DIGEST, &SHA256);
    assert_eq!(FORMAT, EcdsaSignatureFormat::Fixed);
    assert_eq!(SCALAR_LEN, 48);
    assert_eq!(
        *VERIFYING,
        EcdsaVerificationAlgorithm::new(EcdsaCurve::P384, &SHA256, EcdsaSignatureFormat::Fixed)
    );
    // Accessors are also reachable on the signing algorithm through `Deref`.
    assert_eq!(SIGNING.curve(), CURVE);
    assert_eq!(SIGNING.digest_algorithm(), DIGEST);
    assert_eq!(SIGNING.signature_format(), FORMAT);

    for curve in ECDSA_CURVES {
        let expected = match curve {
            EcdsaCurve::P256 | EcdsaCurve::P256K1 => 32,
            EcdsaCurve::P384 => 48,
            EcdsaCurve::P521 => 66,
            _ => unreachable!(),
        };
        assert_eq!(curve.private_key_size(), expected, "{curve:?}");
    }
}

/// Every (curve, digest, format) combination accepted by the constructors can generate a key,
/// sign, and verify, including the combinations that have no predefined constant.
#[test]
fn ecdsa_constructed_algorithm_matrix() {
    const MESSAGE: &[u8] = b"constructed ECDSA algorithm";
    let rng = SystemRandom::new();

    for curve in ECDSA_CURVES {
        for digest_alg in ECDSA_SIGNING_DIGESTS {
            let message_digest = digest::digest(digest_alg, MESSAGE);
            for format in ECDSA_SIGNATURE_FORMATS {
                // `EcdsaKeyPair` requires `&'static` algorithms; leak the constructed ones
                // so this test can iterate over the matrix at runtime.
                let signing: &'static EcdsaSigningAlgorithm = Box::leak(Box::new(
                    EcdsaSigningAlgorithm::new(curve, digest_alg, format),
                ));
                let verifying: &'static EcdsaVerificationAlgorithm = Box::leak(Box::new(
                    EcdsaVerificationAlgorithm::new(curve, digest_alg, format),
                ));
                assert_eq!(signing.verification_algorithm(), verifying);
                assert_eq!(signing.curve(), curve);
                assert_eq!(signing.digest_algorithm(), digest_alg);
                assert_eq!(signing.signature_format(), format);

                let key_pair = EcdsaKeyPair::generate(signing).unwrap();
                assert_eq!(key_pair.algorithm(), signing);
                let public_key = key_pair.public_key().as_ref();
                for signature in [
                    key_pair.sign(&rng, MESSAGE),
                    key_pair.sign_digest(&message_digest),
                ] {
                    let signature = signature.unwrap_or_else(|err| panic!("{signing:?}: {err:?}"));
                    if format == EcdsaSignatureFormat::Fixed {
                        assert_eq!(signature.as_ref().len(), 2 * curve.private_key_size());
                    }
                    UnparsedPublicKey::new(verifying, public_key)
                        .verify(MESSAGE, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                    verifying
                        .verify_digest_sig(public_key, &message_digest, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                }

                // A same-length digest from a different algorithm must not be accepted.
                let other_digest = match digest_alg.output_len {
                    32 if digest_alg == &SHA256 => Some(&SHA3_256),
                    32 if digest_alg == &SHA3_256 => Some(&SHA256),
                    48 if digest_alg == &SHA384 => Some(&SHA3_384),
                    48 if digest_alg == &SHA3_384 => Some(&SHA384),
                    64 if digest_alg == &SHA512 => Some(&SHA3_512),
                    64 if digest_alg == &SHA3_512 => Some(&SHA512),
                    _ => None,
                };
                if let Some(other_digest) = other_digest {
                    let wrong_digest = digest::digest(other_digest, MESSAGE);
                    assert!(key_pair.sign_digest(&wrong_digest).is_err());
                    let signature = key_pair.sign_digest(&message_digest).unwrap();
                    assert!(verifying
                        .verify_digest_sig(public_key, &wrong_digest, signature.as_ref())
                        .is_err());
                }
            }
        }
    }
}

#[test]
fn ecdsa_sha1_verification_only() {
    for curve in ECDSA_CURVES {
        for format in ECDSA_SIGNATURE_FORMATS {
            let verifying =
                EcdsaVerificationAlgorithm::new(curve, &SHA1_FOR_LEGACY_USE_ONLY, format);
            assert_eq!(verifying.curve(), curve);
            assert_eq!(verifying.digest_algorithm(), &SHA1_FOR_LEGACY_USE_ONLY);
            assert!(std::panic::catch_unwind(|| {
                EcdsaSigningAlgorithm::new(curve, &SHA1_FOR_LEGACY_USE_ONLY, format)
            })
            .is_err());
        }
    }
}

#[cfg(all(not(feature = "fips"), feature = "unstable"))]
#[test]
fn ecdsa_keccak_rejected() {
    use aws_lc_rs::unstable::digest::KECCAK256;

    for curve in ECDSA_CURVES {
        for format in ECDSA_SIGNATURE_FORMATS {
            assert!(std::panic::catch_unwind(|| {
                EcdsaSigningAlgorithm::new(curve, &KECCAK256, format)
            })
            .is_err());
            assert!(std::panic::catch_unwind(|| {
                EcdsaVerificationAlgorithm::new(curve, &KECCAK256, format)
            })
            .is_err());
        }
    }
}

#[test]
fn ecdsa_key_pair_clone() {
    const MESSAGE: &[u8] = b"hello, world";

    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let cloned = key_pair.clone();
    assert_eq!(key_pair.public_key().as_ref(), cloned.public_key().as_ref());
    let public_key = cloned.public_key().as_ref().to_vec();

    // The clone must remain usable after the original is dropped.
    drop(key_pair);

    let sig = cloned.sign(&rng, MESSAGE).unwrap();
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &public_key)
        .verify(MESSAGE, sig.as_ref())
        .unwrap();
}

#[test]
fn ecdsa_from_pkcs8_test() {
    test::run(
        test_file!("data/ecdsa_from_pkcs8_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let ((this_fixed, this_asn1), (other_fixed, other_asn1)) = match curve_name.as_str() {
                "P-256" => (
                    (
                        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ),
                    (
                        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ),
                ),
                "P-384" => (
                    (
                        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ),
                    (
                        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ),
                ),
                "P-521" => (
                    (
                        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
                    ),
                    (
                        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ),
                ),
                _ => unreachable!(),
            };

            let input = test_case.consume_bytes("Input");

            let error = test_case.consume_optional_string("Error");

            match (EcdsaKeyPair::from_pkcs8(this_fixed, &input), error.clone()) {
                (Ok(_), None) => (),
                (Err(e), None) => panic!(
                    "Failed with error \"{}\", but expected to succeed. Input: {}",
                    e,
                    test::to_hex(&input)
                ),
                (Ok(_), Some(e)) => panic!(
                    "Succeeded, but expected error \"{}\" - Input: {}",
                    e,
                    test::to_hex(&input)
                ),
                (Err(actual), Some(expected)) => assert_eq!(
                    format!("{actual}"),
                    expected,
                    "Input: {}",
                    test::to_hex(&input)
                ),
            }

            match (EcdsaKeyPair::from_pkcs8(this_asn1, &input), error) {
                (Ok(_), None) => (),
                (Err(e), None) => {
                    panic!("Failed with error \"{e}\", but expected to succeed");
                }
                (Ok(_), Some(e)) => panic!("Succeeded, but expected error \"{e}\""),
                (Err(actual), Some(expected)) => assert_eq!(format!("{actual}"), expected),
            }

            assert!(
                EcdsaKeyPair::from_pkcs8(other_fixed, &input).is_err(),
                "Input: {}",
                test::to_hex(&input)
            );
            assert!(
                EcdsaKeyPair::from_pkcs8(other_asn1, &input).is_err(),
                "Input: {}",
                test::to_hex(&input)
            );

            Ok(())
        },
    );
}

// Verify that, at least, we generate PKCS#8 documents that we can read.
#[test]
fn ecdsa_generate_pkcs8_test() {
    let rng = SystemRandom::new();

    for alg in &[
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
        &signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P256K1_SHA3_256_ASN1_SIGNING,
        &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
    ] {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        println!();
        for b in pkcs8.as_ref() {
            print!("{:02x}", *b);
        }
        println!();
        println!();

        let key_pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
        assert_eq!(key_pair.algorithm(), *alg);
    }
}

#[test]
fn signature_ecdsa_verify_asn1_test() {
    test_signature_ecdsa_verify_asn1(test_file!("data/ecdsa_verify_asn1_tests.txt"));
}

#[test]
fn signature_ecdsa_verify_asn1_sha3_test() {
    test_signature_ecdsa_verify_asn1(test_file!("data/ecdsa_verify_asn1_sha3_tests.txt"));
}

fn test_signature_ecdsa_verify_asn1(data_file: test::File) {
    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");
        let msg = test_case.consume_bytes("Msg");
        let public_key = test_case.consume_bytes("Q");
        let sig = test_case.consume_bytes("Sig");
        let is_valid = test_case.consume_string("Result") == "P (0 )";

        let (alg, digest_alg) = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA1") => (&signature::ECDSA_P256_SHA1_ASN1, &SHA1_FOR_LEGACY_USE_ONLY),
            ("P-256", "SHA256") => (&signature::ECDSA_P256_SHA256_ASN1, &SHA256),
            ("P-256", "SHA384") => (&signature::ECDSA_P256_SHA384_ASN1, &SHA384),
            ("P-256", "SHA512") => (&signature::ECDSA_P256_SHA512_ASN1, &SHA512),
            ("P-384", "SHA256") => (&signature::ECDSA_P384_SHA256_ASN1, &SHA256),
            ("P-384", "SHA384") => (&signature::ECDSA_P384_SHA384_ASN1, &SHA384),
            ("P-384", "SHA512") => (&signature::ECDSA_P384_SHA512_ASN1, &SHA512),
            ("P-384", "SHA3-384") => (&signature::ECDSA_P384_SHA3_384_ASN1, &SHA3_384),
            ("P-521", "SHA1") => (&signature::ECDSA_P521_SHA1_ASN1, &SHA1_FOR_LEGACY_USE_ONLY),
            ("P-521", "SHA224") => (&signature::ECDSA_P521_SHA224_ASN1, &SHA224),
            ("P-521", "SHA256") => (&signature::ECDSA_P521_SHA256_ASN1, &SHA256),
            ("P-521", "SHA384") => (&signature::ECDSA_P521_SHA384_ASN1, &SHA384),
            ("P-521", "SHA512") => (&signature::ECDSA_P521_SHA512_ASN1, &SHA512),
            ("P-521", "SHA3-512") => (&signature::ECDSA_P521_SHA3_512_ASN1, &SHA3_512),
            ("secp256k1", "SHA256") => (&signature::ECDSA_P256K1_SHA256_ASN1, &SHA256),
            ("secp256k1", "SHA3-256") => (&signature::ECDSA_P256K1_SHA3_256_ASN1, &SHA3_256),
            _ => {
                panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
            }
        };

        {
            let upk = UnparsedPublicKey::new(alg, &public_key);
            assert_eq!(upk.as_ref(), public_key.as_slice());

            let actual_result = upk.verify(&msg, &sig);
            assert_eq!(actual_result.is_ok(), is_valid);

            let digest = digest::digest(digest_alg, &msg);
            let actual_digest_result = upk.verify_digest(&digest, &sig);
            assert_eq!(actual_digest_result.is_ok(), is_valid);
        }

        {
            let ppk = ParsedPublicKey::new(alg, &public_key).unwrap();
            assert_eq!(ppk.as_ref(), public_key.as_slice());
            let actual_result = ppk.verify_sig(&msg, &sig);
            assert_eq!(actual_result.is_ok(), is_valid);

            let digest = digest::digest(digest_alg, &msg);
            let actual_digest_result = ppk.verify_digest_sig(&digest, &sig);
            assert_eq!(actual_digest_result.is_ok(), is_valid);

            let x509_bytes = ppk.as_der().unwrap();
            let actual_x509_result = alg.verify_sig(x509_bytes.as_ref(), &msg, &sig);
            assert_eq!(actual_x509_result.is_ok(), is_valid);
        }

        Ok(())
    });
}

#[test]
fn signature_ecdsa_verify_fixed_test() {
    test_signature_ecdsa_verify_fixed(test_file!("data/ecdsa_verify_fixed_tests.txt"));
}

#[test]
fn signature_ecdsa_verify_sha3_fixed_test() {
    test_signature_ecdsa_verify_fixed(test_file!("data/ecdsa_verify_fixed_sha3_tests.txt"));
}

fn test_signature_ecdsa_verify_fixed(data_file: test::File) {
    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let public_key = test_case.consume_bytes("Q");
        let sig = test_case.consume_bytes("Sig");
        let expected_result = test_case.consume_string("Result");

        let (alg, digest_alg) = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => (&signature::ECDSA_P256_SHA256_FIXED, &SHA256),
            ("P-384", "SHA384") => (&signature::ECDSA_P384_SHA384_FIXED, &SHA384),
            ("P-384", "SHA3-384") => (&signature::ECDSA_P384_SHA3_384_FIXED, &SHA3_384),
            ("P-521", "SHA1") => (&signature::ECDSA_P521_SHA1_FIXED, &SHA1_FOR_LEGACY_USE_ONLY),
            ("P-521", "SHA224") => (&signature::ECDSA_P521_SHA224_FIXED, &SHA224),
            ("P-521", "SHA256") => (&signature::ECDSA_P521_SHA256_FIXED, &SHA256),
            ("P-521", "SHA384") => (&signature::ECDSA_P521_SHA384_FIXED, &SHA384),
            ("P-521", "SHA512") => (&signature::ECDSA_P521_SHA512_FIXED, &SHA512),
            ("P-521", "SHA3-512") => (&signature::ECDSA_P521_SHA3_512_FIXED, &SHA3_512),
            ("secp256k1", "SHA256") => (&signature::ECDSA_P256K1_SHA256_FIXED, &SHA256),
            ("secp256k1", "SHA3-256") => (&signature::ECDSA_P256K1_SHA3_256_FIXED, &SHA3_256),
            _ => {
                panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
            }
        };

        let is_valid = expected_result == "P (0 )";

        let upk = UnparsedPublicKey::new(alg, &public_key);

        let actual_result = upk.verify(&msg, &sig);
        assert_eq!(actual_result.is_ok(), is_valid);

        let digest = digest::digest(digest_alg, &msg);
        let actual_digest_result = upk.verify_digest(&digest, &sig);
        assert_eq!(actual_digest_result.is_ok(), is_valid);

        Ok(())
    });
}

#[test]
fn ecdsa_test_public_key_coverage() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/ecdsa_test_private_key_p256.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/ecdsa_test_public_key_p256.der");
    const PUBLIC_KEY_DEBUG: &str = include_str!("data/ecdsa_test_public_key_p256_debug.txt");

    let key_pair =
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, PRIVATE_KEY).unwrap();

    // Test `AsRef<[u8]>`
    assert_eq!(key_pair.public_key().as_ref(), PUBLIC_KEY);

    // Test `Clone`.
    #[allow(let_underscore_drop, clippy::let_underscore_untyped)]
    let _ = key_pair.public_key().clone();

    // Test `Copy`.
    #[allow(let_underscore_drop)]
    let _: <EcdsaKeyPair as KeyPair>::PublicKey = *key_pair.public_key();

    // Test `Debug`.
    assert_eq!(PUBLIC_KEY_DEBUG, format!("{:?}", key_pair.public_key()));
    assert_eq!(
        format!("EcdsaKeyPair {{ public_key: {:?} }}", key_pair.public_key()),
        format!("{key_pair:?}")
    );
}

#[test]
fn signature_ecdsa_sign_fixed_sign_and_verify_test() {
    test_signature_ecdsa_sign_fixed_sign_and_verify(test_file!("data/ecdsa_sign_fixed_tests.txt"));
}

#[test]
fn signature_ecdsa_sign_fixed_sign_and_verify_sha3_test() {
    test_signature_ecdsa_sign_fixed_sign_and_verify(test_file!(
        "data/ecdsa_sign_fixed_sha3_tests.txt"
    ));
}

// This test is not a known-answer test, though it re-uses the known-answer
// test vectors. Because the nonce is randomized, the signature will be
// different each time. Because of that, here we simply verify that the
// signature verifies correctly.
fn test_signature_ecdsa_sign_fixed_sign_and_verify(data_file: test::File) {
    let rng = SystemRandom::new();

    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let d = test_case.consume_bytes("d");
        let q = test_case.consume_bytes("Q");

        // Ignored since the actual signature will use a randomized nonce.
        let _k = test_case.consume_optional_bytes("k");
        let _expected_result = test_case.consume_bytes("Sig");

        let (signing_alg, verification_alg, digest_alg) =
            match (curve_name.as_str(), digest_name.as_str()) {
                ("P-256", "SHA256") => (
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &signature::ECDSA_P256_SHA256_FIXED,
                    &SHA256,
                ),
                ("P-384", "SHA384") => (
                    &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    &signature::ECDSA_P384_SHA384_FIXED,
                    &SHA384,
                ),
                ("P-384", "SHA3-384") => (
                    &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
                    &signature::ECDSA_P384_SHA3_384_FIXED,
                    &SHA3_384,
                ),
                ("P-521", "SHA224") => (
                    &signature::ECDSA_P521_SHA224_FIXED_SIGNING,
                    &signature::ECDSA_P521_SHA224_FIXED,
                    &SHA224,
                ),
                ("P-521", "SHA256") => (
                    &signature::ECDSA_P521_SHA256_FIXED_SIGNING,
                    &signature::ECDSA_P521_SHA256_FIXED,
                    &SHA256,
                ),
                ("P-521", "SHA384") => (
                    &signature::ECDSA_P521_SHA384_FIXED_SIGNING,
                    &signature::ECDSA_P521_SHA384_FIXED,
                    &SHA384,
                ),
                ("P-521", "SHA512") => (
                    &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                    &signature::ECDSA_P521_SHA512_FIXED,
                    &SHA512,
                ),
                ("P-521", "SHA3-512") => (
                    &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
                    &signature::ECDSA_P521_SHA3_512_FIXED,
                    &SHA3_512,
                ),
                ("secp256k1", "SHA256") => (
                    &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
                    &signature::ECDSA_P256K1_SHA256_FIXED,
                    &SHA256,
                ),
                ("secp256k1", "SHA3-256") => (
                    &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
                    &signature::ECDSA_P256K1_SHA3_256_FIXED,
                    &SHA3_256,
                ),
                _ => {
                    panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
                }
            };

        let private_key =
            EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &d, &q).unwrap();

        let signature = private_key.sign(&rng, &msg).unwrap();

        let og_digest = digest::digest(digest_alg, &msg);
        let digest = Digest::import_less_safe(og_digest.as_ref(), digest_alg).unwrap();
        let digest_signature = private_key.sign_digest(&digest).unwrap();

        let public_key = UnparsedPublicKey::new(verification_alg, q);
        let vfy_result = public_key.verify(&msg, signature.as_ref());
        assert!(vfy_result.is_ok());

        let vfy_digest_result = public_key.verify_digest(&digest, digest_signature.as_ref());
        assert!(vfy_digest_result.is_ok());

        Ok(())
    });
}

#[test]
fn signature_ecdsa_sign_asn1_test() {
    test_signature_ecdsa_sign_asn1(test_file!("data/ecdsa_sign_asn1_tests.txt"));
}

#[test]
fn signature_ecdsa_sign_asn1_sha3_test() {
    test_signature_ecdsa_sign_asn1(test_file!("data/ecdsa_sign_asn1_sha3_tests.txt"));
}

// This test is not a known-answer test, though it re-uses the known-answer
// test vectors. Because the nonce is randomized, the signature will be
// different each time. Because of that, here we simply verify that the
// signature verifies correctly.
#[allow(clippy::too_many_lines)]
fn test_signature_ecdsa_sign_asn1(data_file: test::File) {
    let rng = SystemRandom::new();

    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let d = test_case.consume_bytes("d");
        let q = test_case.consume_bytes("Q");

        // Ignored since the actual signature will use a randomized nonce.
        let _k = test_case.consume_optional_bytes("k");
        let _expected_result = test_case.consume_bytes("Sig");

        let (signing_alg, verification_alg, digest_alg) =
            match (curve_name.as_str(), digest_name.as_str()) {
                ("P-256", "SHA224") => (
                    &ECDSA_P256_SHA224_ASN1_SIGNING,
                    &ECDSA_P256_SHA224_ASN1,
                    &SHA224,
                ),
                ("P-256", "SHA256") => (
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &SHA256,
                ),
                ("P-256", "SHA384") => (
                    &ECDSA_P256_SHA384_ASN1_SIGNING,
                    &ECDSA_P256_SHA384_ASN1,
                    &SHA384,
                ),
                ("P-256", "SHA512") => (
                    &ECDSA_P256_SHA512_ASN1_SIGNING,
                    &ECDSA_P256_SHA512_ASN1,
                    &SHA512,
                ),
                ("P-384", "SHA224") => (
                    &ECDSA_P384_SHA224_ASN1_SIGNING,
                    &ECDSA_P384_SHA224_ASN1,
                    &SHA224,
                ),
                ("P-384", "SHA256") => (
                    &ECDSA_P384_SHA256_ASN1_SIGNING,
                    &ECDSA_P384_SHA256_ASN1,
                    &SHA256,
                ),
                ("P-384", "SHA384") => (
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &signature::ECDSA_P384_SHA384_ASN1,
                    &SHA384,
                ),
                ("P-384", "SHA512") => (
                    &ECDSA_P384_SHA512_ASN1_SIGNING,
                    &ECDSA_P384_SHA512_ASN1,
                    &SHA512,
                ),
                ("P-384", "SHA3-384") => (
                    &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
                    &signature::ECDSA_P384_SHA3_384_ASN1,
                    &SHA3_384,
                ),
                ("P-521", "SHA224") => (
                    &signature::ECDSA_P521_SHA224_ASN1_SIGNING,
                    &signature::ECDSA_P521_SHA224_ASN1,
                    &SHA224,
                ),
                ("P-521", "SHA256") => (
                    &signature::ECDSA_P521_SHA256_ASN1_SIGNING,
                    &signature::ECDSA_P521_SHA256_ASN1,
                    &SHA256,
                ),
                ("P-521", "SHA384") => (
                    &signature::ECDSA_P521_SHA384_ASN1_SIGNING,
                    &signature::ECDSA_P521_SHA384_ASN1,
                    &SHA384,
                ),
                ("P-521", "SHA512") => (
                    &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
                    &signature::ECDSA_P521_SHA512_ASN1,
                    &SHA512,
                ),
                ("P-521", "SHA3-512") => (
                    &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
                    &signature::ECDSA_P521_SHA3_512_ASN1,
                    &SHA3_512,
                ),
                ("secp256k1", "SHA256") => (
                    &signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
                    &signature::ECDSA_P256K1_SHA256_ASN1,
                    &SHA256,
                ),
                ("secp256k1", "SHA3-256") => (
                    &signature::ECDSA_P256K1_SHA3_256_ASN1_SIGNING,
                    &signature::ECDSA_P256K1_SHA3_256_ASN1,
                    &SHA3_256,
                ),
                _ => {
                    panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
                }
            };

        let private_key =
            EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &d, &q).unwrap();

        let signature = private_key.sign(&rng, &msg).unwrap();

        let digest = digest::digest(digest_alg, &msg);
        let digest_signature = private_key.sign_digest(&digest).unwrap();

        let public_key = UnparsedPublicKey::new(verification_alg, q);
        let vfy_result = public_key.verify(&msg, signature.as_ref());
        assert!(vfy_result.is_ok());

        let vfy_digest_result = public_key.verify_digest(&digest, digest_signature.as_ref());
        assert!(vfy_digest_result.is_ok());

        Ok(())
    });
}

#[test]
fn test_to_pkcs8() {
    for signing_alg in [
        &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    ] {
        let rnd = SystemRandom::new();
        let key_pair_doc = EcdsaKeyPair::generate_pkcs8(signing_alg, &rnd).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, key_pair_doc.as_ref()).unwrap();

        let key_pair_export_doc = key_pair.to_pkcs8v1().unwrap();
        // Verify that the exported bytes match the original generated bytes
        assert_eq!(key_pair_doc.as_ref(), key_pair_export_doc.as_ref());
    }
}

#[test]
fn test_private_key() {
    for signing_alg in [
        &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    ] {
        let rnd = SystemRandom::new();
        let key_pair_doc = EcdsaKeyPair::generate_pkcs8(signing_alg, &rnd).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, key_pair_doc.as_ref()).unwrap();

        {
            let private_key = key_pair.private_key().as_be_bytes().unwrap();
            let public_key = key_pair.public_key();
            let key_pair_copy = EcdsaKeyPair::from_private_key_and_public_key(
                signing_alg,
                private_key.as_ref(),
                public_key.as_ref(),
            )
            .unwrap();
            let key_pair_copy_doc = key_pair_copy.to_pkcs8v1().unwrap();
            assert_eq!(key_pair_doc.as_ref(), key_pair_copy_doc.as_ref());
        }
        {
            let private_key_der: EcPrivateKeyRfc5915Der = key_pair.private_key().as_der().unwrap();
            assert_eq!("EcPrivateKeyRfc5915Der", format!("{private_key_der:?}"));
            assert!(EcdsaKeyPair::from_pkcs8(signing_alg, private_key_der.as_ref()).is_err());

            let key_pair_copy =
                EcdsaKeyPair::from_private_key_der(signing_alg, private_key_der.as_ref()).unwrap();
            let key_pair_copy_doc = key_pair_copy.to_pkcs8v1().unwrap();
            assert_eq!(key_pair_doc.as_ref(), key_pair_copy_doc.as_ref());
        }
    }
}
#[test]
// For code coverage
fn test_wrong_digest() {
    let key_pair = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let msg = "Hello World!";

    let digest_sha256 = digest::digest(&SHA256, msg.as_bytes());
    let digest_sha384 = digest::digest(&SHA384, msg.as_bytes());

    let signature_sha256 = key_pair.sign_digest(&digest_sha256).unwrap();
    assert!(key_pair.sign_digest(&digest_sha384).is_err());

    let public_key = key_pair.public_key();
    let upk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key.as_ref());
    upk.verify(msg.as_bytes(), signature_sha256.as_ref())
        .unwrap();

    assert!(upk
        .verify_digest(&digest_sha384, signature_sha256.as_ref())
        .is_err());
}
