// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(debug_assertions)]

use crate::digest;
use crate::fips::{assert_fips_status_indicator, FipsServiceStatus};
use crate::rand::SystemRandom;
use crate::rsa::KeySize;
use crate::signature::{
    EcdsaCurve, EcdsaKeyPair, EcdsaSignatureFormat, EcdsaSigningAlgorithm,
    EcdsaVerificationAlgorithm, Ed25519KeyPair, EdDSAParameters, KeyPair, RsaKeyPair,
    RsaParameters, RsaPssSaltLength, RsaSignatureEncoding, RsaSignaturePadding,
    VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, ECDSA_P384_SHA3_384_ASN1,
    ECDSA_P384_SHA3_384_ASN1_SIGNING, ECDSA_P384_SHA3_384_FIXED, ECDSA_P384_SHA3_384_FIXED_SIGNING,
    ECDSA_P521_SHA3_512_ASN1, ECDSA_P521_SHA3_512_ASN1_SIGNING, ECDSA_P521_SHA3_512_FIXED,
    ECDSA_P521_SHA3_512_FIXED_SIGNING, ECDSA_P521_SHA512_ASN1, ECDSA_P521_SHA512_ASN1_SIGNING,
    ECDSA_P521_SHA512_FIXED, ECDSA_P521_SHA512_FIXED_SIGNING,
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
};

mod keys;

use keys::*;

const TEST_MESSAGE: &str = "test message";

macro_rules! ecdsa_generate_sign_verify {
    ($name:ident, $sign_alg:expr, $verify_alg:expr, $generate_expect:path, $sign_verify_expect:path) => {
        #[test]
        fn $name() {
            let rng = SystemRandom::new();

            let key_document = assert_fips_status_indicator!(
                EcdsaKeyPair::generate_pkcs8($sign_alg, &rng),
                $generate_expect
            )
            .unwrap();

            let keypair = assert_fips_status_indicator!(
                EcdsaKeyPair::from_pkcs8($sign_alg, key_document.as_ref()),
                FipsServiceStatus::Approved
            )
            .unwrap();

            let signature = assert_fips_status_indicator!(
                keypair.sign(&rng, TEST_MESSAGE.as_bytes()),
                $sign_verify_expect
            )
            .unwrap();

            let public_key = keypair.public_key();

            assert_fips_status_indicator!(
                $verify_alg.verify_sig(
                    public_key.as_ref(),
                    TEST_MESSAGE.as_bytes(),
                    signature.as_ref()
                ),
                $sign_verify_expect
            )
            .unwrap();
        }
    };
}

ecdsa_generate_sign_verify!(
    ecdsa_p256_sha256_asn1,
    &ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P256_SHA256_ASN1,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p256_sha256_fixed,
    &ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P256_SHA256_FIXED,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p384_sha3_384_asn1,
    &ECDSA_P384_SHA3_384_ASN1_SIGNING,
    ECDSA_P384_SHA3_384_ASN1,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p384_sha3_384_fixed,
    &ECDSA_P384_SHA3_384_FIXED_SIGNING,
    ECDSA_P384_SHA3_384_FIXED,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p384_sha384_asn1,
    &ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p384_sha384_fixed,
    &ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p521_sha3_512_asn1,
    &ECDSA_P521_SHA3_512_ASN1_SIGNING,
    ECDSA_P521_SHA3_512_ASN1,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p521_sha3_512_fixed,
    &ECDSA_P521_SHA3_512_FIXED_SIGNING,
    ECDSA_P521_SHA3_512_FIXED,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p521_sha512_asn1,
    &ECDSA_P521_SHA512_ASN1_SIGNING,
    ECDSA_P521_SHA512_ASN1,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
ecdsa_generate_sign_verify!(
    ecdsa_p521_sha512_fixed,
    &ECDSA_P521_SHA512_FIXED_SIGNING,
    ECDSA_P521_SHA512_FIXED,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);

// These tests check the AWS-LC service indicator for combinations without named signing constants.
macro_rules! ecdsa_lookup_asn1 {
    ($($name:ident = ($curve:ident, $digest:ident);)+) => {
        $(
            ecdsa_generate_sign_verify!(
                $name,
                EcdsaSigningAlgorithm::get(
                    EcdsaCurve::$curve,
                    &digest::$digest,
                    EcdsaSignatureFormat::Asn1,
                ).unwrap(),
                EcdsaVerificationAlgorithm::get(
                    EcdsaCurve::$curve,
                    &digest::$digest,
                    EcdsaSignatureFormat::Asn1,
                ).unwrap(),
                FipsServiceStatus::Approved,
                FipsServiceStatus::Approved
            );
        )+
    };
}
ecdsa_lookup_asn1! {
    ecdsa_p256_sha224_asn1_lookup = (P256, SHA224);
    ecdsa_p256_sha384_asn1_lookup = (P256, SHA384);
    ecdsa_p256_sha512_asn1_lookup = (P256, SHA512);
    ecdsa_p384_sha224_asn1_lookup = (P384, SHA224);
    ecdsa_p384_sha256_asn1_lookup = (P384, SHA256);
    ecdsa_p384_sha512_asn1_lookup = (P384, SHA512);
}

/// Rebinding leaves the service indicator unset; signing and verification still report approval
/// for the selected algorithm, including the weaker SHA-224 pairing tested above.
#[test]
fn ecdsa_with_algorithm() {
    let rng = SystemRandom::new();

    let key_pair = assert_fips_status_indicator!(
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING),
        FipsServiceStatus::Approved
    )
    .unwrap();

    for (digest_alg, format) in [
        (&digest::SHA224, EcdsaSignatureFormat::Asn1),
        (&digest::SHA512, EcdsaSignatureFormat::Asn1),
        (&digest::SHA256, EcdsaSignatureFormat::Fixed),
    ] {
        let signing_alg = EcdsaSigningAlgorithm::get(EcdsaCurve::P256, digest_alg, format).unwrap();
        let verification_alg =
            EcdsaVerificationAlgorithm::get(EcdsaCurve::P256, digest_alg, format).unwrap();
        let rebound = assert_fips_status_indicator!(
            key_pair.with_algorithm(signing_alg),
            FipsServiceStatus::Unset
        )
        .unwrap();
        assert_eq!(rebound.algorithm(), signing_alg);

        let signature = assert_fips_status_indicator!(
            rebound.sign(&rng, TEST_MESSAGE.as_bytes()),
            FipsServiceStatus::Approved
        )
        .unwrap();

        assert_fips_status_indicator!(
            verification_alg.verify_sig(
                rebound.public_key().as_ref(),
                TEST_MESSAGE.as_bytes(),
                signature.as_ref()
            ),
            FipsServiceStatus::Approved
        )
        .unwrap();
    }
}

#[test]
fn ecdsa_with_algorithm_rejects_curve_mismatch_without_crypto() {
    let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();

    assert_fips_status_indicator!(
        key_pair.with_algorithm(&ECDSA_P384_SHA384_ASN1_SIGNING),
        FipsServiceStatus::Unset
    )
    .unwrap_err();
    assert_eq!(key_pair.algorithm(), &ECDSA_P256_SHA256_ASN1_SIGNING);
}

#[test]
fn ecdsa_sign_digest_rejects_mismatch_before_signing() {
    let original = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let message_digest = digest::digest(&digest::SHA512, TEST_MESSAGE.as_bytes());
    // Identical bytes and length ensure rejection depends on the digest algorithm identity.
    let wrong_digest =
        digest::Digest::import_less_safe(message_digest.as_ref(), &digest::SHA3_512).unwrap();

    for format in [EcdsaSignatureFormat::Asn1, EcdsaSignatureFormat::Fixed] {
        let signing_alg =
            EcdsaSigningAlgorithm::get(EcdsaCurve::P256, &digest::SHA512, format).unwrap();
        let verification_alg =
            EcdsaVerificationAlgorithm::get(EcdsaCurve::P256, &digest::SHA512, format).unwrap();

        for key_pair in [
            EcdsaKeyPair::generate(signing_alg).unwrap(),
            original.with_algorithm(signing_alg).unwrap(),
        ] {
            assert!(assert_fips_status_indicator!(
                key_pair.sign_digest(&wrong_digest),
                FipsServiceStatus::Unset
            )
            .is_err());

            let signature = assert_fips_status_indicator!(
                key_pair.sign_digest(&message_digest),
                FipsServiceStatus::NonApproved
            )
            .unwrap();
            verification_alg
                .verify_sig(
                    key_pair.public_key().as_ref(),
                    TEST_MESSAGE.as_bytes(),
                    signature.as_ref(),
                )
                .unwrap();
        }
    }
}

#[test]
fn ed25519() {
    let rng = SystemRandom::new();

    let key_document = assert_fips_status_indicator!(
        Ed25519KeyPair::generate_pkcs8(&rng),
        FipsServiceStatus::Approved
    )
    .unwrap();

    let keypair = assert_fips_status_indicator!(
        Ed25519KeyPair::from_pkcs8(key_document.as_ref()),
        FipsServiceStatus::Unset
    )
    .unwrap();

    let signature = assert_fips_status_indicator!(
        keypair.sign(TEST_MESSAGE.as_bytes()),
        FipsServiceStatus::Approved
    );

    let public_key = keypair.public_key();

    assert_fips_status_indicator!(
        EdDSAParameters.verify_sig(
            public_key.as_ref(),
            TEST_MESSAGE.as_bytes(),
            signature.as_ref()
        ),
        FipsServiceStatus::Approved
    )
    .unwrap();
}

macro_rules! ecdsa_verify {
    ($name:ident, $public_key:expr, $verify_alg:expr, $signature:expr, $expect:path) => {
        #[test]
        fn $name() {
            assert_fips_status_indicator!(
                $verify_alg.verify_sig($public_key, TEST_MESSAGE.as_bytes(), $signature),
                $expect
            )
            .unwrap();
        }
    };
}

ecdsa_verify!(
    ecdsa_p256_sha384_asn1,
    &TEST_P256_PUBLIC_BYTES[..],
    ECDSA_P256_SHA384_ASN1,
    &TEST_MESSGAE_P256_SHA384_ASN1[..],
    FipsServiceStatus::Approved
);

ecdsa_verify!(
    ecdsa_p384_sha256_asn1,
    &TEST_P384_PUBLIC_BYTES[..],
    ECDSA_P384_SHA256_ASN1,
    &TEST_MESSAGE_P384_SHA256_ASN1[..],
    FipsServiceStatus::Approved
);

macro_rules! rsa_sign_verify {
    ($name:ident, $key:expr, $sign_alg:expr, $verify_alg:expr, $sign_expect:path, $verify_expect:path) => {
        #[test]
        fn $name() {
            let rng = SystemRandom::new();

            let private_key = RsaKeyPair::from_pkcs8($key).unwrap();

            let mut signature = vec![0u8; private_key.public_modulus_len()];

            assert_fips_status_indicator!(
                private_key.sign($sign_alg, &rng, TEST_MESSAGE.as_bytes(), &mut signature,),
                $sign_expect
            )
            .unwrap();

            let public_key = private_key.public_key();

            assert_fips_status_indicator!(
                $verify_alg.verify_sig(public_key.as_ref(), TEST_MESSAGE.as_bytes(), &signature),
                $verify_expect
            )
            .unwrap();
        }
    };
}

rsa_sign_verify!(
    rsa_pkcs1_2048_sha256,
    &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA256,
    RSA_PKCS1_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_2048_sha384,
    &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA384,
    RSA_PKCS1_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_2048_sha512,
    &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA512,
    RSA_PKCS1_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_3072_sha256,
    &TEST_RSA_3072_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA256,
    RSA_PKCS1_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_3072_sha384,
    &TEST_RSA_3072_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA384,
    RSA_PKCS1_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_3072_sha512,
    &TEST_RSA_3072_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA512,
    RSA_PKCS1_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_4096_sha256,
    &TEST_RSA_4096_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA256,
    RSA_PKCS1_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_4096_sha384,
    &TEST_RSA_4096_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA384,
    RSA_PKCS1_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_4096_sha512,
    &TEST_RSA_4096_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA512,
    RSA_PKCS1_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_8192_sha256,
    &TEST_RSA_8192_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA256,
    RSA_PKCS1_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_8192_sha384,
    &TEST_RSA_8192_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA384,
    RSA_PKCS1_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pkcs1_8192_sha512,
    &TEST_RSA_8192_PRIVATE_PKCS8_DER[..],
    &RSA_PKCS1_SHA512,
    RSA_PKCS1_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_2048_sha256,
    &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA256,
    RSA_PSS_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_2048_sha384,
    &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA384,
    RSA_PSS_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_2048_sha512,
    &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA512,
    RSA_PSS_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_4096_sha256,
    &TEST_RSA_4096_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA256,
    RSA_PSS_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_4096_sha384,
    &TEST_RSA_4096_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA384,
    RSA_PSS_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_4096_sha512,
    &TEST_RSA_4096_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA512,
    RSA_PSS_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_8192_sha256,
    &TEST_RSA_8192_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA256,
    RSA_PSS_2048_8192_SHA256,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_8192_sha384,
    &TEST_RSA_8192_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA384,
    RSA_PSS_2048_8192_SHA384,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);
rsa_sign_verify!(
    rsa_pss_8192_sha512,
    &TEST_RSA_8192_PRIVATE_PKCS8_DER[..],
    &RSA_PSS_SHA512,
    RSA_PSS_2048_8192_SHA512,
    FipsServiceStatus::Approved,
    FipsServiceStatus::Approved
);

// These tests check the AWS-LC service indicator for combinations without named constants.
macro_rules! rsa_lookup_sign_verify {
    ($($name:ident = ($padding:ident, $digest:ident);)+) => {
        $(
            rsa_sign_verify!(
                $name,
                &TEST_RSA_2048_PRIVATE_PKCS8_DER[..],
                RsaSignatureEncoding::get(RsaSignaturePadding::$padding, &digest::$digest)
                    .unwrap(),
                RsaParameters::get(
                    RsaSignaturePadding::$padding,
                    &digest::$digest,
                    KeySize::Rsa2048,
                )
                .unwrap(),
                FipsServiceStatus::Approved,
                FipsServiceStatus::Approved
            );
        )+
    };
}
rsa_lookup_sign_verify! {
    rsa_pkcs1_2048_sha224_lookup = (PKCS1, SHA224);
    rsa_pkcs1_2048_sha512_256_lookup = (PKCS1, SHA512_256);
    rsa_pkcs1_2048_sha3_256_lookup = (PKCS1, SHA3_256);
    rsa_pkcs1_2048_sha3_384_lookup = (PKCS1, SHA3_384);
    rsa_pkcs1_2048_sha3_512_lookup = (PKCS1, SHA3_512);
    rsa_pss_2048_sha224_lookup = (PSS, SHA224);
    rsa_pss_2048_sha512_256_lookup = (PSS, SHA512_256);
    rsa_pss_2048_sha3_256_lookup = (PSS, SHA3_256);
    rsa_pss_2048_sha3_384_lookup = (PSS, SHA3_384);
    rsa_pss_2048_sha3_512_lookup = (PSS, SHA3_512);
}

/// A PSS salt length chosen at runtime is approved only when it equals the digest length.
#[test]
fn rsa_pss_runtime_salt_length() {
    let rng = SystemRandom::new();
    let private_key = RsaKeyPair::from_pkcs8(&TEST_RSA_2048_PRIVATE_PKCS8_DER[..]).unwrap();
    let public_key = private_key.public_key();
    let mut signature = vec![0u8; private_key.public_modulus_len()];

    for (salt_len, is_approved) in [(20, false), (32, true), (33, false)] {
        let salt_length = RsaPssSaltLength::Custom(salt_len);
        let signing = RsaSignatureEncoding::get(RsaSignaturePadding::PSS, &digest::SHA3_256)
            .unwrap()
            .copy_with_pss_salt_length(salt_length);
        let verifying = RsaParameters::get(
            RsaSignaturePadding::PSS,
            &digest::SHA3_256,
            KeySize::Rsa2048,
        )
        .unwrap()
        .copy_with_pss_salt_length(salt_length);

        if is_approved {
            assert_fips_status_indicator!(
                private_key.sign(&signing, &rng, TEST_MESSAGE.as_bytes(), &mut signature),
                FipsServiceStatus::Approved
            )
            .unwrap();
            assert_fips_status_indicator!(
                verifying.verify_sig(public_key.as_ref(), TEST_MESSAGE.as_bytes(), &signature),
                FipsServiceStatus::Approved
            )
            .unwrap();
        } else {
            assert_fips_status_indicator!(
                private_key.sign(&signing, &rng, TEST_MESSAGE.as_bytes(), &mut signature),
                FipsServiceStatus::NonApproved
            )
            .unwrap();
            assert_fips_status_indicator!(
                verifying.verify_sig(public_key.as_ref(), TEST_MESSAGE.as_bytes(), &signature),
                FipsServiceStatus::NonApproved
            )
            .unwrap();
        }
    }
}

macro_rules! rsa_verify {
    ($name:ident, $key:expr, $verify_alg:expr, $signature:expr, $verify_expect:path) => {
        #[test]
        fn $name() {
            assert_fips_status_indicator!(
                $verify_alg.verify_sig($key, TEST_MESSAGE.as_bytes(), $signature),
                $verify_expect
            )
            .unwrap();
        }
    };
}

rsa_verify!(
    rsa_pkcs1_1024_sha1,
    &TEST_RSA_1024_PUBLIC_BYTES[..],
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    &TEST_MESSAGE_RSA_PKCS1_1024_SHA1,
    FipsServiceStatus::Approved
);
rsa_verify!(
    rsa_pkcs1_1024_sha256,
    &TEST_RSA_1024_PUBLIC_BYTES[..],
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    &TEST_MESSAGE_RSA_PKCS1_1024_SHA256,
    FipsServiceStatus::Approved
);
// TODO: Ring API never had SHA384 with RSA-1024?
// rsa_verify!(
//     rsa_pkcs1_1024_sha384,
//     &TEST_RSA_1024_PUBLIC_BYTES[..],
//     RSA_PKCS1_1024_8192_SHA38,
//     &TEST_MESSAGE_RSA_PKCS1_1024_SHA384,
//     FipsServiceStatus::Approved
// );
rsa_verify!(
    rsa_pkcs1_1024_sha512,
    &TEST_RSA_1024_PUBLIC_BYTES[..],
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    &TEST_MESSAGE_RSA_PKCS1_1024_SHA512,
    FipsServiceStatus::Approved
);

mod pqdsa {
    use super::TEST_MESSAGE;
    use crate::fips::{assert_fips_status_indicator, FipsServiceStatus};
    use crate::signature::{
        KeyPair, PqdsaKeyPair, VerificationAlgorithm, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65,
        ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
    };

    macro_rules! mldsa_generate_sign_verify {
        ($name:ident, $sign_alg:expr, $verify_alg:expr) => {
            #[test]
            fn $name() {
                let keypair = assert_fips_status_indicator!(
                    PqdsaKeyPair::generate($sign_alg),
                    FipsServiceStatus::Approved
                )
                .unwrap();

                let mut signature = vec![0u8; $sign_alg.signature_len()];
                let signature_len = assert_fips_status_indicator!(
                    keypair.sign(TEST_MESSAGE.as_bytes(), &mut signature),
                    FipsServiceStatus::Approved
                )
                .unwrap();
                assert_eq!(signature_len, signature.len());

                let public_key = keypair.public_key();

                assert_fips_status_indicator!(
                    $verify_alg.verify_sig(
                        public_key.as_ref(),
                        TEST_MESSAGE.as_bytes(),
                        signature.as_ref()
                    ),
                    FipsServiceStatus::Approved
                )
                .unwrap();
            }
        };
    }

    mldsa_generate_sign_verify!(mldsa_44_generate_sign_verify, &ML_DSA_44_SIGNING, ML_DSA_44);
    mldsa_generate_sign_verify!(mldsa_65_generate_sign_verify, &ML_DSA_65_SIGNING, ML_DSA_65);
    mldsa_generate_sign_verify!(mldsa_87_generate_sign_verify, &ML_DSA_87_SIGNING, ML_DSA_87);
}
