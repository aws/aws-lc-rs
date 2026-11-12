// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(debug_assertions)]

use crate::digest;
use crate::fips::{assert_fips_status_indicator, FipsServiceStatus};
use crate::rand::SystemRandom;
use crate::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, Ed25519KeyPair,
    EdDSAParameters, KeyPair, RsaKeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P384_SHA3_384_ASN1, ECDSA_P384_SHA3_384_ASN1_SIGNING, ECDSA_P384_SHA3_384_FIXED,
    ECDSA_P384_SHA3_384_FIXED_SIGNING, ECDSA_P521_SHA3_512_ASN1, ECDSA_P521_SHA3_512_ASN1_SIGNING,
    ECDSA_P521_SHA3_512_FIXED, ECDSA_P521_SHA3_512_FIXED_SIGNING, ECDSA_P521_SHA512_ASN1,
    ECDSA_P521_SHA512_ASN1_SIGNING, ECDSA_P521_SHA512_FIXED, ECDSA_P521_SHA512_FIXED_SIGNING,
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

const fn signing_with_digest(
    base: &EcdsaSigningAlgorithm,
    digest: &'static digest::Algorithm,
) -> EcdsaSigningAlgorithm {
    match base.with_digest_algorithm(digest) {
        Some(algorithm) => algorithm,
        None => panic!("unsupported ECDSA digest algorithm"),
    }
}

const fn verification_with_digest(
    base: &EcdsaVerificationAlgorithm,
    digest: &'static digest::Algorithm,
) -> EcdsaVerificationAlgorithm {
    match base.with_digest_algorithm(digest) {
        Some(algorithm) => algorithm,
        None => panic!("unsupported ECDSA digest algorithm"),
    }
}

// (curve, digest) pairs with no predefined signing constant, declared with
// `with_digest_algorithm`.
macro_rules! ecdsa_with_digest_asn1 {
    ($($name:ident = ($signing_base:ident, $verification_base:ident, $digest:ident);)+) => {
        $(
            ecdsa_generate_sign_verify!(
                $name,
                {
                    static SIGNING: EcdsaSigningAlgorithm =
                        signing_with_digest(&$signing_base, &digest::$digest);
                    &SIGNING
                },
                {
                    static VERIFICATION: EcdsaVerificationAlgorithm =
                        verification_with_digest(&$verification_base, &digest::$digest);
                    &VERIFICATION
                },
                FipsServiceStatus::Approved,
                FipsServiceStatus::Approved
            );
        )+
    };
}
// The digest is at least as strong as the curve.
ecdsa_with_digest_asn1! {
    ecdsa_p256_sha384_asn1_with_digest =
        (ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_ASN1, SHA384);
    ecdsa_p256_sha512_asn1_with_digest =
        (ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_ASN1, SHA512);
    ecdsa_p384_sha512_asn1_with_digest =
        (ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, SHA512);
    ecdsa_p256_sha512_256_asn1_with_digest =
        (ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_ASN1, SHA512_256);
    ecdsa_p256_sha3_256_asn1_with_digest =
        (ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_ASN1, SHA3_256);
}

// The digest is weaker than the curve. FIPS 186-5 says such a digest "shall not be used"
// (section 6.1.1) and "ordinarily should not be used" (section 6.4). AWS-LC's service indicator
// evaluates the curve and the digest independently and does not compare their strengths. These
// tests record the indicator's current result, not compliance; expect them to change if the
// indicator starts comparing strengths.
ecdsa_with_digest_asn1! {
    ecdsa_p256_sha224_asn1_with_digest =
        (ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_ASN1, SHA224);
    ecdsa_p384_sha224_asn1_with_digest =
        (ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, SHA224);
    ecdsa_p384_sha256_asn1_with_digest =
        (ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, SHA256);
}

/// A key pair rebound with `with_algorithm` signs and verifies with the same approval status as
/// one constructed directly for the target algorithm.
#[test]
fn ecdsa_with_algorithm() {
    static P256_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm =
        signing_with_digest(&ECDSA_P256_SHA256_ASN1_SIGNING, &digest::SHA384);
    static P256_SHA384_ASN1: EcdsaVerificationAlgorithm =
        verification_with_digest(&ECDSA_P256_SHA256_ASN1, &digest::SHA384);
    static P256_SHA512_ASN1_SIGNING: EcdsaSigningAlgorithm =
        signing_with_digest(&ECDSA_P256_SHA256_ASN1_SIGNING, &digest::SHA512);
    static P256_SHA512_ASN1: EcdsaVerificationAlgorithm =
        verification_with_digest(&ECDSA_P256_SHA256_ASN1, &digest::SHA512);

    let rng = SystemRandom::new();

    let key_pair = assert_fips_status_indicator!(
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING),
        FipsServiceStatus::Approved
    )
    .unwrap();

    let algorithms: [(&'static EcdsaSigningAlgorithm, &EcdsaVerificationAlgorithm); 3] = [
        (&P256_SHA384_ASN1_SIGNING, &P256_SHA384_ASN1),
        (&P256_SHA512_ASN1_SIGNING, &P256_SHA512_ASN1),
        (&ECDSA_P256_SHA256_FIXED_SIGNING, &ECDSA_P256_SHA256_FIXED),
    ];
    for (signing_alg, verification_alg) in algorithms {
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
    static P256_SHA512_ASN1_SIGNING: EcdsaSigningAlgorithm =
        signing_with_digest(&ECDSA_P256_SHA256_ASN1_SIGNING, &digest::SHA512);
    static P256_SHA512_FIXED_SIGNING: EcdsaSigningAlgorithm =
        signing_with_digest(&ECDSA_P256_SHA256_FIXED_SIGNING, &digest::SHA512);

    let original = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let message_digest = digest::digest(&digest::SHA512, TEST_MESSAGE.as_bytes());
    // Identical bytes and length ensure rejection depends on the algorithm, not the digest value.
    let wrong_digest =
        digest::Digest::import_less_safe(message_digest.as_ref(), &digest::SHA3_512).unwrap();

    for algorithm in [&P256_SHA512_ASN1_SIGNING, &P256_SHA512_FIXED_SIGNING] {
        for key_pair in [
            EcdsaKeyPair::generate(algorithm).unwrap(),
            original.with_algorithm(algorithm).unwrap(),
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
            algorithm
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
