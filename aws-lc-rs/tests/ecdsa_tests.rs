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
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, KeyPair,
    ParsedPublicKey, Signature, UnparsedPublicKey, VerificationAlgorithm,
};
use aws_lc_rs::{digest, test, test_file};

/// The curves that have predefined ECDSA algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Curve {
    P256,
    P384,
    P521,
    P256K1,
}

/// The signature encodings that have predefined ECDSA algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
    Asn1,
    Fixed,
}

impl Curve {
    /// The length in bytes of each of `r` and `s` in a fixed-length signature.
    const fn scalar_len(self) -> usize {
        match self {
            Curve::P256 | Curve::P256K1 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    /// A predefined signing algorithm for this curve and encoding.
    const fn signing_base(self, encoding: Encoding) -> EcdsaSigningAlgorithm {
        match (self, encoding) {
            (Curve::P256, Encoding::Asn1) => signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            (Curve::P256, Encoding::Fixed) => signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            (Curve::P384, Encoding::Asn1) => signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            (Curve::P384, Encoding::Fixed) => signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            (Curve::P521, Encoding::Asn1) => signature::ECDSA_P521_SHA512_ASN1_SIGNING,
            (Curve::P521, Encoding::Fixed) => signature::ECDSA_P521_SHA512_FIXED_SIGNING,
            (Curve::P256K1, Encoding::Asn1) => signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
            (Curve::P256K1, Encoding::Fixed) => signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
        }
    }

    /// A predefined verification algorithm for this curve and encoding.
    const fn verification_base(self, encoding: Encoding) -> EcdsaVerificationAlgorithm {
        match (self, encoding) {
            (Curve::P256, Encoding::Asn1) => signature::ECDSA_P256_SHA256_ASN1,
            (Curve::P256, Encoding::Fixed) => signature::ECDSA_P256_SHA256_FIXED,
            (Curve::P384, Encoding::Asn1) => signature::ECDSA_P384_SHA384_ASN1,
            (Curve::P384, Encoding::Fixed) => signature::ECDSA_P384_SHA384_FIXED,
            (Curve::P521, Encoding::Asn1) => signature::ECDSA_P521_SHA512_ASN1,
            (Curve::P521, Encoding::Fixed) => signature::ECDSA_P521_SHA512_FIXED,
            (Curve::P256K1, Encoding::Asn1) => signature::ECDSA_P256K1_SHA256_ASN1,
            (Curve::P256K1, Encoding::Fixed) => signature::ECDSA_P256K1_SHA256_FIXED,
        }
    }
}

const CURVES: [Curve; 4] = [Curve::P256, Curve::P384, Curve::P521, Curve::P256K1];
const ENCODINGS: [Encoding; 2] = [Encoding::Asn1, Encoding::Fixed];
/// The digest algorithms accepted by `with_digest_algorithm`.
const DIGESTS: [&digest::Algorithm; 8] = [
    &SHA224,
    &SHA256,
    &SHA384,
    &SHA512,
    &SHA512_256,
    &SHA3_256,
    &SHA3_384,
    &SHA3_512,
];
const ALGORITHM_COUNT: usize = CURVES.len() * DIGESTS.len() * ENCODINGS.len();

/// The parameters of the algorithm at `index` in the tables below.
const fn parameters_at(index: usize) -> (Curve, &'static digest::Algorithm, Encoding) {
    (
        CURVES[index / (DIGESTS.len() * ENCODINGS.len())],
        DIGESTS[index / ENCODINGS.len() % DIGESTS.len()],
        ENCODINGS[index % ENCODINGS.len()],
    )
}

fn algorithm_index(curve: Curve, digest: &digest::Algorithm, encoding: Encoding) -> usize {
    let curve = CURVES.iter().position(|c| *c == curve).unwrap();
    let digest = DIGESTS.iter().position(|d| *d == digest).unwrap();
    let encoding = ENCODINGS.iter().position(|e| *e == encoding).unwrap();
    (curve * DIGESTS.len() + digest) * ENCODINGS.len() + encoding
}

/// A signing algorithm for every (curve, digest, encoding) combination. Each is derived at
/// compile time from a predefined algorithm for its curve and encoding, the way an application
/// declares the `const` or `static` items it needs.
static SIGNING_ALGORITHMS: [EcdsaSigningAlgorithm; ALGORITHM_COUNT] = {
    const FILLER: EcdsaSigningAlgorithm = signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let mut algorithms = [FILLER; ALGORITHM_COUNT];
    let mut index = 0;
    while index < ALGORITHM_COUNT {
        let (curve, digest, encoding) = parameters_at(index);
        algorithms[index] = match curve.signing_base(encoding).with_digest_algorithm(digest) {
            Some(algorithm) => algorithm,
            None => panic!("unsupported ECDSA digest algorithm"),
        };
        index += 1;
    }
    algorithms
};

/// The verification counterpart of [`SIGNING_ALGORITHMS`].
static VERIFICATION_ALGORITHMS: [EcdsaVerificationAlgorithm; ALGORITHM_COUNT] = {
    const FILLER: EcdsaVerificationAlgorithm = signature::ECDSA_P256_SHA256_ASN1;
    let mut algorithms = [FILLER; ALGORITHM_COUNT];
    let mut index = 0;
    while index < ALGORITHM_COUNT {
        let (curve, digest, encoding) = parameters_at(index);
        algorithms[index] = match curve
            .verification_base(encoding)
            .with_digest_algorithm(digest)
        {
            Some(algorithm) => algorithm,
            None => panic!("unsupported ECDSA digest algorithm"),
        };
        index += 1;
    }
    algorithms
};

fn signing_algorithm(
    curve: Curve,
    digest: &digest::Algorithm,
    encoding: Encoding,
) -> &'static EcdsaSigningAlgorithm {
    &SIGNING_ALGORITHMS[algorithm_index(curve, digest, encoding)]
}

fn verification_algorithm(
    curve: Curve,
    digest: &digest::Algorithm,
    encoding: Encoding,
) -> &'static EcdsaVerificationAlgorithm {
    &VERIFICATION_ALGORITHMS[algorithm_index(curve, digest, encoding)]
}

#[test]
fn ecdsa_traits() {
    test::compile_time_assert_send::<EcdsaKeyPair>();
    test::compile_time_assert_sync::<EcdsaKeyPair>();
    test::compile_time_assert_clone::<EcdsaKeyPair>();
    test::compile_time_assert_send::<Signature>();
    test::compile_time_assert_sync::<Signature>();

    test::compile_time_assert_eq::<EcdsaVerificationAlgorithm>();
    test::compile_time_assert_eq::<EcdsaSigningAlgorithm>();
}

/// `with_digest_algorithm` replaces only the digest algorithm, and rejects SHA-1.
#[test]
fn ecdsa_with_digest_algorithm() {
    // The curve and encoding are those of the algorithm it is called on.
    assert_eq!(
        signature::ECDSA_P521_SHA512_FIXED_SIGNING.with_digest_algorithm(&SHA384),
        Some(signature::ECDSA_P521_SHA384_FIXED_SIGNING)
    );
    assert_eq!(
        signature::ECDSA_P521_SHA512_FIXED.with_digest_algorithm(&SHA384),
        Some(signature::ECDSA_P521_SHA384_FIXED)
    );

    // Selecting the digest the algorithm already has changes nothing.
    assert_eq!(
        signature::ECDSA_P256_SHA256_ASN1_SIGNING.with_digest_algorithm(&SHA256),
        Some(signature::ECDSA_P256_SHA256_ASN1_SIGNING)
    );

    // A SHA-1 verification constant can be the starting point...
    assert_eq!(
        signature::ECDSA_P256_SHA1_ASN1.with_digest_algorithm(&SHA256),
        Some(signature::ECDSA_P256_SHA256_ASN1)
    );
    // ...but SHA-1 cannot be selected, for signing or for verification.
    for curve in CURVES {
        for encoding in ENCODINGS {
            assert_eq!(
                curve
                    .signing_base(encoding)
                    .with_digest_algorithm(&SHA1_FOR_LEGACY_USE_ONLY),
                None,
                "{curve:?}/{encoding:?}"
            );
            assert_eq!(
                curve
                    .verification_base(encoding)
                    .with_digest_algorithm(&SHA1_FOR_LEGACY_USE_ONLY),
                None,
                "{curve:?}/{encoding:?}"
            );
        }
    }
}

/// `with_digest_algorithm` leaves the algorithm it is called on (the template) usable and
/// unchanged, so one template can produce any number of derived algorithms.
///
/// The repeated calls on a single binding are the regression guard: neither algorithm type is
/// `Copy`, so this stops compiling if the receiver reverts from `&self` to by-value `self`.
#[test]
fn ecdsa_with_digest_algorithm_preserves_templates() {
    for curve in CURVES {
        for encoding in ENCODINGS {
            let signing = curve.signing_base(encoding);
            let verifying = curve.verification_base(encoding);
            for digest in DIGESTS {
                assert_eq!(
                    &signing.with_digest_algorithm(digest).unwrap(),
                    signing_algorithm(curve, digest, encoding)
                );
                assert_eq!(
                    &verifying.with_digest_algorithm(digest).unwrap(),
                    verification_algorithm(curve, digest, encoding)
                );
            }
            assert!(signing
                .with_digest_algorithm(&SHA1_FOR_LEGACY_USE_ONLY)
                .is_none());
            assert!(verifying
                .with_digest_algorithm(&SHA1_FOR_LEGACY_USE_ONLY)
                .is_none());
            assert_eq!(signing, curve.signing_base(encoding));
            assert_eq!(verifying, curve.verification_base(encoding));
        }
    }
}

#[test]
fn ecdsa_with_digest_algorithm_borrows_static_templates() {
    static SIGNING_TEMPLATE: EcdsaSigningAlgorithm = signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    static VERIFICATION_TEMPLATE: EcdsaVerificationAlgorithm = signature::ECDSA_P256_SHA256_ASN1;
    static SIGNING: EcdsaSigningAlgorithm = match SIGNING_TEMPLATE.with_digest_algorithm(&SHA512) {
        Some(algorithm) => algorithm,
        None => panic!("unsupported ECDSA digest algorithm"),
    };
    static VERIFYING: EcdsaVerificationAlgorithm =
        match VERIFICATION_TEMPLATE.with_digest_algorithm(&SHA512) {
            Some(algorithm) => algorithm,
            None => panic!("unsupported ECDSA digest algorithm"),
        };

    let key_pair = EcdsaKeyPair::generate(&SIGNING).unwrap();
    let original_algorithm = key_pair.algorithm();
    assert_eq!(
        original_algorithm.with_digest_algorithm(&SHA256).unwrap(),
        SIGNING_TEMPLATE
    );
    assert_eq!(
        VERIFYING.with_digest_algorithm(&SHA256).unwrap(),
        VERIFICATION_TEMPLATE
    );
    assert_eq!(key_pair.algorithm(), &SIGNING);
    assert_eq!(SIGNING_TEMPLATE, signature::ECDSA_P256_SHA256_ASN1_SIGNING);
    assert_eq!(VERIFICATION_TEMPLATE, signature::ECDSA_P256_SHA256_ASN1);

    let signature = key_pair
        .sign(&SystemRandom::new(), b"borrowed algorithm")
        .unwrap();
    UnparsedPublicKey::new(&VERIFYING, key_pair.public_key())
        .verify(b"borrowed algorithm", signature.as_ref())
        .unwrap();
}

#[cfg(all(not(feature = "fips"), feature = "unstable"))]
#[test]
fn ecdsa_with_digest_algorithm_rejects_keccak() {
    use aws_lc_rs::unstable::digest::KECCAK256;

    for curve in CURVES {
        for encoding in ENCODINGS {
            assert_eq!(
                curve
                    .signing_base(encoding)
                    .with_digest_algorithm(&KECCAK256),
                None
            );
            assert_eq!(
                curve
                    .verification_base(encoding)
                    .with_digest_algorithm(&KECCAK256),
                None
            );
        }
    }
}

/// Algorithms derived with `with_digest_algorithm` equal every predefined constant that has the
/// same curve, digest, and encoding.
#[test]
fn ecdsa_with_digest_algorithm_matches_constants() {
    macro_rules! assert_matches_constant {
        ($derived:ident: $($constant:ident = ($curve:ident, $digest:ident, $encoding:ident);)+) => {
            $(
                assert_eq!(
                    *$derived(Curve::$curve, &$digest, Encoding::$encoding),
                    signature::$constant,
                    stringify!($constant)
                );
            )+
        };
    }

    // Every predefined verification algorithm other than the SHA-1 ones.
    assert_matches_constant! { verification_algorithm:
        ECDSA_P256_SHA256_FIXED = (P256, SHA256, Fixed);
        ECDSA_P384_SHA384_FIXED = (P384, SHA384, Fixed);
        ECDSA_P384_SHA3_384_FIXED = (P384, SHA3_384, Fixed);
        ECDSA_P521_SHA224_FIXED = (P521, SHA224, Fixed);
        ECDSA_P521_SHA256_FIXED = (P521, SHA256, Fixed);
        ECDSA_P521_SHA384_FIXED = (P521, SHA384, Fixed);
        ECDSA_P521_SHA512_FIXED = (P521, SHA512, Fixed);
        ECDSA_P521_SHA3_512_FIXED = (P521, SHA3_512, Fixed);
        ECDSA_P256K1_SHA256_FIXED = (P256K1, SHA256, Fixed);
        ECDSA_P256K1_SHA3_256_FIXED = (P256K1, SHA3_256, Fixed);
        ECDSA_P256_SHA256_ASN1 = (P256, SHA256, Asn1);
        ECDSA_P256_SHA384_ASN1 = (P256, SHA384, Asn1);
        ECDSA_P256_SHA512_ASN1 = (P256, SHA512, Asn1);
        ECDSA_P384_SHA256_ASN1 = (P384, SHA256, Asn1);
        ECDSA_P384_SHA384_ASN1 = (P384, SHA384, Asn1);
        ECDSA_P384_SHA512_ASN1 = (P384, SHA512, Asn1);
        ECDSA_P384_SHA3_384_ASN1 = (P384, SHA3_384, Asn1);
        ECDSA_P521_SHA224_ASN1 = (P521, SHA224, Asn1);
        ECDSA_P521_SHA256_ASN1 = (P521, SHA256, Asn1);
        ECDSA_P521_SHA384_ASN1 = (P521, SHA384, Asn1);
        ECDSA_P521_SHA512_ASN1 = (P521, SHA512, Asn1);
        ECDSA_P521_SHA3_512_ASN1 = (P521, SHA3_512, Asn1);
        ECDSA_P256K1_SHA256_ASN1 = (P256K1, SHA256, Asn1);
        ECDSA_P256K1_SHA3_256_ASN1 = (P256K1, SHA3_256, Asn1);
    }

    // Every predefined signing algorithm.
    assert_matches_constant! { signing_algorithm:
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

/// Every (curve, digest, encoding) combination can generate a key, sign, and verify, including
/// combinations with no predefined constant, and its signatures are specific to its digest.
#[test]
fn ecdsa_with_digest_algorithm_matrix() {
    const MESSAGE: &[u8] = b"ECDSA with_digest_algorithm";
    let rng = SystemRandom::new();

    for curve in CURVES {
        for digest_alg in DIGESTS {
            let message_digest = digest::digest(digest_alg, MESSAGE);
            for encoding in ENCODINGS {
                let signing = signing_algorithm(curve, digest_alg, encoding);
                let verifying = verification_algorithm(curve, digest_alg, encoding);
                // A signing algorithm dereferences to its verification counterpart.
                let dereferenced: &EcdsaVerificationAlgorithm = signing;
                assert_eq!(dereferenced, verifying);

                let key_pair = EcdsaKeyPair::generate(signing).unwrap();
                assert_eq!(key_pair.algorithm(), signing);
                let public_key = key_pair.public_key().as_ref();
                let parsed_public_key = ParsedPublicKey::new(verifying, public_key)
                    .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                for signature in [
                    key_pair.sign(&rng, MESSAGE),
                    key_pair.sign_digest(&message_digest),
                ] {
                    let signature = signature.unwrap_or_else(|err| panic!("{signing:?}: {err:?}"));
                    if encoding == Encoding::Fixed {
                        assert_eq!(signature.as_ref().len(), 2 * curve.scalar_len());
                    }
                    UnparsedPublicKey::new(verifying, public_key)
                        .verify(MESSAGE, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                    parsed_public_key
                        .verify_sig(MESSAGE, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                    parsed_public_key
                        .verify_digest_sig(&message_digest, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                    verifying
                        .verify_digest_sig(public_key, &message_digest, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));

                    // The signature does not verify under any other digest algorithm, so each
                    // derived algorithm really does use the digest it was given.
                    for other_digest in DIGESTS.into_iter().filter(|other| *other != digest_alg) {
                        let other = verification_algorithm(curve, other_digest, encoding);
                        assert!(
                            other
                                .verify_sig(public_key, MESSAGE, signature.as_ref())
                                .is_err(),
                            "{signing:?} verified by {other:?}"
                        );
                    }
                }

                // Keep the bytes unchanged so rejection depends on algorithm identity, not
                // a different hash value. Include every other digest of the same length.
                for other_digest in DIGESTS.into_iter().filter(|other| {
                    *other != digest_alg && other.output_len() == digest_alg.output_len()
                }) {
                    let wrong_digest =
                        Digest::import_less_safe(message_digest.as_ref(), other_digest).unwrap();
                    assert!(key_pair.sign_digest(&wrong_digest).is_err());
                    let signature = key_pair.sign_digest(&message_digest).unwrap();
                    assert!(verifying
                        .verify_digest_sig(public_key, &wrong_digest, signature.as_ref())
                        .is_err());
                    assert!(UnparsedPublicKey::new(verifying, public_key)
                        .verify_digest(&wrong_digest, signature.as_ref())
                        .is_err());
                    assert!(parsed_public_key
                        .verify_digest_sig(&wrong_digest, signature.as_ref())
                        .is_err());
                }
            }
        }
    }
}

/// `VerificationAlgorithm` methods take `&self`, not `&'static self`, so callers can verify with
/// an algorithm that is not a `const` or `static` item. Requiring `'static` would be a breaking
/// change.
#[test]
fn ecdsa_verify_with_non_static_algorithm() {
    const MESSAGE: &[u8] = b"non-static verification algorithm";
    let key_pair =
        EcdsaKeyPair::generate(signing_algorithm(Curve::P256, &SHA512, Encoding::Asn1)).unwrap();
    let public_key = key_pair.public_key().as_ref();
    let signature = key_pair.sign(&SystemRandom::new(), MESSAGE).unwrap();

    let verifying = signature::ECDSA_P256_SHA256_ASN1
        .with_digest_algorithm(&SHA512)
        .unwrap();
    verifying
        .verify_sig(public_key, MESSAGE, signature.as_ref())
        .unwrap();
    verifying
        .verify_digest_sig(
            public_key,
            &digest::digest(&SHA512, MESSAGE),
            signature.as_ref(),
        )
        .unwrap();
}

/// The predefined ASN.1 signing algorithm for a curve, used as the algorithm a key pair is
/// initially bound to before `with_algorithm` rebinds it.
fn default_asn1_signing_algorithm(curve: Curve) -> &'static EcdsaSigningAlgorithm {
    match curve {
        Curve::P256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        Curve::P384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        Curve::P521 => &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        Curve::P256K1 => &signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
    }
}

/// `with_algorithm` rebinds a key pair to any algorithm for its curve without changing the key
/// material, and both handles remain independently usable.
#[test]
fn ecdsa_key_pair_with_algorithm() {
    const MESSAGE: &[u8] = b"EcdsaKeyPair::with_algorithm";
    let rng = SystemRandom::new();

    for curve in CURVES {
        let original_alg = default_asn1_signing_algorithm(curve);
        let original = EcdsaKeyPair::generate(original_alg).unwrap();
        assert_eq!(
            original.with_algorithm(original_alg).unwrap().algorithm(),
            original_alg
        );
        let public_key = original.public_key().as_ref().to_vec();
        let pkcs8 = original.to_pkcs8v1().unwrap();

        for digest_alg in DIGESTS {
            let message_digest = digest::digest(digest_alg, MESSAGE);
            for encoding in ENCODINGS {
                let alg = signing_algorithm(curve, digest_alg, encoding);
                let verifying = verification_algorithm(curve, digest_alg, encoding);
                let rebound = original.with_algorithm(alg).unwrap();
                assert_eq!(rebound.algorithm(), alg);
                assert_eq!(rebound.public_key().as_ref(), public_key.as_slice());
                assert_eq!(rebound.to_pkcs8v1().unwrap().as_ref(), pkcs8.as_ref());
                assert_eq!(format!("{rebound:?}"), format!("{original:?}"));

                for signature in [
                    rebound.sign(&rng, MESSAGE),
                    rebound.sign_digest(&message_digest),
                ] {
                    let signature = signature.unwrap_or_else(|err| panic!("{alg:?}: {err:?}"));
                    verifying
                        .verify_sig(&public_key, MESSAGE, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                    verifying
                        .verify_digest_sig(&public_key, &message_digest, signature.as_ref())
                        .unwrap_or_else(|err| panic!("{verifying:?}: {err:?}"));
                    // The signature is specific to the rebound algorithm.
                    if alg != original_alg {
                        assert!(original_alg
                            .verify_sig(&public_key, MESSAGE, signature.as_ref())
                            .is_err());
                    }
                }

                // The original handle is unaffected.
                assert_eq!(original.algorithm(), original_alg);
                let signature = original.sign(&rng, MESSAGE).unwrap();
                original_alg
                    .verify_sig(&public_key, MESSAGE, signature.as_ref())
                    .unwrap();
            }
        }
    }
}

/// A rebound key pair outlives the key pair it was created from.
#[test]
fn ecdsa_key_pair_with_algorithm_outlives_source() {
    const MESSAGE: &[u8] = b"EcdsaKeyPair::with_algorithm lifetimes";
    let rng = SystemRandom::new();
    let message_digest = digest::digest(&SHA512_256, MESSAGE);

    for encoding in ENCODINGS {
        let signing = signing_algorithm(Curve::P384, &SHA512_256, encoding);
        let verifying = verification_algorithm(Curve::P384, &SHA512_256, encoding);
        let key_pair = {
            let original =
                EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_ASN1_SIGNING).unwrap();
            original.with_algorithm(signing).unwrap()
        };
        assert_eq!(key_pair.algorithm(), signing);

        let signature = key_pair.sign(&rng, MESSAGE).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        drop(key_pair);

        let unparsed = UnparsedPublicKey::new(verifying, &public_key);
        unparsed.verify(MESSAGE, signature.as_ref()).unwrap();
        unparsed
            .verify_digest(&message_digest, signature.as_ref())
            .unwrap();
    }
}

#[test]
fn ecdsa_key_pair_with_algorithm_rejects_curve_mismatch() {
    for curve in CURVES {
        let key_pair = EcdsaKeyPair::generate(default_asn1_signing_algorithm(curve)).unwrap();
        // Includes the same-width P-256 / secp256k1 pair.
        for wrong_curve in CURVES.into_iter().filter(|other| *other != curve) {
            for encoding in ENCODINGS {
                let alg = signing_algorithm(wrong_curve, &SHA256, encoding);
                let err = key_pair.with_algorithm(alg).unwrap_err();
                assert_eq!(
                    err.description_(),
                    "WrongAlgorithm",
                    "{curve:?}/{wrong_curve:?}"
                );
            }
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

// Signing uses a randomized nonce, so its output cannot be compared with the reference
// signature. Verify both independently supplied reference signatures and generated signatures.
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
        let known_signature = test_case.consume_bytes("Sig");

        let (curve, digest_alg) = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA224") => (Curve::P256, &SHA224),
            ("P-256", "SHA256") => (Curve::P256, &SHA256),
            ("P-256", "SHA384") => (Curve::P256, &SHA384),
            ("P-256", "SHA512") => (Curve::P256, &SHA512),
            ("P-384", "SHA224") => (Curve::P384, &SHA224),
            ("P-384", "SHA256") => (Curve::P384, &SHA256),
            ("P-384", "SHA384") => (Curve::P384, &SHA384),
            ("P-384", "SHA512") => (Curve::P384, &SHA512),
            ("P-384", "SHA3-384") => (Curve::P384, &SHA3_384),
            ("P-521", "SHA224") => (Curve::P521, &SHA224),
            ("P-521", "SHA256") => (Curve::P521, &SHA256),
            ("P-521", "SHA384") => (Curve::P521, &SHA384),
            ("P-521", "SHA512") => (Curve::P521, &SHA512),
            ("P-521", "SHA3-512") => (Curve::P521, &SHA3_512),
            ("secp256k1", "SHA256") => (Curve::P256K1, &SHA256),
            ("secp256k1", "SHA3-256") => (Curve::P256K1, &SHA3_256),
            _ => panic!("Unsupported curve+digest: {curve_name}+{digest_name}"),
        };
        let signing_alg = signing_algorithm(curve, digest_alg, Encoding::Asn1);
        let verification_alg = verification_algorithm(curve, digest_alg, Encoding::Asn1);

        let private_key =
            EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &d, &q).unwrap();

        let signature = private_key.sign(&rng, &msg).unwrap();

        let digest = digest::digest(digest_alg, &msg);
        let digest_signature = private_key.sign_digest(&digest).unwrap();

        let public_key = UnparsedPublicKey::new(verification_alg, q.as_slice());
        let parsed_public_key = public_key.parse().unwrap();
        for signature in [
            known_signature.as_slice(),
            signature.as_ref(),
            digest_signature.as_ref(),
        ] {
            public_key.verify(&msg, signature).unwrap();
            public_key.verify_digest(&digest, signature).unwrap();
            parsed_public_key.verify_sig(&msg, signature).unwrap();
            parsed_public_key
                .verify_digest_sig(&digest, signature)
                .unwrap();
        }

        // The same key parsed under the curve's default algorithm and rebound.
        let rebound = EcdsaKeyPair::from_private_key_and_public_key(
            default_asn1_signing_algorithm(curve),
            &d,
            &q,
        )
        .unwrap()
        .with_algorithm(signing_alg)
        .unwrap();
        assert_eq!(rebound.public_key().as_ref(), q.as_slice());
        let signature = rebound.sign(&rng, &msg).unwrap();
        public_key.verify(&msg, signature.as_ref()).unwrap();
        let digest_signature = rebound.sign_digest(&digest).unwrap();
        public_key
            .verify_digest(&digest, digest_signature.as_ref())
            .unwrap();

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
