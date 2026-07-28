// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::ml_dsa::{external_mu_len, ExternalMu, ExternalMuSigner, ExternalMuVerifier};
use aws_lc_rs::signature::{
    KeyPair, ParsedPublicKey, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm,
    UnparsedPublicKey, ED25519, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING,
    ML_DSA_87, ML_DSA_87_SIGNING,
};
use aws_lc_rs::{test, test_file};

const ALGORITHMS: &[(&PqdsaSigningAlgorithm, &PqdsaVerificationAlgorithm)] = &[
    (&ML_DSA_44_SIGNING, &ML_DSA_44),
    (&ML_DSA_65_SIGNING, &ML_DSA_65),
    (&ML_DSA_87_SIGNING, &ML_DSA_87),
];

/// Pins this crate's `mu` derivation against AWS-LC's internal one, using known-good
/// signatures produced over the message (not over `mu`). If the SHAKE256 composition,
/// the `tr` binding, or the pure-mode domain separator were wrong, `mu` would differ
/// from what AWS-LC computes internally and these verifications would fail.
macro_rules! mldsa_external_mu_sigver_test {
    ($file:literal, $verification:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let public_key = test_case.consume_bytes("PUBLIC");
            let message = test_case.consume_bytes("MESSAGE");
            let signature = test_case.consume_bytes("SIGNATURE");
            let context = test_case.consume_bytes("CONTEXT");
            let expected_result = test_case.consume_bool("RESULT");

            // These vectors are pure-mode signatures, which this crate only produces and
            // verifies with an empty context string. A vector with a context could not be
            // expected to match a `mu` derived with an empty context.
            assert!(
                context.is_empty(),
                "external-mu equivalence assumes an empty context string"
            );

            let parsed = ParsedPublicKey::new($verification, public_key.as_slice()).unwrap();
            let verifier = ExternalMuVerifier::try_from(&parsed).unwrap();
            let mu = verifier.compute_mu(message.as_ref()).unwrap();

            assert_eq!(
                verifier.verify(&mu, signature.as_ref()).is_ok(),
                expected_result
            );
            Ok(())
        });
    };
}

#[test]
fn mldsa_44_external_mu_sigver_test() {
    mldsa_external_mu_sigver_test!("data/MLDSA_44_sigVer.txt", &ML_DSA_44);
}

#[test]
fn mldsa_65_external_mu_sigver_test() {
    mldsa_external_mu_sigver_test!("data/MLDSA_65_sigVer.txt", &ML_DSA_65);
}

#[test]
fn mldsa_87_external_mu_sigver_test() {
    mldsa_external_mu_sigver_test!("data/MLDSA_87_sigVer.txt", &ML_DSA_87);
}

fn signer_and_verifier(
    signing_alg: &'static PqdsaSigningAlgorithm,
    verify_alg: &'static PqdsaVerificationAlgorithm,
) -> (PqdsaKeyPair, ExternalMuSigner, ExternalMuVerifier) {
    let key_pair = PqdsaKeyPair::generate(signing_alg).expect("keygen");
    let parsed =
        ParsedPublicKey::new(verify_alg, key_pair.public_key().as_ref()).expect("parse public key");
    let signer = ExternalMuSigner::try_from(&key_pair).expect("signer");
    let verifier = ExternalMuVerifier::try_from(&parsed).expect("verifier");
    (key_pair, signer, verifier)
}

#[test]
fn test_external_mu_round_trip() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_key_pair, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let message = b"external mu round trip";

        // Signer and verifier derive the same mu.
        let mu = signer.compute_mu(message).expect("signer compute_mu");
        let mu_verifier = verifier.compute_mu(message).expect("verifier compute_mu");
        assert_eq!(mu.as_ref(), mu_verifier.as_ref());
        assert_eq!(Some(mu.as_ref().len()), external_mu_len(verify_alg));
        assert!(mu.as_ref().len() <= ExternalMu::MAX_LEN);
        assert_eq!(mu.algorithm(), verify_alg);

        let mut signature = vec![0u8; signing_alg.signature_len()];
        let len = signer.sign(&mu, &mut signature).expect("sign");
        assert_eq!(len, signing_alg.signature_len());
        verifier.verify(&mu, &signature).expect("verify");

        // A different message yields a different mu, which the signature does not match.
        let other_mu = signer
            .compute_mu(b"a different message")
            .expect("compute_mu");
        assert_ne!(mu.as_ref(), other_mu.as_ref());
        assert!(verifier.verify(&other_mu, &signature).is_err());
    }
}

#[test]
fn test_external_mu_interchangeable_with_pure_mode() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (key_pair, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let message = b"interchangeable with pure mode";
        let mu = signer.compute_mu(message).expect("compute_mu");

        // An external-mu signature verifies as an ordinary ML-DSA signature over the message.
        let mut external_sig = vec![0u8; signing_alg.signature_len()];
        signer.sign(&mu, &mut external_sig).expect("sign");
        UnparsedPublicKey::new(verify_alg, key_pair.public_key().as_ref())
            .verify(message, &external_sig)
            .expect("external-mu signature should verify in pure mode");

        // ...and an ordinary ML-DSA signature verifies against the externally derived mu.
        let mut pure_sig = vec![0u8; signing_alg.signature_len()];
        key_pair.sign(message, &mut pure_sig).expect("pure sign");
        verifier
            .verify(&mu, &pure_sig)
            .expect("pure-mode signature should verify against external mu");
    }
}

#[test]
fn test_external_mu_binds_to_public_key() {
    // mu incorporates tr = SHAKE256(public_key), so two keys of the same parameter set
    // produce different mu values for the same message, and signatures do not cross over.
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_, signer_a, verifier_a) = signer_and_verifier(signing_alg, verify_alg);
        let (_, signer_b, verifier_b) = signer_and_verifier(signing_alg, verify_alg);
        let message = b"bound to the public key";

        let mu_a = signer_a.compute_mu(message).expect("compute_mu");
        let mu_b = signer_b.compute_mu(message).expect("compute_mu");
        assert_ne!(mu_a.as_ref(), mu_b.as_ref());

        let mut sig_a = vec![0u8; signing_alg.signature_len()];
        signer_a.sign(&mu_a, &mut sig_a).expect("sign");
        verifier_a.verify(&mu_a, &sig_a).expect("verify");
        assert!(verifier_b.verify(&mu_b, &sig_a).is_err());
        assert!(verifier_a.verify(&mu_b, &sig_a).is_err());
    }
}

#[test]
fn test_external_mu_import_less_safe() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let mu = signer.compute_mu(b"imported").expect("compute_mu");

        // Round trip through raw bytes.
        let imported = ExternalMu::import_less_safe(mu.as_ref(), verify_alg).expect("import");
        assert_eq!(imported.as_ref(), mu.as_ref());
        assert_eq!(imported.algorithm(), verify_alg);

        let mut signature = vec![0u8; signing_alg.signature_len()];
        signer.sign(&imported, &mut signature).expect("sign");
        verifier.verify(&imported, &signature).expect("verify");

        // Only exactly the algorithm's mu length is accepted.
        let expected_len = external_mu_len(verify_alg).expect("ML-DSA supports external mu");
        for bad_len in [0, 1, 32, expected_len - 1, expected_len + 1, 128] {
            assert!(
                ExternalMu::import_less_safe(&vec![0u8; bad_len], verify_alg).is_err(),
                "{bad_len} bytes should be rejected"
            );
        }

        // A tampered mu fails verification.
        let mut tampered = mu.as_ref().to_vec();
        tampered[0] ^= 0x01;
        let tampered = ExternalMu::import_less_safe(&tampered, verify_alg).expect("import");
        assert!(verifier.verify(&tampered, &signature).is_err());
    }
}

#[test]
fn test_external_mu_algorithm_mismatch_rejected() {
    // A mu computed for one parameter set is meaningless for another; both sign and verify
    // reject it rather than silently operating on the wrong representative.
    let (_, signer_44, verifier_44) = signer_and_verifier(&ML_DSA_44_SIGNING, &ML_DSA_44);
    let (_, signer_65, verifier_65) = signer_and_verifier(&ML_DSA_65_SIGNING, &ML_DSA_65);

    let mu_44 = signer_44.compute_mu(b"mismatch").expect("compute_mu");
    let mu_65 = signer_65.compute_mu(b"mismatch").expect("compute_mu");

    let mut sig = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
    assert!(signer_44.sign(&mu_65, &mut sig).is_err());
    assert!(signer_65.sign(&mu_44, &mut sig).is_err());

    let len = signer_44.sign(&mu_44, &mut sig).expect("sign");
    assert!(verifier_65.verify(&mu_44, &sig[..len]).is_err());
    assert!(verifier_44.verify(&mu_65, &sig[..len]).is_err());
}

#[test]
fn test_external_mu_signature_buffer_too_small() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_, signer, _) = signer_and_verifier(signing_alg, verify_alg);
        let mu = signer.compute_mu(b"short buffer").expect("compute_mu");

        let mut too_small = vec![0u8; signing_alg.signature_len() - 1];
        assert!(signer.sign(&mu, &mut too_small).is_err());

        // An oversized buffer is fine; only signature_len bytes are written.
        let mut oversized = vec![0u8; signing_alg.signature_len() + 64];
        let len = signer.sign(&mu, &mut oversized).expect("sign");
        assert_eq!(len, signing_alg.signature_len());
    }
}

#[test]
fn test_external_mu_verifier_accepts_x509_public_key() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let key_pair = PqdsaKeyPair::generate(signing_alg).expect("keygen");
        let signer = ExternalMuSigner::try_from(&key_pair).expect("signer");

        let raw = ParsedPublicKey::new(verify_alg, key_pair.public_key().as_ref()).expect("parse");
        let x509 = AsDer::<aws_lc_rs::encoding::PublicKeyX509Der>::as_der(&raw).expect("as_der");
        let parsed_x509 = ParsedPublicKey::new(verify_alg, x509.as_ref()).expect("parse x509");

        let verifier = ExternalMuVerifier::try_from(&parsed_x509).expect("verifier");
        let mu = signer.compute_mu(b"x509 encoded key").expect("compute_mu");
        assert_eq!(
            mu.as_ref(),
            verifier.compute_mu(b"x509 encoded key").unwrap().as_ref(),
            "mu must be derived from the raw public key regardless of input encoding"
        );

        let mut signature = vec![0u8; signing_alg.signature_len()];
        signer.sign(&mu, &mut signature).expect("sign");
        verifier.verify(&mu, &signature).expect("verify");
    }
}

#[test]
fn test_external_mu_verifier_rejects_non_ml_dsa_key() {
    let ed25519 = ParsedPublicKey::new(
        &ED25519,
        include_bytes!("data/ed25519_test_public_key.bin").as_slice(),
    )
    .expect("parse ed25519 key");
    assert!(ExternalMuVerifier::try_from(&ed25519).is_err());
}

#[test]
fn test_external_mu_accessors_and_debug() {
    let (_, signer, verifier) = signer_and_verifier(&ML_DSA_65_SIGNING, &ML_DSA_65);
    assert_eq!(signer.algorithm(), &ML_DSA_65_SIGNING);
    assert_eq!(verifier.algorithm(), &ML_DSA_65);

    // Every ML-DSA parameter set uses a 64-byte mu, which is also the current maximum.
    assert_eq!(ExternalMu::MAX_LEN, 64);
    for alg in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        assert_eq!(external_mu_len(alg), Some(64));
    }

    let mu = signer.compute_mu(b"debug").expect("compute_mu");
    let mu_debug = format!("{mu:?}");
    assert!(mu_debug.contains("ExternalMu"));
    assert!(mu_debug.contains("ML_DSA_65"));
    // The Debug output renders mu as hex.
    assert!(mu_debug.contains(&aws_lc_rs::test::to_hex(mu.as_ref())));

    assert!(format!("{signer:?}").contains("ExternalMuSigner"));
    assert!(format!("{verifier:?}").contains("ExternalMuVerifier"));

    // Copy/Clone
    let copied = mu;
    assert_eq!(copied.as_ref(), mu.as_ref());
}
