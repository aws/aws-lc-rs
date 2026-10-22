// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::ml_dsa::{ExternalMu, ExternalMuSigner, ExternalMuVerifier, MuContext, MU_LEN};
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
            // expected to match a `mu` derived with an empty context, so fail loudly rather
            // than silently skipping if one is ever added to the file.
            assert!(
                context.is_empty(),
                "external-mu equivalence assumes an empty context string"
            );

            let parsed = ParsedPublicKey::new($verification, public_key.as_slice()).unwrap();
            let verifier = ExternalMuVerifier::new(&parsed).unwrap();
            let mu = verifier.compute_mu(message.as_ref()).unwrap();

            assert_eq!(
                verifier.verify(&mu, signature.as_ref()).is_ok(),
                expected_result
            );

            // The streaming derivation must agree with the one-shot one.
            let mut context = MuContext::new(&parsed).unwrap();
            context.update(message.as_ref()).unwrap();
            assert_eq!(context.finish().unwrap().as_ref(), mu.as_ref());
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
    let signer = ExternalMuSigner::new(&key_pair).expect("signer");
    let verifier = ExternalMuVerifier::new(&parsed).expect("verifier");
    (key_pair, signer, verifier)
}

#[test]
fn test_external_mu_round_trip() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_key_pair, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let message = b"external mu round trip";

        // Streaming and one-shot derivations agree, and mu has the documented shape.
        let mut context = verifier.mu_context().expect("context");
        context.update(message).expect("update");
        let mu = context.finish().expect("finish");
        let mu_one_shot = verifier.compute_mu(message).expect("verifier compute_mu");
        assert_eq!(mu.as_ref(), mu_one_shot.as_ref());
        assert_eq!(mu.as_ref().len(), MU_LEN);
        assert_eq!(mu.algorithm(), verify_alg);

        let mut signature = vec![0u8; signing_alg.signature_len()];
        let len = signer.sign(&mu, &mut signature).expect("sign");
        assert_eq!(len, signing_alg.signature_len());
        verifier.verify(&mu, &signature).expect("verify");

        // A different message yields a different mu, which the signature does not match.
        let other_mu = verifier
            .compute_mu(b"a different message")
            .expect("compute_mu");
        assert_ne!(mu.as_ref(), other_mu.as_ref());
        assert!(verifier.verify(&other_mu, &signature).is_err());
    }
}

#[test]
fn test_external_mu_streaming_matches_one_shot() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (key_pair, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let parsed = ParsedPublicKey::new(verify_alg, key_pair.public_key().as_ref()).unwrap();
        let message: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let expected = verifier.compute_mu(&message).expect("one-shot");

        // Chunked in a variety of ways, from both entry points.
        for chunk_size in [1, 7, 64, 333, 1000, 4096] {
            for mut context in [
                MuContext::new(&parsed).expect("from public key"),
                verifier.mu_context().expect("from verifier"),
            ] {
                for chunk in message.chunks(chunk_size) {
                    context.update(chunk).expect("update");
                }
                assert_eq!(
                    context.finish().expect("finish").as_ref(),
                    expected.as_ref(),
                    "chunk size {chunk_size}"
                );
            }
        }

        // Zero updates is the empty message, and matches the one-shot over an empty slice.
        let context = MuContext::new(&parsed).expect("context");
        assert_eq!(context.algorithm(), verify_alg);
        assert_eq!(
            context.finish().expect("finish").as_ref(),
            verifier.compute_mu(b"").expect("empty one-shot").as_ref()
        );

        // A streamed mu is a fully-fledged mu: it signs and verifies.
        let mut context = MuContext::new(&parsed).expect("context");
        context.update(&message).expect("update");
        let mu = context.finish().expect("finish");
        let mut signature = vec![0u8; signing_alg.signature_len()];
        signer.sign(&mu, &mut signature).expect("sign");
        verifier.verify(&mu, &signature).expect("verify");
        UnparsedPublicKey::new(verify_alg, key_pair.public_key().as_ref())
            .verify(&message, &signature)
            .expect("streamed-mu signature should verify in pure mode");
    }
}

#[test]
fn test_mu_context_clone_forks_state() {
    let (_key_pair, _, verifier) = signer_and_verifier(&ML_DSA_44_SIGNING, &ML_DSA_44);
    let mut context = verifier.mu_context().expect("context");
    context.update(b"common prefix").expect("update");

    let mut fork = context.clone();
    context.update(b"-a").expect("update");
    fork.update(b"-b").expect("update");

    let mu_a = context.finish().expect("finish");
    let mu_b = fork.finish().expect("finish");
    assert_ne!(mu_a.as_ref(), mu_b.as_ref());
    assert_eq!(
        mu_a.as_ref(),
        verifier.compute_mu(b"common prefix-a").unwrap().as_ref()
    );
    assert_eq!(
        mu_b.as_ref(),
        verifier.compute_mu(b"common prefix-b").unwrap().as_ref()
    );
}

#[test]
fn test_external_mu_interchangeable_with_pure_mode() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (key_pair, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let message = b"interchangeable with pure mode";
        let mu = verifier.compute_mu(message).expect("compute_mu");

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
        let (_, _, verifier_b) = signer_and_verifier(signing_alg, verify_alg);
        let message = b"bound to the public key";

        let mu_a = verifier_a.compute_mu(message).expect("compute_mu");
        let mu_b = verifier_b.compute_mu(message).expect("compute_mu");
        assert_ne!(mu_a.as_ref(), mu_b.as_ref());

        let mut sig_a = vec![0u8; signing_alg.signature_len()];
        signer_a.sign(&mu_a, &mut sig_a).expect("sign");
        verifier_a.verify(&mu_a, &sig_a).expect("verify");
        assert!(verifier_b.verify(&mu_b, &sig_a).is_err());

        // A mu derived under a different key of the same parameter set is caught up front,
        // rather than silently producing a signature that verifies under no key at all.
        assert!(signer_a.sign(&mu_b, &mut sig_a).is_err());
        assert!(verifier_a.verify(&mu_b, &sig_a).is_err());
    }
}

#[test]
fn test_external_mu_import_less_safe() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let mu = verifier.compute_mu(b"imported").expect("compute_mu");

        // Round trip through raw bytes.
        let imported = ExternalMu::import_less_safe(mu.as_ref(), verify_alg).expect("import");
        assert_eq!(imported.as_ref(), mu.as_ref());
        assert_eq!(imported.algorithm(), verify_alg);

        let mut signature = vec![0u8; signing_alg.signature_len()];
        signer.sign(&imported, &mut signature).expect("sign");
        verifier.verify(&imported, &signature).expect("verify");

        // Only exactly MU_LEN bytes are accepted.
        for bad_len in [0, 1, 32, MU_LEN - 1, MU_LEN + 1, 128] {
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
fn test_imported_mu_is_not_key_bound() {
    // Importing discards the provenance that lets sign/verify reject a mu belonging to
    // another key of the same parameter set. That is the "less safe" in the name.
    //
    // Note carefully what the resulting signature is and is not. External-mu verification
    // takes mu on faith -- it does not re-derive it -- so the verifier for key A accepts the
    // signature against the mismatched mu. But it is not a valid signature over the original
    // message under either key, so nothing outside this one pairing accepts it. That is
    // exactly the blind-signing hazard `import_less_safe` warns about, and the reason a
    // derived mu carries its key binding.
    let message = b"cross key";
    let key_pair_a = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).expect("keygen");
    let key_pair_b = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).expect("keygen");
    let parsed_a =
        ParsedPublicKey::new(&ML_DSA_44, key_pair_a.public_key().as_ref()).expect("parse");
    let signer_a = ExternalMuSigner::new(&key_pair_a).expect("signer");
    let verifier_a = ExternalMuVerifier::new(&parsed_a).expect("verifier");
    let parsed_b =
        ParsedPublicKey::new(&ML_DSA_44, key_pair_b.public_key().as_ref()).expect("parse");
    let mut context_b = MuContext::new(&parsed_b).expect("context");
    context_b.update(message).expect("update");
    let mu_b = context_b.finish().expect("finish");

    let mut sig = vec![0u8; ML_DSA_44_SIGNING.signature_len()];
    assert!(
        signer_a.sign(&mu_b, &mut sig).is_err(),
        "a derived mu is key-bound"
    );

    let imported = ExternalMu::import_less_safe(mu_b.as_ref(), &ML_DSA_44).expect("import");
    let len = signer_a
        .sign(&imported, &mut sig)
        .expect("an imported mu is not key-bound");
    let sig = &sig[..len];

    // External-mu verification does not re-derive mu, so this pairing is accepted.
    verifier_a
        .verify(&imported, sig)
        .expect("mu taken on faith");

    // It is not a signature over the message under either key.
    for public_key in [key_pair_a.public_key(), key_pair_b.public_key()] {
        assert!(
            UnparsedPublicKey::new(&ML_DSA_44, public_key.as_ref())
                .verify(message, sig)
                .is_err(),
            "not a valid signature over the message"
        );
    }
    // Nor against the mu that key A would actually derive for that message.
    assert!(verifier_a
        .verify(&verifier_a.compute_mu(message).unwrap(), sig)
        .is_err());
}

#[test]
fn test_external_mu_algorithm_mismatch_rejected() {
    // A mu computed for one parameter set is meaningless for another; both sign and verify
    // reject it rather than silently operating on the wrong representative.
    let (_, signer_44, verifier_44) = signer_and_verifier(&ML_DSA_44_SIGNING, &ML_DSA_44);
    let (_, signer_65, verifier_65) = signer_and_verifier(&ML_DSA_65_SIGNING, &ML_DSA_65);

    let mu_44 = verifier_44.compute_mu(b"mismatch").expect("compute_mu");
    let mu_65 = verifier_65.compute_mu(b"mismatch").expect("compute_mu");

    let mut sig = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
    assert!(signer_44.sign(&mu_65, &mut sig).is_err());
    assert!(signer_65.sign(&mu_44, &mut sig).is_err());

    let len = signer_44.sign(&mu_44, &mut sig).expect("sign");
    assert!(verifier_65.verify(&mu_44, &sig[..len]).is_err());
    assert!(verifier_44.verify(&mu_65, &sig[..len]).is_err());

    // Importing under the wrong parameter set is also rejected, even though every ML-DSA
    // parameter set uses the same mu length.
    let imported = ExternalMu::import_less_safe(mu_44.as_ref(), &ML_DSA_65).expect("import");
    assert!(signer_44.sign(&imported, &mut sig).is_err());
    assert!(verifier_44.verify(&imported, &sig[..len]).is_err());
}

#[test]
fn test_external_mu_signature_buffer_too_small() {
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (_, signer, verifier) = signer_and_verifier(signing_alg, verify_alg);
        let mu = verifier.compute_mu(b"short buffer").expect("compute_mu");

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
        let signer = ExternalMuSigner::new(&key_pair).expect("signer");

        let raw = ParsedPublicKey::new(verify_alg, key_pair.public_key().as_ref()).expect("parse");
        let x509 = AsDer::<aws_lc_rs::encoding::PublicKeyX509Der>::as_der(&raw).expect("as_der");
        let parsed_x509 = ParsedPublicKey::new(verify_alg, x509.as_ref()).expect("parse x509");

        let verifier = ExternalMuVerifier::new(&parsed_x509).expect("verifier");
        let mut context = MuContext::new(&raw).expect("context from raw key");
        context.update(b"x509 encoded key").expect("update");
        let mu = context.finish().expect("finish");
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
fn test_external_mu_rejects_non_ml_dsa_key() {
    // There is deliberately no `ExternalMuSigner` counterpart to this test: every PQDSA
    // algorithm this crate supports is an ML-DSA parameter set, so a non-ML-DSA
    // `PqdsaKeyPair` cannot be constructed. `ExternalMuSigner::new` still performs the
    // check, and `pqdsa::external_representative_len` is an exhaustive match, so adding an
    // algorithm forces the question to be answered there.
    let ed25519 = ParsedPublicKey::new(
        &ED25519,
        include_bytes!("data/ed25519_test_public_key.bin").as_slice(),
    )
    .expect("parse ed25519 key");

    let err = ExternalMuVerifier::new(&ed25519).expect_err("ed25519 is not ML-DSA");
    assert_eq!(err.description_(), "WrongAlgorithm");
    assert_eq!(
        MuContext::new(&ed25519)
            .expect_err("ed25519 is not ML-DSA")
            .description_(),
        "WrongAlgorithm"
    );
    assert!(ExternalMuVerifier::try_from(&ed25519).is_err());
}

#[test]
fn test_external_mu_signer_outlives_key_pair() {
    // `ExternalMuSigner` holds its own counted reference to the signing key, as documented.
    for &(signing_alg, verify_alg) in ALGORITHMS {
        let (signer, public_key_bytes) = {
            let key_pair = PqdsaKeyPair::generate(signing_alg).expect("keygen");
            let public_key_bytes = key_pair.public_key().as_ref().to_vec();
            (
                ExternalMuSigner::new(&key_pair).expect("signer"),
                public_key_bytes,
            )
        };

        let parsed = ParsedPublicKey::new(verify_alg, public_key_bytes.as_slice()).expect("parse");
        let verifier = ExternalMuVerifier::new(&parsed).expect("verifier");
        let mu = verifier.compute_mu(b"after drop").expect("compute_mu");
        let mut signature = vec![0u8; signing_alg.signature_len()];
        signer.sign(&mu, &mut signature).expect("sign");
        verifier.verify(&mu, &signature).expect("verify");
    }
}

#[test]
fn test_try_from_matches_new() {
    let key_pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("keygen");
    let parsed =
        ParsedPublicKey::new(&ML_DSA_65, key_pair.public_key().as_ref()).expect("parse public key");

    let signer = ExternalMuSigner::try_from(&key_pair).expect("signer");
    let verifier = ExternalMuVerifier::try_from(&parsed).expect("verifier");
    let mu = verifier.compute_mu(b"try_from").expect("compute_mu");
    assert_eq!(
        mu.as_ref(),
        ExternalMuVerifier::new(&parsed)
            .unwrap()
            .compute_mu(b"try_from")
            .unwrap()
            .as_ref()
    );

    let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    signer.sign(&mu, &mut signature).expect("sign");
    verifier.verify(&mu, &signature).expect("verify");
}

#[test]
fn test_external_mu_types_are_send_and_sync() {
    // All three handles carry hand-written `unsafe impl Send`/`Sync` or rely on auto traits
    // through a raw-pointer-holding field, so pin the property down.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ExternalMu>();
    assert_send_sync::<MuContext>();
    assert_send_sync::<ExternalMuSigner>();
    assert_send_sync::<ExternalMuVerifier>();
}

#[test]
fn test_external_mu_accessors_and_debug() {
    let (_, signer, verifier) = signer_and_verifier(&ML_DSA_65_SIGNING, &ML_DSA_65);
    assert_eq!(signer.algorithm(), &ML_DSA_65_SIGNING);
    assert_eq!(verifier.algorithm(), &ML_DSA_65);

    // FIPS 204 fixes mu at 64 bytes for every ML-DSA parameter set.
    assert_eq!(MU_LEN, 64);

    let mu = verifier.compute_mu(b"debug").expect("compute_mu");
    let mu_debug = format!("{mu:?}");
    assert!(mu_debug.contains("ExternalMu"));
    assert!(mu_debug.contains("ML_DSA_65"));
    // The Debug output renders mu as hex.
    assert!(mu_debug.contains(&aws_lc_rs::test::to_hex(mu.as_ref())));

    assert!(format!("{signer:?}").contains("ExternalMuSigner"));
    assert!(format!("{verifier:?}").contains("ExternalMuVerifier"));
    assert!(format!("{:?}", verifier.mu_context().unwrap()).contains("MuContext"));

    // Copy/Clone
    let copied = mu;
    assert_eq!(copied.as_ref(), mu.as_ref());
}
