// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#![cfg(all(not(feature = "fips"), feature = "unstable"))]

use aws_lc_rs::encoding::{AsDer, AsRawBytes};
use aws_lc_rs::signature::{KeyPair, ParsedPublicKey, VerificationAlgorithm};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87,
    ML_DSA_87_SIGNING,
};
use aws_lc_rs::{test, test_file};

macro_rules! mldsa_keygen_test {
    ($file:literal, $signing:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let seed = test_case.consume_bytes("SEED");
            let public = test_case.consume_bytes("PUBLIC");
            let secret = test_case.consume_bytes("SECRET");

            // Verify key construction from raw private key produces expected public key
            let key_pair_secret = PqdsaKeyPair::from_raw_private_key($signing, secret.as_slice())?;
            let public_secret = key_pair_secret.public_key();
            assert_eq!(public.as_slice(), public_secret.as_ref());

            // Verify seed-based key generation produces the same public key
            let key_pair_seed = PqdsaKeyPair::from_seed($signing, seed.as_slice())?;
            assert_eq!(public.as_slice(), key_pair_seed.public_key().as_ref());

            // Verify seed-based key generation produces the same raw private key
            let seed_raw_private = key_pair_seed.private_key().as_raw_bytes()?;
            assert_eq!(secret.as_slice(), seed_raw_private.as_ref());

            Ok(())
        });
    };
}

macro_rules! mldsa_sigver_test {
    ($file:literal, $verification:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let public_key = test_case.consume_bytes("PUBLIC");
            let message = test_case.consume_bytes("MESSAGE");
            let signature = test_case.consume_bytes("SIGNATURE");
            let _context = test_case.consume_bytes("CONTEXT");
            let expected_result = test_case.consume_bool("RESULT");

            let result =
                $verification.verify_sig(public_key.as_ref(), message.as_ref(), signature.as_ref());
            if expected_result {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }

            let ppk = ParsedPublicKey::new($verification, public_key.as_slice()).unwrap();
            let result = ppk.verify_sig(message.as_ref(), signature.as_ref());
            if expected_result {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
            let x509_bytes = ppk.as_der().unwrap();
            let result =
                $verification.verify_sig(x509_bytes.as_ref(), message.as_ref(), signature.as_ref());
            if expected_result {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
            Ok(())
        });
    };
}

macro_rules! mldsa_sigver_digest_test {
    ($file:literal, $verification:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let public_key = test_case.consume_bytes("PUBLIC");
            let message = test_case.consume_bytes("MESSAGE");
            let signature = test_case.consume_bytes("SIGNATURE");
            let _context = test_case.consume_bytes("CONTEXT");
            let _expected_result = test_case.consume_bool("RESULT");

            // For code coverage
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, message.as_ref());
            let result =
                $verification.verify_digest_sig(public_key.as_ref(), &digest, signature.as_ref());
            assert!(result.is_err());

            let ppk = ParsedPublicKey::new($verification, public_key.as_slice()).unwrap();
            let result = ppk.verify_digest_sig(&digest, signature.as_ref());
            assert!(result.is_err());

            Ok(())
        });
    };
}

#[test]
fn mldsa_44_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_44_ACVP_keyGen.txt", &ML_DSA_44_SIGNING);
}

#[test]
fn mldsa_65_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_65_ACVP_keyGen.txt", &ML_DSA_65_SIGNING);
}

#[test]
fn mldsa_87_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_87_ACVP_keyGen.txt", &ML_DSA_87_SIGNING);
}

#[test]
fn mldsa_44_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_44_sigVer.txt", &ML_DSA_44);
}

#[test]
fn mldsa_65_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_65_sigVer.txt", &ML_DSA_65);
}

#[test]
fn mldsa_87_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_87_sigVer.txt", &ML_DSA_87);
}

#[test]
// For code coverage
fn mldsa_44_sigver_digest_test() {
    mldsa_sigver_digest_test!("data/MLDSA_44_sigVer.txt", &ML_DSA_44);
}

#[test]
fn test_mldsa_seed_sign_verify() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let seed = [7u8; 32];
        let kp = PqdsaKeyPair::from_seed(signing_alg, &seed)
            .expect("from_seed should succeed with valid 32-byte seed");
        let msg = b"test message";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        let sig_len = kp
            .sign(msg, &mut sig)
            .expect("signing with seed-derived key should succeed");
        assert_eq!(sig_len, signing_alg.signature_len());
        let pk = aws_lc_rs::signature::UnparsedPublicKey::new(verify_alg, kp.public_key().as_ref());
        pk.verify(msg, &sig)
            .expect("verification of seed-derived signature should succeed");
    }
}

#[test]
fn test_mldsa_seed_wrong_size() {
    for signing_alg in [&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING] {
        let too_short = PqdsaKeyPair::from_seed(signing_alg, &[0u8; 31]);
        assert!(
            too_short.is_err(),
            "31 bytes should be rejected as too short"
        );

        let too_long = PqdsaKeyPair::from_seed(signing_alg, &[0u8; 33]);
        assert!(too_long.is_err(), "33 bytes should be rejected as too long");

        let empty = PqdsaKeyPair::from_seed(signing_alg, &[]);
        assert!(empty.is_err(), "empty seed should be rejected");

        // Exact size (32 bytes) should succeed
        let exact = PqdsaKeyPair::from_seed(signing_alg, &[0u8; 32]);
        assert!(exact.is_ok(), "32 bytes should be accepted");
    }
}

#[test]
fn test_mldsa_seed_serialization_roundtrip() {
    for signing_alg in [&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING] {
        let seed = [99u8; 32];
        let kp = PqdsaKeyPair::from_seed(signing_alg, &seed).unwrap();

        // PKCS#8 round-trip
        let pkcs8 = kp.to_pkcs8().expect("to_pkcs8 should succeed");
        let kp_pkcs8 = PqdsaKeyPair::from_pkcs8(signing_alg, pkcs8.as_ref())
            .expect("from_pkcs8 should reconstruct the key");
        assert_eq!(
            kp.public_key().as_ref(),
            kp_pkcs8.public_key().as_ref(),
            "PKCS#8 round-trip should preserve public key"
        );

        // Raw private key round-trip
        let raw = kp
            .private_key()
            .as_raw_bytes()
            .expect("as_raw_bytes should succeed");
        let kp_raw = PqdsaKeyPair::from_raw_private_key(signing_alg, raw.as_ref())
            .expect("from_raw_private_key should reconstruct the key");
        assert_eq!(
            kp.public_key().as_ref(),
            kp_raw.public_key().as_ref(),
            "raw private key round-trip should preserve public key"
        );

        // Stability: re-exported bytes should be identical
        let raw2 = kp_raw
            .private_key()
            .as_raw_bytes()
            .expect("re-export should succeed");
        assert_eq!(
            raw.as_ref(),
            raw2.as_ref(),
            "raw private key bytes should be stable across round-trips"
        );
    }
}

#[test]
fn test_mldsa_seed_different_seeds_different_keys() {
    for signing_alg in [&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING] {
        let kp1 = PqdsaKeyPair::from_seed(signing_alg, &[1u8; 32]).unwrap();
        let kp2 = PqdsaKeyPair::from_seed(signing_alg, &[2u8; 32]).unwrap();
        assert_ne!(
            kp1.public_key().as_ref(),
            kp2.public_key().as_ref(),
            "different seeds should produce different public keys"
        );
    }
}

#[test]
fn test_mldsa_seed_zeroed_bytes() {
    // Test behavior when constructing from an all-zeros seed.
    // ML-DSA should accept any 32-byte seed and produce a valid, functional key pair.
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let zeroed_seed = [0u8; 32];

        // Constructing a key from zeroed seed should succeed
        let kp = PqdsaKeyPair::from_seed(signing_alg, &zeroed_seed);
        assert!(
            kp.is_ok(),
            "from_seed should accept zeroed bytes of correct size"
        );
        let kp = kp.unwrap();

        // Key should be functional: sign and verify
        let msg = b"zeroed seed test";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        let sig_len = kp
            .sign(msg, &mut sig)
            .expect("signing with zeroed-seed key should succeed");
        assert_eq!(sig_len, signing_alg.signature_len());

        let pk = aws_lc_rs::signature::UnparsedPublicKey::new(verify_alg, kp.public_key().as_ref());
        pk.verify(msg, &sig)
            .expect("verification with zeroed-seed key should succeed");

        // Determinism: same zeroed seed should produce the same key
        let kp2 = PqdsaKeyPair::from_seed(signing_alg, &zeroed_seed).unwrap();
        assert_eq!(
            kp.public_key().as_ref(),
            kp2.public_key().as_ref(),
            "same seed should always produce the same key"
        );
    }
}

#[test]
fn test_mldsa_seed_functional_equivalence() {
    // Verify that a seed-generated key and a key reconstructed from its
    // exported private bytes both produce verifiable signatures.
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let seed = [123u8; 32];
        let original =
            PqdsaKeyPair::from_seed(signing_alg, &seed).expect("from_seed should succeed");

        // Export and reconstruct via raw private key
        let raw = original
            .private_key()
            .as_raw_bytes()
            .expect("as_raw_bytes should succeed");
        let reconstructed = PqdsaKeyPair::from_raw_private_key(signing_alg, raw.as_ref())
            .expect("from_raw_private_key should reconstruct the key");

        // Verify public keys match
        assert_eq!(
            original.public_key().as_ref(),
            reconstructed.public_key().as_ref(),
            "reconstructed key should have the same public key"
        );

        let msg = b"equivalence test";

        // Both keys should produce verifiable signatures
        let mut sig_original = vec![0u8; signing_alg.signature_len()];
        original
            .sign(msg, &mut sig_original)
            .expect("signing with original key should succeed");

        let mut sig_reconstructed = vec![0u8; signing_alg.signature_len()];
        reconstructed
            .sign(msg, &mut sig_reconstructed)
            .expect("signing with reconstructed key should succeed");

        let pk = aws_lc_rs::signature::UnparsedPublicKey::new(
            verify_alg,
            original.public_key().as_ref(),
        );
        pk.verify(msg, &sig_original)
            .expect("original signature should verify");
        pk.verify(msg, &sig_reconstructed)
            .expect("reconstructed signature should verify");
    }
}
