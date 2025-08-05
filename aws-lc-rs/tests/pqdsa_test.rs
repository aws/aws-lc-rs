// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#![cfg(all(not(feature = "fips"), feature = "unstable"))]

use aws_lc_rs::signature::{KeyPair, VerificationAlgorithm};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87,
    ML_DSA_87_SIGNING,
};
use aws_lc_rs::{test, test_file};

macro_rules! mldsa_keygen_test {
    ($file:literal, $signing:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let _seed = test_case.consume_bytes("SEED");
            let public = test_case.consume_bytes("PUBLIC");
            let secret = test_case.consume_bytes("SECRET");

            let key_pair_secret = PqdsaKeyPair::from_raw_private_key($signing, secret.as_slice())?;
            let public_secret = key_pair_secret.public_key();
            assert_eq!(public.as_slice(), public_secret.as_ref());

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
