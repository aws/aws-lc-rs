// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Unstable KEM Algorithms for usage with the [`crate::kem`] module.
//!
//! # ⚠️ Warning
//! Algorithms contained in this module are subject to changes, relocation,
//! or removal across minor releases, and thus are not subject to semantic versioning policies.

use crate::kem::Algorithm;
use aws_lc::{NID_KYBER1024_R3, NID_KYBER512_R3, NID_KYBER768_R3};

// Key lengths defined as stated on the CRYSTALS website:
// https://pq-crystals.org/kyber/

const KYBER512_R3_SECRET_KEY_LENGTH: usize = 1632;
const KYBER512_R3_CIPHERTEXT_LENGTH: usize = 768;
const KYBER512_R3_PUBLIC_KEY_LENGTH: usize = 800;
const KYBER512_R3_SHARED_SECRET_LENGTH: usize = 32;

const KYBER768_R3_SECRET_KEY_LENGTH: usize = 2400;
const KYBER768_R3_CIPHERTEXT_LENGTH: usize = 1088;
const KYBER768_R3_PUBLIC_KEY_LENGTH: usize = 1184;
const KYBER768_R3_SHARED_SECRET_LENGTH: usize = 32;

const KYBER1024_R3_SECRET_KEY_LENGTH: usize = 3168;
const KYBER1024_R3_CIPHERTEXT_LENGTH: usize = 1568;
const KYBER1024_R3_PUBLIC_KEY_LENGTH: usize = 1568;
const KYBER1024_R3_SHARED_SECRET_LENGTH: usize = 32;

/// NIST Round 3 submission of the Kyber-512 algorithm.
const KYBER512_R3: Algorithm<AlgorithmId> = Algorithm::new(
    AlgorithmId::Kyber512_R3,
    KYBER512_R3_SECRET_KEY_LENGTH,
    KYBER512_R3_PUBLIC_KEY_LENGTH,
    KYBER512_R3_CIPHERTEXT_LENGTH,
    KYBER512_R3_SHARED_SECRET_LENGTH,
);

/// NIST Round 3 submission of the Kyber-768 algorithm.
const KYBER768_R3: Algorithm<AlgorithmId> = Algorithm::new(
    AlgorithmId::Kyber768_R3,
    KYBER768_R3_SECRET_KEY_LENGTH,
    KYBER768_R3_PUBLIC_KEY_LENGTH,
    KYBER768_R3_CIPHERTEXT_LENGTH,
    KYBER768_R3_SHARED_SECRET_LENGTH,
);

/// NIST Round 3 submission of the Kyber-1024 algorithm.
const KYBER1024_R3: Algorithm<AlgorithmId> = Algorithm::new(
    AlgorithmId::Kyber1024_R3,
    KYBER1024_R3_SECRET_KEY_LENGTH,
    KYBER1024_R3_PUBLIC_KEY_LENGTH,
    KYBER1024_R3_CIPHERTEXT_LENGTH,
    KYBER1024_R3_SHARED_SECRET_LENGTH,
);

/// Identifier for an unstable KEM algorithm.
#[allow(non_camel_case_types)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AlgorithmId {
    /// NIST Round 3 submission of the Kyber-512 algorithm.
    Kyber512_R3,

    /// NIST Round 3 submission of the Kyber-768 algorithm.
    Kyber768_R3,

    /// NIST Round 3 submission of the Kyber-1024 algorithm.
    Kyber1024_R3,
}

impl crate::kem::AlgorithmIdentifier for AlgorithmId {
    #[inline]
    fn nid(self) -> i32 {
        match self {
            AlgorithmId::Kyber512_R3 => NID_KYBER512_R3,
            AlgorithmId::Kyber768_R3 => NID_KYBER768_R3,
            AlgorithmId::Kyber1024_R3 => NID_KYBER1024_R3,
        }
    }
}

impl crate::kem::sealed::Sealed for AlgorithmId {}

/// Retrieve an unstable KEM [`Algorithm`] using the [`AlgorithmId`] specified by `id`.
/// May return [`Option::None`] if support for the algorithm has been removed from the unstable module.
#[must_use]
pub const fn get_algorithm(id: AlgorithmId) -> Option<&'static Algorithm<AlgorithmId>> {
    match id {
        AlgorithmId::Kyber512_R3 => Some(&KYBER512_R3),
        AlgorithmId::Kyber768_R3 => Some(&KYBER768_R3),
        AlgorithmId::Kyber1024_R3 => Some(&KYBER1024_R3),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::KeyRejected,
        kem::{PrivateKey, PublicKey},
    };

    use super::{KYBER1024_R3, KYBER512_R3, KYBER768_R3};

    #[cfg(private_api)]
    macro_rules! kem_kat_test {
        ($file:literal, $alg:expr) => {
            use crate::{
                aws_lc::{
                    pq_custom_randombytes_init_for_testing,
                    pq_custom_randombytes_use_deterministic_for_testing,
                },
                test, test_file,
            };
            test::run(test_file!($file), |_section, test_case| {
                let seed = test_case.consume_bytes("seed");
                let public_key_bytes = test_case.consume_bytes("pk");
                let secret_key_bytes = test_case.consume_bytes("sk");
                let ciphertext_bytes = test_case.consume_bytes("ct");
                let shared_secret_bytes = test_case.consume_bytes("ss");

                // Set randomness generation in deterministic mode.
                unsafe {
                    pq_custom_randombytes_use_deterministic_for_testing();
                    pq_custom_randombytes_init_for_testing(seed.as_ptr());
                }

                let priv_key = PrivateKey::generate($alg).unwrap();

                assert_eq!(priv_key.as_ref(), secret_key_bytes);

                let pub_key = priv_key.public_key().unwrap();
                assert_eq!(pub_key.as_ref(), public_key_bytes);

                let (ciphertext, bob_shared_secret) = pub_key.encapsulate().unwrap();
                assert_eq!(ciphertext.as_ref(), ciphertext_bytes);
                assert_eq!(bob_shared_secret.as_ref(), shared_secret_bytes);

                let alice_shared_secret = priv_key.decapsulate(ciphertext).unwrap();
                assert_eq!(alice_shared_secret.as_ref(), shared_secret_bytes);

                Ok(())
            });
        };
    }

    #[cfg(private_api)]
    #[test]
    fn test_kem_kyber512() {
        kem_kat_test!("../../tests/data/kyber512r3.txt", &KYBER512_R3);
    }

    #[cfg(private_api)]
    #[test]
    fn test_kem_kyber768() {
        kem_kat_test!("../../tests/data/kyber768r3.txt", &KYBER768_R3);
    }

    #[cfg(private_api)]
    #[test]
    fn test_kem_kyber1024() {
        kem_kat_test!("../../tests/data/kyber1024r3.txt", &KYBER1024_R3);
    }

    #[test]
    fn test_kem_serialize() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let priv_key = PrivateKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.public_key().unwrap();
            let pubkey_raw_bytes = pub_key.as_ref();
            let pub_key_from_bytes = PublicKey::new(algorithm, pubkey_raw_bytes).unwrap();

            assert_eq!(pub_key.as_ref(), pub_key_from_bytes.as_ref());
            assert_eq!(pub_key.algorithm(), pub_key_from_bytes.algorithm());

            let privkey_raw_bytes = priv_key.as_ref();
            let priv_key_from_bytes = PrivateKey::new(algorithm, privkey_raw_bytes).unwrap();

            assert_eq!(priv_key.as_ref(), priv_key_from_bytes.as_ref());
            assert_eq!(priv_key.algorithm(), priv_key_from_bytes.algorithm());
        }
    }

    #[test]
    fn test_kem_wrong_sizes() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let too_long_bytes = vec![0u8; algorithm.secret_key_size() + 1];
            let long_priv_key_from_bytes = PrivateKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_priv_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_long_bytes = vec![0u8; algorithm.public_key_size() + 1];
            let long_pub_key_from_bytes = PublicKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_pub_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_short_bytes = vec![0u8; algorithm.secret_key_size() - 1];
            let short_priv_key_from_bytes = PrivateKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_priv_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );

            let too_short_bytes = vec![0u8; algorithm.public_key_size() - 1];
            let short_pub_key_from_bytes = PublicKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_pub_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );
        }
    }
}
