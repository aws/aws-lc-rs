// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Unstable KEM Algorithms for usage with the [`crate::kem`] module.
//!
//! # ⚠️ Warning
//! Algorithms contained in this module are subject to changes, relocation,
//! or removal across minor releases, and thus are not subject to semantic versioning policies.
//!
//! # Example
//!
//! ```
//! use aws_lc_rs::{
//!     error::Unspecified,
//!     kem::{Ciphertext, DecapsulationKey, EncapsulationKey},
//!     unstable::kem::{AlgorithmId, get_algorithm}
//! };
//!
//! let kyber512_r3 = get_algorithm(AlgorithmId::Kyber512_R3).ok_or(Unspecified)?;
//!
//! // Alice generates their (private) decapsulation key.
//! let decapsulation_key = DecapsulationKey::generate(kyber512_r3)?;
//!
//! // Alices computes the (public) encapsulation key.
//! let encapsulation_key = decapsulation_key.encapsulation_key()?;
//!
//! let encapsulation_key_bytes = encapsulation_key.key_bytes()?;
//!
//! // Alice sends the encapsulation key bytes to bob through some
//! // protocol message.
//! let encapsulation_key_bytes = encapsulation_key_bytes.as_ref();
//!
//! // Bob constructs the (public) encapsulation key from the key bytes provided by Alice.
//! let retrieved_encapsulation_key = EncapsulationKey::new(kyber512_r3, encapsulation_key_bytes)?;
//!
//! // Bob executes the encapsulation algorithm to to produce their copy of the secret, and associated ciphertext.
//! let (ciphertext, bob_secret) = retrieved_encapsulation_key.encapsulate()?;
//!
//! // Alice recieves ciphertext bytes from bob
//! let ciphertext_bytes = ciphertext.as_ref();
//!
//! // Bob sends Alice the ciphertext computed from the encapsulation algorithm, Alice runs decapsulation to derive their
//! // copy of the secret.
//! let alice_secret = decapsulation_key.decapsulate(Ciphertext::from(ciphertext_bytes))?;
//!
//! // Alice and Bob have now arrived to the same secret
//! assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```

use core::fmt::Debug;

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
const KYBER512_R3: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::Kyber512_R3,
    decapsulate_key_size: KYBER512_R3_SECRET_KEY_LENGTH,
    encapsulate_key_size: KYBER512_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER512_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER512_R3_SHARED_SECRET_LENGTH,
};

/// NIST Round 3 submission of the Kyber-768 algorithm.
const KYBER768_R3: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::Kyber768_R3,
    decapsulate_key_size: KYBER768_R3_SECRET_KEY_LENGTH,
    encapsulate_key_size: KYBER768_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER768_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER768_R3_SHARED_SECRET_LENGTH,
};

/// NIST Round 3 submission of the Kyber-1024 algorithm.
const KYBER1024_R3: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::Kyber1024_R3,
    decapsulate_key_size: KYBER1024_R3_SECRET_KEY_LENGTH,
    encapsulate_key_size: KYBER1024_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER1024_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER1024_R3_SHARED_SECRET_LENGTH,
};

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

impl crate::sealed::Sealed for AlgorithmId {}

/// Retrieve an unstable KEM [`Algorithm`] using the [`AlgorithmId`] specified by `id`.
/// May return [`None`] if support for the algorithm has been removed from the unstable module.
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
        kem::{DecapsulationKey, EncapsulationKey},
    };

    use super::{get_algorithm, AlgorithmId, KYBER1024_R3, KYBER512_R3, KYBER768_R3};

    #[test]
    fn test_kem_serialize() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();
            let pubkey_raw_bytes = pub_key.key_bytes().unwrap();
            let pub_key_from_bytes =
                EncapsulationKey::new(algorithm, pubkey_raw_bytes.as_ref()).unwrap();

            assert_eq!(
                pub_key.key_bytes().unwrap().as_ref(),
                pub_key_from_bytes.key_bytes().unwrap().as_ref()
            );
            assert_eq!(pub_key.algorithm(), pub_key_from_bytes.algorithm());
        }
    }

    #[test]
    fn test_kem_wrong_sizes() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let too_long_bytes = vec![0u8; algorithm.encapsulate_key_size() + 1];
            let long_pub_key_from_bytes = EncapsulationKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_pub_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_short_bytes = vec![0u8; algorithm.encapsulate_key_size() - 1];
            let short_pub_key_from_bytes = EncapsulationKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_pub_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );
        }
    }

    #[test]
    fn test_kem_e2e() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();

            let (alice_ciphertext, alice_secret) =
                pub_key.encapsulate().expect("encapsulate successful");

            let bob_secret = priv_key
                .decapsulate(alice_ciphertext)
                .expect("decapsulate successful");

            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
    }

    #[test]
    fn test_serialized_kem_e2e() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();

            // Generate public key bytes to send to bob
            let pub_key_bytes = pub_key.key_bytes().unwrap();

            // Test that priv_key's EVP_PKEY isn't entirely freed since we remove this pub_key's reference.
            drop(pub_key);

            let retrieved_pub_key =
                EncapsulationKey::new(algorithm, pub_key_bytes.as_ref()).unwrap();
            let (ciphertext, bob_secret) = retrieved_pub_key
                .encapsulate()
                .expect("encapsulate successful");

            let alice_secret = priv_key
                .decapsulate(ciphertext)
                .expect("encapsulate successful");

            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
    }

    #[test]
    fn test_get_algorithm() {
        for id in [
            AlgorithmId::Kyber512_R3,
            AlgorithmId::Kyber768_R3,
            AlgorithmId::Kyber1024_R3,
        ] {
            let alg = get_algorithm(id).expect("algorithm retrievable");
            assert_eq!(alg.id(), id);
        }
    }

    #[test]
    fn test_debug_fmt() {
        let alg = get_algorithm(AlgorithmId::Kyber512_R3).expect("algorithm retrievable");
        let private = DecapsulationKey::generate(alg).expect("successful generation");
        assert_eq!(
            format!("{private:?}"),
            "DecapsulationKey { algorithm: Kyber512_R3, .. }"
        );
        assert_eq!(
            format!(
                "{:?}",
                private.encapsulation_key().expect("public key retrievable")
            ),
            "EncapsulationKey { algorithm: Kyber512_R3, .. }"
        );
    }
}
