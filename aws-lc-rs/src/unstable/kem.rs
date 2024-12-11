// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(deprecated)]
use core::fmt::Debug;

use crate::kem::Algorithm;
use aws_lc::{NID_KYBER1024_R3, NID_KYBER512_R3, NID_KYBER768_R3};

#[deprecated(note = "use aws_lc_rs::kem::{ML_KEM_512, ML_KEM_768, ML_KEM_1024}")]
pub use crate::kem::{ML_KEM_1024, ML_KEM_512, ML_KEM_768};

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
#[allow(deprecated)]
const KYBER512_R3: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::Kyber512_R3,
    decapsulate_key_size: KYBER512_R3_SECRET_KEY_LENGTH,
    encapsulate_key_size: KYBER512_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER512_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER512_R3_SHARED_SECRET_LENGTH,
};

/// NIST Round 3 submission of the Kyber-768 algorithm.
#[allow(deprecated)]
const KYBER768_R3: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::Kyber768_R3,
    decapsulate_key_size: KYBER768_R3_SECRET_KEY_LENGTH,
    encapsulate_key_size: KYBER768_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER768_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER768_R3_SHARED_SECRET_LENGTH,
};

/// NIST Round 3 submission of the Kyber-1024 algorithm.
#[allow(deprecated)]
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
    #[deprecated(note = "use aws_lc_rs:kem::ML_KEM_512")]
    Kyber512_R3,

    /// NIST Round 3 submission of the Kyber-768 algorithm.
    #[deprecated(note = "use aws_lc_rs:kem::ML_KEM_768")]
    Kyber768_R3,

    /// NIST Round 3 submission of the Kyber-1024 algorithm.
    #[deprecated(note = "use aws_lc_rs:kem::ML_KEM_1024")]
    Kyber1024_R3,
}

impl crate::kem::AlgorithmIdentifier for AlgorithmId {
    #[inline]
    fn nid(self) -> i32 {
        #[allow(deprecated)]
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
    #[allow(deprecated)]
    match id {
        AlgorithmId::Kyber512_R3 => Some(&KYBER512_R3),
        AlgorithmId::Kyber768_R3 => Some(&KYBER768_R3),
        AlgorithmId::Kyber1024_R3 => Some(&KYBER1024_R3),
    }
}
