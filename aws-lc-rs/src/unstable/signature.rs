// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! This module contains unstable/experimental APIs.
//!
//! # ⚠️ Warning
//! The APIs under this module are not stable and may change in the future.
//! They are not covered by semver guarantees.
//!
//! # Signing and verifying with MLDSA-44
//!
//! ```rust
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//!     use aws_lc_rs::encoding::AsDer;
//!     use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
//!     use aws_lc_rs::unstable::signature::{PqdsaKeyPair, MLDSA_44_SIGNING, MLDSA_44};
//!
//!     let signing_alg = &MLDSA_44_SIGNING;
//!     let key_pair = PqdsaKeyPair::generate(signing_alg)?;
//!
//!     const MESSAGE: &'static [u8] = b"hello, world";
//!     let mut signature = vec![0; signing_alg.signature_len()];
//!
//!     let signature_len = key_pair.sign(MESSAGE, &mut signature)?;
//!     assert_eq!(signature_len, signature.len());
//!
//!     // Verify the signature.
//!     let public_key_bytes = key_pair.public_key().as_der()?;
//!     let public_key = UnparsedPublicKey::new(&MLDSA_44, public_key_bytes.as_ref());
//!
//!     assert!(public_key.verify(MESSAGE, &signature).is_ok());
//! #   Ok(())
//! # }
//! ```
//!

pub use crate::pqdsa::key_pair::{PqdsaKeyPair, PqdsaPrivateKey};
pub use crate::pqdsa::signature::{
    PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, PublicKey as PqdsaPublicKey,
};

use crate::pqdsa::AlgorithmID;

/// Verification of MLDSA-44 signatures
pub static MLDSA_44: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::MLDSA_44,
};

/// Verification of MLDSA-65 signatures
pub static MLDSA_65: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::MLDSA_65,
};

/// Verification of MLDSA-87 signatures
pub static MLDSA_87: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::MLDSA_87,
};

/// Sign using MLDSA-44
pub static MLDSA_44_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&MLDSA_44);

/// Sign using MLDSA-65
pub static MLDSA_65_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&MLDSA_65);

/// Sign using MLDSA-87
pub static MLDSA_87_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&MLDSA_87);
