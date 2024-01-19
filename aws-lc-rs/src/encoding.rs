// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Serialization formats

use crate::buffer::Buffer;
use crate::encoding::types::{
    Curve25519SeedBufferType, EcPrivateKeyBinType, EcPrivateKeyRfc5915DerType,
    EcPublicKeyX509DerType,
};

mod types {
    pub struct EcPrivateKeyBinType {
        _priv: (),
    }

    pub struct EcPrivateKeyRfc5915DerType {
        _priv: (),
    }

    pub struct EcPublicKeyX509DerType {
        _priv: (),
    }

    pub struct Curve25519SeedBufferType {
        _priv: (),
    }
}

/// Trait for types that can be serialized into a DER format.
pub trait AsDer<T> {
    /// Serializes into a DER format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_der(&self) -> Result<T, crate::error::Unspecified>;
}

/// Trait for values that can be serialized into a big-endian format
pub trait AsBigEndian<T> {
    /// Serializes into a big-endian format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_be_bytes(&self) -> Result<T, crate::error::Unspecified>;
}

/// Elliptic curve private key data encoded as a big-endian fixed-length integer.
pub type EcPrivateKeyBin<'a> = Buffer<'a, EcPrivateKeyBinType>;

/// Elliptic curve private key as a DER-encoded `ECPrivateKey` (RFC 5915) structure.
pub type EcPrivateKeyRfc5915Der<'a> = Buffer<'a, EcPrivateKeyRfc5915DerType>;

/// An elliptic curve public key as a DER-encoded (X509) `SubjectPublicKeyInfo` structure
pub type EcPublicKeyX509Der<'a> = Buffer<'a, EcPublicKeyX509DerType>;

/// Elliptic curve private key data encoded as a big-endian fixed-length integer.
pub type Curve25519SeedBin<'a> = Buffer<'a, Curve25519SeedBufferType>;
