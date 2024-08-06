// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

pub(super) mod oaep;

use super::{
    encoding,
    key::{generate_rsa_key, is_rsa_key, key_size_bits, key_size_bytes},
    KeySize,
};
use crate::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    error::{KeyRejected, Unspecified},
    ptr::LcPtr,
};
use aws_lc::EVP_PKEY;
use core::fmt::Debug;

/// RSA Encryption Algorithm Identifier
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum EncryptionAlgorithmId {
    /// RSA-OAEP with SHA1 Hash and SHA1 MGF1
    OaepSha1Mgf1sha1,

    /// RSA-OAEP with SHA256 Hash and SHA256 MGF1
    OaepSha256Mgf1sha256,

    /// RSA-OAEP with SHA384 Hash and SHA384 MGF1
    OaepSha384Mgf1sha384,

    /// RSA-OAEP with SHA512 Hash and SHA512 MGF1
    OaepSha512Mgf1sha512,
}

/// An RSA private key used for decrypting ciphertext encrypted by a [`PublicEncryptingKey`].
pub struct PrivateDecryptingKey(LcPtr<EVP_PKEY>);

impl PrivateDecryptingKey {
    fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        Self::validate_key(&evp_pkey)?;
        Ok(Self(evp_pkey))
    }

    fn validate_key(key: &LcPtr<EVP_PKEY>) -> Result<(), Unspecified> {
        if !is_rsa_key(key) {
            return Err(Unspecified);
        };
        match key_size_bits(key) {
            2048..=8192 => Ok(()),
            _ => Err(Unspecified),
        }
    }

    /// Generate a new RSA private key pair for use with asymmetrical encryption.
    ///
    /// Supports the following key sizes:
    /// * `KeySize::Rsa2048`
    /// * `KeySize::Rsa3072`
    /// * `KeySize::Rsa4096`
    /// * `KeySize::Rsa8192`
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs during the generation of the RSA keypair.
    pub fn generate(size: KeySize) -> Result<Self, Unspecified> {
        let key = generate_rsa_key(size.bits(), false)?;
        Self::new(key)
    }

    /// Generate a new RSA private key pair for use with asymmetrical encryption.
    ///
    /// Supports the following key sizes:
    /// * `KeySize::Rsa2048`
    /// * `KeySize::Rsa3072`
    /// * `KeySize::Rsa4096`
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    #[cfg(feature = "fips")]
    pub fn generate_fips(size: KeySize) -> Result<Self, Unspecified> {
        let key = generate_rsa_key(size.bits(), true)?;
        Self::new(key)
    }

    /// Construct a `PrivateDecryptingKey` from the provided PKCS#8 (v1) document.
    ///
    /// Supports RSA key sizes between 2048 and 8192 (inclusive).
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs during deserialization of this key from PKCS#8.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let key = encoding::pkcs8::decode_der(pkcs8)?;
        Ok(Self::new(key)?)
    }

    /// Returns a boolean indicator if this RSA key is an approved FIPS 140-3 key.
    #[cfg(feature = "fips")]
    #[must_use]
    pub fn is_valid_fips_key(&self) -> bool {
        super::key::is_valid_fips_key(&self.0)
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size_bytes(&self) -> usize {
        key_size_bytes(&self.0)
    }

    /// Returns the RSA key size in bits.
    #[must_use]
    pub fn key_size_bits(&self) -> usize {
        key_size_bits(&self.0)
    }

    /// Retrieves the `PublicEncryptingKey` corresponding with this `PrivateDecryptingKey`.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn public_key(&self) -> PublicEncryptingKey {
        PublicEncryptingKey::new(self.0.clone()).expect(
            "PublicEncryptingKey key size to be supported by PrivateDecryptingKey key sizes",
        )
    }
}

impl Debug for PrivateDecryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PrivateDecryptingKey").finish()
    }
}

impl AsDer<Pkcs8V1Der<'static>> for PrivateDecryptingKey {
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        Ok(Pkcs8V1Der::new(encoding::pkcs8::encode_v1_der(&self.0)?))
    }
}

impl Clone for PrivateDecryptingKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// An RSA public key used for encrypting plaintext that is decrypted by a [`PrivateDecryptingKey`].
pub struct PublicEncryptingKey(LcPtr<EVP_PKEY>);

impl PublicEncryptingKey {
    fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        Self::validate_key(&evp_pkey)?;
        Ok(Self(evp_pkey))
    }

    fn validate_key(key: &LcPtr<EVP_PKEY>) -> Result<(), Unspecified> {
        if !is_rsa_key(key) {
            return Err(Unspecified);
        };
        match key_size_bits(key) {
            2048..=8192 => Ok(()),
            _ => Err(Unspecified),
        }
    }

    /// Construct a `PublicEncryptingKey` from X.509 `SubjectPublicKeyInfo` DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs deserializing from bytes.
    pub fn from_der(value: &[u8]) -> Result<Self, KeyRejected> {
        Ok(Self(encoding::rfc5280::decode_public_key_der(value)?))
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size_bytes(&self) -> usize {
        key_size_bytes(&self.0)
    }

    /// Returns the RSA key size in bits.
    #[must_use]
    pub fn key_size_bits(&self) -> usize {
        key_size_bits(&self.0)
    }
}

impl Debug for PublicEncryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PublicEncryptingKey").finish()
    }
}

impl Clone for PublicEncryptingKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl AsDer<PublicKeyX509Der<'static>> for PublicEncryptingKey {
    /// Serialize this `PublicEncryptingKey` to a X.509 `SubjectPublicKeyInfo` structure as DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs serializing to bytes.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        encoding::rfc5280::encode_public_key_der(&self.0)
    }
}
