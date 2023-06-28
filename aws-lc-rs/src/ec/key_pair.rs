// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ec::{
    validate_ec_key, EcdsaSignatureFormat, EcdsaSigningAlgorithm, PublicKey, SCALAR_MAX_BYTES,
};
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::{Document, Version};
use crate::ptr::{DetachableLcPtr, LcPtr};
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature};
use crate::{digest, ec};
#[cfg(not(feature = "fips"))]
use aws_lc::EC_KEY_generate_key;
#[cfg(feature = "fips")]
use aws_lc::EC_KEY_generate_key_fips;
use aws_lc::{
    ECDSA_do_sign, EC_KEY_new_by_curve_name, EVP_PKEY_assign_EC_KEY, EVP_PKEY_new,
    EVP_PKEY_set1_EC_KEY, EC_KEY, EVP_PKEY,
};
use std::fmt;

use std::fmt::{Debug, Formatter};
use zeroize::Zeroize;

/// An ECDSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct EcdsaKeyPair {
    algorithm: &'static EcdsaSigningAlgorithm,
    ec_key: LcPtr<EC_KEY>,
    pubkey: PublicKey,
}

impl Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("EcdsaKeyPair {{ public_key: {:?} }}", self.pubkey))
    }
}

unsafe impl Send for EcdsaKeyPair {}

unsafe impl Sync for EcdsaKeyPair {}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        &self.pubkey
    }
}

pub(crate) unsafe fn generate_key(nid: i32) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new_by_curve_name(nid))?;

    #[cfg(feature = "fips")]
    if 1 != EC_KEY_generate_key_fips(*ec_key) {
        return Err(Unspecified);
    }

    #[cfg(not(feature = "fips"))]
    if 1 != EC_KEY_generate_key(*ec_key) {
        return Err(Unspecified);
    }

    let evp_pkey = LcPtr::new(EVP_PKEY_new())?;
    if 1 != EVP_PKEY_assign_EC_KEY(*evp_pkey, *ec_key) {
        return Err(Unspecified);
    }
    ec_key.detach();

    Ok(evp_pkey)
}

impl EcdsaKeyPair {
    unsafe fn new(
        algorithm: &'static EcdsaSigningAlgorithm,
        ec_key: LcPtr<EC_KEY>,
    ) -> Result<Self, ()> {
        let pubkey = ec::marshal_public_key(&ec_key.as_const())?;
        Ok(Self {
            algorithm,
            ec_key,
            pubkey,
        })
    }

    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an ECDSA key pair or if the key is otherwise not
    /// acceptable.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let evp_pkey = LcPtr::try_from(pkcs8)?;

            let ec_key = evp_pkey.get_ec_key()?;

            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;

            let key_pair = Self::new(alg, ec_key)?;

            Ok(key_pair)
        }
    }

    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 v1 document.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        _rng: &dyn SecureRandom,
    ) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = generate_key(alg.0.id.nid())?;

            evp_pkey.marshall_private_key(Version::V1)
        }
    }

    /// Serializes this `EcdsaKeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8(&self) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = LcPtr::new(EVP_PKEY_new())?;
            if 1 != EVP_PKEY_set1_EC_KEY(*evp_pkey, *self.ec_key) {
                return Err(Unspecified);
            }
            evp_pkey.marshall_private_key(Version::V1)
        }
    }

    /// Constructs an ECDSA key pair from the private key and public key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// The public key is encoding in uncompressed form using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `EcdsaKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let ec_group = ec::ec_group_from_nid(alg.0.id.nid())?;
            let public_ec_point = ec::ec_point_from_bytes(&ec_group, public_key)
                .map_err(|_| KeyRejected::invalid_encoding())?;
            let private_bn = DetachableLcPtr::try_from(private_key)?;
            let ec_key = ec::ec_key_from_public_private(&ec_group, &public_ec_point, &private_bn)?;
            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;
            let key_pair = Self::new(alg, ec_key)?;
            Ok(key_pair)
        }
    }

    /// Exposes the private key encoded as a big-endian fixed-length integer.
    ///
    /// For most use-cases, `EcdsaKeyPair::to_pkcs8()` should be preferred.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn private_key(&self) -> Result<PrivateKey, Unspecified> {
        unsafe {
            let mut priv_key_bytes = [0u8; SCALAR_MAX_BYTES];

            let key_len = ec::marshal_private_key_to_buffer(
                self.algorithm.id,
                &mut priv_key_bytes,
                &self.ec_key.as_const(),
            )?;

            Ok(PrivateKey::new(self, priv_key_bytes[0..key_len].into()))
        }
    }

    /// Returns the signature of the message using a random nonce.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    #[inline]
    pub fn sign(&self, _rng: &dyn SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        unsafe {
            let digest = digest::digest(self.algorithm.digest, message);
            let digest = digest.as_ref();
            let ecdsa_sig = LcPtr::new(ECDSA_do_sign(digest.as_ptr(), digest.len(), *self.ec_key))?;
            match self.algorithm.sig_format {
                EcdsaSignatureFormat::ASN1 => ec::ecdsa_sig_to_asn1(&ecdsa_sig),
                EcdsaSignatureFormat::Fixed => {
                    ec::ecdsa_sig_to_fixed(self.algorithm.id, &ecdsa_sig)
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct PrivateKey<'a>(&'a EcdsaKeyPair, Box<[u8]>);

impl Drop for PrivateKey<'_> {
    fn drop(&mut self) {
        self.1.zeroize();
    }
}

impl Debug for PrivateKey<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("EcdsaPrivateKey()")
    }
}

impl<'a> PrivateKey<'a> {
    fn new(key_pair: &'a EcdsaKeyPair, box_bytes: Box<[u8]>) -> Self {
        PrivateKey(key_pair, box_bytes)
    }
}

impl AsRef<[u8]> for PrivateKey<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.1.as_ref()
    }
}

unsafe impl Send for PrivateKey<'_> {}
unsafe impl Sync for PrivateKey<'_> {}
