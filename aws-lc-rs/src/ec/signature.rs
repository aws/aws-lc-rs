// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::digest::digest_ctx::DigestContext;
use crate::ec::ec_point_from_bytes;
use crate::ec::ecdsa_sig_from_fixed;
use crate::ec::marshal_ec_public_key_to_buffer;
use crate::ec::try_parse_public_key_raw_bytes;
use crate::ec::try_parse_subject_public_key_info_bytes;
use crate::ec::validate_evp_key;
use crate::ec::KeyRejected;
use crate::ec::VerificationAlgorithm;
use crate::ec::{
    compressed_public_key_size_bytes, marshal_public_key_to_buffer, PUBLIC_KEY_MAX_LEN,
};
use crate::encoding::AsDer;
use crate::encoding::EcPublicKeyCompressedBin;
use crate::encoding::PublicKeyX509Der;
use crate::encoding::{AsBigEndian, EcPublicKeyUncompressedBin};
use crate::error::Unspecified;
use crate::ptr::ConstPointer;
use crate::ptr::LcPtr;

use crate::fips::indicator_check;
use crate::{digest, sealed};
use aws_lc::{
    CBS_init, ECDSA_SIG_to_bytes, EC_GROUP_new_by_curve_name, EC_KEY_new, EC_KEY_set_group,
    EC_KEY_set_public_key, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY_get0_EC_KEY,
    EVP_PKEY_id, EVP_PKEY_new_raw_public_key, EVP_parse_public_key, NID_X9_62_prime256v1,
    NID_secp256k1, NID_secp384r1, NID_secp521r1, CBS, EVP_PKEY, EVP_PKEY_X25519, NID_X25519,
};
use core::fmt;
use core::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::ptr::null_mut;
#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

#[derive(Debug)]
pub(crate) struct ParsedPublicKey {
    format: ParsedPublicKeyFormat,
    nid: i32,
    key: LcPtr<EVP_PKEY>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// The format of a parsed public key.
///
/// This is used to distinguish between different types of public key formats
/// supported by *aws-lc-rs*.
#[non_exhaustive]
pub enum ParsedPublicKeyFormat {
    /// The key is in an X.509 SubjectPublicKeyInfo format.
    X509,
    /// The key is in an uncompressed form (X9.62).
    Uncompressed,
    /// The key is in a compressed form (SEC 1: Elliptic Curve Cryptography, Version 2.0).
    Compressed,
    /// The key is in a raw form.
    Raw,
}

/// A parsed public key for key agreement.
impl ParsedPublicKey {
    pub fn nid(&self) -> i32 {
        self.nid
    }

    pub fn format(&self) -> ParsedPublicKeyFormat {
        self.format
    }

    pub(crate) fn key(&self) -> &LcPtr<EVP_PKEY> {
        &self.key
    }

    pub(crate) fn key_mut(&mut self) -> &mut LcPtr<EVP_PKEY> {
        &mut self.key
    }
}

impl ParsedPublicKey {
    #[allow(non_upper_case_globals)]
    pub(crate) fn new(bytes: impl AsRef<[u8]>, nid: i32) -> Result<Self, KeyRejected> {
        let key_bytes = bytes.as_ref();
        if key_bytes.is_empty() {
            return Err(KeyRejected::unspecified());
        }
        let format = match key_bytes[0] {
            0x04 => ParsedPublicKeyFormat::Uncompressed,
            0x02 | 0x03 => ParsedPublicKeyFormat::Compressed,
            _ => ParsedPublicKeyFormat::X509,
        };
        match nid {
            NID_X25519 => {
                let pub_key = try_parse_x25519_public_key_bytes(key_bytes)?;
                Ok(ParsedPublicKey {
                    format,
                    nid,
                    key: pub_key,
                })
            }
            NID_X9_62_prime256v1 | NID_secp256k1 | NID_secp384r1 | NID_secp521r1 => {
                try_parse_subject_public_key_info_bytes(key_bytes)
                    .and_then(|key| {
                        validate_evp_key(&key.as_const(), nid).map(|()| ParsedPublicKey {
                            format: ParsedPublicKeyFormat::X509,
                            nid,
                            key,
                        })
                    })
                    .or(
                        try_parse_public_key_raw_bytes(key_bytes, nid).map(|key| ParsedPublicKey {
                            format,
                            nid,
                            key,
                        }),
                    )
            }
            _ => Err(KeyRejected::unspecified()),
        }
    }
}

pub(crate) fn try_parse_x25519_public_key_bytes(
    key_bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    try_parse_x25519_subject_public_key_info_bytes(key_bytes)
        .or(try_parse_x25519_public_key_raw_bytes(key_bytes))
}

fn try_parse_x25519_public_key_raw_bytes(key_bytes: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    const EXPECTED_PUB_KEY_LEN: usize = 32;
    if key_bytes.len() != EXPECTED_PUB_KEY_LEN {
        return Err(Unspecified);
    }

    Ok(LcPtr::new(unsafe {
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            null_mut(),
            key_bytes.as_ptr(),
            key_bytes.len(),
        )
    })?)
}

fn try_parse_x25519_subject_public_key_info_bytes(
    key_bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    // Try to parse as SubjectPublicKeyInfo first
    let mut cbs = {
        let mut cbs = MaybeUninit::<CBS>::uninit();
        unsafe {
            CBS_init(cbs.as_mut_ptr(), key_bytes.as_ptr(), key_bytes.len());
            cbs.assume_init()
        }
    };
    let evp_pkey = LcPtr::new(unsafe { EVP_parse_public_key(&mut cbs) })?;
    if EVP_PKEY_X25519 != unsafe { EVP_PKEY_id(*evp_pkey.as_const()) } {
        return Err(Unspecified);
    }
    Ok(evp_pkey)
}

/// An ECDSA verification algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaVerificationAlgorithm {
    pub(crate) id: &'static AlgorithmID,
    pub(crate) digest: &'static digest::Algorithm,
    pub(crate) sig_format: EcdsaSignatureFormat,
}

/// An ECDSA signing algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaSigningAlgorithm(pub(crate) &'static EcdsaVerificationAlgorithm);

impl Deref for EcdsaSigningAlgorithm {
    type Target = EcdsaVerificationAlgorithm;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}
impl sealed::Sealed for EcdsaSigningAlgorithm {}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EcdsaSignatureFormat {
    ASN1,
    Fixed,
}

#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub(crate) enum AlgorithmID {
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    ECDSA_P256K1,
}

impl AlgorithmID {
    #[inline]
    pub(crate) fn nid(&'static self) -> i32 {
        match self {
            AlgorithmID::ECDSA_P256 => NID_X9_62_prime256v1,
            AlgorithmID::ECDSA_P384 => NID_secp384r1,
            AlgorithmID::ECDSA_P521 => NID_secp521r1,
            AlgorithmID::ECDSA_P256K1 => NID_secp256k1,
        }
    }
    pub(crate) fn private_key_size(&self) -> usize {
        match self {
            AlgorithmID::ECDSA_P256 | AlgorithmID::ECDSA_P256K1 => 32,
            AlgorithmID::ECDSA_P384 => 48,
            AlgorithmID::ECDSA_P521 => 66,
        }
    }
    // Compressed public key length in bytes
    #[inline]
    const fn compressed_pub_key_len(&self) -> usize {
        match self {
            AlgorithmID::ECDSA_P256 | AlgorithmID::ECDSA_P256K1 => {
                compressed_public_key_size_bytes(256)
            }
            AlgorithmID::ECDSA_P384 => compressed_public_key_size_bytes(384),
            AlgorithmID::ECDSA_P521 => compressed_public_key_size_bytes(521),
        }
    }
}

pub(crate) fn public_key_from_evp_pkey(
    evp_pkey: &LcPtr<EVP_PKEY>,
    algorithm: &'static EcdsaSigningAlgorithm,
) -> Result<PublicKey, Unspecified> {
    let mut pub_key_bytes = [0u8; PUBLIC_KEY_MAX_LEN];
    let key_len = marshal_public_key_to_buffer(&mut pub_key_bytes, evp_pkey, false)?;

    Ok(PublicKey {
        evp_pkey: evp_pkey.clone(),
        algorithm,
        octets: pub_key_bytes[0..key_len].into(),
    })
}

/// Elliptic curve public key.
#[derive(Clone)]
pub struct PublicKey {
    algorithm: &'static EcdsaSigningAlgorithm,
    evp_pkey: LcPtr<EVP_PKEY>,
    octets: Box<[u8]>,
}

impl AsDer<PublicKeyX509Der<'static>> for PublicKey {
    /// Provides the public key as a DER-encoded (X.509) `SubjectPublicKeyInfo` structure.
    /// # Errors
    /// Returns an error if the public key fails to marshal to X.509.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        let ec_group = LcPtr::new(unsafe { EC_GROUP_new_by_curve_name(self.algorithm.id.nid()) })?;
        let ec_point = ec_point_from_bytes(&ec_group, self.as_ref())?;
        let mut ec_key = LcPtr::new(unsafe { EC_KEY_new() })?;
        if 1 != unsafe { EC_KEY_set_group(*ec_key.as_mut(), *ec_group.as_const()) } {
            return Err(Unspecified);
        }
        if 1 != unsafe { EC_KEY_set_public_key(*ec_key.as_mut(), *ec_point.as_const()) } {
            return Err(Unspecified);
        }
        let mut buffer = null_mut::<u8>();
        let len = unsafe { aws_lc::i2d_EC_PUBKEY(*ec_key.as_const(), &mut buffer) };
        if len < 0 || buffer.is_null() {
            return Err(Unspecified);
        }
        let buffer = LcPtr::new(buffer)?;
        let der =
            unsafe { core::slice::from_raw_parts(*buffer.as_const(), len.try_into()?) }.to_owned();

        Ok(PublicKeyX509Der::new(der))
    }
}

impl AsBigEndian<EcPublicKeyCompressedBin<'static>> for PublicKey {
    /// Provides the public key elliptic curve point to a compressed point bytes format.
    /// # Errors
    /// Returns an error if the public key fails to marshal.
    fn as_be_bytes(&self) -> Result<EcPublicKeyCompressedBin<'static>, crate::error::Unspecified> {
        let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(*self.evp_pkey.as_const()) })?;

        let mut buffer = vec![0u8; self.algorithm.0.id.compressed_pub_key_len()];

        let out_len = marshal_ec_public_key_to_buffer(&mut buffer, &ec_key, true)?;

        debug_assert_eq!(buffer.len(), out_len);

        buffer.truncate(out_len);

        Ok(EcPublicKeyCompressedBin::new(buffer))
    }
}

impl AsBigEndian<EcPublicKeyUncompressedBin<'static>> for PublicKey {
    /// Provides the public key elliptic curve point to an uncompressed point bytes format.
    /// # Errors
    /// Returns an error if the public key fails to marshal.
    fn as_be_bytes(
        &self,
    ) -> Result<EcPublicKeyUncompressedBin<'static>, crate::error::Unspecified> {
        let mut uncompressed_bytes = vec![0u8; self.octets.len()];
        uncompressed_bytes.copy_from_slice(&self.octets);
        Ok(EcPublicKeyUncompressedBin::new(uncompressed_bytes))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "EcdsaPublicKey(\"{}\")",
            crate::hex::encode(self.octets.as_ref())
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    /// Serializes the public key in an uncompressed form (X9.62) using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
    #[inline]
    #[cfg(feature = "ring-sig-verify")]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        self.verify_sig(
            public_key.as_slice_less_safe(),
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe(),
        )
    }

    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let mut pkey = ParsedPublicKey::new(public_key, self.id.nid())?;
        match self.sig_format {
            EcdsaSignatureFormat::ASN1 => {
                verify_asn1_signature(self.digest, pkey.key_mut(), msg, signature)
            }
            EcdsaSignatureFormat::Fixed => {
                verify_fixed_signature(self.id, self.digest, pkey.key_mut(), msg, signature)
            }
        }
    }
}

fn verify_fixed_signature(
    alg: &'static AlgorithmID,
    digest: &'static digest::Algorithm,
    public_key: &mut LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Unspecified> {
    let mut out_bytes = null_mut::<u8>();
    let mut out_bytes_len = MaybeUninit::<usize>::uninit();
    let sig = unsafe { ecdsa_sig_from_fixed(alg, signature)? };
    if 1 != unsafe {
        ECDSA_SIG_to_bytes(&mut out_bytes, out_bytes_len.as_mut_ptr(), *sig.as_const())
    } {
        return Err(Unspecified);
    }
    let out_bytes = LcPtr::new(out_bytes)?;
    let signature = unsafe { out_bytes.as_slice(out_bytes_len.assume_init()) };
    verify_asn1_signature(digest, public_key, msg, signature)
}

fn verify_asn1_signature(
    digest: &'static digest::Algorithm,
    public_key: &mut LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Unspecified> {
    let mut md_ctx = DigestContext::new_uninit();

    let digest = digest::match_digest_type(&digest.id);

    if 1 != unsafe {
        EVP_DigestVerifyInit(
            md_ctx.as_mut_ptr(),
            null_mut(),
            *digest,
            null_mut(),
            *public_key.as_mut(),
        )
    } {
        return Err(Unspecified);
    }

    if 1 != indicator_check!(unsafe {
        EVP_DigestVerify(
            md_ctx.as_mut_ptr(),
            signature.as_ptr(),
            signature.len(),
            msg.as_ptr(),
            msg.len(),
        )
    }) {
        return Err(Unspecified);
    }

    Ok(())
}
