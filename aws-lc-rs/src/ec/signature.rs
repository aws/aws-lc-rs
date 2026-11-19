// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aws_lc::{
    ECDSA_SIG_new, ECDSA_SIG_set0, ECDSA_SIG_to_bytes, NID_X9_62_prime256v1, NID_secp256k1,
    NID_secp384r1, NID_secp521r1, BIGNUM, ECDSA_SIG, EVP_PKEY,
};

use crate::digest::Digest;
use crate::ec::compressed_public_key_size_bytes;
use crate::ec::encoding::parse_ec_public_key;
use crate::ec::encoding::sec1::marshal_sec1_public_point;
use crate::encoding::{
    AsBigEndian, AsDer, EcPublicKeyCompressedBin, EcPublicKeyUncompressedBin, PublicKeyX509Der,
};
use crate::error::Unspecified;
use crate::evp_pkey::No_EVP_PKEY_CTX_consumer;
use crate::ptr::{DetachableLcPtr, LcPtr};
use crate::signature::{ParsedPublicKey, ParsedVerificationAlgorithm, VerificationAlgorithm};
use crate::{digest, sealed};
use core::fmt;
use core::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::ptr::null_mut;
#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

/// An ECDSA verification algorithm.
///
/// Prefer the recommended constants in [`crate::signature`] (e.g. `ECDSA_P256_SHA256_ASN1`).
/// Use [`EcdsaVerificationAlgorithm::get`] for a combination that has no constant.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaVerificationAlgorithm {
    pub(crate) id: &'static AlgorithmID,
    pub(crate) digest: &'static digest::Algorithm,
    pub(crate) sig_format: EcdsaSignatureFormat,
}

impl EcdsaVerificationAlgorithm {
    /// Returns a verification algorithm for the given curve, digest, and signature format.
    ///
    /// Prefer the recommended constants in [`crate::signature`], which pair curves with digests
    /// of matching security strength. This lookup supports interoperability with peers or
    /// formats that require other combinations. See [`EcdsaSigningAlgorithm::get`] for the
    /// security considerations of pairing a curve with a digest of a different strength.
    ///
    /// Returns `None` for unsupported digests, including SHA-1. To verify a legacy SHA-1
    /// signature, explicitly select one of the predefined SHA-1 verification constants.
    ///
    /// ```
    /// use aws_lc_rs::digest::SHA512;
    /// use aws_lc_rs::error::Unspecified;
    /// use aws_lc_rs::signature::{
    ///     EcdsaCurve, EcdsaSignatureFormat, EcdsaVerificationAlgorithm, UnparsedPublicKey,
    /// };
    ///
    /// let algorithm =
    ///     EcdsaVerificationAlgorithm::get(EcdsaCurve::P256, &SHA512, EcdsaSignatureFormat::Asn1)
    ///         .ok_or(Unspecified)?;
    /// # let public_key: &[u8] = &[];
    /// let public_key = UnparsedPublicKey::new(algorithm, public_key);
    /// # Ok::<(), aws_lc_rs::error::Unspecified>(())
    /// ```
    #[must_use]
    #[inline]
    pub const fn get(
        curve: EcdsaCurve,
        digest: &'static digest::Algorithm,
        sig_format: EcdsaSignatureFormat,
    ) -> Option<&'static Self> {
        match EcdsaSigningAlgorithm::get(curve, digest, sig_format) {
            Some(algorithm) => Some(algorithm.verification_algorithm()),
            None => None,
        }
    }

    /// The elliptic curve used by this algorithm.
    #[must_use]
    #[inline]
    pub const fn curve(&self) -> EcdsaCurve {
        EcdsaCurve::from_id(self.id)
    }

    /// The digest algorithm used to hash the message.
    #[must_use]
    #[inline]
    pub const fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest
    }

    /// The signature encoding.
    #[must_use]
    #[inline]
    pub const fn signature_format(&self) -> EcdsaSignatureFormat {
        self.sig_format
    }
}

/// An ECDSA signing algorithm.
///
/// Prefer the recommended constants in [`crate::signature`]
/// (e.g. `ECDSA_P256_SHA256_ASN1_SIGNING`). Use [`EcdsaSigningAlgorithm::get`] for a combination
/// that has no constant.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaSigningAlgorithm(pub(crate) EcdsaVerificationAlgorithm);

impl EcdsaSigningAlgorithm {
    /// Returns a signing algorithm for the given curve, digest, and signature format.
    ///
    /// Prefer the recommended constants in [`crate::signature`], which pair curves with digests
    /// of matching security strength. This lookup supports interoperability with peers or
    /// formats that require other combinations, such as a PKCS#10 request whose signature
    /// algorithm is chosen by a third party.
    ///
    /// The lookup can be used in a `const` or at runtime without allocating. It returns `None`
    /// for unsupported digests, including SHA-1. Compare algorithms with `==`, not by address.
    ///
    /// ```
    /// use aws_lc_rs::digest::SHA512;
    /// use aws_lc_rs::rand::SystemRandom;
    /// use aws_lc_rs::signature::{
    ///     EcdsaCurve, EcdsaKeyPair, EcdsaSignatureFormat, EcdsaSigningAlgorithm, KeyPair,
    ///     UnparsedPublicKey,
    /// };
    ///
    /// const ALGORITHM: &EcdsaSigningAlgorithm = match EcdsaSigningAlgorithm::get(
    ///     EcdsaCurve::P256, &SHA512, EcdsaSignatureFormat::Asn1,
    /// ) {
    ///     Some(algorithm) => algorithm,
    ///     None => panic!("unsupported ECDSA parameters"),
    /// };
    /// let key_pair = EcdsaKeyPair::generate(ALGORITHM)?;
    /// let signature = key_pair.sign(&SystemRandom::new(), b"message")?;
    ///
    /// let public_key = UnparsedPublicKey::new(
    ///     ALGORITHM.verification_algorithm(),
    ///     key_pair.public_key().as_ref(),
    /// );
    /// public_key.verify(b"message", signature.as_ref())?;
    /// # Ok::<(), aws_lc_rs::error::Unspecified>(())
    /// ```
    ///
    /// # Security strength
    /// The strength of an ECDSA signature is bounded by the weaker of the curve and the digest.
    /// `Some` means the library supports the combination. This lookup does not compare the
    /// security strengths of the curve and digest.
    #[must_use]
    #[inline]
    pub const fn get(
        curve: EcdsaCurve,
        digest: &'static digest::Algorithm,
        sig_format: EcdsaSignatureFormat,
    ) -> Option<&'static Self> {
        use EcdsaSignatureFormat::{Asn1, Fixed};

        // Each match arm borrows a constant expression, so even runtime choices yield a
        // 'static reference without allocating or reading a static in a const fn on Rust 1.71.
        macro_rules! by_digest {
            ($id:ident, $format:ident; $($hash:ident),+) => {
                match digest.id {
                    $(digest::AlgorithmID::$hash => Some(&Self(EcdsaVerificationAlgorithm {
                        id: &AlgorithmID::$id,
                        digest: &digest::$hash,
                        sig_format: $format,
                    })),)+
                    digest::AlgorithmID::SHA1 => None,
                    #[cfg(all(not(feature = "fips"), feature = "unstable"))]
                    digest::AlgorithmID::KECCAK256 => None,
                }
            };
            ($id:ident, $format:ident) => {
                by_digest!($id, $format; SHA224, SHA256, SHA384, SHA512, SHA512_256,
                    SHA3_256, SHA3_384, SHA3_512)
            };
        }

        match (curve, sig_format) {
            (EcdsaCurve::P256, Asn1) => by_digest!(ECDSA_P256, Asn1),
            (EcdsaCurve::P256, Fixed) => by_digest!(ECDSA_P256, Fixed),
            (EcdsaCurve::P384, Asn1) => by_digest!(ECDSA_P384, Asn1),
            (EcdsaCurve::P384, Fixed) => by_digest!(ECDSA_P384, Fixed),
            (EcdsaCurve::P521, Asn1) => by_digest!(ECDSA_P521, Asn1),
            (EcdsaCurve::P521, Fixed) => by_digest!(ECDSA_P521, Fixed),
            (EcdsaCurve::P256K1, Asn1) => by_digest!(ECDSA_P256K1, Asn1),
            (EcdsaCurve::P256K1, Fixed) => by_digest!(ECDSA_P256K1, Fixed),
        }
    }

    // Deref is not const on Rust 1.71, so expose these accessors directly as well.

    /// The elliptic curve used by this algorithm.
    #[must_use]
    #[inline]
    pub const fn curve(&self) -> EcdsaCurve {
        self.0.curve()
    }

    /// The digest algorithm used to hash the message.
    #[must_use]
    #[inline]
    pub const fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0.digest_algorithm()
    }

    /// The signature encoding.
    #[must_use]
    #[inline]
    pub const fn signature_format(&self) -> EcdsaSignatureFormat {
        self.0.signature_format()
    }

    /// The verification algorithm with the same curve, digest, and signature format.
    #[must_use]
    #[inline]
    pub const fn verification_algorithm(&self) -> &EcdsaVerificationAlgorithm {
        &self.0
    }
}

impl Deref for EcdsaSigningAlgorithm {
    type Target = EcdsaVerificationAlgorithm;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}
impl sealed::Sealed for EcdsaSigningAlgorithm {}

/// The encoding of an ECDSA signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum EcdsaSignatureFormat {
    /// ASN.1 DER-encoded `ECDSA-Sig-Value` (RFC 3279), as used in X.509 and PKCS#10.
    Asn1,
    /// Fixed-length `r || s` (IEEE P1363 / PKCS#11 style), with each value zero-padded to the
    /// curve's scalar size.
    Fixed,
}

/// An elliptic curve usable with ECDSA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum EcdsaCurve {
    /// NIST P-256, also known as secp256r1 or prime256v1.
    P256,
    /// NIST P-384, also known as secp384r1.
    P384,
    /// NIST P-521, also known as secp521r1.
    P521,
    /// secp256k1.
    P256K1,
}

impl EcdsaCurve {
    #[inline]
    pub(crate) const fn from_id(id: &AlgorithmID) -> Self {
        match id {
            AlgorithmID::ECDSA_P256 => EcdsaCurve::P256,
            AlgorithmID::ECDSA_P384 => EcdsaCurve::P384,
            AlgorithmID::ECDSA_P521 => EcdsaCurve::P521,
            AlgorithmID::ECDSA_P256K1 => EcdsaCurve::P256K1,
        }
    }
}

// Adding a curve requires a new variant here, matching arms in the `AlgorithmID` methods below,
// in `EcdsaCurve::from_id`, and in `EcdsaSigningAlgorithm::get`, and a public `EcdsaCurve`
// variant.
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
    pub(crate) const fn private_key_size(&self) -> usize {
        match self {
            AlgorithmID::ECDSA_P256 | AlgorithmID::ECDSA_P256K1 => 32,
            AlgorithmID::ECDSA_P384 => 48,
            AlgorithmID::ECDSA_P521 => 66,
        }
    }
    // Compressed public key length in bytes
    #[inline]
    #[allow(dead_code)]
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

/// Elliptic curve public key.
#[derive(Clone)]
pub struct PublicKey {
    evp_pkey: LcPtr<EVP_PKEY>,
    octets: Box<[u8]>,
}

pub(crate) fn public_key_from_evp_pkey(
    evp_pkey: &LcPtr<EVP_PKEY>,
) -> Result<PublicKey, Unspecified> {
    let pub_key_bytes = marshal_sec1_public_point(evp_pkey, false)?;

    Ok(PublicKey {
        evp_pkey: evp_pkey.clone(),
        octets: pub_key_bytes.into_boxed_slice(),
    })
}

impl AsDer<PublicKeyX509Der<'static>> for PublicKey {
    /// Provides the public key as a DER-encoded (X.509) `SubjectPublicKeyInfo` structure.
    /// # Errors
    /// Returns an error if the public key fails to marshal to X.509.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        let der = self.evp_pkey.as_const().marshal_rfc5280_public_key()?;
        Ok(PublicKeyX509Der::new(der))
    }
}

impl AsBigEndian<EcPublicKeyCompressedBin<'static>> for PublicKey {
    /// Provides the public key elliptic curve point to a compressed point bytes format.
    /// # Errors
    /// Returns an error if the public key fails to marshal.
    fn as_be_bytes(&self) -> Result<EcPublicKeyCompressedBin<'static>, crate::error::Unspecified> {
        let pub_point = marshal_sec1_public_point(&self.evp_pkey, true)?;
        Ok(EcPublicKeyCompressedBin::new(pub_point))
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
        let public_key = parse_ec_public_key(public_key, self.id.nid())?;
        self.verify_ecdsa(msg, signature, &public_key)
    }

    fn verify_digest_sig(
        &self,
        public_key: &[u8],
        digest: &digest::Digest,
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let public_key = parse_ec_public_key(public_key, self.id.nid())?;

        self.verify_digest_ecdsa(digest, signature, &public_key)
    }
}

impl EcdsaVerificationAlgorithm {
    fn verify_ecdsa(
        &self,
        msg: &[u8],
        signature: &[u8],
        public_key: &LcPtr<EVP_PKEY>,
    ) -> Result<(), Unspecified> {
        match self.sig_format {
            EcdsaSignatureFormat::Asn1 => {
                verify_asn1_signature(self.digest, public_key, msg, signature)
            }
            EcdsaSignatureFormat::Fixed => {
                let (out_bytes, out_bytes_len) = convert_fixed_signature(self.id, signature)?;
                verify_asn1_signature(self.digest, public_key, msg, unsafe {
                    out_bytes.as_slice(out_bytes_len)
                })
            }
        }
    }

    fn verify_digest_ecdsa(
        &self,
        digest: &Digest,
        signature: &[u8],
        public_key: &LcPtr<EVP_PKEY>,
    ) -> Result<(), Unspecified> {
        if self.digest != digest.algorithm() {
            return Err(Unspecified);
        }
        match self.sig_format {
            EcdsaSignatureFormat::Asn1 => {
                verify_asn1_digest_signature(digest, public_key, signature)
            }
            EcdsaSignatureFormat::Fixed => {
                let (out_bytes, out_bytes_len) = convert_fixed_signature(self.id, signature)?;
                verify_asn1_digest_signature(digest, public_key, unsafe {
                    out_bytes.as_slice(out_bytes_len)
                })
            }
        }
    }
}

impl ParsedVerificationAlgorithm for EcdsaVerificationAlgorithm {
    fn parsed_verify_sig(
        &self,
        public_key: &ParsedPublicKey,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        self.verify_ecdsa(msg, signature, public_key.key())
    }

    fn parsed_verify_digest_sig(
        &self,
        public_key: &ParsedPublicKey,
        digest: &Digest,
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        self.verify_digest_ecdsa(digest, signature, public_key.key())
    }
}

fn convert_fixed_signature(
    alg: &'static AlgorithmID,
    signature: &[u8],
) -> Result<(LcPtr<u8>, usize), Unspecified> {
    let mut out_bytes = null_mut::<u8>();
    let mut out_bytes_len = MaybeUninit::<usize>::uninit();
    let sig = unsafe { ecdsa_sig_from_fixed(alg, signature)? };
    if 1 != unsafe {
        ECDSA_SIG_to_bytes(
            &mut out_bytes,
            out_bytes_len.as_mut_ptr(),
            sig.as_const_ptr(),
        )
    } {
        return Err(Unspecified);
    }
    Ok((LcPtr::new(out_bytes)?, unsafe {
        out_bytes_len.assume_init()
    }))
}

fn verify_asn1_signature(
    digest_alg: &'static digest::Algorithm,
    public_key: &LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Unspecified> {
    public_key.verify(msg, Some(digest_alg), No_EVP_PKEY_CTX_consumer, signature)
}

fn verify_asn1_digest_signature(
    digest: &Digest,
    public_key: &LcPtr<EVP_PKEY>,
    signature: &[u8],
) -> Result<(), Unspecified> {
    public_key.verify_digest_sig(digest, No_EVP_PKEY_CTX_consumer, signature)
}

#[inline]
unsafe fn ecdsa_sig_from_fixed(
    alg_id: &'static AlgorithmID,
    signature: &[u8],
) -> Result<LcPtr<ECDSA_SIG>, ()> {
    let num_size_bytes = alg_id.private_key_size();
    if signature.len() != 2 * num_size_bytes {
        return Err(());
    }
    let mut r_bn = DetachableLcPtr::<BIGNUM>::try_from(&signature[..num_size_bytes])?;
    let mut s_bn = DetachableLcPtr::<BIGNUM>::try_from(&signature[num_size_bytes..])?;

    let mut ecdsa_sig = LcPtr::new(ECDSA_SIG_new())?;

    if 1 != ECDSA_SIG_set0(ecdsa_sig.as_mut_ptr(), r_bn.as_mut_ptr(), s_bn.as_mut_ptr()) {
        return Err(());
    }
    r_bn.detach();
    s_bn.detach();

    Ok(ecdsa_sig)
}
