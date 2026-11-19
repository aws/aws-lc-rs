// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::ffi::c_int;
use std::fmt::{self, Debug, Formatter};
use std::ops::RangeInclusive;

use crate::aws_lc::{
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen,
    EVP_PKEY_CTX_set_signature_md, RSA_bits, EVP_PKEY, EVP_PKEY_CTX, RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST,
};

use crate::digest::{self, match_digest_type, Digest};
use crate::error::Unspecified;
use crate::ptr::LcPtr;
use crate::rsa::key::{parse_rsa_public_key, KeySize};
use crate::sealed::Sealed;
use crate::signature::{ParsedPublicKey, ParsedVerificationAlgorithm, VerificationAlgorithm};

use super::encoding;
#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

/// The largest modulus, in bits, accepted by [`RsaParameters::get`]. It matches the upper bound
/// of the predefined verification algorithms.
const MAX_MODULUS_BITS: u32 = 8192;

/// An RSA signature padding scheme.
///
/// Used to select an algorithm with [`RsaSignatureEncoding::get`] or [`RsaParameters::get`].
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum RsaSignaturePadding {
    /// RSASSA-PKCS1-v1_5, as described in [RFC 8017 Section 8.2].
    ///
    /// [RFC 8017 Section 8.2]: https://www.rfc-editor.org/rfc/rfc8017#section-8.2
    PKCS1,
    /// RSASSA-PSS, as described in [RFC 8017 Section 8.1]. The message digest is also used
    /// as the MGF1 digest.
    ///
    /// [RFC 8017 Section 8.1]: https://www.rfc-editor.org/rfc/rfc8017#section-8.1
    PSS,
}

/// An RSA-PSS padding salt length.
///
/// If a non-default value is used for a signature, then a matching verification
/// should also use the same value, otherwise it will fail.
///
/// Using this type with PSS is FIPS-approved only when the salt length equals
/// the digest length, i.e. either when [`Self::Digest`] or [`Self::Custom`] is
/// used, and the latter with that digest length given. [`Self::Max`] or any
/// other value passed into [`Self::Custom`] will not be FIPS-approved.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RsaPssSaltLength {
    /// The salt length is set to the length of the used digest algorithm.
    ///
    /// Corresponds to [`RSA_PSS_SALTLEN_DIGEST`]. This is the default.
    #[default]
    Digest,
    /// The salt length is set to the maximum possible length with respect to
    /// the used digest algorithm and public key.
    ///
    /// This corresponds to `emLen - hLen - 2`, where
    ///  * `emLen` is `(pub_key_size_bits + 6) / 8`, so depends on the mod size;
    ///  * `hLen` is the digest algorithm's output length;
    ///
    /// A verification of a signature produced using this salt length may only
    /// work when also using this maximum length, not any length up to it.
    Max,
    /// The salt length is set to the given custom value.
    ///
    /// The passed value is not particularly checked here, so may ultimately
    /// result in failures.
    Custom(u16),
}

impl RsaPssSaltLength {
    pub(crate) fn into_value(
        self,
        algorithm: &'static digest::Algorithm,
        pkey: &LcPtr<EVP_PKEY>,
    ) -> Result<c_int, ()> {
        match self {
            RsaPssSaltLength::Digest => Ok(RSA_PSS_SALTLEN_DIGEST),
            RsaPssSaltLength::Max => {
                let digest_len = u16::try_from(algorithm.output_len()).map_err(|_| ())?;
                let pkey_size_bits =
                    u16::try_from(pkey.as_const().key_size_bits()).map_err(|_| ())?;
                let em_len = pkey_size_bits.checked_add(6).ok_or(())? / 8;
                let max_len = em_len
                    .checked_sub(digest_len)
                    .ok_or(())?
                    .checked_sub(2)
                    .ok_or(())?;
                Ok(max_len.into())
            }
            RsaPssSaltLength::Custom(val) => Ok(val.into()),
        }
    }
}

/// Parameters for RSA verification.
///
/// Prefer the recommended constants in [`crate::signature`] (e.g.
/// `RSA_PKCS1_2048_8192_SHA256`). Use [`RsaParameters::get`] for a combination that has no
/// constant.
///
/// Two values are equal when they denote the same verification algorithm, e.g.
/// `RSA_PKCS1_2048_8192_SHA256`. Algorithms differing in digest algorithm,
/// padding scheme, RSA PSS salt length, or modulus size range compare unequal.
/// In short, it is equality of configuration, not equality of effective behavior.
// Deliberately neither `Clone` nor `Copy`, although every field is `Copy`. Either impl would
// change how existing callers compile: `.clone()` on a `&RsaParameters` would return a value
// instead of the reference, and a closure that returns a captured value would borrow it instead
// of moving it. `copy_with_pss_salt_length` covers deriving a value from a borrowed one. The
// `rsa_algorithm_ownership_compatibility` test guards both cases.
#[derive(Eq, PartialEq)]
pub struct RsaParameters {
    digest_alg: &'static digest::Algorithm,
    padding: RsaSignaturePadding,
    pss_salt_length: RsaPssSaltLength,
    min_modulus_bits: u32,
    max_modulus_bits: u32,
}

impl RsaParameters {
    /// Returns verification parameters for the given padding scheme, digest, and minimum key
    /// size.
    ///
    /// Prefer the recommended constants in [`crate::signature`]. This lookup supports
    /// interoperability with peers or formats that require other combinations, such as an
    /// X.509 structure whose signature algorithm is chosen by a third party.
    ///
    /// The returned parameters accept keys of `min_key_size` to 8192 bits. For
    /// [`RsaSignaturePadding::PSS`], the salt length is the digest length. For another length,
    /// call [`Self::copy_with_pss_salt_length`] on the result.
    ///
    /// The lookup can be used in a `const` or at runtime without allocating. It returns
    /// `None` for unsupported digests, including SHA-1. To verify a legacy SHA-1 signature, or
    /// one made with a 1024-bit key, explicitly select one of the predefined
    /// `*_FOR_LEGACY_USE_ONLY` constants. Compare parameters with `==`, not by address.
    ///
    /// ```
    /// use aws_lc_rs::digest::SHA3_256;
    /// use aws_lc_rs::error::Unspecified;
    /// use aws_lc_rs::rsa::KeySize;
    /// use aws_lc_rs::signature::{RsaParameters, RsaSignaturePadding, UnparsedPublicKey};
    ///
    /// let algorithm = RsaParameters::get(RsaSignaturePadding::PSS, &SHA3_256, KeySize::Rsa3072)
    ///     .ok_or(Unspecified)?;
    /// # let public_key: &[u8] = &[];
    /// let public_key = UnparsedPublicKey::new(algorithm, public_key);
    /// # Ok::<(), aws_lc_rs::error::Unspecified>(())
    /// ```
    ///
    /// # Security strength
    /// The strength of an RSA signature is bounded by the weaker of the key and the digest.
    /// `Some` means the library supports the combination. This lookup does not compare the
    /// security strengths of the key size and digest, and it does not check the combination
    /// against the policy of any protocol.
    #[must_use]
    #[inline]
    pub const fn get(
        padding: RsaSignaturePadding,
        digest: &digest::Algorithm,
        min_key_size: KeySize,
    ) -> Option<&'static Self> {
        use RsaSignaturePadding::{PKCS1, PSS};

        // Each match arm borrows a constant expression, so even runtime choices yield a
        // 'static reference without allocating or reading a static in a const fn on Rust 1.71.
        macro_rules! by_digest {
            ($padding:ident, $min_bits:literal; $($hash:ident),+) => {
                match digest.id {
                    $(digest::AlgorithmID::$hash => Some(&Self {
                        digest_alg: &digest::$hash,
                        padding: RsaSignaturePadding::$padding,
                        pss_salt_length: RsaPssSaltLength::Digest,
                        min_modulus_bits: $min_bits,
                        max_modulus_bits: MAX_MODULUS_BITS,
                    }),)+
                    digest::AlgorithmID::SHA1 => None,
                    #[cfg(all(not(feature = "fips"), feature = "unstable"))]
                    digest::AlgorithmID::KECCAK256 => None,
                }
            };
            ($padding:ident, $min_bits:literal) => {
                by_digest!($padding, $min_bits; SHA224, SHA256, SHA384, SHA512, SHA512_256,
                    SHA3_256, SHA3_384, SHA3_512)
            };
        }

        match (padding, min_key_size) {
            (PKCS1, KeySize::Rsa2048) => by_digest!(PKCS1, 2048),
            (PKCS1, KeySize::Rsa3072) => by_digest!(PKCS1, 3072),
            (PKCS1, KeySize::Rsa4096) => by_digest!(PKCS1, 4096),
            (PKCS1, KeySize::Rsa8192) => by_digest!(PKCS1, 8192),
            (PSS, KeySize::Rsa2048) => by_digest!(PSS, 2048),
            (PSS, KeySize::Rsa3072) => by_digest!(PSS, 3072),
            (PSS, KeySize::Rsa4096) => by_digest!(PSS, 4096),
            (PSS, KeySize::Rsa8192) => by_digest!(PSS, 8192),
        }
    }

    /// The digest algorithm used to hash the message.
    #[must_use]
    #[inline]
    pub const fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_alg
    }

    /// The padding scheme.
    #[must_use]
    #[inline]
    pub const fn padding(&self) -> RsaSignaturePadding {
        self.padding
    }

    /// The RSA-PSS salt length. This is ignored for [`RsaSignaturePadding::PKCS1`].
    #[must_use]
    #[inline]
    pub const fn pss_salt_length(&self) -> RsaPssSaltLength {
        self.pss_salt_length
    }

    #[inline]
    pub(crate) fn bit_size_range(&self) -> RangeInclusive<u32> {
        self.min_modulus_bits..=self.max_modulus_bits
    }
}

impl ParsedVerificationAlgorithm for RsaParameters {
    fn parsed_verify_sig(
        &self,
        public_key: &ParsedPublicKey,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = public_key.key();
        verify_rsa_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_salt_length,
            evp_pkey,
            msg,
            signature,
            &self.bit_size_range(),
        )
    }

    fn parsed_verify_digest_sig(
        &self,
        public_key: &ParsedPublicKey,
        digest: &Digest,
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = public_key.key();
        verify_rsa_digest_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_salt_length,
            evp_pkey,
            digest,
            signature,
            &self.bit_size_range(),
        )
    }
}

impl VerificationAlgorithm for RsaParameters {
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
        let evp_pkey = parse_rsa_public_key(public_key)?;
        verify_rsa_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_salt_length,
            &evp_pkey,
            msg,
            signature,
            &self.bit_size_range(),
        )
    }

    fn verify_digest_sig(
        &self,
        public_key: &[u8],
        digest: &Digest,
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = parse_rsa_public_key(public_key)?;
        verify_rsa_digest_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_salt_length,
            &evp_pkey,
            digest,
            signature,
            &self.bit_size_range(),
        )
    }
}

impl Sealed for RsaParameters {}

impl Debug for RsaParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Reproduces the name of the predefined constant for every combination that has one,
        // e.g. `RSA_PKCS1_2048_8192_SHA256`.
        write!(
            f,
            "{{ RSA_{:?}_{}_{}_{:?}",
            self.padding, self.min_modulus_bits, self.max_modulus_bits, self.digest_alg
        )?;

        if self.min_modulus_bits < 2048 || is_sha1(self.digest_alg) {
            write!(f, "_FOR_LEGACY_USE_ONLY")?;
        }

        if self.pss_salt_length != RsaPssSaltLength::Digest {
            write!(f, ", RSA-PSS salt length: {:?}", self.pss_salt_length)?;
        }

        write!(f, " }}")?;
        Ok(())
    }
}

impl RsaParameters {
    pub(crate) const fn new(
        digest_alg: &'static digest::Algorithm,
        padding: RsaSignaturePadding,
        range: RangeInclusive<u32>,
    ) -> Self {
        Self {
            digest_alg,
            padding,
            pss_salt_length: RsaPssSaltLength::Digest,
            min_modulus_bits: *range.start(),
            max_modulus_bits: *range.end(),
        }
    }

    /// Sets the RSA-PSS salt length to the given value.
    ///
    /// This is ignored for PKCS#1 v1.5 parameters. For a borrowed value from [`Self::get`],
    /// use [`Self::copy_with_pss_salt_length`].
    #[must_use]
    pub const fn with_pss_salt_length(mut self, saltlen: RsaPssSaltLength) -> Self {
        self.pss_salt_length = saltlen;
        self
    }

    /// Returns new parameters with the given PSS salt length, leaving `self` unchanged.
    /// The salt length is ignored for PKCS#1 v1.5.
    ///
    /// This does the same as [`Self::with_pss_salt_length`], but borrows `self` instead of
    /// consuming it. `RsaParameters` is not `Clone`, so this is how to derive parameters from
    /// a borrowed value, such as the `&'static` reference returned by [`Self::get`].
    ///
    /// [`UnparsedPublicKey`] and [`ParsedPublicKey`] take a `'static` reference to the
    /// verification algorithm. If the salt length is known at compile time, define a constant
    /// and pass it by reference:
    ///
    /// ```
    /// use aws_lc_rs::digest::SHA3_256;
    /// use aws_lc_rs::rsa::KeySize;
    /// use aws_lc_rs::signature::{RsaParameters, RsaPssSaltLength, RsaSignaturePadding};
    ///
    /// const VERIFY_ALG: RsaParameters =
    ///     match RsaParameters::get(RsaSignaturePadding::PSS, &SHA3_256, KeySize::Rsa2048) {
    ///         Some(params) => params.copy_with_pss_salt_length(RsaPssSaltLength::Custom(20)),
    ///         None => panic!("unsupported RSA parameters"),
    ///     };
    /// ```
    ///
    /// If the salt length is only known at runtime, use [`VerificationAlgorithm::verify_sig`]
    /// on the parameters directly:
    ///
    /// ```
    /// use aws_lc_rs::digest;
    /// use aws_lc_rs::error::Unspecified;
    /// use aws_lc_rs::rsa::KeySize;
    /// use aws_lc_rs::signature::{
    ///     RsaParameters, RsaPssSaltLength, RsaSignaturePadding, VerificationAlgorithm,
    /// };
    ///
    /// # fn verify(
    /// #     digest_alg: &digest::Algorithm,
    /// #     salt_len: u16,
    /// #     public_key: &[u8],
    /// #     msg: &[u8],
    /// #     sig: &[u8],
    /// # ) -> Result<(), Unspecified> {
    /// let algorithm = RsaParameters::get(RsaSignaturePadding::PSS, digest_alg, KeySize::Rsa2048)
    ///     .ok_or(Unspecified)?
    ///     .copy_with_pss_salt_length(RsaPssSaltLength::Custom(salt_len));
    /// algorithm.verify_sig(public_key, msg, sig)
    /// # }
    /// ```
    ///
    /// [`UnparsedPublicKey`]: crate::signature::UnparsedPublicKey
    #[must_use]
    pub const fn copy_with_pss_salt_length(&self, saltlen: RsaPssSaltLength) -> Self {
        Self {
            pss_salt_length: saltlen,
            ..*self
        }
    }

    /// Parses a DER-encoded `RSAPublicKey` structure (RFC 8017) to determine its size in bits.
    ///
    /// # Errors
    /// `error::Unspecified` on parse error.
    pub fn public_modulus_len(public_key: &[u8]) -> Result<u32, Unspecified> {
        let rsa = encoding::rfc8017::decode_public_key_der(public_key)?;
        Ok(unsafe { RSA_bits(rsa.as_const().get_rsa()?.as_const_ptr()) })
    }

    #[must_use]
    /// Minimum modulus length in bits.
    pub const fn min_modulus_len(&self) -> u32 {
        self.min_modulus_bits
    }

    #[must_use]
    /// Maximum modulus length in bits.
    pub const fn max_modulus_len(&self) -> u32 {
        self.max_modulus_bits
    }
}

#[inline]
fn is_sha1(algorithm: &digest::Algorithm) -> bool {
    matches!(algorithm.id, digest::AlgorithmID::SHA1)
}

/// Encoding type for an RSA signature
///
/// Prefer the recommended constants in [`crate::signature`] (e.g. `RSA_PSS_SHA256`). Use
/// [`RsaSignatureEncoding::get`] for a combination that has no constant.
///
/// Two values are equal when they have the same digest algorithm, padding scheme, and RSA
/// PSS salt length.
// Deliberately neither `Clone` nor `Copy`; see the note on `RsaParameters`.
#[allow(clippy::module_name_repetitions)]
#[derive(Eq, PartialEq)]
pub struct RsaSignatureEncoding {
    digest_alg: &'static digest::Algorithm,
    padding: RsaSignaturePadding,
    pss_salt_length: RsaPssSaltLength,
}

impl RsaSignatureEncoding {
    pub(crate) const fn new(
        digest_alg: &'static digest::Algorithm,
        padding: RsaSignaturePadding,
    ) -> Self {
        Self {
            digest_alg,
            padding,
            pss_salt_length: RsaPssSaltLength::Digest,
        }
    }

    /// Returns a signature encoding for the given padding scheme and digest.
    ///
    /// Prefer the recommended constants in [`crate::signature`]. This lookup supports
    /// interoperability with peers or formats that require other combinations, such as a
    /// PKCS#10 request whose signature algorithm is chosen by a third party.
    ///
    /// For [`RsaSignaturePadding::PSS`], the salt length is the digest length. For another
    /// length, call [`Self::copy_with_pss_salt_length`] on the result.
    ///
    /// The lookup can be used in a `const` or at runtime without allocating. It returns
    /// `None` for unsupported digests, including SHA-1. Compare encodings with `==`, not by
    /// address.
    ///
    /// ```
    /// use aws_lc_rs::digest::SHA3_256;
    /// use aws_lc_rs::rand::SystemRandom;
    /// use aws_lc_rs::rsa::KeySize;
    /// use aws_lc_rs::signature::{
    ///     KeyPair, RsaKeyPair, RsaParameters, RsaSignatureEncoding, RsaSignaturePadding,
    ///     UnparsedPublicKey,
    /// };
    ///
    /// const SIGNING: &RsaSignatureEncoding =
    ///     match RsaSignatureEncoding::get(RsaSignaturePadding::PSS, &SHA3_256) {
    ///         Some(encoding) => encoding,
    ///         None => panic!("unsupported RSA parameters"),
    ///     };
    /// const VERIFYING: &RsaParameters =
    ///     match RsaParameters::get(RsaSignaturePadding::PSS, &SHA3_256, KeySize::Rsa2048) {
    ///         Some(parameters) => parameters,
    ///         None => panic!("unsupported RSA parameters"),
    ///     };
    ///
    /// let key_pair = RsaKeyPair::generate(KeySize::Rsa2048)?;
    /// let mut signature = vec![0; key_pair.public_modulus_len()];
    /// key_pair.sign(SIGNING, &SystemRandom::new(), b"message", &mut signature)?;
    ///
    /// let public_key = UnparsedPublicKey::new(VERIFYING, key_pair.public_key().as_ref());
    /// public_key.verify(b"message", &signature)?;
    /// # Ok::<(), aws_lc_rs::error::Unspecified>(())
    /// ```
    ///
    /// # Security strength
    /// The strength of an RSA signature is bounded by the weaker of the key and the digest.
    /// `Some` means the library supports the combination. This lookup does not compare the
    /// security strengths of the key size and digest, and it does not check the combination
    /// against the policy of any protocol.
    #[must_use]
    #[inline]
    pub const fn get(
        padding: RsaSignaturePadding,
        digest: &digest::Algorithm,
    ) -> Option<&'static Self> {
        // Each match arm borrows a constant expression, so even runtime choices yield a
        // 'static reference without allocating or reading a static in a const fn on Rust 1.71.
        macro_rules! by_digest {
            ($padding:ident; $($hash:ident),+) => {
                match digest.id {
                    $(digest::AlgorithmID::$hash => Some(&Self {
                        digest_alg: &digest::$hash,
                        padding: RsaSignaturePadding::$padding,
                        pss_salt_length: RsaPssSaltLength::Digest,
                    }),)+
                    digest::AlgorithmID::SHA1 => None,
                    #[cfg(all(not(feature = "fips"), feature = "unstable"))]
                    digest::AlgorithmID::KECCAK256 => None,
                }
            };
            ($padding:ident) => {
                by_digest!($padding; SHA224, SHA256, SHA384, SHA512, SHA512_256,
                    SHA3_256, SHA3_384, SHA3_512)
            };
        }

        match padding {
            RsaSignaturePadding::PKCS1 => by_digest!(PKCS1),
            RsaSignaturePadding::PSS => by_digest!(PSS),
        }
    }

    /// The digest algorithm used to hash the message.
    #[must_use]
    #[inline]
    pub const fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_alg
    }

    /// The padding scheme.
    #[must_use]
    #[inline]
    pub const fn padding(&self) -> RsaSignaturePadding {
        self.padding
    }

    /// The RSA-PSS salt length. This is ignored for [`RsaSignaturePadding::PKCS1`].
    #[must_use]
    #[inline]
    pub const fn pss_salt_length(&self) -> RsaPssSaltLength {
        self.pss_salt_length
    }

    /// Sets the PSS salt length to the given value.
    ///
    /// This is ignored for PKCS#1 v1.5 parameters. For a borrowed value from [`Self::get`],
    /// use [`Self::copy_with_pss_salt_length`].
    ///
    /// The result can be passed directly to [`RsaKeyPair::sign`], including when the salt
    /// length is only known at runtime:
    ///
    /// ```
    /// use aws_lc_rs::rand::SystemRandom;
    /// use aws_lc_rs::signature::{self, RsaKeyPair, RsaPssSaltLength};
    ///
    /// # fn sign(key_pair: &RsaKeyPair, salt_len: u16, msg: &[u8], sig: &mut [u8])
    /// # -> Result<(), aws_lc_rs::error::Unspecified> {
    /// let encoding =
    ///     signature::RSA_PSS_SHA256.with_pss_salt_length(RsaPssSaltLength::Custom(salt_len));
    /// key_pair.sign(&encoding, &SystemRandom::new(), msg, sig)
    /// # }
    /// ```
    ///
    /// [`RsaKeyPair::sign`]: crate::signature::RsaKeyPair::sign
    #[must_use]
    pub const fn with_pss_salt_length(mut self, saltlen: RsaPssSaltLength) -> Self {
        self.pss_salt_length = saltlen;
        self
    }

    /// Returns a new encoding with the given PSS salt length, leaving `self` unchanged.
    /// The salt length is ignored for PKCS#1 v1.5.
    ///
    /// This does the same as [`Self::with_pss_salt_length`], but borrows `self` instead of
    /// consuming it. `RsaSignatureEncoding` is not `Clone`, so this is how to derive an
    /// encoding from a borrowed value, such as the `&'static` reference returned by
    /// [`Self::get`]:
    ///
    /// ```
    /// use aws_lc_rs::digest;
    /// use aws_lc_rs::error::Unspecified;
    /// use aws_lc_rs::rand::SystemRandom;
    /// use aws_lc_rs::signature::{
    ///     RsaKeyPair, RsaPssSaltLength, RsaSignatureEncoding, RsaSignaturePadding,
    /// };
    ///
    /// # fn sign(
    /// #     key_pair: &RsaKeyPair,
    /// #     digest_alg: &digest::Algorithm,
    /// #     salt_len: u16,
    /// #     msg: &[u8],
    /// #     sig: &mut [u8],
    /// # ) -> Result<(), Unspecified> {
    /// let encoding = RsaSignatureEncoding::get(RsaSignaturePadding::PSS, digest_alg)
    ///     .ok_or(Unspecified)?
    ///     .copy_with_pss_salt_length(RsaPssSaltLength::Custom(salt_len));
    /// key_pair.sign(&encoding, &SystemRandom::new(), msg, sig)
    /// # }
    /// ```
    #[must_use]
    pub const fn copy_with_pss_salt_length(&self, saltlen: RsaPssSaltLength) -> Self {
        Self {
            pss_salt_length: saltlen,
            ..*self
        }
    }
}

impl Sealed for RsaSignatureEncoding {}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[allow(clippy::module_name_repetitions)]
pub trait RsaEncoding: 'static + Sync + Sealed + Debug {
    /// The signature encoding.
    fn encoding(&self) -> &RsaSignatureEncoding;
}

impl RsaEncoding for RsaSignatureEncoding {
    fn encoding(&self) -> &RsaSignatureEncoding {
        self
    }
}

impl Debug for RsaSignatureEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        // Reproduces the name of the predefined constant for every combination that has one,
        // e.g. `RSA_PSS_SHA256`.
        write!(f, "{{ RSA_{:?}_{:?}", self.padding, self.digest_alg)?;

        if self.pss_salt_length != RsaPssSaltLength::Digest {
            write!(f, ", RSA-PSS salt length: {:?}", self.pss_salt_length)?;
        }

        write!(f, " }}")?;
        Ok(())
    }
}

#[inline]
pub(super) fn configure_signature_padding(
    pctx: *mut EVP_PKEY_CTX,
    padding: RsaSignaturePadding,
    saltlen: RsaPssSaltLength,
    algorithm: &'static digest::Algorithm,
    pkey: &LcPtr<EVP_PKEY>,
) -> Result<(), ()> {
    // An RSA-PSS key can supply its own defaults. The selected algorithm must agree
    // with the key's restrictions, not silently inherit its padding or MGF1 digest.
    let mode = match padding {
        RsaSignaturePadding::PKCS1 => RSA_PKCS1_PADDING,
        RsaSignaturePadding::PSS => RSA_PKCS1_PSS_PADDING,
    };
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, mode) } {
        return Err(());
    }
    if padding == RsaSignaturePadding::PSS {
        let md = match_digest_type(&algorithm.id);
        if 1 != unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md.as_const_ptr()) } {
            return Err(());
        }
        let saltlen = saltlen.into_value(algorithm, pkey)?;
        if 1 != unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen) } {
            return Err(());
        }
    }
    Ok(())
}

#[inline]
pub(crate) fn verify_rsa_signature(
    algorithm: &'static digest::Algorithm,
    padding: RsaSignaturePadding,
    pss_salt_length: RsaPssSaltLength,
    public_key: &LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    if !allowed_bit_size.contains(&public_key.as_const().key_size_bits().try_into()?) {
        return Err(Unspecified);
    }

    let padding_fn =
        |pctx| configure_signature_padding(pctx, padding, pss_salt_length, algorithm, public_key);
    public_key.verify(msg, Some(algorithm), Some(padding_fn), signature)
}

#[inline]
pub(crate) fn verify_rsa_digest_signature(
    algorithm: &'static digest::Algorithm,
    padding: RsaSignaturePadding,
    pss_salt_length: RsaPssSaltLength,
    public_key: &LcPtr<EVP_PKEY>,
    digest: &Digest,
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    // Enforced here so no caller can omit it; the ctx below is configured from `digest`.
    if algorithm != digest.algorithm() {
        return Err(Unspecified);
    }

    if !allowed_bit_size.contains(&public_key.as_const().key_size_bits().try_into()?) {
        return Err(Unspecified);
    }

    let padding_fn = Some({
        |pctx: *mut EVP_PKEY_CTX| {
            let evp_md = match_digest_type(&digest.algorithm().id);
            if 1 != unsafe { EVP_PKEY_CTX_set_signature_md(pctx, evp_md.as_const_ptr()) } {
                return Err(());
            }
            configure_signature_padding(pctx, padding, pss_salt_length, algorithm, public_key)
        }
    });

    public_key.verify_digest_sig(digest, padding_fn, signature)
}
