// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// *R* and *r* in Montgomery math refer to different things, so we always use
// `R` to refer to *R* to avoid confusion, even when that's against the normal
// naming conventions. Also the standard camelCase names are used for `KeyPair`
// components.

use crate::digest::digest_ctx::DigestContext;
use crate::error::{KeyRejected, Unspecified};
use crate::fips::indicator_check;
#[cfg(feature = "ring-io")]
use crate::io;
use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};
use crate::sealed::Sealed;
use crate::signature::{KeyPair, VerificationAlgorithm};
use crate::{cbs, digest, rand, test};
#[cfg(feature = "fips")]
use aws_lc::RSA_check_fips;
#[cfg(not(feature = "fips"))]
use aws_lc::RSA_check_key;
use aws_lc::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit,
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_assign_RSA,
    EVP_PKEY_get0_RSA, EVP_PKEY_new, RSA_bits, RSA_get0_e, RSA_get0_n, RSA_get0_p, RSA_get0_q,
    RSA_new, RSA_parse_private_key, RSA_parse_public_key, RSA_public_key_to_bytes, RSA_set0_key,
    RSA_size, EVP_PKEY, EVP_PKEY_CTX, RSA, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST,
};
use core::fmt;
use mirai_annotations::verify_unreachable;

use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::RangeInclusive;
use std::ptr::{null, null_mut};

#[cfg(any(feature = "ring-sig-verify", feature = "ring-io"))]
use untrusted::Input;
use zeroize::Zeroize;

/// An RSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct RsaKeyPair {
    // https://github.com/aws/aws-lc/blob/ebaa07a207fee02bd68fe8d65f6b624afbf29394/include/openssl/evp.h#L295
    // An |EVP_PKEY| object represents a public or private RSA key. A given object may be
    // used concurrently on multiple threads by non-mutating functions, provided no
    // other thread is concurrently calling a mutating function. Unless otherwise
    // documented, functions which take a |const| pointer are non-mutating and
    // functions which take a non-|const| pointer are mutating.
    evp_pkey: LcPtr<EVP_PKEY>,
    serialized_public_key: RsaSubjectPublicKey,
}

impl Sealed for RsaKeyPair {}
unsafe impl Send for RsaKeyPair {}
unsafe impl Sync for RsaKeyPair {}

impl RsaKeyPair {
    fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Result<Self, KeyRejected> {
        unsafe {
            let rsa_key = evp_pkey.get_rsa()?;
            let serialized_public_key = RsaSubjectPublicKey::new(&rsa_key.as_const())?;
            Ok(RsaKeyPair {
                evp_pkey,
                serialized_public_key,
            })
        }
    }

    /// Parses an unencrypted PKCS#8-encoded RSA private key.
    ///
    /// Only two-prime (not multi-prime) keys are supported. The public modulus
    /// (n) must be at least 2047 bits. The public modulus must be no larger
    /// than 4096 bits. It is recommended that the public modulus be exactly
    /// 2048 or 3072 bits. The public exponent must be at least 65537.
    ///
    /// The following will generate a 2048-bit RSA private key of the correct form using
    /// OpenSSL's command line tool:
    ///
    /// ```sh
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:2048 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-2048-private-key.pk8
    /// ```
    ///
    /// The following will generate a 3072-bit RSA private key of the correct form:
    ///
    /// ```sh
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:3072 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-3072-private-key.pk8
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are stored in
    /// the Base64 “PEM” format without the PKCS#8 wrapper. Such keys can be
    /// converted to binary PKCS#8 form using the OpenSSL command line tool like
    /// this:
    ///
    /// ```sh
    /// openssl pkcs8 -topk8 -nocrypt -outform der \
    ///     -in rsa-2048-private-key.pem > rsa-2048-private-key.pk8
    /// ```
    ///
    /// Base64 (“PEM”) PKCS#8-encoded keys can be converted to the binary PKCS#8
    /// form like this:
    ///
    /// ```sh
    /// openssl pkcs8 -nocrypt -outform der \
    ///     -in rsa-2048-private-key.pem > rsa-2048-private-key.pk8
    /// ```
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an RSA private key or if the key is otherwise
    /// not acceptable.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let evp_pkey = LcPtr::try_from(pkcs8)?;
            Self::validate_rsa_pkey(&evp_pkey)?;
            Self::new(evp_pkey)
        }
    }

    /// Parses a DER-encoded `RSAPrivateKey` structure (RFC 8017).
    ///
    /// # Errors
    /// `error:KeyRejected` on error.
    pub fn from_der(input: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let pkey = build_private_RSA_PKEY(input)?;
            Self::validate_rsa_pkey(&pkey)?;
            Self::new(pkey)
        }
    }

    const MIN_RSA_PRIME_BITS: u32 = 1024;
    const MAX_RSA_PRIME_BITS: u32 = 4096;

    /// ⚠️ Function assumes that `aws_lc::RSA_check_key` / `aws_lc::RSA_validate_key` has already been invoked beforehand.
    /// `aws_lc::RSA_validate_key` is already invoked by `aws_lc::EVP_parse_private_key` / `aws_lc::RSA_parse_private_key`.
    /// If the `EVP_PKEY` was constructed through another mechanism, then the key should be validated through the use of
    /// one those verifier functions first.
    unsafe fn validate_rsa_pkey(rsa: &LcPtr<EVP_PKEY>) -> Result<(), KeyRejected> {
        let rsa = rsa.get_rsa()?.as_const();

        let p = ConstPointer::new(RSA_get0_p(*rsa))?;
        let q = ConstPointer::new(RSA_get0_q(*rsa))?;
        let p_bits = p.num_bits();
        let q_bits = q.num_bits();

        if p_bits != q_bits {
            return Err(KeyRejected::inconsistent_components());
        }

        if p_bits < Self::MIN_RSA_PRIME_BITS {
            return Err(KeyRejected::too_small());
        }
        if p_bits > Self::MAX_RSA_PRIME_BITS {
            return Err(KeyRejected::too_large());
        }

        if p_bits % 512 != 0 {
            return Err(KeyRejected::private_modulus_len_not_multiple_of_512_bits());
        }

        let e = ConstPointer::new(RSA_get0_e(*rsa))?;
        let min_exponent = DetachableLcPtr::try_from(65537)?;
        match e.compare(&min_exponent.as_const()) {
            Ordering::Less => Err(KeyRejected::too_small()),
            Ordering::Equal | Ordering::Greater => Ok(()),
        }?;

        // For the FIPS feature this will perform the necessary public-key validaiton steps and pairwise consistency tests.
        // TODO: This also result in another call to `aws_lc::RSA_validate_key`, meaning duplicate effort is performed
        // even after having already performing this operation during key parsing. Ideally the FIPS specific checks
        // could be pulled out and invoked seperatly from the standard checks.
        #[cfg(feature = "fips")]
        if 1 != RSA_check_fips(*rsa as *mut RSA) {
            return Err(KeyRejected::inconsistent_components());
        }

        Ok(())
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
        unsafe {
            let rsa = build_public_RSA_PKEY(public_key)?;
            verify_RSA(self.0, self.1, &rsa, msg, signature, &self.2)
        }
    }
}

impl RsaKeyPair {
    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    // # FIPS
    // The following conditions must be met:
    // * RSA Key Sizes: 2048, 3072, 4096
    // * Digest Algorithms: SHA256, SHA384, SHA512
    //
    /// # Errors
    /// `error::Unspecified` on error.
    /// With "fips" feature enabled, errors if digest length is greater than `u32::MAX`.
    pub fn sign(
        &self,
        padding_alg: &'static dyn RsaEncoding,
        _rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Unspecified> {
        let encoding = padding_alg.encoding();

        let mut md_ctx = digest::digest_ctx::DigestContext::new_uninit();
        let mut pctx = null_mut::<EVP_PKEY_CTX>();
        let digest = digest::match_digest_type(&encoding.0.id);

        if 1 != unsafe {
            EVP_DigestSignInit(
                md_ctx.as_mut_ptr(),
                &mut pctx,
                *digest,
                null_mut(),
                *self.evp_pkey,
            )
        } {
            return Err(Unspecified);
        }

        if let RsaPadding::RSA_PKCS1_PSS_PADDING = encoding.1 {
            // AWS-LC owns pctx, check for null and then immediately detach so we don't drop it.
            let pctx = DetachableLcPtr::new(pctx)?.detach();
            configure_rsa_pkcs1_pss_padding(pctx)?;
        }

        let max_len = get_signature_length(&mut md_ctx)?;

        debug_assert!(signature.len() >= max_len);

        let computed_signature = compute_rsa_signature(&mut md_ctx, msg, signature)?;

        debug_assert!(computed_signature.len() >= signature.len());

        Ok(())
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    #[must_use]
    pub fn public_modulus_len(&self) -> usize {
        // This was already validated to be an RSA key so this can't fail
        match self.evp_pkey.get_rsa() {
            Ok(rsa) => {
                // https://github.com/awslabs/aws-lc/blob/main/include/openssl/rsa.h#L99
                unsafe { (RSA_size(*rsa)) as usize }
            }
            Err(_) => verify_unreachable!(),
        }
    }
}

impl Debug for RsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaKeyPair {{ public_key: {:?} }}",
            self.serialized_public_key
        ))
    }
}

#[inline]
fn configure_rsa_pkcs1_pss_padding(pctx: *mut EVP_PKEY_CTX) -> Result<(), ()> {
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) } {
        return Err(());
    };
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) } {
        return Err(());
    };
    Ok(())
}

#[inline]
fn get_signature_length(ctx: &mut DigestContext) -> Result<usize, Unspecified> {
    let mut out_sig_len = MaybeUninit::<usize>::uninit();

    // determine signature size
    if 1 != unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            null_mut(),
            out_sig_len.as_mut_ptr(),
            null(),
            0,
        )
    } {
        return Err(Unspecified);
    }

    Ok(unsafe { out_sig_len.assume_init() })
}

#[inline]
fn compute_rsa_signature<'a>(
    ctx: &mut DigestContext,
    message: &[u8],
    signature: &'a mut [u8],
) -> Result<&'a mut [u8], Unspecified> {
    let mut out_sig_len = signature.len();

    if 1 != indicator_check!(unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut out_sig_len,
            message.as_ptr(),
            message.len(),
        )
    }) {
        return Err(Unspecified);
    }

    Ok(&mut signature[0..out_sig_len])
}

#[allow(non_snake_case)]
unsafe fn serialize_RSA_pubkey(pubkey: &ConstPointer<RSA>) -> Result<Box<[u8]>, ()> {
    let mut pubkey_bytes = null_mut::<u8>();
    let mut outlen = MaybeUninit::<usize>::uninit();
    if 1 != RSA_public_key_to_bytes(&mut pubkey_bytes, outlen.as_mut_ptr(), **pubkey) {
        return Err(());
    }
    let pubkey_bytes = LcPtr::new(pubkey_bytes)?;
    let outlen = outlen.assume_init();
    let pubkey_slice = pubkey_bytes.as_slice(outlen);
    let pubkey_vec = Vec::from(pubkey_slice);
    Ok(pubkey_vec.into_boxed_slice())
}

impl KeyPair for RsaKeyPair {
    type PublicKey = RsaSubjectPublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.serialized_public_key
    }
}

/// A serialized RSA public key.
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct RsaSubjectPublicKey {
    key: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    modulus: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    exponent: Box<[u8]>,
}

impl Drop for RsaSubjectPublicKey {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(feature = "ring-io")]
        self.modulus.zeroize();
        #[cfg(feature = "ring-io")]
        self.exponent.zeroize();
    }
}

impl RsaSubjectPublicKey {
    unsafe fn new(pubkey: &ConstPointer<RSA>) -> Result<Self, ()> {
        let key = serialize_RSA_pubkey(pubkey)?;
        #[cfg(feature = "ring-io")]
        {
            let modulus = ConstPointer::new(RSA_get0_n(**pubkey))?;
            let modulus = modulus.to_be_bytes().into_boxed_slice();
            let exponent = ConstPointer::new(RSA_get0_e(**pubkey))?;
            let exponent = exponent.to_be_bytes().into_boxed_slice();
            Ok(RsaSubjectPublicKey {
                key,
                modulus,
                exponent,
            })
        }

        #[cfg(not(feature = "ring-io"))]
        Ok(RsaSubjectPublicKey { key })
    }
}

impl Debug for RsaSubjectPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaSubjectPublicKey(\"{}\")",
            test::to_hex(self.key.as_ref())
        ))
    }
}

impl AsRef<[u8]> for RsaSubjectPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

#[cfg(feature = "ring-io")]
impl RsaSubjectPublicKey {
    /// The public modulus (n).
    #[must_use]
    pub fn modulus(&self) -> io::Positive<'_> {
        io::Positive::new_non_empty_without_leading_zeros(Input::from(self.modulus.as_ref()))
    }

    /// The public exponent (e).
    #[must_use]
    pub fn exponent(&self) -> io::Positive<'_> {
        io::Positive::new_non_empty_without_leading_zeros(Input::from(self.exponent.as_ref()))
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RSASigningAlgorithmId {
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
}

#[allow(clippy::module_name_repetitions)]
pub struct RsaSignatureEncoding(
    pub(super) &'static digest::Algorithm,
    pub(super) &'static RsaPadding,
    pub(super) &'static RSASigningAlgorithmId,
);

impl Sealed for RsaSignatureEncoding {}

#[allow(non_camel_case_types)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum RsaPadding {
    RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING,
}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[allow(clippy::module_name_repetitions)]
pub trait RsaEncoding: 'static + Sync + Sealed + Debug {
    /// The signature encoding.
    fn encoding(&'static self) -> &'static RsaSignatureEncoding;
}

impl RsaEncoding for RsaSignatureEncoding {
    fn encoding(&'static self) -> &'static RsaSignatureEncoding {
        self
    }
}

impl Debug for RsaSignatureEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("{{ {:?} }}", self.2))
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RSAVerificationAlgorithmId {
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
}

/// Parameters for RSA verification.
#[allow(clippy::module_name_repetitions)]
pub struct RsaParameters(
    pub(super) &'static digest::Algorithm,
    pub(super) &'static RsaPadding,
    pub(super) RangeInclusive<u32>,
    pub(super) &'static RSAVerificationAlgorithmId,
);
impl Sealed for RsaParameters {}

impl Debug for RsaParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{{ {:?} }}", self.3))
    }
}

impl RsaParameters {
    /// Parses a DER-encoded `RSAPublicKey` structure (RFC 8017) to determine its size in bits.
    ///
    /// # Errors
    /// `error::Unspecified` on parse error.
    pub fn public_modulus_len(public_key: &[u8]) -> Result<u32, Unspecified> {
        unsafe {
            let mut cbs = cbs::build_CBS(public_key);
            let rsa = LcPtr::new(RSA_parse_public_key(&mut cbs))?;
            let mod_len = RSA_bits(*rsa);

            Ok(mod_len)
        }
    }

    #[must_use]
    /// Minimum modulus length in bits.
    pub fn min_modulus_len(&self) -> u32 {
        *self.2.start()
    }

    #[must_use]
    /// Maximum modulus length in bits.
    pub fn max_modulus_len(&self) -> u32 {
        *self.2.end()
    }
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_public_RSA_PKEY(public_key: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut cbs = cbs::build_CBS(public_key);

    let rsa = DetachableLcPtr::new(RSA_parse_public_key(&mut cbs))?;

    let pkey = LcPtr::new(EVP_PKEY_new())?;

    if 1 != EVP_PKEY_assign_RSA(*pkey, *rsa) {
        return Err(Unspecified);
    }

    rsa.detach();

    Ok(pkey)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_private_RSA_PKEY(private_key: &[u8]) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut cbs = cbs::build_CBS(private_key);

    let rsa = DetachableLcPtr::new(RSA_parse_private_key(&mut cbs))?;

    let pkey = LcPtr::new(EVP_PKEY_new())?;

    if 1 != EVP_PKEY_assign_RSA(*pkey, *rsa) {
        return Err(KeyRejected::unexpected_error());
    }

    rsa.detach();

    Ok(pkey)
}

#[inline]
#[allow(non_snake_case)]
fn verify_RSA(
    algorithm: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    public_key: &LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    let rsa = DetachableLcPtr::new(unsafe { EVP_PKEY_get0_RSA(**public_key) })?;
    let n = ConstPointer::new(unsafe { RSA_get0_n(rsa.detach()) })?;
    let n_bits = n.num_bits();
    if !allowed_bit_size.contains(&n_bits) {
        return Err(Unspecified);
    }

    let mut md_ctx = digest::digest_ctx::DigestContext::new_uninit();
    let digest = digest::match_digest_type(&algorithm.id);

    let mut pctx = null_mut::<EVP_PKEY_CTX>();

    if 1 != unsafe {
        EVP_DigestVerifyInit(
            md_ctx.as_mut_ptr(),
            &mut pctx,
            *digest,
            null_mut(),
            **public_key,
        )
    } {
        return Err(Unspecified);
    }

    if let RsaPadding::RSA_PKCS1_PSS_PADDING = padding {
        // AWS-LC owns pctx, check for null and then immediately detach so we don't drop it.
        let pctx = DetachableLcPtr::new(pctx)?.detach();
        configure_rsa_pkcs1_pss_padding(pctx)?;
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

/// Low-level API for the verification of RSA signatures.
///
/// When the public key is in DER-encoded PKCS#1 ASN.1 format, it is
/// recommended to use `aws_lc_rs::signature::verify()` with
/// `aws_lc_rs::signature::RSA_PKCS1_*`, because `aws_lc_rs::signature::verify()`
/// will handle the parsing in that case. Otherwise, this function can be used
/// to pass in the raw bytes for the public key components as
/// `untrusted::Input` arguments.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
pub struct RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,
    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: Copy + AsRef<[u8]> + Debug> Copy for RsaPublicKeyComponents<B> {}

impl<B> RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    #[allow(non_snake_case)]
    #[inline]
    unsafe fn build_RSA(&self) -> Result<LcPtr<EVP_PKEY>, ()> {
        let n_bytes = self.n.as_ref();
        if n_bytes.is_empty() || n_bytes[0] == 0u8 {
            return Err(());
        }
        let n_bn = DetachableLcPtr::try_from(n_bytes)?;

        let e_bytes = self.e.as_ref();
        if e_bytes.is_empty() || e_bytes[0] == 0u8 {
            return Err(());
        }
        let e_bn = DetachableLcPtr::try_from(e_bytes)?;

        let rsa = DetachableLcPtr::new(RSA_new())?;
        if 1 != RSA_set0_key(*rsa, *n_bn, *e_bn, null_mut()) {
            return Err(());
        }
        n_bn.detach();
        e_bn.detach();

        let pkey = LcPtr::new(EVP_PKEY_new())?;
        if 1 != EVP_PKEY_assign_RSA(*pkey, *rsa) {
            return Err(());
        }
        rsa.detach();

        Ok(pkey)
    }

    /// Verifies that `signature` is a valid signature of `message` using `self`
    /// as the public key. `params` determine what algorithm parameters
    /// (padding, digest algorithm, key length range, etc.) are used in the
    /// verification.
    ///
    /// # Errors
    /// `error::Unspecified` if `message` was not verified.
    pub fn verify(
        &self,
        params: &RsaParameters,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let rsa = self.build_RSA()?;
            verify_RSA(params.0, params.1, &rsa, message, signature, &params.2)
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ring-io")]
    #[test]
    fn test_rsa() {
        use crate::signature::KeyPair;
        use crate::signature::RsaKeyPair;
        use crate::test::from_dirty_hex;
        let rsa_pkcs8_input: Vec<u8> = from_dirty_hex(
            r"308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b9d7a
        f84fa4184a5f22037ec8aff2db5f78bd8c21e714e579ae57c6398c4950f3a694b17bfccf488766159aec5bb7c2c4
        3d59c798cbd45a09c9c86933f126879ee7eadcd404f61ecfc425197cab03946ba381a49ef3b4d0f60b17f8a747cd
        e56a834a7f6008f35ffb2f60a54ceda1974ff2a9963aba7f80d4e2916a93d8c74bb1ba5f3b189a4e8f0377bd3e94
        b5cc3f9c53cb8c8c7c0af394818755e968b7a76d9cada8da7af5fbe25da2a09737d5e4e4d7092aa16a0718d7322c
        e8aca767015128d6d35775ea9cb8bb1ac6512e1b787d34015221be780a37b1d69bc3708bfd8832591be6095a768f
        0fd3b3457927e6ae3641d55799a29a0a269cb4a693bc14b0203010001028201001c5fb7e69fa6dd2fd0f5e653f12
        ce0b7c5a1ce6864e97bc2985dad4e2f86e4133d21d25b3fe774f658cca83aace9e11d8905d62c20b6cd28a680a77
        357cfe1afac201f3d1532898afb40cce0560bedd2c49fc833bd98da3d1cd03cded0c637d4173e62de865b572d410
        f9ba83324cd7a3573359428232f1628f6d104e9e6c5f380898b5570201cf11eb5f7e0c4933139c7e7fba67582287
        ffb81b84fa81e9a2d9739815a25790c06ead7abcf286bd43c6e3d009d01f15fca3d720bbea48b0c8ccf8764f3c82
        2e61159d8efcbff38c794f8afe040b45df14c976a91b1b6d886a55b8e68969bcb30c7197920d97d7721d78d954d8
        9ffecbcc93c6ee82a86fe754102818100eba1cbe453f5cb2fb7eabc12d697267d25785a8f7b43cc2cb14555d3618
        c63929b19839dcd4212397ecda8ad872f97ede6ac95ebda7322bbc9409bac2b24ae56ad62202800c670365ae2867
        1195fe934978a5987bee2fcea06561b782630b066b0a35c3f559a281f0f729fc282ef8ebdbb065d60000223da6ed
        b732fa32d82bb02818100c9e81e353315fd88eff53763ed7b3859f419a0a158f5155851ce0fe6e43188e44fb43dd
        25bcdb7f3839fe84a5db88c6525e5bcbae513bae5ff54398106bd8ae4d241c082f8a64a9089531f7b57b09af5204
        2efa097140702dda55a2141c174dd7a324761267728a6cc4ce386c034393d855ebe985c4e5f2aec2bd3f2e2123ab
        1028180566889dd9c50798771397a68aa1ad9b970e136cc811676ac3901c51c741c48737dbf187de8c47eec68acc
        05b8a4490c164230c0366a36c2c52fc075a56a3e7eecf3c39b091c0336c2b5e00913f0de5f62c5046ceb9d88188c
        c740d34bd44839bd4d0c346527cea93a15596727d139e53c35eed25043bc4ac18950f237c02777b0281800f9dd98
        049e44088efee6a8b5b19f5c0d765880c12c25a154bb6817a5d5a0b798544aea76f9c58c707fe3d4c4b3573fe7ad
        0eb291580d22ae9f5ccc0d311a40590d1af1f3236427c2d72f57367d3ec185b9771cb5d041a8ab93409e59a9d68f
        99c72f91c658a3fe5aed59f9f938c368530a4a45f4a7c7155f3906c4354030ef102818100c89e0ba805c970abd84
        a70770d8fc57bfaa34748a58b77fcddaf0ca285db91953ef5728c1be7470da5540df6af56bb04c0f5ec500f83b08
        057664cb1551e1e29c58d8b1e9d70e23ed57fdf9936c591a83c1dc954f6654d4a245b6d8676d045c2089ffce537d
        234fc88e98d92afa92926c75b286e8fee70e273d762bbe63cd63b",
        );

        let key = RsaKeyPair::from_pkcs8(&rsa_pkcs8_input).unwrap();
        let pk = key.public_key();
        let modulus_bytes = pk.modulus().big_endian_without_leading_zero();
        assert_eq!(&rsa_pkcs8_input[38..294], modulus_bytes);
    }

    #[test]
    fn test_debug() {
        use crate::signature;
        assert_eq!(
            "{ RSA_PSS_SHA512 }",
            format!("{:?}", signature::RSA_PSS_SHA512)
        );

        assert_eq!(
            "{ RSA_PSS_2048_8192_SHA256 }",
            format!("{:?}", signature::RSA_PSS_2048_8192_SHA256)
        );
    }
}
