// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    mem::MaybeUninit,
    ptr::null_mut,
};
// TODO: Uncomment when MSRV >= 1.64
// use core::ffi::c_int;
use std::os::raw::c_int;

use crate::{
    encoding::{AsDer, Pkcs8V1Der},
    fips::indicator_check,
};

#[cfg(feature = "fips")]
use aws_lc::RSA_check_fips;
use aws_lc::{
    EVP_DigestSignInit, EVP_PKEY_assign_RSA, EVP_PKEY_new, RSA_generate_key_ex,
    RSA_generate_key_fips, RSA_get0_e, RSA_get0_n, RSA_get0_p, RSA_get0_q, RSA_new,
    RSA_parse_private_key, RSA_parse_public_key, RSA_public_key_to_bytes, RSA_set0_key, RSA_size,
    BIGNUM, EVP_PKEY, EVP_PKEY_CTX, RSA,
};

use mirai_annotations::verify_unreachable;

#[cfg(feature = "ring-io")]
use untrusted::Input;

use zeroize::Zeroize;

use super::{
    encoding,
    signature::{compute_rsa_signature, RsaEncoding, RsaPadding},
    RsaParameters,
};

#[cfg(feature = "ring-io")]
use crate::io;
use crate::{
    cbs, digest,
    error::{KeyRejected, Unspecified},
    hex,
    ptr::{ConstPointer, DetachableLcPtr, LcPtr},
    rand,
    sealed::Sealed,
};

/// RSA key-size.
#[allow(clippy::module_name_repetitions)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySize {
    /// 2048-bit key
    Rsa2048,

    /// 3072-bit key
    Rsa3072,

    /// 4096-bit key
    Rsa4096,

    /// 8192-bit key
    Rsa8192,
}

#[allow(clippy::len_without_is_empty)]
impl KeySize {
    /// Returns the size of the key in bytes.
    #[inline]
    #[must_use]
    pub fn len(self) -> usize {
        match self {
            Self::Rsa2048 => 256,
            Self::Rsa3072 => 384,
            Self::Rsa4096 => 512,
            Self::Rsa8192 => 1024,
        }
    }

    /// Returns the key size in bits.
    #[inline]
    fn bit_len(self) -> i32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Rsa8192 => 8192,
        }
    }
}

/// An RSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct KeyPair {
    // https://github.com/aws/aws-lc/blob/ebaa07a207fee02bd68fe8d65f6b624afbf29394/include/openssl/evp.h#L295
    // An |EVP_PKEY| object represents a public or private RSA key. A given object may be
    // used concurrently on multiple threads by non-mutating functions, provided no
    // other thread is concurrently calling a mutating function. Unless otherwise
    // documented, functions which take a |const| pointer are non-mutating and
    // functions which take a non-|const| pointer are mutating.
    evp_pkey: LcPtr<EVP_PKEY>,
    serialized_public_key: PublicKey,
}

impl Sealed for KeyPair {}
unsafe impl Send for KeyPair {}
unsafe impl Sync for KeyPair {}

impl KeyPair {
    fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Result<Self, KeyRejected> {
        unsafe {
            let rsa_key = evp_pkey.get_rsa()?;
            let serialized_public_key = PublicKey::new(&rsa_key.as_const())?;
            Ok(KeyPair {
                evp_pkey,
                serialized_public_key,
            })
        }
    }

    /// Generate a RSA `KeyPair` of the specified key-strength.
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    pub fn generate(size: KeySize) -> Result<Self, Unspecified> {
        let private_key = generate_rsa_key(size.bit_len(), false)?;
        Self::new(private_key).map_err(|_| Unspecified)
    }

    /// Generate a RSA `KeyPair` of the specified key-strength.
    ///
    /// Supports the following key sizes:
    /// * `SignatureKeySize::Rsa2048`
    /// * `SignatureKeySize::Rsa3072`
    /// * `SignatureKeySize::Rsa4096`
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    #[cfg(feature = "fips")]
    pub fn generate_fips(size: KeySize) -> Result<Self, Unspecified> {
        let private_key = generate_rsa_key(size.bit_len(), true)?;
        Self::new(private_key).map_err(|_| Unspecified)
    }

    /// Parses an unencrypted PKCS#8-encoded RSA private key.
    ///
    /// A RSA keypair may be generated using [`KeyPair::generate`].
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
            let evp_pkey = encoding::pkcs8::decode_der(pkcs8)?;
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
        let digest = digest::match_digest_type(&encoding.digest_algorithm().id);

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

        if let RsaPadding::RSA_PKCS1_PSS_PADDING = encoding.padding() {
            // AWS-LC owns pctx, check for null and then immediately detach so we don't drop it.
            let pctx = DetachableLcPtr::new(pctx)?.detach();
            super::signature::configure_rsa_pkcs1_pss_padding(pctx)?;
        }

        let max_len = super::signature::get_signature_length(&mut md_ctx)?;

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

impl Debug for KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaKeyPair {{ public_key: {:?} }}",
            self.serialized_public_key
        ))
    }
}

impl crate::signature::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.serialized_public_key
    }
}

impl AsDer<Pkcs8V1Der<'static>> for KeyPair {
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        Ok(Pkcs8V1Der::new(encoding::pkcs8::encode_v1_der(
            &self.evp_pkey,
        )?))
    }
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
pub(super) unsafe fn build_public_RSA_PKEY(
    public_key: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut cbs = cbs::build_CBS(public_key);

    let rsa = DetachableLcPtr::new(RSA_parse_public_key(&mut cbs))?;

    let pkey = LcPtr::new(EVP_PKEY_new())?;

    if 1 != EVP_PKEY_assign_RSA(*pkey, *rsa) {
        return Err(Unspecified);
    }

    rsa.detach();

    Ok(pkey)
}

/// A serialized RSA public key.
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKey {
    key: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    modulus: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    exponent: Box<[u8]>,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(feature = "ring-io")]
        self.modulus.zeroize();
        #[cfg(feature = "ring-io")]
        self.exponent.zeroize();
    }
}

impl PublicKey {
    pub(super) unsafe fn new(pubkey: &ConstPointer<RSA>) -> Result<Self, ()> {
        let key = serialize_RSA_pubkey(pubkey)?;
        #[cfg(feature = "ring-io")]
        {
            let modulus = ConstPointer::new(RSA_get0_n(**pubkey))?;
            let modulus = modulus.to_be_bytes().into_boxed_slice();
            let exponent = ConstPointer::new(RSA_get0_e(**pubkey))?;
            let exponent = exponent.to_be_bytes().into_boxed_slice();
            Ok(PublicKey {
                key,
                modulus,
                exponent,
            })
        }

        #[cfg(not(feature = "ring-io"))]
        Ok(PublicKey { key })
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaPublicKey(\"{}\")",
            hex::encode(self.key.as_ref())
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

#[cfg(feature = "ring-io")]
impl PublicKey {
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

/// Low-level API for the verification of RSA signatures.
///
/// When the public key is in DER-encoded PKCS#1 ASN.1 format, it is
/// recommended to use `aws_lc_rs::signature::verify()` with
/// `aws_lc_rs::signature::RSA_PKCS1_*`, because `aws_lc_rs::signature::verify()`
/// will handle the parsing in that case. Otherwise, this function can be used
/// to pass in the raw bytes for the public key components as
/// `untrusted::Input` arguments.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone)]
pub struct PublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,
    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: AsRef<[u8]> + Debug> Debug for PublicKeyComponents<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKeyComponents")
            .field("n", &self.n)
            .field("e", &self.e)
            .finish()
    }
}

impl<B: Copy + AsRef<[u8]> + Debug> Copy for PublicKeyComponents<B> {}

impl<B> PublicKeyComponents<B>
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
            super::signature::verify_RSA(
                params.digest_algorithm(),
                params.padding(),
                &rsa,
                message,
                signature,
                params.bit_size_range(),
            )
        }
    }
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

pub(super) fn generate_rsa_key(size: c_int, fips: bool) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    // We explicitly don't use `EVP_PKEY_keygen`, as it will force usage of either the FIPS or non-FIPS
    // keygen function based on the whether the build of AWS-LC had FIPS enbaled. Rather we delegate to the desired
    // generation function.

    const RSA_F4: u64 = 65537;

    let rsa = DetachableLcPtr::new(unsafe { RSA_new() })?;

    if 1 != if fips {
        indicator_check!(unsafe { RSA_generate_key_fips(*rsa, size, null_mut()) })
    } else {
        let e: LcPtr<BIGNUM> = RSA_F4.try_into()?;
        unsafe { RSA_generate_key_ex(*rsa, size, *e, null_mut()) }
    } {
        return Err(Unspecified);
    }

    let evp_pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

    if 1 != unsafe { EVP_PKEY_assign_RSA(*evp_pkey, *rsa) } {
        return Err(Unspecified);
    };

    rsa.detach();

    Ok(evp_pkey)
}
