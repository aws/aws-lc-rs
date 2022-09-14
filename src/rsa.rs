// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// *R* and *r* in Montgomery math refer to different things, so we always use
// `R` to refer to *R* to avoid confusion, even when that's against the normal
// naming conventions. Also the standard camelCase names are used for `KeyPair`
// components.

use crate::error::{KeyRejected, Unspecified};
use crate::rand;
use crate::sealed::Sealed;
use crate::signature::{KeyPair, VerificationAlgorithm};
use crate::{digest, error};
use aws_lc_sys::{
    BN_cmp, BN_free, BN_init, BN_set_u64, EVP_parse_private_key, RSA_free, RSA_new, BIGNUM,
    EVP_PKEY, EVP_PKEY_CTX, RSA,
};
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::RangeInclusive;
use std::os::raw::c_uint;
use std::ptr::null_mut;
use std::slice;
use zeroize::Zeroize;

pub struct RsaKeyPair {
    evp_pkey: *const EVP_PKEY,
    serialized_public_key: RsaSubjectPublicKey,
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        unsafe {
            aws_lc_sys::EVP_PKEY_free(self.mut_ptr_evp_pkey());
            self.serialized_public_key.0.zeroize();
        }
    }
}

impl RsaKeyPair {
    fn mut_ptr_evp_pkey(&self) -> *mut EVP_PKEY {
        self.evp_pkey as *mut EVP_PKEY
    }

    fn new(evp_pkey: *const EVP_PKEY) -> Self {
        unsafe {
            let nonowning_pubkey = aws_lc_sys::EVP_PKEY_get0_RSA(evp_pkey);
            let pubkey_bytes = serialize_RSA_pubkey(nonowning_pubkey)
                .expect("Unable to serialize RSA public key!");
            let serialized_public_key = RsaSubjectPublicKey::new(pubkey_bytes);
            RsaKeyPair {
                evp_pkey,
                serialized_public_key,
            }
        }
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let mut cbs = build_CBS(pkcs8);

            let evp_pkey = EVP_parse_private_key(&mut cbs);
            if evp_pkey.is_null() {
                return Err(error::KeyRejected::invalid_encoding());
            }
            let rsa = aws_lc_sys::EVP_PKEY_get0_RSA(evp_pkey);
            if rsa.is_null() {
                aws_lc_sys::EVP_PKEY_free(evp_pkey);
                return Err(error::KeyRejected::wrong_algorithm());
            }

            if let Err(err) = Self::validate_pkey(evp_pkey) {
                aws_lc_sys::EVP_PKEY_free(evp_pkey);
                return Err(err);
            }
            if let Err(err) = Self::validate_rsa(rsa) {
                aws_lc_sys::EVP_PKEY_free(evp_pkey);
                return Err(err);
            }

            Ok(Self::new(evp_pkey))
        }
    }

    pub fn from_der(der: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let rsa = build_private_RSA(der)?;
            if let Err(e) = Self::validate_rsa(rsa) {
                aws_lc_sys::RSA_free(rsa);
                return Err(e);
            }

            let evp_pkey = build_EVP_PKEY_from_RSA(rsa, || {
                aws_lc_sys::RSA_free(rsa);
                KeyRejected::invalid_encoding()
            })?;

            if let Err(err) = Self::validate_pkey(evp_pkey) {
                aws_lc_sys::EVP_PKEY_free(evp_pkey);
                return Err(err);
            }

            Ok(Self::new(evp_pkey))
        }
    }

    unsafe fn validate_pkey(evp_pkey: *mut EVP_PKEY) -> Result<(), KeyRejected> {
        const MIN_PKEY_BITS: c_uint = 2041;
        const MAX_PKEY_BITS: c_uint = 4096;
        let key_type = aws_lc_sys::EVP_PKEY_id(evp_pkey);
        if key_type != aws_lc_sys::EVP_PKEY_RSA {
            return Err(error::KeyRejected::wrong_algorithm());
        }

        let bits = aws_lc_sys::EVP_PKEY_bits(evp_pkey);
        let bits = bits as c_uint;
        if bits < MIN_PKEY_BITS {
            return Err(KeyRejected::too_small());
        }

        if bits > MAX_PKEY_BITS {
            return Err(KeyRejected::too_large());
        }
        Ok(())
    }

    unsafe fn validate_rsa(rsa: *mut RSA) -> Result<(), KeyRejected> {
        let p = aws_lc_sys::RSA_get0_p(rsa);
        let q = aws_lc_sys::RSA_get0_q(rsa);
        let p_bits = aws_lc_sys::BN_num_bits(p);
        let q_bits = aws_lc_sys::BN_num_bits(q);
        if p_bits != q_bits {
            return Err(KeyRejected::inconsistent_components());
        }
        if p_bits % 512 != 0 {
            return Err(KeyRejected::private_modulus_len_not_multiple_of_512_bits());
        }

        let exponent = aws_lc_sys::RSA_get0_e(rsa);
        if Self::compare(exponent, 65537)? == Ordering::Less {
            return Err(KeyRejected::too_small());
        }
        Ok(())
    }

    unsafe fn compare(a: *const BIGNUM, b: u64) -> Result<core::cmp::Ordering, KeyRejected> {
        let mut b_val = MaybeUninit::<BIGNUM>::uninit();
        BN_init(b_val.as_mut_ptr());
        let mut b_val = b_val.assume_init();
        if 1 != BN_set_u64(&mut b_val, b) {
            BN_free(&mut b_val);
            return Err(KeyRejected::unexpected_error());
        }
        let result = BN_cmp(a, &b_val) as i32;
        BN_free(&mut b_val);

        Ok(result.cmp(&0))
    }
}

impl VerificationAlgorithm for RsaParameters {
    fn verify(&self, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), Unspecified> {
        unsafe {
            let rsa = build_public_RSA(public_key)?;
            let result = RSA_verify(self.0, self.1, rsa, msg, signature, &self.2);

            result
        }
    }
}

impl RsaKeyPair {
    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` may be used to randomize the padding
    /// (e.g. for PSS).
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly.
    pub fn sign(
        &self,
        padding_alg: &RsaEncoding,
        _rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let evp_pkey_ctx = aws_lc_sys::EVP_PKEY_CTX_new(self.mut_ptr_evp_pkey(), null_mut());
            if evp_pkey_ctx.is_null() {
                return Err(Unspecified);
            }

            if 1 != aws_lc_sys::EVP_PKEY_sign_init(evp_pkey_ctx) {
                return Err(Unspecified);
            }

            let digest = digest::digest(padding_alg.0, msg);
            let digest = digest.as_ref();

            if 1 != aws_lc_sys::EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, padding_alg.1) {
                return Err(Unspecified);
            }

            let evp_md = digest::match_digest_type(&padding_alg.0.id);
            if 1 != aws_lc_sys::EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md) {
                return Err(Unspecified);
            }

            let mut sig_len = MaybeUninit::<usize>::uninit();
            let result = aws_lc_sys::EVP_PKEY_sign(
                evp_pkey_ctx,
                signature.as_mut_ptr(),
                sig_len.as_mut_ptr(),
                digest.as_ptr(),
                digest.len(),
            );

            aws_lc_sys::EVP_PKEY_CTX_free(evp_pkey_ctx);

            if result != 1 {
                return Err(Unspecified);
            }
        }
        Ok(())
    }

    pub fn public_modulus_len(&self) -> usize {
        unsafe { aws_lc_sys::EVP_PKEY_size(self.evp_pkey) as usize }
    }
}

impl Debug for RsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "RsaKeyPair {{ public_key: {:?} }}",
            self.serialized_public_key
        ))
    }
}

impl Sealed for RsaKeyPair {}
unsafe impl Sync for RsaKeyPair {}
unsafe impl Send for RsaKeyPair {}

#[derive(Clone)]
pub struct RsaSubjectPublicKey(Box<[u8]>);

impl RsaSubjectPublicKey {
    fn new(pubkey_box: Box<[u8]>) -> Self {
        RsaSubjectPublicKey(pubkey_box)
    }
}

#[allow(non_snake_case)]
unsafe fn serialize_RSA_pubkey(pubkey: *const RSA) -> Result<Box<[u8]>, Unspecified> {
    let mut pubkey_bytes = MaybeUninit::<*mut u8>::uninit();
    let mut outlen = MaybeUninit::<usize>::uninit();
    if 1 != aws_lc_sys::RSA_public_key_to_bytes(
        pubkey_bytes.as_mut_ptr(),
        outlen.as_mut_ptr(),
        pubkey,
    ) {
        return Err(Unspecified);
    }
    let pubkey_bytes = pubkey_bytes.assume_init();
    let outlen = outlen.assume_init();
    let pubkey_slice = slice::from_raw_parts(pubkey_bytes, outlen);
    let mut pubkey_vec = Vec::<u8>::new();
    pubkey_vec.extend_from_slice(pubkey_slice);

    aws_lc_sys::OPENSSL_free(pubkey_bytes.cast());

    Ok(pubkey_vec.into_boxed_slice())
}

impl KeyPair for RsaKeyPair {
    type PublicKey = RsaSubjectPublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.serialized_public_key
    }
}

impl Debug for RsaSubjectPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "RsaSubjectPublicKey(\"{}\")",
            hex::encode(self.0.as_ref())
        ))
    }
}

impl AsRef<[u8]> for RsaSubjectPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "alloc")]
pub struct RsaEncoding(
    pub(super) &'static digest::Algorithm,
    pub(super) i32,
    pub(super) &'static str,
);

impl Debug for RsaEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{{ {} }}", self.2))
    }
}

#[cfg(feature = "alloc")]
pub struct RsaParameters(
    pub(super) &'static digest::Algorithm,
    pub(super) i32,
    pub(super) RangeInclusive<u32>,
    pub(super) &'static str,
);
impl Sealed for RsaParameters {}

impl Debug for RsaParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{{ {} }}", self.3))
    }
}

impl RsaParameters {
    pub fn public_modulus_len(public_key: &[u8]) -> Result<u32, Unspecified> {
        unsafe {
            let mut cbs = MaybeUninit::<aws_lc_sys::CBS>::uninit();
            aws_lc_sys::CBS_init(cbs.as_mut_ptr(), public_key.as_ptr(), public_key.len());
            let mut cbs = cbs.assume_init();

            let rsa = aws_lc_sys::RSA_parse_public_key(&mut cbs);
            if rsa.is_null() {
                return Err(Unspecified);
            }
            let mod_len = aws_lc_sys::RSA_bits(rsa);
            aws_lc_sys::RSA_free(rsa);

            Ok(mod_len)
        }
    }

    pub fn min_modulus_len(&self) -> u32 {
        *self.2.start()
    }

    pub fn max_modulus_len(&self) -> u32 {
        *self.2.end()
    }
}

#[allow(non_snake_case)]
unsafe fn build_EVP_PKEY_CTX<F, U>(
    evp_pkey: *mut EVP_PKEY,
    err_fn: F,
) -> Result<*mut EVP_PKEY_CTX, U>
where
    F: FnOnce() -> U,
{
    let evp_pkey_ctx = aws_lc_sys::EVP_PKEY_CTX_new(evp_pkey, null_mut());
    if evp_pkey_ctx.is_null() {
        return Err(err_fn());
    }
    Ok(evp_pkey_ctx)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_EVP_PKEY_from_RSA<F, U>(rsa: *mut RSA, err_fn: F) -> Result<*mut EVP_PKEY, U>
where
    F: FnOnce() -> U,
{
    let evp_pkey = aws_lc_sys::EVP_PKEY_new();
    if evp_pkey.is_null() {
        return Err(err_fn());
    }

    if 1 != aws_lc_sys::EVP_PKEY_assign_RSA(evp_pkey, rsa) {
        aws_lc_sys::EVP_PKEY_free(evp_pkey);
        return Err(err_fn());
    }
    Ok(evp_pkey)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_CBS(data: &[u8]) -> aws_lc_sys::CBS {
    let mut cbs = MaybeUninit::<aws_lc_sys::CBS>::uninit();
    aws_lc_sys::CBS_init(cbs.as_mut_ptr(), data.as_ptr(), data.len());
    cbs.assume_init()
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_public_RSA(public_key: &[u8]) -> Result<*mut RSA, Unspecified> {
    let mut cbs = build_CBS(public_key);

    let rsa = aws_lc_sys::RSA_parse_public_key(&mut cbs);
    if rsa.is_null() {
        return Err(Unspecified);
    }
    Ok(rsa)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_private_RSA(public_key: &[u8]) -> Result<*mut RSA, KeyRejected> {
    let mut cbs = build_CBS(public_key);

    let rsa = aws_lc_sys::RSA_parse_private_key(&mut cbs);
    if rsa.is_null() {
        return Err(KeyRejected::invalid_encoding());
    }
    Ok(rsa)
}

#[inline]
#[allow(non_snake_case)]
fn RSA_verify(
    algorithm: &'static digest::Algorithm,
    padding: i32,
    public_key: *mut RSA,
    msg: &[u8],
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    unsafe {
        let evp_pkey = build_EVP_PKEY_from_RSA(public_key, || {
            aws_lc_sys::RSA_free(public_key);
            Unspecified
        })?;

        let bits = aws_lc_sys::EVP_PKEY_bits(evp_pkey);
        let bits = bits as c_uint;
        if !allowed_bit_size.contains(&bits) {
            aws_lc_sys::EVP_PKEY_free(evp_pkey);
            return Err(Unspecified);
        }

        let evp_pkey_ctx = build_EVP_PKEY_CTX(evp_pkey, || {
            aws_lc_sys::EVP_PKEY_free(evp_pkey);
            Unspecified
        })?;

        let result = EVP_PKEY_CTX_verify(algorithm, padding, msg, signature, evp_pkey_ctx);
        aws_lc_sys::EVP_PKEY_CTX_free(evp_pkey_ctx);
        aws_lc_sys::EVP_PKEY_free(evp_pkey);
        result
    }
}

#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_PKEY_CTX_verify(
    algorithm: &'static digest::Algorithm,
    padding: i32,
    msg: &[u8],
    signature: &[u8],
    evp_pkey_ctx: *mut EVP_PKEY_CTX,
) -> Result<(), Unspecified> {
    if 1 != aws_lc_sys::EVP_PKEY_verify_init(evp_pkey_ctx) {
        return Err(Unspecified);
    }

    let digest = digest::digest(algorithm, msg);
    let digest = digest.as_ref();

    if 1 != aws_lc_sys::EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, padding) {
        return Err(Unspecified);
    }

    let evp_md = digest::match_digest_type(&algorithm.id);
    if 1 != aws_lc_sys::EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md) {
        return Err(Unspecified);
    }

    if 1 != aws_lc_sys::EVP_PKEY_verify(
        evp_pkey_ctx,
        signature.as_ptr(),
        signature.len(),
        digest.as_ptr(),
        digest.len(),
    ) {
        return Err(Unspecified);
    }
    Ok(())
}

#[derive(Debug)]
pub struct RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    pub n: B,
    pub e: B,
}

impl<B> RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    #[allow(non_snake_case)]
    #[inline]
    unsafe fn build_RSA(&self) -> Result<*mut RSA, Unspecified> {
        let n_bytes = self.n.as_ref();
        if n_bytes.is_empty() || n_bytes[0] == 0u8 {
            return Err(Unspecified);
        }
        let n_bn = aws_lc_sys::BN_bin2bn(n_bytes.as_ptr(), n_bytes.len(), null_mut());
        if n_bn.is_null() {
            return Err(Unspecified);
        }

        let e_bytes = self.e.as_ref();
        if e_bytes.is_empty() || e_bytes[0] == 0u8 {
            BN_free(n_bn);
            return Err(Unspecified);
        }
        let e_bn = aws_lc_sys::BN_bin2bn(e_bytes.as_ptr(), e_bytes.len(), null_mut());
        if e_bn.is_null() {
            BN_free(n_bn);
            return Err(Unspecified);
        }

        let rsa = RSA_new();
        if 1 != aws_lc_sys::RSA_set0_key(rsa, n_bn, e_bn, null_mut()) {
            BN_free(n_bn);
            BN_free(e_bn);
            RSA_free(rsa);
            return Err(Unspecified);
        }
        Ok(rsa)
    }

    #[allow(unused_variables, dead_code)]
    pub fn verify(
        &self,
        params: &RsaParameters,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let rsa = self.build_RSA()?;
            let result = RSA_verify(params.0, params.1, rsa, msg, signature, &params.2);
            result
        }
    }
}
