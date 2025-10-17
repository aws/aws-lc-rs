//! CMAC is specified in [RFC 4493] and [NIST SP 800-38B].
//!
//! After a `Key` is constructed, it can be used for multiple signing or
//! verification operations. Separating the construction of the key from the
//! rest of the CMAC operation allows the per-key precomputation to be done
//! only once, instead of it being done in every CMAC operation.
//!
//! Frequently all the data to be signed in a message is available in a single
//! contiguous piece. In that case, the module-level `sign` function can be
//! used. Otherwise, if the input is in multiple parts, `Context` should be
//! used.
//!
//! # Examples:
//!
//! ## Signing a value and verifying it wasn't tampered with
//!
//! ```
//! use aws_lc_rs::cmac;
//!
//! let key = cmac::Key::generate(cmac::AES_128)?;
//!
//! let msg = "hello, world";
//!
//! let tag = cmac::sign(&key, msg.as_bytes())?;
//!
//! // [We give access to the message to an untrusted party, and they give it
//! // back to us. We need to verify they didn't tamper with it.]
//!
//! cmac::verify(&key, msg.as_bytes(), tag.as_ref())?;
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
//!
//! ## Using the one-shot API:
//!
//! ```
//! use aws_lc_rs::rand::SecureRandom;
//! use aws_lc_rs::{cmac, rand};
//!
//! let msg = "hello, world";
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let key_value: [u8; 16] = rand::generate(&rng)?.expose();
//!
//! let s_key = cmac::Key::new(cmac::AES_128, key_value.as_ref())?;
//! let tag = cmac::sign(&s_key, msg.as_bytes())?;
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = cmac::Key::new(cmac::AES_128, key_value.as_ref())?;
//! cmac::verify(&v_key, msg.as_bytes(), tag.as_ref())?;
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
//!
//! ## Using the multi-part API:
//! ```
//! use aws_lc_rs::rand::SecureRandom;
//! use aws_lc_rs::{cmac, rand};
//!
//! let parts = ["hello", ", ", "world"];
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let key_value: [u8; 32] = rand::generate(&rng)?.expose();
//!
//! let s_key = cmac::Key::new(cmac::AES_256, key_value.as_ref())?;
//! let mut s_ctx = cmac::Context::with_key(&s_key);
//! for part in &parts {
//!     s_ctx.update(part.as_bytes())?;
//! }
//! let tag = s_ctx.sign()?;
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = cmac::Key::new(cmac::AES_256, key_value.as_ref())?;
//! let mut msg = Vec::<u8>::new();
//! for part in &parts {
//!     msg.extend(part.as_bytes());
//! }
//! cmac::verify(&v_key, &msg.as_ref(), tag.as_ref())?;
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
//! [RFC 4493]: https://tools.ietf.org/html/rfc4493
//! [NIST SP 800-38B]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf

use crate::aws_lc::{
    CMAC_CTX, CMAC_CTX_copy, CMAC_CTX_new, CMAC_Final, CMAC_Init,
    CMAC_Update, EVP_CIPHER, EVP_aes_128_cbc, EVP_aes_192_cbc, EVP_aes_256_cbc, EVP_des_ede3_cbc,
};
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::ptr::{ConstPointer, LcPtr};
use crate::{constant_time, rand};
use core::mem::MaybeUninit;
use core::ptr::null_mut;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AlgorithmId {
    Aes128,
    Aes192,
    Aes256,
    Tdes,
}

/// A CMAC algorithm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Algorithm {
    id: AlgorithmId,
    key_len: usize,
    tag_len: usize,
}

impl core::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Algorithm")
            .field("id", &self.id)
            .field("key_len", &self.key_len)
            .field("tag_len", &self.tag_len)
            .finish()
    }
}

impl Algorithm {
    /// The key length for this CMAC algorithm.
    #[inline]
    #[must_use]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The tag length for this CMAC algorithm.
    #[inline]
    #[must_use]
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

impl AlgorithmId {
    fn evp_cipher(&self) -> ConstPointer<'_, EVP_CIPHER> {
        unsafe {
            ConstPointer::new_static(match self {
                AlgorithmId::Aes128 => EVP_aes_128_cbc(),
                AlgorithmId::Aes192 => EVP_aes_192_cbc(),
                AlgorithmId::Aes256 => EVP_aes_256_cbc(),
                AlgorithmId::Tdes => EVP_des_ede3_cbc(),
            }).unwrap()
        }
    }
}

/// CMAC using AES-128.
pub const AES_128: Algorithm = Algorithm {
    id: AlgorithmId::Aes128,
    key_len: 16,
    tag_len: 16,
};

/// CMAC using AES-192.
pub const AES_192: Algorithm = Algorithm {
    id: AlgorithmId::Aes192,
    key_len: 24,
    tag_len: 16,
};

/// CMAC using AES-256.
pub const AES_256: Algorithm = Algorithm {
    id: AlgorithmId::Aes256,
    key_len: 32,
    tag_len: 16,
};

/// CMAC using 3DES (Triple DES). Obsolete
pub const TDES_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    id: AlgorithmId::Tdes,
    key_len: 24,
    tag_len: 8,
};

/// Maximum CMAC tag length (AES block size).
const MAX_CMAC_TAG_LEN: usize = 16;

/// A CMAC tag.
///
/// For a given tag `t`, use `t.as_ref()` to get the tag value as a byte slice.
#[derive(Clone, Copy, Debug)]
pub struct Tag {
    bytes: [u8; MAX_CMAC_TAG_LEN],
    len: usize,
}

impl AsRef<[u8]> for Tag {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// A key to use for CMAC signing.
//
// # FIPS
// Use this type with one of the following algorithms:
// * `AES_128`
// * `AES_256`
#[derive(Clone)]
pub struct Key {
    algorithm: Algorithm,
    ctx: LcPtr<CMAC_CTX>,
}

impl Clone for LcPtr<CMAC_CTX> {
    fn clone(&self) -> Self {
        let mut new_ctx = LcPtr::new(unsafe { CMAC_CTX_new() }).expect("CMAC_CTX_new failed");
        unsafe {
            if 1 != CMAC_CTX_copy(*new_ctx.as_mut(), *self.as_const()) {
                panic!("CMAC_CTX_copy failed");
            }
        }
        new_ctx
    }
}

unsafe impl Send for Key {}
// All uses of *mut CMAC_CTX require the creation of a Context, which will clone the Key.
unsafe impl Sync for Key {}

#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Key")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl Key {
    /// Generate a CMAC signing key using the given algorithm with a
    /// random value.
    ///
    //
    // # FIPS
    // Use this type with one of the following algorithms:
    // * `AES_128`
    // * `AES_256`
    //
    /// # Errors
    /// `error::Unspecified` if random generation or key construction fails.
    pub fn generate(algorithm: Algorithm) -> Result<Self, Unspecified> {
        let mut key_bytes = vec![0u8; algorithm.key_len()];
        rand::fill(&mut key_bytes)?;
        Self::new(algorithm, &key_bytes)
    }

    /// Construct a CMAC signing key using the given algorithm and key value.
    ///
    /// `key_value` should be a value generated using a secure random number
    /// generator or derived from a random key by a key derivation function.
    ///
    /// # Errors
    /// `error::Unspecified` if the key length doesn't match the algorithm or if CMAC context
    /// initialization fails.
    pub fn new(algorithm: Algorithm, key_value: &[u8]) -> Result<Self, Unspecified> {
        if key_value.len() != algorithm.key_len() {
            return Err(Unspecified);
        }

        let mut ctx = LcPtr::new(unsafe { CMAC_CTX_new() })?;
        
        unsafe {
            let cipher = algorithm.id.evp_cipher();
            if 1 != CMAC_Init(
                *ctx.as_mut(),
                key_value.as_ptr().cast(),
                key_value.len(),
                *cipher,
                null_mut(),
            ) {
                return Err(Unspecified);
            }
        }

        Ok(Self { algorithm, ctx })
    }

    /// The algorithm for the key.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

/// A context for multi-step (Init-Update-Finish) CMAC signing.
///
/// Use `sign` for single-step CMAC signing.
pub struct Context {
    key: Key,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
        }
    }
}

unsafe impl Send for Context {}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Context")
            .field("algorithm", &self.key.algorithm)
            .finish()
    }
}

impl Context {
    /// Constructs a new CMAC signing context using the given key.
    #[inline]
    #[must_use]
    pub fn with_key(key: &Key) -> Self {
        Self {
            key: key.clone(),
        }
    }

    /// Updates the CMAC with all the data in `data`. `update` may be called
    /// zero or more times until `sign` is called.
    ///
    /// # Errors
    /// `error::Unspecified` if the CMAC cannot be updated.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Unspecified> {
        unsafe {
            if 1 != CMAC_Update(*self.key.ctx.as_mut(), data.as_ptr(), data.len()) {
                return Err(Unspecified);
            }
        }
        Ok(())
    }

    /// Finalizes the CMAC calculation and returns the CMAC value. `sign`
    /// consumes the context so it cannot be (mis-)used after `sign` has been
    /// called.
    ///
    /// It is generally not safe to implement CMAC verification by comparing
    /// the return value of `sign` to a tag. Use `verify` for verification
    /// instead.
    ///
    //
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128`
    // * `AES_256`
    //
    /// # Errors
    /// `error::Unspecified` if the CMAC calculation cannot be finalized.
    pub fn sign(mut self) -> Result<Tag, Unspecified> {
        let mut output = [0u8; MAX_CMAC_TAG_LEN];
        let mut out_len = MaybeUninit::<usize>::uninit();
        
        unsafe {
            if 1 != indicator_check!(CMAC_Final(
                *self.key.ctx.as_mut(),
                output.as_mut_ptr(),
                out_len.as_mut_ptr(),
            )) {
                return Err(Unspecified);
            }
            
            let actual_len = out_len.assume_init();
            if actual_len != self.key.algorithm.tag_len() {
                return Err(Unspecified);
            }
            
            Ok(Tag {
                bytes: output,
                len: actual_len,
            })
        }
    }
}

/// Calculates the CMAC of `data` using the key `key` in one step.
///
/// Use `Context` to calculate CMACs where the input is in multiple parts.
///
/// It is generally not safe to implement CMAC verification by comparing the
/// return value of `sign` to a tag. Use `verify` for verification instead.
//
// # FIPS
// Use this function with one of the following algorithms:
// * `AES_128`
// * `AES_256`
//
/// # Errors
/// `error::Unspecified` if the CMAC calculation fails.
#[inline]
pub fn sign(key: &Key, data: &[u8]) -> Result<Tag, Unspecified> {
    let mut ctx = Context::with_key(key);
    ctx.update(data)?;
    ctx.sign()
}

/// Calculates the CMAC of `data` using the signing key `key`, and verifies
/// whether the resultant value equals `tag`, in one step.
///
/// This is logically equivalent to, but more efficient than, constructing a
/// `Key` with the same value as `key` and then using `verify`.
///
/// The verification will be done in constant time to prevent timing attacks.
///
/// # Errors
/// `error::Unspecified` if the inputs are not verified or CMAC calculation fails.
//
// # FIPS
// Use this function with one of the following algorithms:
// * `AES_128`
// * `AES_256`
#[inline]
pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<(), Unspecified> {
    let computed_tag = sign(key, data)?;
    constant_time::verify_slices_are_equal(computed_tag.as_ref(), tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "fips")]
    mod fips;

    #[test]
    fn cmac_basic_test() {
        for &algorithm in &[AES_128, AES_192, AES_256, TDES_FOR_LEGACY_USE_ONLY] {
            let key = Key::generate(algorithm).unwrap();
            let data = b"hello, world";
            
            let tag = sign(&key, data).unwrap();
            assert!(verify(&key, data, tag.as_ref()).is_ok());
            assert!(verify(&key, b"hello, worle", tag.as_ref()).is_err());
        }
    }

    // Make sure that `Key::generate` and `verify` aren't completely wacky.
    #[test]
    pub fn cmac_signing_key_coverage() {
        const HELLO_WORLD_GOOD: &[u8] = b"hello, world";
        const HELLO_WORLD_BAD: &[u8] = b"hello, worle";

        for algorithm in &[AES_128, AES_192, AES_256, TDES_FOR_LEGACY_USE_ONLY] {
            let key = Key::generate(*algorithm).unwrap();
            let tag = sign(&key, HELLO_WORLD_GOOD).unwrap();
            println!("{key:?}");
            assert!(verify(&key, HELLO_WORLD_GOOD, tag.as_ref()).is_ok());
            assert!(verify(&key, HELLO_WORLD_BAD, tag.as_ref()).is_err());
        }
    }

    #[test]
    fn cmac_coverage() {
        // Something would have gone horribly wrong for this to not pass, but we test this so our
        // coverage reports will look better.
        assert_ne!(AES_128, AES_256);
        assert_ne!(AES_192, AES_256);

        for &alg in &[AES_128, AES_192, AES_256, TDES_FOR_LEGACY_USE_ONLY] {
            // Clone after updating context with message, then check if the final Tag is the same.
            let key_bytes = vec![0u8; alg.key_len()];
            let key = Key::new(alg, &key_bytes).unwrap();
            let mut ctx = Context::with_key(&key);
            ctx.update(b"hello, world").unwrap();
            let ctx_clone = ctx.clone();

            let orig_tag = ctx.sign().unwrap();
            let clone_tag = ctx_clone.sign().unwrap();
            assert_eq!(orig_tag.as_ref(), clone_tag.as_ref());
            assert_eq!(orig_tag.clone().as_ref(), clone_tag.as_ref());
        }
    }

    #[test]
    fn cmac_context_test() {
        let key = Key::generate(AES_192).unwrap();
        
        let mut ctx = Context::with_key(&key);
        ctx.update(b"hello").unwrap();
        ctx.update(b", ").unwrap();
        ctx.update(b"world").unwrap();
        let tag1 = ctx.sign().unwrap();
        
        let tag2 = sign(&key, b"hello, world").unwrap();
        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }

    #[test]
    fn cmac_multi_part_test() {
        let parts = ["hello", ", ", "world"];
        
        for &algorithm in &[AES_128, AES_256] {
            let key = Key::generate(algorithm).unwrap();
            
            // Multi-part signing
            let mut ctx = Context::with_key(&key);
            for part in &parts {
                ctx.update(part.as_bytes()).unwrap();
            }
            let tag = ctx.sign().unwrap();
            
            // Verification with concatenated message
            let mut msg = Vec::<u8>::new();
            for part in &parts {
                msg.extend(part.as_bytes());
            }
            assert!(verify(&key, &msg, tag.as_ref()).is_ok());
        }
    }

    #[test]
    fn cmac_key_new_test() {
        // Test Key::new with explicit key values
        let key_128 = [0u8; 16];
        let key_192 = [0u8; 24]; 
        let key_256 = [0u8; 32];
        let key_3des = [0u8; 24];
        
        let k1 = Key::new(AES_128, &key_128).unwrap();
        let k2 = Key::new(AES_192, &key_192).unwrap();
        let k3 = Key::new(AES_256, &key_256).unwrap();
        let k4 = Key::new(TDES_FOR_LEGACY_USE_ONLY, &key_3des).unwrap();
        
        let data = b"test message";
        
        // All should produce valid tags
        let _ = sign(&k1, data).unwrap();
        let _ = sign(&k2, data).unwrap();
        let _ = sign(&k3, data).unwrap();
        let _ = sign(&k4, data).unwrap();
    }

    #[test]
    fn cmac_key_new_wrong_length_test() {
        let key_256 = [0u8; 32];
        // Wrong key length should return error
        assert!(Key::new(AES_128, &key_256).is_err());
    }

    #[test]
    fn cmac_algorithm_properties() {
        assert_eq!(AES_128.key_len(), 16);
        assert_eq!(AES_128.tag_len(), 16);
        
        assert_eq!(AES_192.key_len(), 24);
        assert_eq!(AES_192.tag_len(), 16);
        
        assert_eq!(AES_256.key_len(), 32);
        assert_eq!(AES_256.tag_len(), 16);
        
        assert_eq!(TDES_FOR_LEGACY_USE_ONLY.key_len(), 24);
        assert_eq!(TDES_FOR_LEGACY_USE_ONLY.tag_len(), 8);
    }

    #[test]
    fn cmac_empty_data() {
        let key = Key::generate(AES_128).unwrap();
        
        // CMAC should work with empty data
        let tag = sign(&key, b"").unwrap();
        assert!(verify(&key, b"", tag.as_ref()).is_ok());
        
        // Context version
        let ctx = Context::with_key(&key);
        let tag2 = ctx.sign().unwrap();
        assert_eq!(tag.as_ref(), tag2.as_ref());
    }

    #[test]
    fn des_ede3_cmac_test() {
        let key = Key::generate(TDES_FOR_LEGACY_USE_ONLY).unwrap();
        let data = b"test data for 3DES CMAC";
        
        let tag = sign(&key, data).unwrap();
        assert_eq!(tag.as_ref().len(), 8); // 3DES block size
        assert!(verify(&key, data, tag.as_ref()).is_ok());
    }
}
