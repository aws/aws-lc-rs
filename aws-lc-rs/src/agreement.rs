// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key Agreement: ECDH, including X25519.
//!
//! # Example
//!
//! Note that this example uses X25519, but ECDH using NIST P-256/P-384 is done
//! exactly the same way, just substituting
//! `agreement::ECDH_P256`/`agreement::ECDH_P384` for `agreement::X25519`.
//!
//! ```
//! use aws_lc_rs::{agreement, rand};
//!
//! let rng = rand::SystemRandom::new();
//!
//! let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
//!
//! // Make `my_public_key` a byte slice containing my public key. In a real
//! // application, this would be sent to the peer in an encoded protocol
//! // message.
//! let my_public_key = my_private_key.compute_public_key()?;
//!
//! let peer_public_key = {
//!     // In a real application, the peer public key would be parsed out of a
//!     // protocol message. Here we just generate one.
//!     let peer_public_key = {
//!         let peer_private_key =
//!             agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
//!         peer_private_key.compute_public_key()?
//!     };
//!
//!     agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key)
//! };
//!
//! agreement::agree_ephemeral(
//!     my_private_key,
//!     &peer_public_key,
//!     aws_lc_rs::error::Unspecified,
//!     |_key_material| {
//!         // In a real application, we'd apply a KDF to the key material and the
//!         // public keys (as recommended in RFC 7748) and then derive session
//!         // keys from the result. We omit all that here.
//!         Ok(())
//!     },
//! )?;
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
use crate::ec::{
    ec_group_from_nid, ec_key_from_public_point, ec_key_generate, ec_point_from_bytes,
};
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::ptr::LcPtr;
use crate::rand::SecureRandom;
use crate::{ec, test};
use aws_lc::{
    EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id, EVP_PKEY_assign_EC_KEY, EVP_PKEY_derive,
    EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer, EVP_PKEY_get_raw_public_key, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_new_raw_public_key, NID_X9_62_prime256v1,
    NID_secp384r1, NID_secp521r1, EVP_PKEY, EVP_PKEY_X25519, NID_X25519,
};

use core::fmt;
use std::fmt::{Debug, Formatter};
use std::ptr::null_mut;

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum AlgorithmID {
    ECDH_P256,
    ECDH_P384,
    ECDH_P521,
    X25519,
}

impl AlgorithmID {
    #[inline]
    fn nid(&self) -> i32 {
        match self {
            AlgorithmID::ECDH_P256 => NID_X9_62_prime256v1,
            AlgorithmID::ECDH_P384 => NID_secp384r1,
            AlgorithmID::ECDH_P521 => NID_secp521r1,
            AlgorithmID::X25519 => NID_X25519,
        }
    }

    #[inline]
    fn pub_key_len(&self) -> usize {
        match self {
            AlgorithmID::ECDH_P256 => 65,
            AlgorithmID::ECDH_P384 => 97,
            AlgorithmID::ECDH_P521 => 133,
            AlgorithmID::X25519 => 32,
        }
    }
}

impl Debug for AlgorithmID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let output = match self {
            AlgorithmID::ECDH_P256 => "curve: P256",
            AlgorithmID::ECDH_P384 => "curve: P384",
            AlgorithmID::ECDH_P521 => "curve: P521",
            AlgorithmID::X25519 => "curve: Curve25519",
        };
        f.write_str(output)
    }
}

/// A key agreement algorithm.
#[derive(PartialEq, Eq)]
pub struct Algorithm {
    id: AlgorithmID,
}

impl Debug for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("Algorithm {{ {:?} }}", self.id))
    }
}

/// ECDH using the NSA Suite B P-256 (secp256r1) curve.
pub static ECDH_P256: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P256,
};

/// ECDH using the NSA Suite B P-384 (secp384r1) curve.
pub static ECDH_P384: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P384,
};

/// ECDH using the NSA Suite B P-521 (secp521r1) curve.
pub static ECDH_P521: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P521,
};

/// X25519 (ECDH using Curve25519) as described in [RFC 7748].
///
/// Everything is as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in [RFC 7748 section 6.1].
///
/// [RFC 7748]: https://tools.ietf.org/html/rfc7748
/// [RFC 7748 section 6.1]: https://tools.ietf.org/html/rfc7748#section-6.1
pub static X25519: Algorithm = Algorithm {
    id: AlgorithmID::X25519,
};
#[cfg(test)]
const X25519_PRIVATE_KEY_LEN: usize = aws_lc::X25519_PRIVATE_KEY_LEN as usize;
#[cfg(test)]
const ECDH_P256_PRIVATE_KEY_LEN: usize = 32;
#[cfg(test)]
const ECDH_P384_PRIVATE_KEY_LEN: usize = 48;
const ECDH_P521_PRIVATE_KEY_LEN: usize = 66;
const X25519_SHARED_KEY_LEN: usize = aws_lc::X25519_SHARED_KEY_LEN as usize;
#[allow(non_camel_case_types)]
enum KeyInner {
    ECDH_P256(LcPtr<EVP_PKEY>),
    ECDH_P384(LcPtr<EVP_PKEY>),
    ECDH_P521(LcPtr<EVP_PKEY>),
    X25519(LcPtr<EVP_PKEY>),
}

/// An ephemeral private key for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `EphemeralPrivateKey` can be
/// used for at most one key agreement.
pub struct EphemeralPrivateKey {
    inner_key: KeyInner,
}

impl KeyInner {
    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        match self {
            KeyInner::ECDH_P256(..) => &ECDH_P256,
            KeyInner::ECDH_P384(..) => &ECDH_P384,
            KeyInner::ECDH_P521(..) => &ECDH_P521,
            KeyInner::X25519(..) => &X25519,
        }
    }
}

unsafe impl Send for EphemeralPrivateKey {}

// https://github.com/awslabs/aws-lc/blob/main/include/openssl/ec_key.h#L88
// An |EC_KEY| object represents a public or private EC key. A given object may
// be used concurrently on multiple threads by non-mutating functions, provided
// no other thread is concurrently calling a mutating function. Unless otherwise
// documented, functions which take a |const| pointer are non-mutating and
// functions which take a non-|const| pointer are mutating.
unsafe impl Sync for EphemeralPrivateKey {}

impl Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "EphemeralPrivateKey {{ algorithm: {:?} }}",
            self.inner_key.algorithm()
        ))
    }
}

impl EphemeralPrivateKey {
    #[inline]
    /// Generate a new ephemeral private key for the given algorithm.
    ///
    /// # *ring* Compatibility
    ///  Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    ///
    /// # FIPS
    /// FIPS users should only utilize this method with `ECDH_P256`, `ECDH_P384`, or `ECDH_P521` algorithms.
    pub fn generate(alg: &'static Algorithm, _rng: &dyn SecureRandom) -> Result<Self, Unspecified> {
        match alg.id {
            AlgorithmID::X25519 => {
                let priv_key = generate_x25519()?;
                Ok(EphemeralPrivateKey {
                    inner_key: KeyInner::X25519(priv_key),
                })
            }
            AlgorithmID::ECDH_P256 => {
                let ec_key = ec_key_generate(ECDH_P256.id.nid())?;
                Ok(EphemeralPrivateKey {
                    inner_key: KeyInner::ECDH_P256(ec_key),
                })
            }
            AlgorithmID::ECDH_P384 => {
                let ec_key = ec_key_generate(ECDH_P384.id.nid())?;
                Ok(EphemeralPrivateKey {
                    inner_key: KeyInner::ECDH_P384(ec_key),
                })
            }
            AlgorithmID::ECDH_P521 => {
                let ec_key = ec_key_generate(ECDH_P521.id.nid())?;
                Ok(EphemeralPrivateKey {
                    inner_key: KeyInner::ECDH_P521(ec_key),
                })
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::missing_errors_doc)]
    pub fn generate_for_test(
        alg: &'static Algorithm,
        rng: &dyn SecureRandom,
    ) -> Result<Self, Unspecified> {
        match alg.id {
            AlgorithmID::X25519 => {
                let mut priv_key = [0u8; X25519_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_x25519_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P256 => {
                let mut priv_key = [0u8; ECDH_P256_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_p256_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P384 => {
                let mut priv_key = [0u8; ECDH_P384_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_p384_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P521 => {
                let mut priv_key = [0u8; ECDH_P521_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_p521_private_key(&priv_key)
            }
        }
    }

    #[cfg(test)]
    fn from_x25519_private_key(
        priv_key: &[u8; X25519_PRIVATE_KEY_LEN],
    ) -> Result<Self, Unspecified> {
        use aws_lc::EVP_PKEY_new_raw_private_key;

        let pkey = LcPtr::new(unsafe {
            EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519,
                null_mut(),
                priv_key.as_ptr(),
                priv_key.len(),
            )
        })?;

        Ok(EphemeralPrivateKey {
            inner_key: KeyInner::X25519(pkey),
        })
    }

    #[cfg(test)]
    fn from_p256_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        let pkey = from_ec_private_key(priv_key, ECDH_P256.id.nid())?;
        Ok(EphemeralPrivateKey {
            inner_key: KeyInner::ECDH_P256(pkey),
        })
    }

    #[cfg(test)]
    fn from_p384_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        let pkey = from_ec_private_key(priv_key, ECDH_P384.id.nid())?;
        Ok(EphemeralPrivateKey {
            inner_key: KeyInner::ECDH_P384(pkey),
        })
    }

    #[cfg(test)]
    fn from_p521_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        let pkey = from_ec_private_key(priv_key, ECDH_P521.id.nid())?;
        Ok(EphemeralPrivateKey {
            inner_key: KeyInner::ECDH_P521(pkey),
        })
    }

    /// Computes the public key from the private key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        match &self.inner_key {
            KeyInner::ECDH_P256(evp_pkey)
            | KeyInner::ECDH_P384(evp_pkey)
            | KeyInner::ECDH_P521(evp_pkey) => {
                let mut buffer = [0u8; MAX_PUBLIC_KEY_LEN];
                unsafe {
                    let key_len =
                        ec::marshal_public_key_to_buffer(&mut buffer, &evp_pkey.as_const())?;
                    Ok(PublicKey {
                        alg: self.algorithm(),
                        public_key: buffer,
                        len: key_len,
                    })
                }
            }
            KeyInner::X25519(priv_key) => {
                let mut buffer = [0u8; MAX_PUBLIC_KEY_LEN];
                let mut out_len = buffer.len();

                if 1 != unsafe {
                    EVP_PKEY_get_raw_public_key(**priv_key, buffer.as_mut_ptr(), &mut out_len)
                } {
                    return Err(Unspecified);
                }

                Ok(PublicKey {
                    alg: self.algorithm(),
                    public_key: buffer,
                    len: out_len,
                })
            }
        }
    }

    /// The algorithm for the private key.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.inner_key.algorithm()
    }
}

#[cfg(test)]
fn from_ec_private_key(priv_key: &[u8], nid: i32) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    use crate::ptr::DetachableLcPtr;

    let ec_group = unsafe { ec_group_from_nid(nid)? };
    let priv_key = DetachableLcPtr::try_from(priv_key)?;

    let pkey = unsafe { ec::ec_key_from_private(&ec_group.as_const(), &priv_key.as_const())? };

    Ok(pkey)
}

pub(crate) fn generate_x25519() -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx) } {
        return Err(Unspecified);
    }

    let mut pkey: *mut EVP_PKEY = null_mut();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx, &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

const MAX_PUBLIC_KEY_LEN: usize = ec::PUBLIC_KEY_MAX_LEN;

/// A public key for key agreement.
pub struct PublicKey {
    alg: &'static Algorithm,
    public_key: [u8; MAX_PUBLIC_KEY_LEN],
    len: usize,
}

impl PublicKey {
    /// The algorithm for the public key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.alg
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "PublicKey {{ algorithm: {:?}, bytes: \"{}\" }}",
            self.alg,
            test::to_hex(&self.public_key[0..self.len])
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.public_key[0..self.len]
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey {
            alg: self.alg,
            public_key: self.public_key,
            len: self.len,
        }
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
#[derive(Clone)]
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    alg: &'static Algorithm,
    bytes: B,
}

impl<B: Copy + AsRef<[u8]>> Copy for UnparsedPublicKey<B> {}

impl<B: Debug + AsRef<[u8]>> Debug for UnparsedPublicKey<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "UnparsedPublicKey {{ algorithm: {:?}, bytes: {:?} }}",
            self.alg,
            test::to_hex(self.bytes.as_ref())
        ))
    }
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Constructs a new `UnparsedPublicKey`.
    pub fn new(algorithm: &'static Algorithm, bytes: B) -> Self {
        UnparsedPublicKey {
            alg: algorithm,
            bytes,
        }
    }

    /// The agreement algorithm associated with this public key
    pub fn algorithm(&self) -> &'static Algorithm {
        self.alg
    }

    /// The bytes provided for this public key
    pub fn bytes(&self) -> &B {
        &self.bytes
    }
}

/// Performs a key agreement with an ephemeral private key and the given public
/// key.
///
/// `my_private_key` is the ephemeral private key to use. Since it is moved, it
/// will not be usable after calling `agree_ephemeral`, thus guaranteeing that
/// the key is used for only one key agreement.
///
/// `peer_public_key` is the peer's public key. `agree_ephemeral` will return
/// `Err(error_value)` if it does not match `my_private_key's` algorithm/curve.
/// `agree_ephemeral` verifies that it is encoded in the standard form for the
/// algorithm and that the key is *valid*; see the algorithm's documentation for
/// details on how keys are to be encoded and what constitutes a valid key for
/// that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree_ephemeral` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
///
/// # Errors
/// `error_value` on internal failure.
///
/// # FIPS
/// FIPS users should only utilize this method with `ECDH_P256`, `ECDH_P384`, or `ECDH_P521` keys.
#[inline]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::missing_panics_doc)]
pub fn agree_ephemeral<B: AsRef<[u8]>, F, R, E>(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
    error_value: E,
    kdf: F,
) -> Result<R, E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    let expected_alg = my_private_key.algorithm();
    let expected_pub_key_len = expected_alg.id.pub_key_len();
    let expected_nid = expected_alg.id.nid();

    if peer_public_key.alg != expected_alg {
        return Err(error_value);
    }
    let peer_pub_bytes = peer_public_key.bytes.as_ref();
    if peer_pub_bytes.len() != expected_pub_key_len {
        return Err(error_value);
    }

    let mut buffer = [0u8; MAX_AGREEMENT_SECRET_LEN];

    let secret: &[u8] = match &my_private_key.inner_key {
        KeyInner::X25519(priv_key) => {
            x25519_diffie_hellman(&mut buffer, priv_key, peer_pub_bytes).or(Err(error_value))?
        }
        KeyInner::ECDH_P256(priv_key)
        | KeyInner::ECDH_P384(priv_key)
        | KeyInner::ECDH_P521(priv_key) => {
            ec_key_ecdh(&mut buffer, priv_key, peer_pub_bytes, expected_nid).or(Err(error_value))?
        }
    };
    kdf(secret)
}

// Current max secret length is P-521's.
const MAX_AGREEMENT_SECRET_LEN: usize = ECDH_P521_PRIVATE_KEY_LEN;

#[inline]
#[allow(clippy::needless_pass_by_value)]
fn ec_key_ecdh<'a>(
    buffer: &'a mut [u8; MAX_AGREEMENT_SECRET_LEN],
    priv_key: &LcPtr<EVP_PKEY>,
    peer_pub_key_bytes: &[u8],
    nid: i32,
) -> Result<&'a [u8], ()> {
    let ec_group = unsafe { ec_group_from_nid(nid)? };
    let pub_key_point = unsafe { ec_point_from_bytes(&ec_group, peer_pub_key_bytes) }?;
    let peer_ec_key = unsafe { ec_key_from_public_point(&ec_group, &pub_key_point) }?;

    let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(**priv_key, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_derive_init(*pkey_ctx) } {
        return Err(());
    };

    let pub_key = LcPtr::new(unsafe { EVP_PKEY_new() })?;
    if 1 != unsafe { EVP_PKEY_assign_EC_KEY(*pub_key, *peer_ec_key) } {
        return Err(());
    }
    peer_ec_key.detach();

    if 1 != unsafe { EVP_PKEY_derive_set_peer(*pkey_ctx, *pub_key) } {
        return Err(());
    }

    let mut out_key_len = buffer.len();

    if 1 != indicator_check!(unsafe {
        EVP_PKEY_derive(*pkey_ctx, buffer.as_mut_ptr(), &mut out_key_len)
    }) {
        return Err(());
    }

    if 0 == out_key_len {
        return Err(());
    }

    Ok(&buffer[0..out_key_len])
}

#[inline]
fn x25519_diffie_hellman<'a>(
    buffer: &'a mut [u8; MAX_AGREEMENT_SECRET_LEN],
    priv_key: &LcPtr<EVP_PKEY>,
    peer_pub_key: &[u8],
) -> Result<&'a [u8], ()> {
    let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(**priv_key, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_derive_init(*pkey_ctx) } {
        return Err(());
    };

    let pub_key = LcPtr::new(unsafe {
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            null_mut(),
            peer_pub_key.as_ptr(),
            peer_pub_key.len(),
        )
    })?;

    if 1 != unsafe { EVP_PKEY_derive_set_peer(*pkey_ctx, *pub_key) } {
        return Err(());
    }

    let mut out_key_len = buffer.len();

    if 1 != indicator_check!(unsafe {
        EVP_PKEY_derive(*pkey_ctx, buffer.as_mut_ptr(), &mut out_key_len)
    }) {
        return Err(());
    }

    debug_assert!(out_key_len == X25519_SHARED_KEY_LEN);

    Ok(&buffer[0..X25519_SHARED_KEY_LEN])
}

#[cfg(test)]
mod tests {
    use crate::error::Unspecified;
    use crate::{agreement, rand, test, test_file};

    #[cfg(feature = "fips")]
    mod fips;

    #[test]
    fn test_agreement_ecdh_x25519_rfc_iterated() {
        fn expect_iterated_x25519(
            expected_result: &str,
            range: core::ops::Range<usize>,
            k: &mut Vec<u8>,
            u: &mut Vec<u8>,
        ) {
            for _ in range {
                let new_k = x25519(k, u);
                *u = k.clone();
                *k = new_k;
            }
            assert_eq!(&h(expected_result), k);
        }

        let mut k = h("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k.clone();

        expect_iterated_x25519(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            0..1,
            &mut k,
            &mut u,
        );
        expect_iterated_x25519(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            1..1_000,
            &mut k,
            &mut u,
        );

        // The spec gives a test vector for 1,000,000 iterations but it takes
        // too long to do 1,000,000 iterations by default right now. This
        // 10,000 iteration vector is self-computed.
        expect_iterated_x25519(
            "2c125a20f639d504a7703d2e223c79a79de48c4ee8c23379aa19a62ecd211815",
            1_000..10_000,
            &mut k,
            &mut u,
        );

        if cfg!(feature = "slow_tests") {
            expect_iterated_x25519(
                "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
                10_000..1_000_000,
                &mut k,
                &mut u,
            );
        }
    }

    #[test]
    fn test_agreement_x25519() {
        let alg = &agreement::X25519;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            ),
        );

        let my_private = test::from_dirty_hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019",
        );
        let output = test::from_dirty_hex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_agreement_ecdh_p256() {
        let alg = &agreement::ECDH_P256;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
            ),
        );
        assert_eq!(peer_public.algorithm(), alg);
        assert_eq!(peer_public.bytes(), &peer_public.bytes);

        let my_private = test::from_dirty_hex(
            "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C37725811805271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        );
        let output = test::from_dirty_hex(
            "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_agreement_ecdh_p384() {
        let alg = &agreement::ECDH_P384;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "04E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C",
            ),
        );

        let my_private = test::from_dirty_hex(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C",
        );
        let output = test::from_dirty_hex(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_agreement_ecdh_p521() {
        let alg = &agreement::ECDH_P521;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "0401a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359dbbc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f446d017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67cde85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d1a46",
            ),
        );

        let my_private = test::from_dirty_hex(
            "00df14b1f1432a7b0fb053965fd8643afee26b2451ecb6a8a53a655d5fbe16e4c64ce8647225eb11e7fdcb23627471dffc5c2523bd2ae89957cba3a57a23933e5a78",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04004e8583bbbb2ecd93f0714c332dff5ab3bc6396e62f3c560229664329baa5138c3bb1c36428abd4e23d17fcb7a2cfcc224b2e734c8941f6f121722d7b6b9415457601cf0874f204b0363f020864672fadbf87c8811eb147758b254b74b14fae742159f0f671a018212bbf25b8519e126d4cad778cfff50d288fd39ceb0cac635b175ec0",
        );
        let output = test::from_dirty_hex(
            "01aaf24e5d47e4080c18c55ea35581cd8da30f1a079565045d2008d51b12d0abb4411cda7a0785b15d149ed301a3697062f42da237aa7f07e0af3fd00eb1800d9c41",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn agreement_traits() {
        use regex;
        use regex::Regex;

        let rng = rand::SystemRandom::new();
        let private_key =
            agreement::EphemeralPrivateKey::generate_for_test(&agreement::ECDH_P256, &rng).unwrap();

        test::compile_time_assert_send::<agreement::EphemeralPrivateKey>();
        //test::compile_time_assert_sync::<agreement::EphemeralPrivateKey>();

        assert_eq!(
            format!("{:?}", &private_key),
            "EphemeralPrivateKey { algorithm: Algorithm { curve: P256 } }"
        );

        let public_key = private_key.compute_public_key().unwrap();
        let pubkey_re = Regex::new(
            "PublicKey \\{ algorithm: Algorithm \\{ curve: P256 \\}, bytes: \"[0-9a-f]+\" \\}",
        )
        .unwrap();
        let pubkey_debug = format!("{:?}", &public_key);

        assert!(
            pubkey_re.is_match(&pubkey_debug),
            "pubkey_debug: {pubkey_debug}"
        );

        #[allow(clippy::redundant_clone)]
        let pubkey_clone = public_key.clone();
        assert_eq!(public_key.as_ref(), pubkey_clone.as_ref());
        assert_eq!(pubkey_debug, format!("{:?}", &pubkey_clone));

        test::compile_time_assert_clone::<agreement::PublicKey>();
        test::compile_time_assert_send::<agreement::PublicKey>();
        //test::compile_time_assert_sync::<agreement::PublicKey>();

        // Verify `PublicKey` implements `Debug`.
        //
        // TODO: Test the actual output.
        let _: &dyn core::fmt::Debug = &public_key;

        test::compile_time_assert_clone::<agreement::UnparsedPublicKey<&[u8]>>();
        test::compile_time_assert_copy::<agreement::UnparsedPublicKey<&[u8]>>();
        test::compile_time_assert_sync::<agreement::UnparsedPublicKey<&[u8]>>();

        test::compile_time_assert_clone::<agreement::UnparsedPublicKey<Vec<u8>>>();
        test::compile_time_assert_sync::<agreement::UnparsedPublicKey<Vec<u8>>>();

        let bytes = [0x01, 0x02, 0x03];

        let unparsed_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, &bytes);
        let unparsed_pubkey_clone = unparsed_public_key;
        assert_eq!(
            format!("{unparsed_public_key:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );
        assert_eq!(
            format!("{unparsed_pubkey_clone:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );

        let unparsed_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, Vec::from(bytes));
        #[allow(clippy::redundant_clone)]
        let unparsed_pubkey_clone = unparsed_public_key.clone();
        assert_eq!(
            format!("{unparsed_public_key:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );
        assert_eq!(
            format!("{unparsed_pubkey_clone:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );
    }

    #[test]
    fn agreement_agree_ephemeral() {
        let rng = rand::SystemRandom::new();

        test::run(
            test_file!("data/agreement_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let curve_name = test_case.consume_string("Curve");
                let alg = alg_from_curve_name(&curve_name);
                let peer_public =
                    agreement::UnparsedPublicKey::new(alg, test_case.consume_bytes("PeerQ"));

                match test_case.consume_optional_string("Error") {
                    None => {
                        let my_private_bytes = test_case.consume_bytes("D");
                        let my_private = {
                            let rng = test::rand::FixedSliceRandom {
                                bytes: &my_private_bytes,
                            };
                            agreement::EphemeralPrivateKey::generate_for_test(alg, &rng)?
                        };
                        let my_public = test_case.consume_bytes("MyQ");
                        let output = test_case.consume_bytes("Output");

                        assert_eq!(my_private.algorithm(), alg);

                        let computed_public = my_private.compute_public_key().unwrap();
                        assert_eq!(computed_public.as_ref(), &my_public[..]);

                        assert_eq!(my_private.algorithm(), alg);

                        let result = agreement::agree_ephemeral(
                            my_private,
                            &peer_public,
                            (),
                            |key_material| {
                                assert_eq!(key_material, &output[..]);
                                Ok(())
                            },
                        );
                        assert_eq!(
                            result,
                            Ok(()),
                            "Failed on private key: {:?}",
                            test::to_hex(my_private_bytes)
                        );
                    }

                    Some(_) => {
                        fn kdf_not_called(_: &[u8]) -> Result<(), ()> {
                            panic!(
                                "The KDF was called during ECDH when the peer's \
                         public key is invalid."
                            );
                        }
                        let dummy_private_key =
                            agreement::EphemeralPrivateKey::generate(alg, &rng)?;
                        assert!(agreement::agree_ephemeral(
                            dummy_private_key,
                            &peer_public,
                            (),
                            kdf_not_called
                        )
                        .is_err());
                    }
                }

                Ok(())
            },
        );
    }

    fn h(s: &str) -> Vec<u8> {
        match test::from_hex(s) {
            Ok(v) => v,
            Err(msg) => {
                panic!("{msg} in {s}");
            }
        }
    }

    fn alg_from_curve_name(curve_name: &str) -> &'static agreement::Algorithm {
        if curve_name == "P-256" {
            &agreement::ECDH_P256
        } else if curve_name == "P-384" {
            &agreement::ECDH_P384
        } else if curve_name == "P-521" {
            &agreement::ECDH_P521
        } else if curve_name == "X25519" {
            &agreement::X25519
        } else {
            panic!("Unsupported curve: {curve_name}");
        }
    }

    fn x25519(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
        x25519_(private_key, public_key).unwrap()
    }

    fn x25519_(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let rng = test::rand::FixedSliceRandom { bytes: private_key };
        let private_key =
            agreement::EphemeralPrivateKey::generate_for_test(&agreement::X25519, &rng)?;
        let public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, public_key);
        agreement::agree_ephemeral(private_key, &public_key, Unspecified, |agreed_value| {
            Ok(Vec::from(agreed_value))
        })
    }
}
