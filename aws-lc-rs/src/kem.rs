// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key-Encapsulation Mechanisms (KEMs), including support for Kyber Round 3 Submission.
//!
//! # Example
//!
//! Note that this example uses the Kyber-512 Round 3 algorithm, but other algorithms can be used
//! in the exact same way by substituting
//! `kem::<desired_algorithm_here>` for `kem::KYBER512_R3`.
//!
//! ```
//! use aws_lc_rs::{
//!     error::Unspecified,
//!     kem::{Ciphertext, PrivateKey, PublicKey, KYBER512_R3},
//! };
//!
//! // Alice generates their (private) decapsulation key.
//! let priv_key = PrivateKey::generate(&KYBER512_R3)?;
//!
//! // Alices computes the (public) encapsulation key.
//! let pub_key = priv_key.public_key()?;
//!
//! // Alice sends the public key bytes to bob through some
//! // protocol message.
//! let pub_key_bytes = pub_key.as_ref();
//!
//! // Bob constructs the (public) encapsulation key from the key bytes provided by Alice.
//! let retrieved_pub_key = PublicKey::new(&KYBER512_R3, pub_key_bytes)?;
//!
//! // Bob executes the encapsulation algorithm to to produce their copy of the secret, and associated ciphertext.
//! let (ciphertext, bob_secret) = retrieved_pub_key.encapsulate()?;
//!
//! // Alice recieves ciphertext bytes from bob
//! let ciphertext_bytes = ciphertext.as_ref();
//!
//! // Bob sends Alice the ciphertext computed from the encapsulation algorithm, Alice runs decapsulation to derive their
//! // copy of the secret.
//! let alice_secret = priv_key.decapsulate(Ciphertext::from(ciphertext_bytes))?;
//!
//! // Alice and Bob have now arrived to the same secret
//! assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
use crate::{
    error::{KeyRejected, Unspecified},
    ptr::LcPtr,
    ptr::Pointer,
};
use aws_lc::{
    EVP_PKEY_CTX_kem_set_params, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id, EVP_PKEY_decapsulate,
    EVP_PKEY_encapsulate, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_kem_new_raw_public_key, EVP_PKEY_kem_new_raw_secret_key, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY, EVP_PKEY_KEM, NID_KYBER1024_R3, NID_KYBER512_R3,
    NID_KYBER768_R3,
};
use std::{borrow::Cow, ptr::null_mut};
use std::{cmp::Ordering, ops::Deref};
use zeroize::Zeroize;

// Key lengths defined as stated on the CRYSTALS website:
// https://pq-crystals.org/kyber/
//
const KYBER512_R3_SECRET_KEY_LENGTH: usize = 1632;
const KYBER512_R3_CIPHERTEXT_LENGTH: usize = 768;
const KYBER512_R3_PUBLIC_KEY_LENGTH: usize = 800;
const KYBER512_R3_SHARED_SECRET_LENGTH: usize = 32;

const KYBER768_R3_SECRET_KEY_LENGTH: usize = 2400;
const KYBER768_R3_CIPHERTEXT_LENGTH: usize = 1088;
const KYBER768_R3_PUBLIC_KEY_LENGTH: usize = 1184;
const KYBER768_R3_SHARED_SECRET_LENGTH: usize = 32;

const KYBER1024_R3_SECRET_KEY_LENGTH: usize = 3168;
const KYBER1024_R3_CIPHERTEXT_LENGTH: usize = 1568;
const KYBER1024_R3_PUBLIC_KEY_LENGTH: usize = 1568;
const KYBER1024_R3_SHARED_SECRET_LENGTH: usize = 32;

/// KEM algorithm identifier.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AlgorithmId {
    /// NIST Round 3 submission of the Kyber-512 algorithm.
    Kyber512_R3,

    /// NIST Round 3 submission of the Kyber-768 algorithm.
    Kyber768_R3,

    /// NIST Round 3 submission of the Kyber-1024 algorithm.
    Kyber1024_R3,
}

/// A KEM algorithm
#[derive(Debug, PartialEq)]
pub struct Algorithm {
    id: AlgorithmId,
    secret_key_size: usize,
    public_key_size: usize,
    ciphertext_size: usize,
    shared_secret_size: usize,
}

/// NIST Round 3 submission of the Kyber-512 algorithm.
pub static KYBER512_R3: Algorithm = Algorithm {
    id: AlgorithmId::Kyber512_R3,
    secret_key_size: KYBER512_R3_SECRET_KEY_LENGTH,
    public_key_size: KYBER512_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER512_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER512_R3_SHARED_SECRET_LENGTH,
};

/// NIST Round 3 submission of the Kyber-768 algorithm.
pub static KYBER768_R3: Algorithm = Algorithm {
    id: AlgorithmId::Kyber768_R3,
    secret_key_size: KYBER768_R3_SECRET_KEY_LENGTH,
    public_key_size: KYBER768_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER768_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER768_R3_SHARED_SECRET_LENGTH,
};

/// NIST Round 3 submission of the Kyber-1024 algorithm.
pub static KYBER1024_R3: Algorithm = Algorithm {
    id: AlgorithmId::Kyber1024_R3,
    secret_key_size: KYBER1024_R3_SECRET_KEY_LENGTH,
    public_key_size: KYBER1024_R3_PUBLIC_KEY_LENGTH,
    ciphertext_size: KYBER1024_R3_CIPHERTEXT_LENGTH,
    shared_secret_size: KYBER1024_R3_SHARED_SECRET_LENGTH,
};

impl AlgorithmId {
    #[inline]
    fn nid(self) -> i32 {
        match self {
            AlgorithmId::Kyber512_R3 => NID_KYBER512_R3,
            AlgorithmId::Kyber768_R3 => NID_KYBER768_R3,
            AlgorithmId::Kyber1024_R3 => NID_KYBER1024_R3,
        }
    }
}

impl Algorithm {
    /// Returns the identifier for this algorithm.
    #[must_use]
    pub fn id(&self) -> AlgorithmId {
        self.id
    }

    #[inline]
    fn secret_key_size(&self) -> usize {
        self.secret_key_size
    }

    #[inline]
    fn public_key_size(&self) -> usize {
        self.public_key_size
    }

    #[inline]
    fn ciphertext_size(&self) -> usize {
        self.ciphertext_size
    }

    #[inline]
    fn shared_secret_size(&self) -> usize {
        self.shared_secret_size
    }
}

/// A serializable private key usable with KEMs. This can be randomly generated with `KemPrivateKey::generate`
/// or constructed from raw bytes.
#[derive(Debug)]
pub struct PrivateKey {
    algorithm: &'static Algorithm,
    evp_pkey: LcPtr<EVP_PKEY>,
    priv_key: Box<[u8]>,
}

impl PrivateKey {
    /// Generate a new KEM private key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(alg: &'static Algorithm) -> Result<Self, Unspecified> {
        let mut secret_key_size = alg.secret_key_size();
        let mut priv_key_bytes = vec![0u8; secret_key_size];
        let kyber_key = kem_key_generate(alg.id.nid())?;
        if 1 != unsafe {
            EVP_PKEY_get_raw_private_key(
                kyber_key.as_const_ptr(),
                priv_key_bytes.as_mut_ptr(),
                &mut secret_key_size,
            )
        } {
            return Err(Unspecified);
        }
        Ok(PrivateKey {
            algorithm: alg,
            evp_pkey: kyber_key,
            priv_key: priv_key_bytes.into(),
        })
    }

    /// Return the algorithm associated with the given KEM private key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// Computes the KEM public key from the KEM private key
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn public_key(&self) -> Result<PublicKey, Unspecified> {
        let mut public_key_size = self.algorithm.public_key_size();
        let mut pubkey_bytes = vec![0u8; public_key_size];
        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(
                self.evp_pkey.as_const_ptr(),
                pubkey_bytes.as_mut_ptr(),
                &mut public_key_size,
            )
        } {
            return Err(Unspecified);
        }

        let pubkey = LcPtr::new(unsafe {
            EVP_PKEY_kem_new_raw_public_key(
                self.algorithm.id.nid(),
                pubkey_bytes.as_ptr(),
                public_key_size,
            )
        })?;

        Ok(PublicKey {
            algorithm: self.algorithm,
            evp_pkey: pubkey,
            pub_key: pubkey_bytes.into(),
        })
    }

    /// Performs the decapsulate operation using the current KEM private key on the given ciphertext.
    ///
    /// `ciphertext` is the ciphertext generated by the encapsulate operation using the KEM public key
    /// associated with the current KEM private key.
    ///
    /// After the decapsulation is finished, `decapsulate` calls `kdf` with the raw shared secret
    /// from the operation and then returns what `kdf` returns.
    ///
    /// # Errors
    /// `Unspecified` when operation fails due to internal error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn decapsulate(&self, ciphertext: Ciphertext<'_>) -> Result<SharedSecret, Unspecified> {
        let mut shared_secret_len = self.algorithm.shared_secret_size();
        let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];

        let ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.evp_pkey, null_mut()) });
        let ctx = if let Ok(ctx) = ctx {
            ctx
        } else {
            return Err(Unspecified);
        };

        if 1 != unsafe {
            EVP_PKEY_decapsulate(
                *ctx,
                shared_secret.as_mut_ptr(),
                &mut shared_secret_len,
                // AWS-LC incorrectly has this as an unqualified `uint8_t *`, it should be qualified with const
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len(),
            )
        } {
            return Err(Unspecified);
        }

        shared_secret.truncate(shared_secret_len);

        Ok(SharedSecret(shared_secret.into_boxed_slice()))
    }

    /// Creates a new KEM private key from raw bytes. This method is NOT meant to generate
    /// a new private key, rather it restores a `KemPrivateKey` that was previously converted
    /// to raw bytes.
    ///
    /// `alg` is the `Algorithm` to be associated with the generated `KemPrivateKey`
    ///
    /// `bytes` is a slice of raw bytes representing a `KemPrivateKey`
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    pub fn new(alg: &'static Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        match bytes.len().cmp(&alg.secret_key_size()) {
            Ordering::Less => Err(KeyRejected::too_small()),
            Ordering::Greater => Err(KeyRejected::too_large()),
            Ordering::Equal => Ok(()),
        }?;
        let privkey = LcPtr::new(unsafe {
            EVP_PKEY_kem_new_raw_secret_key(alg.id.nid(), bytes.as_ptr(), bytes.len())
        })?;
        Ok(PrivateKey {
            algorithm: alg,
            evp_pkey: privkey,
            priv_key: bytes.into(),
        })
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.priv_key.zeroize();
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.priv_key
    }
}

/// A serializable public key usable with KEMS. This can be constructed
/// from a `KemPrivateKey` or constructed from raw bytes.
#[derive(Debug)]
pub struct PublicKey {
    algorithm: &'static Algorithm,
    evp_pkey: LcPtr<EVP_PKEY>,
    pub_key: Box<[u8]>,
}

impl PublicKey {
    /// Return the algorithm associated with the given KEM public key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// Performs the encapsulate operation using the current KEM public key, generating a ciphertext
    /// and associated shared secret.
    ///
    /// After the encapsulation is finished, `encapsulate` calls `kdf` with the ciphertext and raw shared secret
    /// from the operation and then returns what `kdf` returns.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn encapsulate<'a>(&self) -> Result<(Ciphertext<'a>, SharedSecret), Unspecified> {
        let mut ciphertext_len = self.algorithm.ciphertext_size();
        let mut shared_secret_len = self.algorithm.shared_secret_size();
        let mut ciphertext: Vec<u8> = vec![0u8; ciphertext_len];
        let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];

        let ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.evp_pkey, null_mut()) })?;

        if 1 != unsafe {
            EVP_PKEY_encapsulate(
                *ctx,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                shared_secret.as_mut_ptr(),
                &mut shared_secret_len,
            )
        } {
            return Err(Unspecified);
        }

        ciphertext.truncate(ciphertext_len);
        shared_secret.truncate(shared_secret_len);

        Ok((
            Ciphertext::new(ciphertext),
            SharedSecret(shared_secret.into_boxed_slice()),
        ))
    }

    /// Creates a new KEM public key from raw bytes. This method is MUST NOT be used to generate
    /// a new public key, rather it should be used to construct `PublicKey` that was previously serialized
    /// to raw bytes.
    ///
    /// `alg` is the [`Algorithm`] to be associated with the generated `PublicKey`
    ///
    /// `bytes` is a slice of raw bytes representing a `PublicKey`
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    pub fn new(alg: &'static Algorithm, bytes: &[u8]) -> Result<Self, KeyRejected> {
        match bytes.len().cmp(&alg.public_key_size()) {
            Ordering::Less => Err(KeyRejected::too_small()),
            Ordering::Greater => Err(KeyRejected::too_large()),
            Ordering::Equal => Ok(()),
        }?;
        let pubkey = LcPtr::new(unsafe {
            EVP_PKEY_kem_new_raw_public_key(alg.id.nid(), bytes.as_ptr(), bytes.len())
        })?;
        Ok(PublicKey {
            algorithm: alg,
            evp_pkey: pubkey,
            pub_key: bytes.into(),
        })
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        self.pub_key.zeroize();
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.pub_key
    }
}

/// A set of encrypted bytes produced by [`PublicKey::encapsulate`], and used as an input to [`PrivateKey::decapsulate`].
pub struct Ciphertext<'a>(Cow<'a, [u8]>);

impl<'a> Ciphertext<'a> {
    fn new(value: Vec<u8>) -> Ciphertext<'a> {
        Self(Cow::Owned(value))
    }
}

impl<'a> Drop for Ciphertext<'a> {
    fn drop(&mut self) {
        if let Cow::Owned(ref mut v) = self.0 {
            v.zeroize();
        }
    }
}

impl<'a> Deref for Ciphertext<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self.0 {
            Cow::Borrowed(v) => v,
            Cow::Owned(ref v) => v.as_ref(),
        }
    }
}

impl<'a> From<&'a [u8]> for Ciphertext<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(Cow::Borrowed(value))
    }
}

/// The cryptograpic shared secret output from the KEM encapsulate / decapsulate process.
pub struct SharedSecret(Box<[u8]>);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for SharedSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

// Returns an LcPtr to an EVP_PKEY
#[inline]
fn kem_key_generate(nid: i32) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut()) })?;
    if 1 != unsafe { EVP_PKEY_CTX_kem_set_params(*ctx, nid) }
        || 1 != unsafe { EVP_PKEY_keygen_init(*ctx) }
    {
        return Err(Unspecified);
    }

    let mut key_raw: *mut EVP_PKEY = null_mut();
    if 1 != unsafe { EVP_PKEY_keygen(*ctx, &mut key_raw) } {
        return Err(Unspecified);
    }
    Ok(LcPtr::new(key_raw)?)
}

#[cfg(test)]
mod tests {
    use crate::{
        error::KeyRejected,
        kem::{PrivateKey, PublicKey, KYBER1024_R3, KYBER512_R3, KYBER768_R3},
    };

    #[cfg(private_api)]
    macro_rules! kem_kat_test {
        ($file:literal, $alg:expr) => {
            use crate::{
                aws_lc::{
                    pq_custom_randombytes_init_for_testing,
                    pq_custom_randombytes_use_deterministic_for_testing,
                },
                error::Unspecified,
                test, test_file,
            };
            test::run(test_file!($file), |_section, test_case| {
                let seed = test_case.consume_bytes("seed");
                let public_key_bytes = test_case.consume_bytes("pk");
                let secret_key_bytes = test_case.consume_bytes("sk");
                let ciphertext_bytes = test_case.consume_bytes("ct");
                let shared_secret_bytes = test_case.consume_bytes("ss");

                // Set randomness generation in deterministic mode.
                unsafe {
                    pq_custom_randombytes_use_deterministic_for_testing();
                    pq_custom_randombytes_init_for_testing(seed.as_ptr());
                }

                let priv_key = PrivateKey::generate($alg).unwrap();

                assert_eq!(priv_key.as_ref(), secret_key_bytes);

                let pub_key = priv_key.compute_public_key().unwrap();
                assert_eq!(pub_key.as_ref(), public_key_bytes);

                let (mut ciphertext, bob_shared_secret) = pub_key
                    .encapsulate(Unspecified, |ciphertext, shared_secret| {
                        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
                    })
                    .unwrap();
                assert_eq!(ciphertext, ciphertext_bytes);
                assert_eq!(bob_shared_secret, shared_secret_bytes);

                let alice_shared_secret = priv_key
                    .decapsulate(&mut ciphertext, Unspecified, |shared_secret| {
                        Ok(shared_secret.to_vec())
                    })
                    .unwrap();
                assert_eq!(alice_shared_secret, shared_secret_bytes);

                Ok(())
            });
        };
    }

    #[cfg(private_api)]
    #[test]
    fn test_kem_kyber512() {
        kem_kat_test!("../tests/data/kyber512r3.txt", &KYBER512_R3);
    }

    #[cfg(private_api)]
    #[test]
    fn test_kem_kyber768() {
        kem_kat_test!("../tests/data/kyber768r3.txt", &KYBER768_R3);
    }

    #[cfg(private_api)]
    #[test]
    fn test_kem_kyber1024() {
        kem_kat_test!("../tests/data/kyber1024r3.txt", &KYBER1024_R3);
    }

    #[test]
    fn test_kem_serialize() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let priv_key = PrivateKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.public_key().unwrap();
            let pubkey_raw_bytes = pub_key.as_ref();
            let pub_key_from_bytes = PublicKey::new(algorithm, pubkey_raw_bytes).unwrap();

            assert_eq!(pub_key.as_ref(), pub_key_from_bytes.as_ref());
            assert_eq!(pub_key.algorithm(), pub_key_from_bytes.algorithm());

            let privkey_raw_bytes = priv_key.as_ref();
            let priv_key_from_bytes = PrivateKey::new(algorithm, privkey_raw_bytes).unwrap();

            assert_eq!(priv_key.as_ref(), priv_key_from_bytes.as_ref());
            assert_eq!(priv_key.algorithm(), priv_key_from_bytes.algorithm());
        }
    }

    #[test]
    fn test_kem_wrong_sizes() {
        for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
            let too_long_bytes = vec![0u8; algorithm.secret_key_size() + 1];
            let long_priv_key_from_bytes = PrivateKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_priv_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_long_bytes = vec![0u8; algorithm.public_key_size() + 1];
            let long_pub_key_from_bytes = PublicKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_pub_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_short_bytes = vec![0u8; algorithm.secret_key_size() - 1];
            let short_priv_key_from_bytes = PrivateKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_priv_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );

            let too_short_bytes = vec![0u8; algorithm.public_key_size() - 1];
            let short_pub_key_from_bytes = PublicKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_pub_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );
        }
    }
}
