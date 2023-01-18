// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::Document;
use crate::ptr::LcPtr;
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature, VerificationAlgorithm};
use crate::{constant_time, sealed, test};
use aws_lc::{
    ED25519_keypair_from_seed, ED25519_sign, ED25519_verify, EVP_PKEY_get_raw_private_key,
    EVP_PKEY_get_raw_public_key, EVP_PKEY_new_raw_private_key, EVP_PKEY, EVP_PKEY_ED25519,
};
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use untrusted::Input;
use zeroize::Zeroize;

/// The length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = aws_lc::ED25519_PUBLIC_KEY_LEN as usize;
pub(crate) const ED25519_PRIVATE_KEY_LEN: usize = aws_lc::ED25519_PRIVATE_KEY_LEN as usize;
pub(crate) const ED25519_PRIVATE_KEY_PREFIX_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = aws_lc::ED25519_SIGNATURE_LEN as usize;
const ED25519_SEED_LEN: usize = 32;

/// Parameters for `EdDSA` signing and verification.
#[derive(Debug)]
pub struct EdDSAParameters;

impl sealed::Sealed for EdDSAParameters {}

impl VerificationAlgorithm for EdDSAParameters {
    #[inline]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        unsafe {
            if 1 != ED25519_verify(
                msg.as_slice_less_safe().as_ptr(),
                msg.len(),
                signature.as_slice_less_safe().as_ptr(),
                public_key.as_slice_less_safe().as_ptr(),
            ) {
                return Err(Unspecified);
            }
            Ok(())
        }
    }
}

/// An Ed25519 key pair, for signing.
#[allow(clippy::module_name_repetitions)]
pub struct Ed25519KeyPair {
    private_key: [u8; ED25519_PRIVATE_KEY_LEN],
    public_key: PublicKey,
}

impl Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "Ed25519KeyPair {{ public_key: PublicKey(\"{}\") }}",
            test::to_hex(&self.public_key)
        ))
    }
}

#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKey {
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.public_key
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("PublicKey(\"{}\")", test::to_hex(self.public_key)))
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = PublicKey;
    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

pub(crate) unsafe fn generate_key(rng: &dyn SecureRandom) -> Result<LcPtr<*mut EVP_PKEY>, ()> {
    let mut seed = [0u8; ED25519_SEED_LEN];
    rng.fill(&mut seed)?;

    let mut public_key = MaybeUninit::<[u8; ED25519_PUBLIC_KEY_LEN]>::uninit();
    let mut private_key = MaybeUninit::<[u8; ED25519_PRIVATE_KEY_LEN]>::uninit();
    ED25519_keypair_from_seed(
        public_key.as_mut_ptr().cast(),
        private_key.as_mut_ptr().cast(),
        seed.as_ptr(),
    );
    seed.zeroize();

    LcPtr::new(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        null_mut(),
        private_key.assume_init().as_ptr(),
        ED25519_PRIVATE_KEY_PREFIX_LEN,
    ))
}

impl Ed25519KeyPair {
    /// CURRENTLY NOT SUPPORTED. Use `generate_pkcs8v1` instead.
    ///
    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v2 `OneAsymmetricKey` with the public key,
    /// as described in [RFC 5958 Section 2]; see [RFC 8410 Section 10.3] for an
    /// example.
    ///
    /// [RFC 5958 Section 2]: https://tools.ietf.org/html/rfc5958#section-2
    /// [RFC 8410 Section 10.3]: https://tools.ietf.org/html/rfc8410#section-10.3
    ///
    /// # Errors
    /// `error::Unspecified` for all inputs.
    #[deprecated(
        note = "PKCS#8 v2 keys are not supported by AWS-LC. Support may be added in future versions."
    )]
    pub fn generate_pkcs8(_rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        Err(Unspecified)
    }

    /// Generates a `Ed25519KeyPair` using the `rng` provided, then marshals that key as a
    /// DER-encoded `PrivateKeyInfo` structure (RFC5208).
    ///
    /// # Errors
    /// `error::Unspecified` if `rng` cannot provide enough bits or if there's an internal error.
    pub fn generate_pkcs8v1(rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = generate_key(rng)?;

            evp_pkey.marshall_private_key()
        }
    }

    /// Constructs an Ed25519 key pair from the private key seed `seed` and its
    /// public key `public_key`.
    ///
    /// It is recommended to use `Ed25519KeyPair::from_pkcs8()` instead.
    ///
    /// The private and public keys will be verified to be consistent with each
    /// other. This helps avoid misuse of the key (e.g. accidentally swapping
    /// the private key and public key, or using the wrong private key for the
    /// public key). This also detects any corruption of the public or private
    /// key.
    ///
    /// # Errors
    /// `error::KeyRejected` if parse error, or if key is otherwise unacceptable.
    ///
    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self, KeyRejected> {
        if seed.len() < ED25519_SEED_LEN {
            return Err(KeyRejected::inconsistent_components());
        }

        unsafe {
            let mut derived_public_key = MaybeUninit::<[u8; ED25519_PUBLIC_KEY_LEN]>::uninit();
            let mut private_key = MaybeUninit::<[u8; ED25519_PRIVATE_KEY_LEN]>::uninit();
            ED25519_keypair_from_seed(
                derived_public_key.as_mut_ptr().cast(),
                private_key.as_mut_ptr().cast(),
                seed.as_ptr(),
            );
            let derived_public_key = derived_public_key.assume_init();
            let private_key = private_key.assume_init();

            constant_time::verify_slices_are_equal(public_key, &derived_public_key)
                .map_err(|_| KeyRejected::inconsistent_components())?;

            Ok(Self {
                private_key,
                public_key: PublicKey {
                    public_key: derived_public_key,
                },
            })
        }
    }

    /// CURRENTLY NOT SUPPORTED. Constructs an Ed25519 key pair by parsing an unencrypted PKCS#8 v2
    /// Ed25519 private key.
    ///
    /// `openssl genpkey -algorithm ED25519` generates PKCS#8 v1 keys, which
    /// can be parsed with `Ed25519KeyPair::from_pkcs8_maybe_unchecked()`.
    ///
    /// # Errors
    /// `error::KeyRejected("InvalidEncoding")` for all inputs.
    /// PKCS#8 v2 is currently not supported by AWS-LC.
    #[deprecated(
        note = "PKCS#8 v2 keys are not supported by AWS-LC. Support may be added in future versions."
    )]
    pub fn from_pkcs8(_pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        Err(KeyRejected::invalid_encoding())
    }

    /// Constructs an Ed25519 key pair by parsing an unencrypted PKCS#8 v1
    /// Ed25519 private key.
    ///
    /// `openssl genpkey -algorithm ED25519` generates PKCS# v1 keys.
    ///
    /// PKCS#8 v1 files do not contain the public key, so when a v1 file is parsed the public key
    /// will be computed from the private key, and there will be no consistency check
    /// between the public key and the private key.
    ///
    /// # Errors
    /// `error::KeyRejected` on parse error, or if key is otherwise unacceptable.
    ///
    pub fn from_pkcs8_maybe_unchecked(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let evp_pkey = LcPtr::try_from(pkcs8)?;

            evp_pkey.validate_as_ed25519()?;

            let mut private_key = [0u8; ED25519_PRIVATE_KEY_LEN];
            let mut out_len: usize = ED25519_PRIVATE_KEY_LEN;
            if 1 != EVP_PKEY_get_raw_private_key(*evp_pkey, private_key.as_mut_ptr(), &mut out_len)
            {
                return Err(KeyRejected::wrong_algorithm());
            }

            let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
            let mut out_len: usize = ED25519_PUBLIC_KEY_LEN;
            if 1 != EVP_PKEY_get_raw_public_key(*evp_pkey, public_key.as_mut_ptr(), &mut out_len) {
                return Err(KeyRejected::wrong_algorithm());
            }
            private_key[ED25519_PUBLIC_KEY_LEN..].copy_from_slice(&public_key);

            let key_pair = Self {
                private_key,
                public_key: PublicKey { public_key },
            };

            Ok(key_pair)
        }
    }

    /// Returns the signature of the message msg.
    #[inline]
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Self::try_sign(self, msg).expect("ED25519 signing failed")
    }

    #[inline]
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Unspecified> {
        unsafe {
            let mut sig_bytes = MaybeUninit::<[u8; ED25519_SIGNATURE_LEN]>::uninit();
            if 1 != ED25519_sign(
                sig_bytes.as_mut_ptr().cast(),
                msg.as_ptr(),
                msg.len(),
                self.private_key.as_ptr(),
            ) {
                return Err(Unspecified);
            }
            let sig_bytes = sig_bytes.assume_init();

            Ok(Signature::new(|slice| {
                slice[0..ED25519_SIGNATURE_LEN].copy_from_slice(&sig_bytes);
                ED25519_SIGNATURE_LEN
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519::Ed25519KeyPair;
    use crate::test;

    #[test]
    #[allow(deprecated)]
    fn test_generate_pkcs8() {
        let rng = crate::rand::SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8v1(&rng).unwrap();
        let _key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(document.as_ref()).unwrap();

        assert!(Ed25519KeyPair::generate_pkcs8(&rng).is_err());
        assert!(Ed25519KeyPair::from_pkcs8(document.as_ref()).is_err());
    }

    #[test]
    fn test_from_pkcs8() {
        let key = test::from_dirty_hex(
            r#"302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"#,
        );

        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&key).unwrap();

        assert_eq!("Ed25519KeyPair { public_key: PublicKey(\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\") }", 
                   format!("{:?}", key_pair));
    }
}
