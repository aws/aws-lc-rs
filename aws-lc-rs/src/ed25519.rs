// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::{Document, Version};
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

#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;
use zeroize::Zeroize;

/// The length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = aws_lc::ED25519_PUBLIC_KEY_LEN as usize;
pub(crate) const ED25519_PRIVATE_KEY_LEN: usize = aws_lc::ED25519_PRIVATE_KEY_LEN as usize;
pub(crate) const ED25519_PRIVATE_KEY_SEED_LEN: usize =
    aws_lc::ED25519_PRIVATE_KEY_SEED_LEN as usize;
const ED25519_SIGNATURE_LEN: usize = aws_lc::ED25519_SIGNATURE_LEN as usize;
const ED25519_SEED_LEN: usize = 32;

/// Parameters for `EdDSA` signing and verification.
#[derive(Debug)]
pub struct EdDSAParameters;

impl sealed::Sealed for EdDSAParameters {}

impl VerificationAlgorithm for EdDSAParameters {
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
        if 1 != unsafe {
            ED25519_verify(
                msg.as_ptr(),
                msg.len(),
                signature.as_ptr(),
                public_key.as_ptr(),
            )
        } {
            return Err(Unspecified);
        }
        #[cfg(feature = "fips")]
        crate::fips::indicator::set_unapproved();
        Ok(())
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

pub(crate) unsafe fn generate_key(rng: &dyn SecureRandom) -> Result<LcPtr<EVP_PKEY>, ()> {
    // TODO: Should we drop support for using the provided rng in a minor release?

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

    // ED25519_keypair_from_seed doesn't set FIPS indicator, and Ed25119 is not approved anyways at this time.
    // Seems like it could be approved for use in the future per FIPS 186-5 and CMVP guidance.
    #[cfg(feature = "fips")]
    crate::fips::indicator::set_unapproved();

    LcPtr::new(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        null_mut(),
        private_key.assume_init().as_ptr(),
        ED25519_PRIVATE_KEY_SEED_LEN,
    ))
}

impl Ed25519KeyPair {
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
    /// # *ring* Compatibility
    /// The ring 0.16.x API did not produce encoded v2 documents that were compliant with RFC 5958.
    /// The aws-lc-ring implementation produces PKCS#8 v2 encoded documents that are compliant per
    /// the RFC specification.
    ///
    /// # Errors
    /// `error::Unspecified` if `rng` cannot provide enough bits or if there's an internal error.
    pub fn generate_pkcs8(rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        let evp_pkey = unsafe { generate_key(rng)? };
        evp_pkey.marshall_private_key(Version::V2)
    }

    /// Generates a `Ed25519KeyPair` using the `rng` provided, then serializes that key as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v1 `PrivateKeyInfo` structure (RFC5208). Use this method
    /// when needing to produce documents that are compatible with the OpenSSL CLI.
    ///
    /// # Errors
    /// `error::Unspecified` if `rng` cannot provide enough bits or if there's an internal error.
    pub fn generate_pkcs8v1(rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        let evp_pkey = unsafe { generate_key(rng)? };
        evp_pkey.marshall_private_key(Version::V1)
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

    /// Constructs an Ed25519 key pair by parsing an unencrypted PKCS#8 v1 or v2
    /// Ed25519 private key.
    ///
    /// `openssl genpkey -algorithm ED25519` generates PKCS#8 v1 keys.
    ///
    /// # Ring Compatibility
    /// * This method accepts either v1 or v2 encoded keys, if a v2 encoded key is provided, with the
    ///   public key component present, it will be verified to match the one derived from the
    ///   encoded private key.
    /// * The ring 0.16.x API did not produce encoded v2 documents that were compliant with RFC 5958.
    ///   The aws-lc-ring implementation produces PKCS#8 v2 encoded documents that are compliant per
    ///   the RFC specification.
    ///
    /// # Errors
    /// `error::KeyRejected` on parse error, or if key is otherwise unacceptable.
    ///
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        Self::parse_pkcs8(pkcs8)
    }

    /// Constructs an Ed25519 key pair by parsing an unencrypted PKCS#8 v1 or v2
    /// Ed25519 private key.
    ///
    /// `openssl genpkey -algorithm ED25519` generates PKCS# v1 keys.
    ///
    /// # Ring Compatibility
    /// * This method accepts either v1 or v2 encoded keys, if a v2 encoded key is provided, with the
    ///   public key component present, it will be verified to match the one derived from the
    ///   encoded private key.
    /// * The ring 0.16.x API did not produce encoded v2 documents that were compliant with RFC 5958.
    ///   The aws-lc-ring implementation produces PKCS#8 v2 encoded documents that are compliant per
    ///   the RFC specification.
    ///
    /// # Errors
    /// `error::KeyRejected` on parse error, or if key is otherwise unacceptable.
    ///
    pub fn from_pkcs8_maybe_unchecked(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        Self::parse_pkcs8(pkcs8)
    }

    fn parse_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
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
            private_key[ED25519_PRIVATE_KEY_SEED_LEN..].copy_from_slice(&public_key);

            let key_pair = Self {
                private_key,
                public_key: PublicKey { public_key },
            };

            Ok(key_pair)
        }
    }

    /// Returns the signature of the message msg.
    ///
    /// # Panics
    /// Panics if the message is unable to be signed
    #[inline]
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Self::try_sign(self, msg).expect("ED25519 signing failed")
    }

    #[inline]
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Unspecified> {
        let mut sig_bytes = MaybeUninit::<[u8; ED25519_SIGNATURE_LEN]>::uninit();
        if 1 != unsafe {
            ED25519_sign(
                sig_bytes.as_mut_ptr().cast(),
                msg.as_ptr(),
                msg.len(),
                self.private_key.as_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        #[cfg(feature = "fips")]
        crate::fips::indicator::set_unapproved();

        let sig_bytes = unsafe { sig_bytes.assume_init() };

        Ok(Signature::new(|slice| {
            slice[0..ED25519_SIGNATURE_LEN].copy_from_slice(&sig_bytes);
            ED25519_SIGNATURE_LEN
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519::Ed25519KeyPair;
    use crate::test;

    #[test]
    fn test_generate_pkcs8() {
        let rng = crate::rand::SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let _: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let _: Ed25519KeyPair =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(document.as_ref()).unwrap();

        let document = Ed25519KeyPair::generate_pkcs8v1(&rng).unwrap();
        let _: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let _: Ed25519KeyPair =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(document.as_ref()).unwrap();
    }

    #[test]
    fn test_from_pkcs8() {
        struct TestCase {
            key: &'static str,
            expected_public: &'static str,
        }

        for case in [
            TestCase {
                key: "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                expected_public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            },
            TestCase {
                key: "3051020101300506032b657004220420756434bd5b824753007a138d27abbc14b5cc786adb78fb62435e6419a2b2e72b8121000faccd81e57de15fa6343a7fbb43b2b93f28be6435100ae8bd633c6dfee3d198",
                expected_public: "0faccd81e57de15fa6343a7fbb43b2b93f28be6435100ae8bd633c6dfee3d198",
            },
            TestCase {
                key: "304f020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842a01f301d060a2a864886f70d01090914310f0c0d437572646c6520436861697273",
                expected_public: "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
            },
            TestCase {
                key: "3072020101300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842a01f301d060a2a864886f70d01090914310f0c0d437572646c652043686169727381210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
                expected_public: "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
            }
        ] {
            let key_pair = Ed25519KeyPair::from_pkcs8(&test::from_dirty_hex(case.key)).unwrap();
            assert_eq!(
                format!(
                    r#"Ed25519KeyPair {{ public_key: PublicKey("{}") }}"#,
                    case.expected_public
                ),
                format!("{key_pair:?}")
            );
            let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&test::from_dirty_hex(case.key)).unwrap();
            assert_eq!(
                format!(
                    r#"Ed25519KeyPair {{ public_key: PublicKey("{}") }}"#,
                    case.expected_public
                ),
                format!("{key_pair:?}")
            );
        }
    }
}
