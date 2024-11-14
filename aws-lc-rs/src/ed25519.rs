// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::fmt;
use core::fmt::{Debug, Formatter};
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use std::marker::PhantomData;

#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

use aws_lc::{
    CBS_init, EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit,
    EVP_PKEY_CTX_new_id, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_id,
    EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new_raw_private_key,
    EVP_PKEY_new_raw_public_key, EVP_marshal_public_key, EVP_parse_public_key, CBS, EVP_PKEY,
    EVP_PKEY_ED25519,
};

use crate::cbb::LcCBB;
use crate::digest::digest_ctx::DigestContext;
use crate::encoding::{
    AsBigEndian, AsDer, Curve25519SeedBin, Pkcs8V1Der, Pkcs8V2Der, PublicKeyX509Der,
};
use crate::error::{KeyRejected, Unspecified};
use crate::fips::indicator_check;
use crate::pkcs8::{Document, Version};
use crate::ptr::LcPtr;
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature, VerificationAlgorithm};
use crate::{constant_time, hex, sealed};

/// The length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = aws_lc::ED25519_PUBLIC_KEY_LEN as usize;
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
        let public_key = try_ed25519_public_key_from_bytes(public_key)?;

        let mut evp_md_ctx = DigestContext::new_uninit();

        if 1 != unsafe {
            EVP_DigestVerifyInit(
                evp_md_ctx.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                *public_key.as_mut_unsafe(),
            )
        } {
            return Err(Unspecified);
        }

        if 1 != indicator_check!(unsafe {
            EVP_DigestVerify(
                evp_md_ctx.as_mut_ptr(),
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
}

fn try_ed25519_public_key_from_bytes(key_bytes: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    // If the length of key bytes matches the raw public key size then it has to be that
    if key_bytes.len() == ED25519_PUBLIC_KEY_LEN {
        return Ok(LcPtr::new(unsafe {
            EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519,
                null_mut(),
                key_bytes.as_ptr(),
                key_bytes.len(),
            )
        })?);
    }
    // Otherwise we support X.509 SubjectPublicKeyInfo formatted keys which are inherently larger
    let mut cbs = {
        let mut cbs = MaybeUninit::<CBS>::uninit();
        unsafe {
            CBS_init(cbs.as_mut_ptr(), key_bytes.as_ptr(), key_bytes.len());
            cbs.assume_init()
        }
    };
    let evp_pkey = LcPtr::new(unsafe { EVP_parse_public_key(&mut cbs) })?;
    if EVP_PKEY_ED25519 != unsafe { EVP_PKEY_id(*evp_pkey.as_const()) } {
        return Err(Unspecified);
    }
    Ok(evp_pkey)
}

/// An Ed25519 key pair, for signing.
#[allow(clippy::module_name_repetitions)]
pub struct Ed25519KeyPair {
    evp_pkey: LcPtr<EVP_PKEY>,
    public_key: PublicKey,
}

impl Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "Ed25519KeyPair {{ public_key: PublicKey(\"{}\") }}",
            hex::encode(&self.public_key)
        ))
    }
}

#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
/// The seed value for the `EdDSA` signature scheme using Curve25519
pub struct Seed<'a> {
    bytes: Box<[u8]>,
    phantom: PhantomData<&'a [u8]>,
}

impl AsBigEndian<Curve25519SeedBin<'static>> for Seed<'_> {
    /// Exposes the seed encoded as a big-endian fixed-length integer.
    ///
    /// For most use-cases, `EcdsaKeyPair::to_pkcs8()` should be preferred.
    ///
    /// # Errors
    /// `error::Unspecified` if serialization failed.
    fn as_be_bytes(&self) -> Result<Curve25519SeedBin<'static>, Unspecified> {
        Ok(Curve25519SeedBin::new(self.bytes.to_vec()))
    }
}

impl Debug for Seed<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Seed()")
    }
}

#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKey {
    evp_pkey: LcPtr<EVP_PKEY>,
    public_key_bytes: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    /// Returns the "raw" bytes of the ED25519 public key
    fn as_ref(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!(
            "PublicKey(\"{}\")",
            hex::encode(self.public_key_bytes)
        ))
    }
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl AsDer<PublicKeyX509Der<'static>> for PublicKey {
    /// Provides the public key as a DER-encoded (X.509) `SubjectPublicKeyInfo` structure.
    /// # Errors
    /// Returns an error if the public key fails to marshal to X.509.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, crate::error::Unspecified> {
        // Initial size of 44 based on:
        // 0:d=0  hl=2 l=  42 cons: SEQUENCE
        // 2:d=1  hl=2 l=   5 cons:  SEQUENCE
        // 4:d=2  hl=2 l=   3 prim:   OBJECT            :ED25519
        // 9:d=1  hl=2 l=  33 prim:  BIT STRING
        let mut cbb = LcCBB::new(44);
        if 1 != unsafe { EVP_marshal_public_key(cbb.as_mut_ptr(), *self.evp_pkey.as_const()) } {
            return Err(Unspecified);
        }
        Ok(PublicKeyX509Der::from(cbb.into_buffer()?))
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = PublicKey;
    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

unsafe impl Send for Ed25519KeyPair {}
unsafe impl Sync for Ed25519KeyPair {}

pub(crate) fn generate_key() -> Result<LcPtr<EVP_PKEY>, ()> {
    let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx.as_mut()) } {
        return Err(());
    }

    let mut pkey = null_mut::<EVP_PKEY>();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx.as_mut(), &mut pkey) }) {
        return Err(());
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

impl Ed25519KeyPair {
    /// Generates a new key pair and returns the key pair.
    ///
    /// # Errors
    /// `error::Unspecified` if key generation fails.
    pub fn generate() -> Result<Self, Unspecified> {
        let evp_pkey = generate_key()?;

        let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        let mut out_len: usize = ED25519_PUBLIC_KEY_LEN;
        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(*evp_pkey.as_const(), public_key.as_mut_ptr(), &mut out_len)
        } {
            return Err(Unspecified);
        }
        debug_assert_eq!(public_key.len(), out_len);

        Ok(Self {
            public_key: PublicKey {
                public_key_bytes: public_key,
                evp_pkey: evp_pkey.clone(),
            },
            evp_pkey,
        })
    }

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
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    // # FIPS
    // This function must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if `rng` cannot provide enough bits or if there's an internal error.
    pub fn generate_pkcs8(_rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        let evp_pkey = generate_key()?;
        Ok(Document::new(evp_pkey.marshall_private_key(Version::V2)?))
    }

    /// Serializes this `Ed25519KeyPair` into a PKCS#8 v2 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8(&self) -> Result<Document, Unspecified> {
        Ok(Document::new(
            self.evp_pkey.marshall_private_key(Version::V2)?,
        ))
    }

    /// Generates a `Ed25519KeyPair` using the `rng` provided, then serializes that key as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v1 `PrivateKeyInfo` structure (RFC5208). Use this method
    /// when needing to produce documents that are compatible with the OpenSSL CLI.
    ///
    /// # *ring* Compatibility
    ///  Our implementation ignores the `SecureRandom` parameter.
    ///
    // # FIPS
    // This function must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if `rng` cannot provide enough bits or if there's an internal error.
    pub fn generate_pkcs8v1(_rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        let evp_pkey = generate_key()?;
        Ok(Document::new(evp_pkey.marshall_private_key(Version::V1)?))
    }

    /// Serializes this `Ed25519KeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8v1(&self) -> Result<Document, Unspecified> {
        Ok(Document::new(
            self.evp_pkey.marshall_private_key(Version::V1)?,
        ))
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
    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self, KeyRejected> {
        if seed.len() < ED25519_SEED_LEN {
            return Err(KeyRejected::inconsistent_components());
        }

        let evp_pkey = LcPtr::new(unsafe {
            EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, null_mut(), seed.as_ptr(), seed.len())
        })?;

        let mut derived_public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        let mut out_len: usize = derived_public_key.len();
        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(
                *evp_pkey.as_const(),
                derived_public_key.as_mut_ptr().cast(),
                &mut out_len,
            )
        } {
            return Err(KeyRejected::unspecified());
        }
        debug_assert_eq!(derived_public_key.len(), out_len);

        constant_time::verify_slices_are_equal(public_key, &derived_public_key)
            .map_err(|_| KeyRejected::inconsistent_components())?;

        Ok(Self {
            public_key: PublicKey {
                public_key_bytes: derived_public_key,
                evp_pkey: evp_pkey.clone(),
            },
            evp_pkey,
        })
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
    pub fn from_pkcs8_maybe_unchecked(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        Self::parse_pkcs8(pkcs8)
    }

    fn parse_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let evp_pkey = LcPtr::<EVP_PKEY>::try_from(pkcs8)?;

        evp_pkey.validate_as_ed25519()?;

        let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        let mut out_len: usize = ED25519_PUBLIC_KEY_LEN;
        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(*evp_pkey.as_const(), public_key.as_mut_ptr(), &mut out_len)
        } {
            return Err(KeyRejected::wrong_algorithm());
        }
        debug_assert_eq!(public_key.len(), out_len);

        Ok(Self {
            public_key: PublicKey {
                public_key_bytes: public_key,
                evp_pkey: evp_pkey.clone(),
            },
            evp_pkey,
        })
    }

    /// Returns the signature of the message msg.
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Panics
    /// Panics if the message is unable to be signed
    #[inline]
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Self::try_sign(self, msg).expect("ED25519 signing failed")
    }

    #[inline]
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Unspecified> {
        let mut sig_bytes = [0u8; ED25519_SIGNATURE_LEN];

        let mut evp_md_ctx = DigestContext::new_uninit();

        if 1 != unsafe {
            EVP_DigestSignInit(
                evp_md_ctx.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                *self.evp_pkey.as_mut_unsafe(),
            )
        } {
            return Err(Unspecified);
        }

        let mut out_sig_len = sig_bytes.len();
        if 1 != indicator_check!(unsafe {
            EVP_DigestSign(
                evp_md_ctx.as_mut_ptr(),
                sig_bytes.as_mut_ptr().cast(),
                &mut out_sig_len,
                msg.as_ptr(),
                msg.len(),
            )
        }) {
            return Err(Unspecified);
        }

        debug_assert_eq!(out_sig_len, sig_bytes.len());

        Ok(Signature::new(|slice| {
            slice[0..ED25519_SIGNATURE_LEN].copy_from_slice(&sig_bytes);
            ED25519_SIGNATURE_LEN
        }))
    }

    /// Provides the private key "seed" for this `Ed25519` key pair.
    ///
    /// For serialization of the key pair, `Ed25519KeyPair::to_pkcs8()` is preferred.
    ///
    /// # Errors
    /// Currently the function cannot fail, but it might in future implementations.
    pub fn seed(&self) -> Result<Seed<'static>, Unspecified> {
        let mut private_key_bytes = vec![0u8; ED25519_PRIVATE_KEY_SEED_LEN];
        let mut out_len: usize = private_key_bytes.len();
        if 1 != unsafe {
            EVP_PKEY_get_raw_private_key(
                *self.evp_pkey.as_const(),
                private_key_bytes.as_mut_ptr(),
                &mut out_len,
            )
        } {
            return Err(Unspecified);
        }
        debug_assert_eq!(private_key_bytes.len(), out_len);
        Ok(Seed {
            bytes: private_key_bytes.into_boxed_slice(),
            phantom: PhantomData,
        })
    }
}

impl AsDer<Pkcs8V1Der<'static>> for Ed25519KeyPair {
    /// Serializes this `Ed25519KeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, crate::error::Unspecified> {
        Ok(Pkcs8V1Der::new(
            self.evp_pkey.marshall_private_key(Version::V1)?.into_vec(),
        ))
    }
}

impl AsDer<Pkcs8V2Der<'static>> for Ed25519KeyPair {
    /// Serializes this `Ed25519KeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    fn as_der(&self) -> Result<Pkcs8V2Der<'static>, crate::error::Unspecified> {
        Ok(Pkcs8V2Der::new(
            self.evp_pkey.marshall_private_key(Version::V2)?.into_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519::Ed25519KeyPair;
    use crate::encoding::{AsBigEndian, AsDer, Pkcs8V1Der, Pkcs8V2Der, PublicKeyX509Der};
    use crate::rand::SystemRandom;
    use crate::signature::{KeyPair, UnparsedPublicKey, ED25519};
    use crate::{hex, test};

    #[test]
    fn test_generate() {
        const MESSAGE: &[u8] = b"test message";
        let key_pair = Ed25519KeyPair::generate().unwrap();
        let public_key = key_pair.public_key();
        let signature = key_pair.sign(MESSAGE);
        let unparsed_public_key = UnparsedPublicKey::new(&ED25519, public_key.as_ref());
        unparsed_public_key
            .verify(MESSAGE, signature.as_ref())
            .unwrap();
    }

    #[test]
    fn test_generate_pkcs8() {
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp1: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        assert_eq!(
            document.as_ref(),
            AsDer::<Pkcs8V2Der>::as_der(&kp1).unwrap().as_ref()
        );
        let kp2: Ed25519KeyPair =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(document.as_ref()).unwrap();
        assert_eq!(
            kp1.seed().unwrap().as_be_bytes().unwrap().as_ref(),
            kp2.seed().unwrap().as_be_bytes().unwrap().as_ref(),
        );
        assert_eq!(kp1.public_key.as_ref(), kp2.public_key.as_ref());

        let document = Ed25519KeyPair::generate_pkcs8v1(&rng).unwrap();
        let kp1: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        assert_eq!(
            document.as_ref(),
            AsDer::<Pkcs8V1Der>::as_der(&kp1).unwrap().as_ref()
        );
        let kp2: Ed25519KeyPair =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(document.as_ref()).unwrap();
        assert_eq!(
            kp1.seed().unwrap().as_be_bytes().unwrap().as_ref(),
            kp2.seed().unwrap().as_be_bytes().unwrap().as_ref(),
        );
        assert_eq!(kp1.public_key.as_ref(), kp2.public_key.as_ref());
        let seed = kp1.seed().unwrap();
        assert_eq!("Ed25519Seed()", format!("{seed:?}"));
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

    #[test]
    fn test_public_key_as_der_x509() {
        let key_pair = Ed25519KeyPair::from_pkcs8(&hex::decode("302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap()).unwrap();
        let public_key = key_pair.public_key();
        let x509der = AsDer::<PublicKeyX509Der>::as_der(public_key).unwrap();
        assert_eq!(
            x509der.as_ref(),
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7, 0x5a,
                0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
                0x51, 0x1a
            ]
        );
    }
}
