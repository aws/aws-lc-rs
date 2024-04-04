// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    error::{KeyRejected, Unspecified},
    fips::indicator_check,
    ptr::{DetachableLcPtr, LcPtr},
};
use aws_lc::{
    EVP_PKEY_CTX_new, EVP_PKEY_CTX_set0_rsa_oaep_label, EVP_PKEY_CTX_set_rsa_mgf1_md,
    EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_decrypt,
    EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_sha1, EVP_sha256,
    EVP_sha384, EVP_sha512, OPENSSL_malloc, EVP_MD, EVP_PKEY, EVP_PKEY_CTX, RSA_PKCS1_OAEP_PADDING,
};
use core::{fmt::Debug, mem::size_of_val, ptr::null_mut};
use mirai_annotations::verify_unreachable;

use super::{
    key::{generate_rsa_key, RsaEvpPkey, UsageContext},
    KeySize,
};

/// RSA-OAEP with SHA1 Hash and SHA1 MGF1
pub const OAEP_SHA1_MGF1SHA1: OaepAlgorithm = OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha1Mgf1sha1,
    oaep_hash_fn: EVP_sha1,
    mgf1_hash_fn: EVP_sha1,
};

/// RSA-OAEP with SHA256 Hash and SHA256 MGF1
pub const OAEP_SHA256_MGF1SHA256: OaepAlgorithm = OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha256Mgf1sha256,
    oaep_hash_fn: EVP_sha256,
    mgf1_hash_fn: EVP_sha256,
};

/// RSA-OAEP with SHA384 Hash and SHA384  MGF1
pub const OAEP_SHA384_MGF1SHA384: OaepAlgorithm = OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha384Mgf1sha384,
    oaep_hash_fn: EVP_sha384,
    mgf1_hash_fn: EVP_sha384,
};

/// RSA-OAEP with SHA512 Hash and SHA512 MGF1
pub const OAEP_SHA512_MGF1SHA512: OaepAlgorithm = OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha512Mgf1sha512,
    oaep_hash_fn: EVP_sha512,
    mgf1_hash_fn: EVP_sha512,
};

/// RSA Encryption Algorithm Identifier
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum EncryptionAlgorithmId {
    /// RSA-OAEP with SHA1 Hash and SHA1 MGF1
    OaepSha1Mgf1sha1,

    /// RSA-OAEP with SHA256 Hash and SHA256 MGF1
    OaepSha256Mgf1sha256,

    /// RSA-OAEP with SHA384 Hash and SHA384 MGF1
    OaepSha384Mgf1sha384,

    /// RSA-OAEP with SHA512 Hash and SHA512 MGF1
    OaepSha512Mgf1sha512,
}

type OaepHashFn = unsafe extern "C" fn() -> *const EVP_MD;
type Mgf1HashFn = unsafe extern "C" fn() -> *const EVP_MD;

/// An RSA-OAEP algorithm.
pub struct OaepAlgorithm {
    id: EncryptionAlgorithmId,
    oaep_hash_fn: OaepHashFn,
    mgf1_hash_fn: Mgf1HashFn,
}

impl OaepAlgorithm {
    /// Returns the `EncryptionAlgorithmId`.
    #[must_use]
    pub fn id(&self) -> EncryptionAlgorithmId {
        self.id
    }

    #[inline]
    fn oaep_hash_fn(&self) -> OaepHashFn {
        self.oaep_hash_fn
    }

    #[inline]
    fn mgf1_hash_fn(&self) -> Mgf1HashFn {
        self.mgf1_hash_fn
    }
}

impl Debug for OaepAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// An RSA private key used for decrypting ciphertext encrypted by a [`PublicEncryptingKey`].
pub struct PrivateDecryptingKey(RsaEvpPkey);

impl PrivateDecryptingKey {
    fn new(key: LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        Ok(Self(RsaEvpPkey::new(key, UsageContext::Decryption)?))
    }

    /// Generate a new RSA private key for use with asymmetrical encryption.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs during the generation of the RSA keypair.
    pub fn generate(size: KeySize) -> Result<Self, Unspecified> {
        let key = generate_rsa_key(size.bit_len(), false)?;
        Self::new(key)
    }

    /// Generate a RSA `KeyPair` of the specified key-strength.
    ///
    /// Supports the following key sizes:
    /// * `EncryptionKeySize::Rsa2048`
    /// * `EncryptionKeySize::Rsa3072`
    /// * `EncryptionKeySize::Rsa4096`
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    #[cfg(feature = "fips")]
    pub fn generate_fips(size: KeySize) -> Result<Self, Unspecified> {
        let key = generate_rsa_key(size.bit_len(), true)?;
        Self::new(key)
    }

    /// Construct a `PrivateDecryptingKey` from the provided PKCS#8 (v1) document.
    ///
    /// Supports RSA key sizes between 2048 and 8192 (inclusive).
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs during deserialization of this key from PKCS#8.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let evp_pkey = LcPtr::try_from(pkcs8)?;
        Self::new(evp_pkey).map_err(|_| KeyRejected::unexpected_error())
    }

    /// Returns a boolean indicator if this RSA key is an approved FIPS 140-3 key.
    #[cfg(feature = "fips")]
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn is_valid_fips_key(&self) -> bool {
        self.0.is_valid_fips_key()
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.0.key_size()
    }

    /// Retrieves the `PublicEncryptingKey` corresponding with this `PrivateDecryptingKey`.
    /// # Errors
    /// * `Unspecified` for any error that occurs computing the public key.
    pub fn public_key(&self) -> Result<PublicEncryptingKey, Unspecified> {
        Ok(PublicEncryptingKey(RsaEvpPkey::new(
            self.0.evp_pkey.clone(),
            UsageContext::Encryption,
        )?))
    }
}

impl Debug for PrivateDecryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PrivateDecryptingKey").finish()
    }
}

impl AsDer<Pkcs8V1Der<'static>> for PrivateDecryptingKey {
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        AsDer::<Pkcs8V1Der<'_>>::as_der(&self.0)
    }
}

impl Clone for PrivateDecryptingKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// An RSA public key used for encrypting plaintext that is decrypted by a [`PrivateDecryptingKey`].
pub struct PublicEncryptingKey(RsaEvpPkey);

impl PublicEncryptingKey {
    /// Construct a `PublicEncryptingKey` from X.509 `SubjectPublicKeyInfo` DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs deserializing from bytes.
    pub fn from_der(value: &[u8]) -> Result<Self, KeyRejected> {
        Ok(Self(RsaEvpPkey::from_rfc5280_public_key_der(
            value,
            UsageContext::Encryption,
        )?))
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.0.key_size()
    }
}

impl Debug for PublicEncryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PublicEncryptingKey").finish()
    }
}

impl Clone for PublicEncryptingKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// An RSA-OAEP public key for encryption.
pub struct OaepPublicEncryptingKey {
    public_key: PublicEncryptingKey,
}

impl OaepPublicEncryptingKey {
    /// Construcsts an `OaepPublicEncryptingKey` from a `PublicEncryptingKey`.
    /// # Errors
    /// * `Unspecified`: Any error that occurs while attempting to construct an RSA-OAEP public key.
    pub fn new(public_key: PublicEncryptingKey) -> Result<Self, Unspecified> {
        Ok(Self { public_key })
    }

    /// Encrypts the contents in `plaintext` and writes the corresponding ciphertext to `output`.
    /// 
    /// # Max Plaintext Length
    /// The provided length of `plaintext` must be at most [`Self::max_plaintext_size`].
    ///
    /// # Sizing `output`
    /// For `OAEP_SHA1_MGF1SHA1`, `OAEP_SHA256_MGF1SHA256`, `OAEP_SHA384_MGF1SHA384`, `OAEP_SHA512_MGF1SHA512` the
    /// length of `output` must be the RSA key size in bytes. The RSA key size in bytes can be retrieved using
    /// [`Self::key_size`].
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs while encrypting `plaintext`.
    pub fn encrypt<'output>(
        &self,
        algorithm: &'static OaepAlgorithm,
        plaintext: &[u8],
        output: &'output mut [u8],
        label: Option<&[u8]>,
    ) -> Result<&'output mut [u8], Unspecified> {
        let pkey_ctx =
            LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.public_key.0.evp_pkey, null_mut()) })?;

        if 1 != unsafe { EVP_PKEY_encrypt_init(*pkey_ctx) } {
            return Err(Unspecified);
        }

        configure_oaep_crypto_operation(
            &pkey_ctx,
            algorithm.oaep_hash_fn(),
            algorithm.mgf1_hash_fn(),
            label,
        )?;

        let mut out_len = output.len();

        if 1 != indicator_check!(unsafe {
            EVP_PKEY_encrypt(
                *pkey_ctx,
                output.as_mut_ptr(),
                &mut out_len,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        }) {
            return Err(Unspecified);
        };

        Ok(&mut output[..out_len])
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.public_key.key_size()
    }

    /// Returns the max plaintext that could be decrypted using this key and with the provided algorithm.
    #[must_use]
    pub fn max_plaintext_size(&self, algorithm: &'static OaepAlgorithm) -> usize {
        max_plaintext_size(self.key_size(), algorithm)
    }
}

impl Debug for OaepPublicEncryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OaepPublicEncryptingKey")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// An RSA-OAEP private key for decryption.
pub struct OaepPrivateDecryptingKey {
    private_key: PrivateDecryptingKey,
}

impl OaepPrivateDecryptingKey {
    /// Construcsts an `OaepPrivateDecryptingKey` from a `PrivateDecryptingKey`.
    /// # Errors
    /// * `Unspecified`: Any error that occurs while attempting to construct an RSA-OAEP public key.
    pub fn new(private_key: PrivateDecryptingKey) -> Result<Self, Unspecified> {
        Ok(Self { private_key })
    }

    /// Decrypts the contents in `ciphertext` and writes the corresponding plaintext to `output`.
    ///
    /// # Sizing `output`
    /// For `OAEP_SHA1_MGF1SHA1`, `OAEP_SHA256_MGF1SHA256`, `OAEP_SHA384_MGF1SHA384`, `OAEP_SHA512_MGF1SHA512`. The
    /// length of `output` must be equal to [`Self::key_size`].
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs while decrypting `ciphertext`.
    pub fn decrypt<'output>(
        &self,
        algorithm: &'static OaepAlgorithm,
        ciphertext: &[u8],
        output: &'output mut [u8],
        label: Option<&[u8]>,
    ) -> Result<&'output mut [u8], Unspecified> {
        let pkey_ctx =
            LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.private_key.0.evp_pkey, null_mut()) })?;

        if 1 != unsafe { EVP_PKEY_decrypt_init(*pkey_ctx) } {
            return Err(Unspecified);
        }

        configure_oaep_crypto_operation(
            &pkey_ctx,
            algorithm.oaep_hash_fn(),
            algorithm.mgf1_hash_fn(),
            label,
        )?;

        let mut out_len = output.len();

        if 1 != indicator_check!(unsafe {
            EVP_PKEY_decrypt(
                *pkey_ctx,
                output.as_mut_ptr(),
                &mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        }) {
            return Err(Unspecified);
        };

        Ok(&mut output[..out_len])
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.private_key.key_size()
    }
}

impl Debug for OaepPrivateDecryptingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OaepPrivateDecryptingKey")
            .field("private_key", &self.private_key)
            .finish()
    }
}

fn configure_oaep_crypto_operation(
    evp_pkey_ctx: &LcPtr<EVP_PKEY_CTX>,
    oaep_hash_fn: OaepHashFn,
    mgf1_hash_fn: Mgf1HashFn,
    label: Option<&[u8]>,
) -> Result<(), Unspecified> {
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(**evp_pkey_ctx, RSA_PKCS1_OAEP_PADDING) } {
        return Err(Unspecified);
    };

    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_oaep_md(**evp_pkey_ctx, oaep_hash_fn()) } {
        return Err(Unspecified);
    };

    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(**evp_pkey_ctx, mgf1_hash_fn()) } {
        return Err(Unspecified);
    };

    let label = if let Some(label) = label {
        label
    } else {
        &[0u8; 0]
    };

    // No need to set the label if it is zero-length, AWS-LC will handle this correctly.
    if label.is_empty() {
        return Ok(());
    }

    // AWS-LC takes ownership of the label memory, and will call OPENSSL_free, so we are forced to copy it for now.
    let label_ptr =
        DetachableLcPtr::<u8>::new(unsafe { OPENSSL_malloc(size_of_val(label)) }.cast())?;

    {
        // memcpy the label data into the AWS-LC allocation
        let label_ptr = unsafe { core::slice::from_raw_parts_mut(*label_ptr, label.len()) };
        label_ptr.copy_from_slice(label);
    }

    if 1 != unsafe { EVP_PKEY_CTX_set0_rsa_oaep_label(**evp_pkey_ctx, *label_ptr, label.len()) } {
        return Err(Unspecified);
    };

    // AWS-LC owns the allocaiton now, so we detach it to avoid freeing it here when label_ptr goes out of scope.
    label_ptr.detach();

    Ok(())
}

impl AsDer<PublicKeyX509Der<'static>> for PublicEncryptingKey {
    /// Serialize this `PublicEncryptingKey` to a X.509 `SubjectPublicKeyInfo` structure as DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs serializing to bytes.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        AsDer::<PublicKeyX509Der<'_>>::as_der(&self.0)
    }
}

#[inline]
fn max_plaintext_size(key_size: usize, algorithm: &'static OaepAlgorithm) -> usize {
    #[allow(unreachable_patterns)]
    let hash_len: usize = match algorithm.id() {
        EncryptionAlgorithmId::OaepSha1Mgf1sha1 => 20,
        EncryptionAlgorithmId::OaepSha256Mgf1sha256 => 32,
        EncryptionAlgorithmId::OaepSha384Mgf1sha384 => 48,
        EncryptionAlgorithmId::OaepSha512Mgf1sha512 => 64,
        _ => verify_unreachable!(),
    };

    // The RSA-OAEP algorithms we support use the hashing algorithm for the hash and mgf1 functions.
    key_size - 2 * hash_len - 2
}
