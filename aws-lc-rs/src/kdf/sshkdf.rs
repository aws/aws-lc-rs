// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(clippy::module_name_repetitions)]

use core::ffi::c_char;

use crate::aws_lc::{
    EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV, EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI,
    EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV, EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI,
    EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV, EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI,
    EVP_MD, SSHKDF,
};

use crate::digest::{match_digest_type, AlgorithmID};
use crate::error::Unspecified;
use crate::ptr::ConstPointer;

/// SSHKDF with SHA1
#[allow(dead_code)]
const SSHKDF_SHA1: SshkdfAlgorithm = SshkdfAlgorithm {
    id: SshkdfAlgorithmId::Sha1,
};

/// SSHKDF with SHA224
#[allow(dead_code)]
const SSHKDF_SHA224: SshkdfAlgorithm = SshkdfAlgorithm {
    id: SshkdfAlgorithmId::Sha224,
};

/// SSHKDF with SHA256
#[allow(dead_code)]
const SSHKDF_SHA256: SshkdfAlgorithm = SshkdfAlgorithm {
    id: SshkdfAlgorithmId::Sha256,
};

/// SSHKDF with SHA384
#[allow(dead_code)]
const SSHKDF_SHA384: SshkdfAlgorithm = SshkdfAlgorithm {
    id: SshkdfAlgorithmId::Sha384,
};

/// SSHKDF with SHA512
#[allow(dead_code)]
const SSHKDF_SHA512: SshkdfAlgorithm = SshkdfAlgorithm {
    id: SshkdfAlgorithmId::Sha512,
};

/// Retrieve [`SshkdfAlgorithm`] using the [`SshkdfAlgorithmId`] specified by `id`.
#[must_use]
pub const fn get_sshkdf_algorithm(id: SshkdfAlgorithmId) -> Option<&'static SshkdfAlgorithm> {
    {
        match id {
            SshkdfAlgorithmId::Sha1 => Some(&SSHKDF_SHA1),
            SshkdfAlgorithmId::Sha224 => Some(&SSHKDF_SHA224),
            SshkdfAlgorithmId::Sha256 => Some(&SSHKDF_SHA256),
            SshkdfAlgorithmId::Sha384 => Some(&SSHKDF_SHA384),
            SshkdfAlgorithmId::Sha512 => Some(&SSHKDF_SHA512),
        }
    }
}

/// SSHKDF algorithm: the hash the SSH key exchange method names.
pub struct SshkdfAlgorithm {
    id: SshkdfAlgorithmId,
}

impl SshkdfAlgorithm {
    /// Returns the SSHKDF Algorithm Identifier
    #[must_use]
    pub fn id(&self) -> SshkdfAlgorithmId {
        self.id
    }

    #[must_use]
    fn get_evp_md(&self) -> ConstPointer<'_, EVP_MD> {
        match_digest_type(match self.id {
            SshkdfAlgorithmId::Sha1 => &AlgorithmID::SHA1,
            SshkdfAlgorithmId::Sha224 => &AlgorithmID::SHA224,
            SshkdfAlgorithmId::Sha256 => &AlgorithmID::SHA256,
            SshkdfAlgorithmId::Sha384 => &AlgorithmID::SHA384,
            SshkdfAlgorithmId::Sha512 => &AlgorithmID::SHA512,
        })
    }
}

impl PartialEq for SshkdfAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SshkdfAlgorithm {}

impl core::fmt::Debug for SshkdfAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.id, f)
    }
}

/// SSH Key Derivation Function Algorithm Identifier
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SshkdfAlgorithmId {
    /// SSHKDF with SHA1, for the key exchange methods that name it, such as
    /// `diffie-hellman-group14-sha1`. SP 800-131A allows SHA1 in key
    /// derivation, and the module's service indicator approves it here.
    Sha1,

    /// SSHKDF with SHA224
    Sha224,

    /// SSHKDF with SHA256
    Sha256,

    /// SSHKDF with SHA384
    Sha384,

    /// SSHKDF with SHA512
    Sha512,
}

/// The value an SSH key derivation produces: one of the six keys and initial
/// IVs of RFC 4253 section 7.2, each named by a letter from `A` to `F`.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SshkdfKeyType {
    /// Initial IV client to server (`A`)
    InitialIvClientToServer,

    /// Initial IV server to client (`B`)
    InitialIvServerToClient,

    /// Encryption key client to server (`C`)
    EncryptionKeyClientToServer,

    /// Encryption key server to client (`D`)
    EncryptionKeyServerToClient,

    /// Integrity key client to server (`E`)
    IntegrityKeyClientToServer,

    /// Integrity key server to client (`F`)
    IntegrityKeyServerToClient,
}

impl SshkdfKeyType {
    fn as_c_type(self) -> Result<c_char, Unspecified> {
        let value = match self {
            SshkdfKeyType::InitialIvClientToServer => EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV,
            SshkdfKeyType::InitialIvServerToClient => EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI,
            SshkdfKeyType::EncryptionKeyClientToServer => {
                EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV
            }
            SshkdfKeyType::EncryptionKeyServerToClient => {
                EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI
            }
            SshkdfKeyType::IntegrityKeyClientToServer => {
                EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV
            }
            SshkdfKeyType::IntegrityKeyServerToClient => {
                EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI
            }
        };
        c_char::try_from(value).map_err(|_| Unspecified)
    }
}

/// # SSH Key Derivation Function
///
/// Derives one of the six values of RFC 4253 section 7.2 (an initial IV, an
/// encryption key or an integrity key, in either direction) from an SSH key
/// exchange's shared secret, exchange hash and session identifier, using the
/// hash the key exchange method names. The derivation is defined in
/// Section 5.2 of NIST Special Publication 800-135 Revision 1.
///
/// This KDF is specific to the SSH Transport Layer Protocol, and is only
/// approved for FIPS 140-3 use in SSH.
///
/// ## Input Validation and Defaults
/// * `shared_secret` is the shared secret `K` as RFC 4253 section 7.2 hashes
///   it: encoded as an `mpint`, length prefix included. The function does not
///   encode it.
/// * `exchange_hash` is the exchange hash `H` of this key exchange, and
///   `session_id` the session identifier, which is the exchange hash of the
///   first key exchange of the connection.
/// * `output.len()` sets the length of the derived value, which may exceed the
///   hash's output length; `shared_secret.len() > 0`,
///   `exchange_hash.len() > 0`, `session_id.len() > 0` and `output.len() > 0`.
///
/// Specification is available at <https://doi.org/10.6028/NIST.SP.800-135r1>
///
/// # Errors
/// `Unspecified` is returned if input validation fails or an unexpected error occurs.
pub fn sshkdf(
    algorithm: &'static SshkdfAlgorithm,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_type: SshkdfKeyType,
    output: &mut [u8],
) -> Result<(), Unspecified> {
    let evp_md = algorithm.get_evp_md();
    let key_type = key_type.as_c_type()?;
    let out_len = output.len();
    // Unlike the other KDFs, the C function derives nothing for an empty
    // output and reports success; hold it to the same contract as the rest.
    if out_len == 0 {
        return Err(Unspecified);
    }
    if 1 != unsafe {
        SSHKDF(
            evp_md.as_const_ptr(),
            shared_secret.as_ptr(),
            shared_secret.len(),
            exchange_hash.as_ptr(),
            exchange_hash.len(),
            session_id.as_ptr(),
            session_id.len(),
            key_type,
            output.as_mut_ptr(),
            out_len,
        )
    } {
        return Err(Unspecified);
    }
    Ok(())
}
