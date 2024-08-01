// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(clippy::module_name_repetitions)]

use aws_lc::{SSKDF_digest, SSKDF_hmac};

use crate::{
    digest::{match_digest_type, AlgorithmID},
    error::Unspecified,
};

/// SSKDF with HMAC-SHA1
pub const SSKDF_HMAC_SHA1: SskdfHmacAlgorithm = SskdfHmacAlgorithm {
    id: SskdfAlgorithmId::HmacSha1,
    digest: AlgorithmID::SHA1,
};

/// SSKDF with HMAC-SHA224
pub const SSKDF_HMAC_SHA224: SskdfHmacAlgorithm = SskdfHmacAlgorithm {
    id: SskdfAlgorithmId::HmacSha224,
    digest: AlgorithmID::SHA224,
};

/// SSKDF with HMAC-SHA256
pub const SSKDF_HMAC_SHA256: SskdfHmacAlgorithm = SskdfHmacAlgorithm {
    id: SskdfAlgorithmId::HmacSha256,
    digest: AlgorithmID::SHA256,
};

/// SSKDF with HMAC-SHA384
pub const SSKDF_HMAC_SHA384: SskdfHmacAlgorithm = SskdfHmacAlgorithm {
    id: SskdfAlgorithmId::HmacSha384,
    digest: AlgorithmID::SHA384,
};

/// SSKDF with HMAC-SHA512
pub const SSKDF_HMAC_SHA512: SskdfHmacAlgorithm = SskdfHmacAlgorithm {
    id: SskdfAlgorithmId::HmacSha512,
    digest: AlgorithmID::SHA512,
};

/// SSKDF with SHA1
pub const SSKDF_DIGEST_SHA1: SskdfDigestAlgorithm = SskdfDigestAlgorithm {
    id: SskdfAlgorithmId::DigestSha1,
    digest: AlgorithmID::SHA1,
};

/// SSKDF with SHA224
pub const SSKDF_DIGEST_SHA224: SskdfDigestAlgorithm = SskdfDigestAlgorithm {
    id: SskdfAlgorithmId::DigestSha224,
    digest: AlgorithmID::SHA224,
};

/// SSKDF with SHA256
pub const SSKDF_DIGEST_SHA256: SskdfDigestAlgorithm = SskdfDigestAlgorithm {
    id: SskdfAlgorithmId::DigestSha256,
    digest: AlgorithmID::SHA256,
};

/// SSKDF with SHA384
pub const SSKDF_DIGEST_SHA384: SskdfDigestAlgorithm = SskdfDigestAlgorithm {
    id: SskdfAlgorithmId::DigestSha384,
    digest: AlgorithmID::SHA384,
};

/// SSKDF with SHA512
pub const SSKDF_DIGEST_SHA512: SskdfDigestAlgorithm = SskdfDigestAlgorithm {
    id: SskdfAlgorithmId::DigestSha512,
    digest: AlgorithmID::SHA512,
};

/// SSKDF algorithm using HMAC
pub struct SskdfHmacAlgorithm {
    id: SskdfAlgorithmId,
    digest: AlgorithmID,
}

impl SskdfHmacAlgorithm {
    /// Returns the SSKDF Algorithm Identifier
    #[must_use]
    pub fn id(&self) -> SskdfAlgorithmId {
        self.id
    }
}

impl core::fmt::Debug for SskdfHmacAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.id, f)
    }
}

/// SSKDF algorithm using digest
pub struct SskdfDigestAlgorithm {
    id: SskdfAlgorithmId,
    digest: AlgorithmID,
}

impl SskdfDigestAlgorithm {
    /// Returns the SSKDF Algorithm Identifier
    #[must_use]
    pub fn id(&self) -> SskdfAlgorithmId {
        self.id
    }
}

impl core::fmt::Debug for SskdfDigestAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.id, f)
    }
}

/// Single-step (One-step) Key Derivation Function Algorithm Identifier
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SskdfAlgorithmId {
    /// SSKDF with SHA1
    DigestSha1,

    /// SSKDF with SHA224
    DigestSha224,

    /// SSKDF with SHA256
    DigestSha256,

    /// SSKDF with SHA384
    DigestSha384,

    /// SSKDF with SHA512
    DigestSha512,

    /// SSKDF with HMAC-SHA1
    HmacSha1,

    /// SSKDF with HMAC-SHA224
    HmacSha224,

    /// SSKDF with HMAC-SHA256
    HmacSha256,

    /// SSKDF with HMAC-SHA384
    HmacSha384,

    /// SSKDF with HMAC-SHA512
    HmacSha512,
}

/// # Single-step Key Derivation Function using HMAC
///
/// This algorithm may be referred to as "Single-Step KDF" or "NIST Concatenation KDF" by other
/// implementors.
///
/// ## Implementation Notes
///
/// This implementation adheres to the algorithm specified in Section 4 of the
/// NIST Special Publication 800-56C Revision 2 published on August 2020. The
/// parameters relevant to the specification are as follows:
/// * Auxillary Function H is Option 2
/// * `output.len()`, `secret.len()`, `info.len()` each must be <= 2^30
/// * `output.len()` and `secret.len()` > 0
/// * `output.len()`, `secret.len()` are analogous to `L` and `Z` respectively in the
///   specification.
/// * `info` refers to `FixedInfo` in the specification.
/// * `salt.len() == 0` will result in a default salt being used which will be an all-zero byte string
///   whose length is equal to the length of the specified digest input block length in
///   bytes.
///
/// Specification is available at <https://doi.org/10.6028/NIST.SP.800-56Cr2>
///
/// # Errors
/// `Unspecified` is returned under the following conditions:
/// * Either `output.len()`, `secret.len()`, or `info.len()` are > 2^30.
/// * `output.len() == 0 || secret.len() == 0`
pub fn sskdf_hmac(
    algorithm: &'static SskdfHmacAlgorithm,
    secret: &[u8],
    info: &[u8],
    salt: &[u8],
    output: &mut [u8],
) -> Result<(), Unspecified> {
    let evp_md = match_digest_type(&algorithm.digest);
    let out_len = output.len();
    if 1 != unsafe {
        SSKDF_hmac(
            output.as_mut_ptr(),
            out_len,
            *evp_md,
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
            salt.as_ptr(),
            salt.len(),
        )
    } {
        return Err(Unspecified);
    }
    Ok(())
}

/// # Single-step Key Derivation Function using digest
///
/// This algorithm may be referred to as "Single-Step KDF" or "NIST Concatenation KDF" by other
/// implementors.
///
/// ## Implementation Notes
/// This implementation adheres to the algorithm specified in Section 4 of the
/// NIST Special Publication 800-56C Revision 2 published on August 2020. The
/// parameters relevant to the specification are as follows:
/// * Auxillary Function H is Option 1
/// * `output.len()`, `secret.len()`, `info.len()` each must be <= 2^30
/// * `output.len()` and `secret.len()` > 0
/// * `output.len()`, `secret.len()` are analogous to `L` and `Z` respectively in the
///   specification.
/// * `info` refers to `FixedInfo` in the specification.
///
/// Specification is available at <https://doi.org/10.6028/NIST.SP.800-56Cr2>
///
/// # Errors
/// `Unspecified` is returned under the following conditions:
/// * Either `output.len()`, `secret.len()`, or `info.len()` are > 2^30.
/// * `output.len() == 0 || secret.len() == 0`
pub fn sskdf_digest(
    algorithm: &'static SskdfDigestAlgorithm,
    secret: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), Unspecified> {
    let evp_md = match_digest_type(&algorithm.digest);
    let out_len = output.len();
    if 1 != unsafe {
        SSKDF_digest(
            output.as_mut_ptr(),
            out_len,
            *evp_md,
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    } {
        return Err(Unspecified);
    }
    Ok(())
}
