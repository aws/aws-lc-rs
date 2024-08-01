// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(clippy::module_name_repetitions)]

use aws_lc::KBKDF_ctr_hmac;

use crate::{
    digest::{match_digest_type, AlgorithmID},
    error::Unspecified,
};

/// KBKDF in Counter Mode with HMAC-SHA1
pub const KBKDF_CTR_HMAC_SHA1: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfAlgorithmId::CtrHmacSha1,
    digest: AlgorithmID::SHA1,
};

/// KBKDF in Counter Mode with HMAC-SHA224
pub const KBKDF_CTR_HMAC_SHA224: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfAlgorithmId::CtrHmacSha224,
    digest: AlgorithmID::SHA224,
};

/// KBKDF in Counter Mode with HMAC-SHA256
pub const KBKDF_CTR_HMAC_SHA256: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfAlgorithmId::CtrHmacSha256,
    digest: AlgorithmID::SHA256,
};

/// KBKDF in Counter Mode with HMAC-SHA384
pub const KBKDF_CTR_HMAC_SHA384: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfAlgorithmId::CtrHmacSha384,
    digest: AlgorithmID::SHA384,
};

/// KBKDF in Counter Mode with HMAC-SHA512
pub const KBKDF_CTR_HMAC_SHA512: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfAlgorithmId::CtrHmacSha512,
    digest: AlgorithmID::SHA512,
};

/// KBKDF in Counter Mode with HMAC Algorithm
pub struct KbkdfCtrHmacAlgorithm {
    id: KbkdfAlgorithmId,
    digest: AlgorithmID,
}

impl KbkdfCtrHmacAlgorithm {
    /// Return the `KbkdfAlgorithmId` for this algorithm.
    #[must_use]
    pub fn id(&self) -> KbkdfAlgorithmId {
        self.id
    }
}

impl core::fmt::Debug for KbkdfCtrHmacAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.id, f)
    }
}

/// Key-based Derivation Function Algorithm Identifier
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KbkdfAlgorithmId {
    /// KBKDF in Counter Mode with HMAC-SHA1
    CtrHmacSha1,

    /// KBKDF in Counter Mode with HMAC-SHA224
    CtrHmacSha224,

    /// KBKDF in Counter Mode with HMAC-SHA256
    CtrHmacSha256,

    /// KBKDF in Counter Mode with HMAC-SHA384
    CtrHmacSha384,

    /// KBKDF in Counter Mode with HMAC-SHA512
    CtrHmacSha512,
}

/// # Key-based Key Derivation Function (KBKDF) in Counter Mode with HMAC PRF
///
/// ## Implementation Notes
///
/// This implementation adheres to the algorithm specified in Section 4.1 of the
/// NIST Special Publication 800-108 Revision 1 Update 1 published on August
/// 2022. The parameters relevant to the specification are as follows:
/// * `output.len() * 8` is analogous to `L` in the specification.
/// * `r` the length of the binary representation of the counter `i`
///   referred to by the specification. `r` is 32 bits in this implementation.
/// * `K_IN` is analogous to `secret`.
/// * The iteration counter `i` is place before the fixed info.
/// * `PRF` refers to HMAC in this implementation.
///
/// Specification available at <https://doi.org/10.6028/NIST.SP.800-108r1-upd1>
///
/// # Errors
/// `Unspecified` is returned if an error has occurred. This can occur due to the following reasons:
/// * `secret.len() == 0 || output.len() == 0`
/// * `output.len() > usize::MAX - DIGEST_LENGTH`
/// * The requested `output.len()` exceeds the `u32::MAX` counter `i`.
pub fn kbkdf_ctr_hmac(
    algorithm: &'static KbkdfCtrHmacAlgorithm,
    secret: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), Unspecified> {
    let evp_md = match_digest_type(&algorithm.digest);
    let out_len = output.len();
    if 1 != unsafe {
        KBKDF_ctr_hmac(
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
