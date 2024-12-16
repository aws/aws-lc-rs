/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC
 */

#[deprecated(note = "use `aws_lc_rs::kdf` instead")]
pub use crate::kdf::{
    get_kbkdf_ctr_hmac_algorithm, get_sskdf_digest_algorithm, get_sskdf_hmac_algorithm,
    kbkdf_ctr_hmac, sskdf_digest, sskdf_hmac, KbkdfCtrHmacAlgorithm, KbkdfCtrHmacAlgorithmId,
    SskdfDigestAlgorithm, SskdfDigestAlgorithmId, SskdfHmacAlgorithm, SskdfHmacAlgorithmId,
};
