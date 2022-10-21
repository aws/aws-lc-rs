/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 */

use crate::error::KeyRejected;
use aws_lc_sys::EVP_PKEY;
use std::os::raw::{c_int, c_uint};

use crate::ptr::NonNullPtr;

#[inline]
pub(crate) unsafe fn validate_pkey(
    evp_pkey: NonNullPtr<*mut EVP_PKEY>,
    expected_key_type: c_int,
    min_pkey_bits: c_uint,
    max_pkey_bits: c_uint,
) -> Result<(), KeyRejected> {
    let key_type = aws_lc_sys::EVP_PKEY_id(*evp_pkey);
    if key_type != expected_key_type {
        return Err(KeyRejected::wrong_algorithm());
    }

    let bits = aws_lc_sys::EVP_PKEY_bits(*evp_pkey);
    let bits = bits as c_uint;
    if bits < min_pkey_bits {
        return Err(KeyRejected::too_small());
    }

    if bits > max_pkey_bits {
        return Err(KeyRejected::too_large());
    }
    Ok(())
}
