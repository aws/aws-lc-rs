// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::digest::AlgorithmID;
use crate::error;
use crate::hmac::Key;
use std::ptr::null_mut;

#[derive(Clone)]
pub(crate) struct HMACContext {
    pub ctx: *mut aws_lc_sys::HMAC_CTX,
}

impl HMACContext {
    pub fn new(key: &Key) -> Result<HMACContext, error::Unspecified> {
        unsafe {
            let ctx = aws_lc_sys::HMAC_CTX_new();
            if ctx.is_null() {
                return Err(error::Unspecified);
            }
            match key.algorithm.id {
                AlgorithmID::SHA1 => {
                    if 1 != aws_lc_sys::HMAC_Init_ex(
                        ctx,
                        key.key_value.as_ptr().cast(),
                        key.key_value.len(),
                        aws_lc_sys::EVP_sha1(),
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA256 => {
                    if 1 != aws_lc_sys::HMAC_Init_ex(
                        ctx,
                        key.key_value.as_ptr().cast(),
                        key.key_value.len(),
                        aws_lc_sys::EVP_sha256(),
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA384 => {
                    if 1 != aws_lc_sys::HMAC_Init_ex(
                        ctx,
                        key.key_value.as_ptr().cast(),
                        key.key_value.len(),
                        aws_lc_sys::EVP_sha384(),
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA512 => {
                    if 1 != aws_lc_sys::HMAC_Init_ex(
                        ctx,
                        key.key_value.as_ptr().cast(),
                        key.key_value.len(),
                        aws_lc_sys::EVP_sha512(),
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA512_256 => {
                    if 1 != aws_lc_sys::HMAC_Init_ex(
                        ctx,
                        key.key_value.as_ptr().cast(),
                        key.key_value.len(),
                        aws_lc_sys::EVP_sha512_256(),
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    };
                }
            }
            Ok(HMACContext { ctx })
        }
    }
}

impl Drop for HMACContext {
    fn drop(&mut self) {
        unsafe {
            aws_lc_sys::HMAC_CTX_free(self.ctx);
        }
    }
}
