// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::digest::{Algorithm, AlgorithmID};
use crate::error;
use std::ptr::null_mut;

#[derive(Clone)]
pub(crate) struct DigestContext {
    pub ctx: *mut aws_lc_sys::EVP_MD_CTX,
}

impl DigestContext {
    pub fn new(algorithm: &'static Algorithm) -> Result<DigestContext, error::Unspecified> {
        unsafe {
            let ctx = aws_lc_sys::EVP_MD_CTX_new();
            if ctx.is_null() {
                return Err(error::Unspecified);
            }
            match algorithm.id {
                AlgorithmID::SHA1 => {
                    if 1 != aws_lc_sys::EVP_DigestInit_ex(ctx, aws_lc_sys::EVP_sha1(), null_mut()) {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA256 => {
                    if 1 != aws_lc_sys::EVP_DigestInit_ex(ctx, aws_lc_sys::EVP_sha256(), null_mut())
                    {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA384 => {
                    if 1 != aws_lc_sys::EVP_DigestInit_ex(ctx, aws_lc_sys::EVP_sha384(), null_mut())
                    {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA512 => {
                    if 1 != aws_lc_sys::EVP_DigestInit_ex(ctx, aws_lc_sys::EVP_sha512(), null_mut())
                    {
                        return Err(error::Unspecified);
                    };
                }
                AlgorithmID::SHA512_256 => {
                    if 1 != aws_lc_sys::EVP_DigestInit_ex(
                        ctx,
                        aws_lc_sys::EVP_sha512_256(),
                        null_mut(),
                    ) {
                        return Err(error::Unspecified);
                    };
                }
            }
            Ok(DigestContext { ctx })
        }
    }
}

impl Drop for DigestContext {
    fn drop(&mut self) {
        unsafe {
            aws_lc_sys::EVP_MD_CTX_free(self.ctx);
        }
    }
}
