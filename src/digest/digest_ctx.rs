// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::digest::{match_digest_type, Algorithm};
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
            let evp_md_type = match_digest_type(&algorithm.id);
            if 1 != aws_lc_sys::EVP_DigestInit_ex(ctx, evp_md_type, null_mut()) {
                return Err(error::Unspecified);
            };
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
