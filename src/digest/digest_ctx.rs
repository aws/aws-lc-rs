// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::digest::{match_digest_type, Algorithm};
use crate::error;
use std::ptr::null_mut;

pub(super) struct DigestContext {
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

unsafe impl Send for DigestContext {}

impl Drop for DigestContext {
    fn drop(&mut self) {
        unsafe {
            aws_lc_sys::EVP_MD_CTX_free(self.ctx);
        }
    }
}

impl Clone for DigestContext {
    fn clone(&self) -> Self {
        unsafe {
            let ctx = aws_lc_sys::EVP_MD_CTX_new();
            if 1 != aws_lc_sys::EVP_MD_CTX_copy(ctx, self.ctx) {
                panic!("EVP_MD_CTX_copy failed");
            };
            DigestContext { ctx }
        }
    }
}
