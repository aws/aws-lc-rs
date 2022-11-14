// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::digest::{match_digest_type, Algorithm};
use crate::error::Unspecified;
use crate::ptr::LcPtr;
use std::ptr::null_mut;

pub(super) struct DigestContext {
    pub(super) ctx: LcPtr<*mut aws_lc_sys::EVP_MD_CTX>,
}

impl DigestContext {
    pub fn new(algorithm: &'static Algorithm) -> Result<DigestContext, Unspecified> {
        unsafe {
            let ctx = LcPtr::new(aws_lc_sys::EVP_MD_CTX_new())?;
            let evp_md_type = match_digest_type(&algorithm.id);
            if 1 != aws_lc_sys::EVP_DigestInit_ex(*ctx, *evp_md_type, null_mut()) {
                return Err(Unspecified);
            };
            Ok(DigestContext { ctx })
        }
    }
}

unsafe impl Send for DigestContext {}

impl Clone for DigestContext {
    fn clone(&self) -> Self {
        self.try_clone().expect("Unable to clone DigestContext")
    }
}

impl DigestContext {
    fn try_clone(&self) -> Result<Self, &'static str> {
        unsafe {
            let ctx = LcPtr::new(aws_lc_sys::EVP_MD_CTX_new())
                .map_err(|_| "Cloning DigestContext failed during allocation.")?;
            if 1 != aws_lc_sys::EVP_MD_CTX_copy(*ctx, *self.ctx) {
                return Err("EVP_MD_CTX_copy failed");
            };
            Ok(DigestContext { ctx })
        }
    }
}
