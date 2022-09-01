// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::hmac::{Key, Tag};
use crate::{digest, error};
use std::mem::MaybeUninit;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};

pub(crate) struct HMACContext {
    pub ctx: *mut aws_lc_sys::HMAC_CTX,
}

impl HMACContext {
    pub fn new(
        algorithm: &'static digest::Algorithm,
        key_value: &[u8],
    ) -> Result<HMACContext, error::Unspecified> {
        unsafe {
            let ctx = aws_lc_sys::HMAC_CTX_new();
            if ctx.is_null() {
                return Err(error::Unspecified);
            }
            let evp_md_type = digest::match_digest_type(&algorithm.id);
            if 1 != aws_lc_sys::HMAC_Init_ex(
                ctx,
                key_value.as_ptr().cast(),
                key_value.len(),
                evp_md_type,
                null_mut(),
            ) {
                return Err(error::Unspecified);
            };
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

impl Clone for HMACContext {
    fn clone(&self) -> Self {
        unsafe {
            let ctx = aws_lc_sys::HMAC_CTX_new();
            aws_lc_sys::HMAC_CTX_init(ctx);
            if 1 != aws_lc_sys::HMAC_CTX_copy_ex(ctx, self.ctx) {
                panic!("HMAC_Init_ex failed");
            };
            HMACContext { ctx }
        }
    }
}
