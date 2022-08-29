// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::hmac::{Key, Tag};
use crate::{digest, error};
use std::mem::MaybeUninit;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};

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
            let evp_md_type = digest::match_digest_type(&key.algorithm.id);
            if 1 != aws_lc_sys::HMAC_Init_ex(
                ctx,
                key.key_value.as_ptr().cast(),
                key.key_value.len(),
                evp_md_type,
                null_mut(),
            ) {
                return Err(error::Unspecified);
            };
            Ok(HMACContext { ctx })
        }
    }

    /// Uses the one-shot HMAC operation from AWS-LC. No HMAC_CTX has to be maintained
    /// in Rust when the one-shot operation is used.
    pub fn one_shot(key: &Key, data: &[u8]) -> Tag {
        let mut output: Vec<u8> = vec![0u8; digest::MAX_OUTPUT_LEN];
        let mut out_len = MaybeUninit::<c_uint>::uninit();
        let evp_md_type = digest::match_digest_type(&key.algorithm.id);
        unsafe {
            if null()
                == aws_lc_sys::HMAC(
                    evp_md_type,
                    key.key_value.as_ptr().cast(),
                    key.key_value.len(),
                    data.as_ptr(),
                    data.len(),
                    output.as_mut_ptr(),
                    out_len.as_mut_ptr(),
                )
            {
                panic!("{}", "HMAC one-shot failed");
            }
            Tag {
                msg: <[u8; digest::MAX_OUTPUT_LEN]>::try_from(&output[..digest::MAX_OUTPUT_LEN])
                    .unwrap(),
                msg_len: out_len.assume_init() as usize,
            }
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
