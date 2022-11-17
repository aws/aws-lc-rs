// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::digest::{match_digest_type, Algorithm};
use crate::error::Unspecified;
use std::mem::MaybeUninit;
use std::ptr::null_mut;

pub(super) struct DigestContext(aws_lc_sys::EVP_MD_CTX);

impl DigestContext {
    pub fn new(algorithm: &'static Algorithm) -> Result<DigestContext, Unspecified> {
        let evp_md_type = match_digest_type(&algorithm.id);
        let mut dc = MaybeUninit::<aws_lc_sys::EVP_MD_CTX>::uninit();
        unsafe {
            aws_lc_sys::EVP_MD_CTX_init(dc.as_mut_ptr());
            if 1 != aws_lc_sys::EVP_DigestInit_ex(dc.as_mut_ptr(), *evp_md_type, null_mut()) {
                return Err(Unspecified);
            };
            Ok(Self(dc.assume_init()))
        }
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut aws_lc_sys::EVP_MD_CTX {
        &mut self.0
    }

    pub(super) fn as_ptr(&self) -> *const aws_lc_sys::EVP_MD_CTX {
        &self.0
    }
}

unsafe impl Send for DigestContext {}
unsafe impl Sync for DigestContext {}

impl Clone for DigestContext {
    fn clone(&self) -> Self {
        self.try_clone().expect("Unable to clone DigestContext")
    }
}

impl Drop for DigestContext {
    fn drop(&mut self) {
        unsafe {
            aws_lc_sys::EVP_MD_CTX_cleanup(self.as_mut_ptr());
        }
    }
}

impl DigestContext {
    fn try_clone(&self) -> Result<Self, &'static str> {
        let mut dc = MaybeUninit::<aws_lc_sys::EVP_MD_CTX>::uninit();
        unsafe {
            aws_lc_sys::EVP_MD_CTX_init(dc.as_mut_ptr());
            if 1 != aws_lc_sys::EVP_MD_CTX_copy(dc.as_mut_ptr(), self.as_ptr()) {
                return Err("EVP_MD_CTX_copy failed");
            };
            Ok(Self(dc.assume_init()))
        }
    }
}
