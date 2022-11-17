// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ptr::{ConstPointer, DetachableLcPtr};
use aws_lc_sys::{
    BN_bin2bn, BN_bn2bin, BN_cmp, BN_new, BN_num_bits, BN_num_bytes, BN_set_u64, BIGNUM,
};
use core::ffi::c_uint;
use std::cmp::Ordering;

impl TryFrom<&[u8]> for DetachableLcPtr<*mut BIGNUM> {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let bn = DetachableLcPtr::new(BN_new())?;
            let result = BN_bin2bn(bytes.as_ptr(), bytes.len(), *bn);
            if result.is_null() {
                return Err(());
            }
            Ok(bn)
        }
    }
}

impl TryFrom<u64> for DetachableLcPtr<*mut BIGNUM> {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        unsafe {
            let bn = DetachableLcPtr::new(BN_new())?;
            if 1 != BN_set_u64(*bn, value) {
                return Err(());
            }
            Ok(bn)
        }
    }
}

impl ConstPointer<BIGNUM> {
    pub(crate) fn to_be_bytes(&self, byte_buf: &mut [u8]) -> Result<usize, ()> {
        unsafe {
            let bn_bytes = BN_num_bytes(**self);
            let byte_buf_len = c_uint::try_from(byte_buf.len()).map_err(|_| ())?;

            if bn_bytes > byte_buf_len {
                return Err(());
            }

            let out_bytes = BN_bn2bin(**self, byte_buf.as_mut_ptr());
            let out_bytes = c_uint::try_from(out_bytes).map_err(|_| ())?;
            if out_bytes != bn_bytes {
                return Err(());
            }
            Ok(out_bytes as usize)
        }
    }

    pub(crate) fn compare(&self, other: &ConstPointer<BIGNUM>) -> Ordering {
        unsafe {
            let result = BN_cmp(**self, **other);
            result.cmp(&0)
        }
    }

    pub(crate) fn num_bytes(&self) -> u32 {
        unsafe { BN_num_bytes(**self) }
    }

    pub(crate) fn num_bits(&self) -> u32 {
        unsafe { BN_num_bits(**self) }
    }
}
