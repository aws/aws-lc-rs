// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ptr::{ConstPointer, DetachableLcPtr};
use aws_lc::{BN_bin2bn, BN_bn2bin, BN_cmp, BN_new, BN_num_bits, BN_num_bytes, BN_set_u64, BIGNUM};
use mirai_annotations::unrecoverable;
use std::cmp::Ordering;
use std::ptr::null_mut;

impl TryFrom<&[u8]> for DetachableLcPtr<BIGNUM> {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        unsafe { DetachableLcPtr::new(BN_bin2bn(bytes.as_ptr(), bytes.len(), null_mut())) }
    }
}

impl TryFrom<u64> for DetachableLcPtr<BIGNUM> {
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
    pub(crate) fn to_be_bytes(&self) -> Vec<u8> {
        unsafe {
            let bn_bytes = BN_num_bytes(**self);
            let mut byte_vec = Vec::with_capacity(bn_bytes as usize);
            let out_bytes = BN_bn2bin(**self, byte_vec.as_mut_ptr());
            if out_bytes != (bn_bytes as usize) {
                unrecoverable!("More bytes written than allocated.");
            }
            byte_vec.set_len(out_bytes);
            byte_vec
        }
    }

    pub(crate) fn compare(&self, other: &ConstPointer<BIGNUM>) -> Ordering {
        unsafe {
            let result = BN_cmp(**self, **other);
            result.cmp(&0)
        }
    }

    pub(crate) fn num_bits(&self) -> u32 {
        unsafe { BN_num_bits(**self) }
    }
}
