// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::mem::MaybeUninit;

pub(crate) struct LcCBB(aws_lc::CBB);

impl LcCBB {
    pub(crate) fn as_mut_ptr(&mut self) -> *mut aws_lc::CBB {
        &mut self.0
    }
}

impl Drop for LcCBB {
    fn drop(&mut self) {
        unsafe {
            aws_lc::CBB_cleanup(&mut self.0);
        }
    }
}

#[inline]
#[allow(non_snake_case)]
pub(crate) unsafe fn build_CBB(initial_capacity: usize) -> LcCBB {
    let mut cbb = MaybeUninit::<aws_lc::CBB>::uninit();
    aws_lc::CBB_init(cbb.as_mut_ptr(), initial_capacity);
    LcCBB(cbb.assume_init())
}
