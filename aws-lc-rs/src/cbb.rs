// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc::{CBB_cleanup, CBB_init, CBB};
use std::mem::MaybeUninit;

pub(crate) struct LcCBB(CBB);

impl LcCBB {
    pub(crate) fn as_mut_ptr(&mut self) -> *mut CBB {
        &mut self.0
    }
}

impl Drop for LcCBB {
    fn drop(&mut self) {
        unsafe {
            CBB_cleanup(&mut self.0);
        }
    }
}

#[inline]
#[allow(non_snake_case)]
pub(crate) unsafe fn build_CBB(initial_capacity: usize) -> LcCBB {
    let mut cbb = MaybeUninit::<CBB>::uninit();
    CBB_init(cbb.as_mut_ptr(), initial_capacity);
    LcCBB(cbb.assume_init())
}
