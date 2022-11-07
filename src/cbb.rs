// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: ISC

use std::mem::MaybeUninit;

#[inline]
#[allow(non_snake_case)]
pub unsafe fn build_CBB(initial_capacity: usize) -> aws_lc_sys::CBB {
    let mut cbb = MaybeUninit::<aws_lc_sys::CBB>::uninit();
    aws_lc_sys::CBB_init(cbb.as_mut_ptr(), initial_capacity);
    cbb.assume_init()
}
