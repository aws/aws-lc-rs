// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::mem::MaybeUninit;

#[inline]
#[allow(non_snake_case)]
pub unsafe fn build_CBS(data: &[u8]) -> aws_lc_sys::CBS {
    let mut cbs = MaybeUninit::<aws_lc_sys::CBS>::uninit();
    aws_lc_sys::CBS_init(cbs.as_mut_ptr(), data.as_ptr(), data.len());
    cbs.assume_init()
}
