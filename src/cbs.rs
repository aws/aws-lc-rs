// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::mem::MaybeUninit;

#[inline]
#[allow(non_snake_case)]
pub unsafe fn build_CBS(data: &[u8]) -> aws_lc::CBS {
    let mut cbs = MaybeUninit::<aws_lc::CBS>::uninit();
    aws_lc::CBS_init(cbs.as_mut_ptr(), data.as_ptr(), data.len());
    cbs.assume_init()
}
