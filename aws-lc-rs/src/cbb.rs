// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::buffer::Buffer;
use crate::error::Unspecified;
use crate::ptr::LcPtr;
use aws_lc::{CBB_cleanup, CBB_finish, CBB_init, CBB_init_fixed, CBB};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::null_mut;

pub(crate) struct LcCBB<'a>(CBB, PhantomData<&'a CBB>);

impl LcCBB<'static> {
    pub(crate) fn new(initial_capacity: usize) -> LcCBB<'static> {
        let mut cbb = MaybeUninit::<CBB>::uninit();
        let cbb = unsafe {
            CBB_init(cbb.as_mut_ptr(), initial_capacity);
            cbb.assume_init()
        };
        Self(cbb, PhantomData)
    }

    pub(crate) fn into_buffer<'a, T>(mut self) -> Result<Buffer<'a, T>, Unspecified> {
        let mut out_data = null_mut::<u8>();
        let mut out_len: usize = 0;

        if 1 != unsafe { CBB_finish(self.as_mut_ptr(), &mut out_data, &mut out_len) } {
            return Err(Unspecified);
        };

        let out_data = LcPtr::new(out_data)?;

        // TODO: Need a type to just hold the owned pointer from CBB rather then copying
        Ok(Buffer::take_from_slice(unsafe {
            out_data.as_slice_mut(out_len)
        }))
    }
}

impl<'a> LcCBB<'a> {
    pub(crate) fn new_fixed<const N: usize>(buffer: &'a mut [u8; N]) -> LcCBB<'a> {
        let mut cbb = MaybeUninit::<CBB>::uninit();
        let cbb = unsafe {
            CBB_init_fixed(cbb.as_mut_ptr(), buffer.as_mut_ptr(), N);
            cbb.assume_init()
        };
        Self(cbb, PhantomData)
    }

    pub(crate) fn finish(mut self) -> Result<usize, Unspecified> {
        let mut pkcs8_bytes_ptr = null_mut::<u8>();
        let mut out_len: usize = 0;
        if 1 != unsafe { CBB_finish(self.as_mut_ptr(), &mut pkcs8_bytes_ptr, &mut out_len) } {
            return Err(Unspecified);
        }
        Ok(out_len)
    }
}
impl LcCBB<'_> {
    pub(crate) fn as_mut_ptr(&mut self) -> *mut CBB {
        &mut self.0
    }
}

impl Drop for LcCBB<'_> {
    fn drop(&mut self) {
        unsafe {
            CBB_cleanup(&mut self.0);
        }
    }
}
