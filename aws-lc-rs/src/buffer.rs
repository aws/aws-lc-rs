// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! This module exposes a buffer type used in crate APIs returning private keys and other "private"
//! contents.

#![allow(clippy::module_name_repetitions)]

use crate::aws_lc::OPENSSL_cleanse;
use alloc::borrow::Cow;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// This is a buffer type for some data exposed by various APIs in this crate.
///
/// `T` acts as a discriminant between different kinds of data.
///
/// The buffer will be zeroed on drop if it is owned.
pub struct Buffer<'a, T>(Cow<'a, [u8]>, PhantomData<T>);

impl<T> Drop for Buffer<'_, T> {
    fn drop(&mut self) {
        if let Cow::Owned(b) = &mut self.0 {
            b.zeroize();
        }
    }
}

impl<'a, T> Buffer<'a, T> {
    pub(crate) fn new(owned: Vec<u8>) -> Buffer<'a, T> {
        Buffer(Cow::Owned(owned), PhantomData)
    }

    pub(crate) fn take_from_slice(slice: &mut [u8]) -> Buffer<'a, T> {
        let owned = slice.to_vec();
        slice.zeroize();
        Buffer(Cow::Owned(owned), PhantomData)
    }
}

impl<T> fmt::Debug for Buffer<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Buffer(...)")
    }
}

impl<T> AsRef<[u8]> for Buffer<'_, T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Zeroizes `bytes` with `OPENSSL_cleanse`.
///
/// Use this rather than `Zeroize` on a hot path. `OPENSSL_cleanse` zeroizes in bulk, whereas
/// `zeroize` writes an array, a `Vec` or a `Box<[u8]>` one byte at a time, and in older versions a
/// slice as well.
#[inline]
pub(crate) fn cleanse(bytes: &mut [u8]) {
    unsafe { OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len()) };
}

/// A borrowed byte slice that is zeroized when dropped, including when unwinding.
///
/// Use this rather than `zeroize::Zeroizing` for a temporary buffer on a hot path: it zeroizes
/// only the bytes that were borrowed, and does so with [`cleanse`].
pub(crate) struct ZeroizingSlice<'a>(&'a mut [u8]);

impl<'a> ZeroizingSlice<'a> {
    #[inline]
    pub(crate) fn new(bytes: &'a mut [u8]) -> Self {
        Self(bytes)
    }
}

impl Deref for ZeroizingSlice<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl DerefMut for ZeroizingSlice<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Drop for ZeroizingSlice<'_> {
    #[inline]
    fn drop(&mut self) {
        cleanse(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let buffer: Buffer<u8> = Buffer::new(vec![1, 2, 3]);
        assert_eq!(buffer.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn test_take_from_slice() {
        let mut slice = [1, 2, 3];
        let buffer: Buffer<u8> = Buffer::take_from_slice(&mut slice);
        assert_eq!(buffer.as_ref(), &[1, 2, 3]);
        assert_eq!(slice, [0, 0, 0]);
    }

    #[test]
    fn test_zeroizing_slice() {
        let mut bytes = [1u8, 2, 3, 4];
        {
            let mut used = ZeroizingSlice::new(&mut bytes[..3]);
            used[0] = 5;
            assert_eq!(&*used, &[5, 2, 3]);
        }
        // Only the borrowed bytes are zeroized.
        assert_eq!(bytes, [0, 0, 0, 4]);
    }

    #[test]
    fn test_cleanse() {
        let mut bytes = [1u8, 2, 3, 4];
        cleanse(&mut bytes[1..3]);
        assert_eq!(bytes, [1, 0, 0, 4]);
        cleanse(&mut []);
    }
}
