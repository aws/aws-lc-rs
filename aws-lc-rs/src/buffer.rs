// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! This module exposes a buffer type used in crate APIs returning private keys and other "private"
//! contents.

#![allow(clippy::module_name_repetitions)]

use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;

use zeroize::Zeroize;

/// This is a buffer type for some data exposed by various APIs in this crate.
///
/// `T` acts as a discriminant between different kinds of data.
///
/// The buffer will be zeroed on drop if it is owned.
pub struct Buffer<'a, T>(Cow<'a, [u8]>, PhantomData<T>);

impl<'a, T> Drop for Buffer<'a, T> {
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

    // TODO: remove this "allow" once this is used.
    #[allow(dead_code)]
    pub(crate) fn public_from_slice(slice: &[u8]) -> Buffer<'_, T> {
        Buffer(Cow::Borrowed(slice), PhantomData)
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
    fn test_public_from_slice() {
        let slice = [1, 2, 3];
        let buffer: Buffer<u8> = Buffer::public_from_slice(&slice);
        assert_eq!(buffer.as_ref(), &[1, 2, 3]);
    }
}
