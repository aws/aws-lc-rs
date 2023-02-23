// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Serialization and deserialization.

/// A serialized positive integer.
#[derive(Copy, Clone)]
pub struct Positive<'a>(untrusted::Input<'a>);

impl<'a> Positive<'a> {
    pub(crate) fn new_non_empty_without_leading_zeros(input: untrusted::Input<'a>) -> Self {
        debug_assert!(!input.is_empty());
        debug_assert!(input.len() == 1 || input.as_slice_less_safe()[0] != 0);
        Self(input)
    }

    /// Returns the value, ordered from significant byte to least significant
    /// byte, without any leading zeros. The result is guaranteed to be
    /// non-empty.
    #[inline]
    #[must_use]
    pub fn big_endian_without_leading_zero(&self) -> &'a [u8] {
        self.big_endian_without_leading_zero_as_input()
            .as_slice_less_safe()
    }

    #[inline]
    pub(crate) fn big_endian_without_leading_zero_as_input(&self) -> untrusted::Input<'a> {
        self.0
    }
}

impl Positive<'_> {
    /// Returns the first byte.
    ///
    /// Will not panic because the value is guaranteed to have at least one
    /// byte.
    #[must_use]
    pub fn first_byte(&self) -> u8 {
        // This won't panic because
        self.0.as_slice_less_safe()[0]
    }
}
