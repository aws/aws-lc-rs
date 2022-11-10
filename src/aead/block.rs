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

/// An array of 16 bytes that can (in the `x86_64` and `AAarch64` ABIs, at least)
/// be efficiently passed by value and returned by value (i.e. in registers),
/// and which meets the alignment requirements of `u32` and `u64` (at least)
/// for the target.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Block {
    subblocks: [u64; 2],
}

pub const BLOCK_LEN: usize = 16;

impl Block {
    #[inline]
    pub fn zero() -> Self {
        Self { subblocks: [0, 0] }
    }
}

impl From<&'_ [u8; BLOCK_LEN]> for Block {
    #[inline]
    fn from(bytes: &[u8; BLOCK_LEN]) -> Self {
        unsafe { core::mem::transmute_copy(bytes) }
    }
}

impl AsRef<[u8; BLOCK_LEN]> for Block {
    #[allow(clippy::transmute_ptr_to_ptr)]
    #[inline]
    fn as_ref(&self) -> &[u8; BLOCK_LEN] {
        unsafe { core::mem::transmute(self) }
    }
}

mod tests {
    use super::{Block, BLOCK_LEN};

    #[test]
    fn test_block_clone() {
        let block_a = Block::from(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let block_b = block_a.clone();

        for i in 0..BLOCK_LEN {
            assert_eq!(block_a.as_ref()[i], block_b.as_ref()[i]);
        }
    }
}
