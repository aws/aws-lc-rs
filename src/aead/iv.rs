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

use crate::aead::counter::Counter;
use crate::endian::ArrayEncoding;

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
#[repr(C)]
pub struct Iv([u8; IV_LEN]);

pub const IV_LEN: usize = 16;

impl Iv {
    #[inline]
    pub fn assume_unique_for_key(a: [u8; IV_LEN]) -> Self {
        Self(a)
    }

    #[inline]
    pub fn into_bytes_less_safe(self) -> [u8; IV_LEN] {
        self.0
    }
}

impl<U32> From<Counter<U32>> for Iv
where
    [U32; 4]: ArrayEncoding<[u8; IV_LEN]>,
{
    fn from(ctr: Counter<U32>) -> Self {
        Iv::assume_unique_for_key(*ctr.u32s.as_byte_array())
    }
}
