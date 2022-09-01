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

use std::ops::Deref;
use zeroize::Zeroize;

pub(crate) struct Aes128Key(pub(super) [u8; 16]);
impl Deref for Aes128Key {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Aes128Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct Aes256Key(pub(super) [u8; 32]);
impl Deref for Aes256Key {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Aes256Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
