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

use crate::aead::chacha20_poly1305_openssh::CounterLEu32;
use crate::aead::iv::{Iv, IV_LEN};
use crate::aead::CounterBEu32;
use crate::endian::{ArrayEncoding, BigEndian, Encoding, LittleEndian};
use crate::error;
use std::cmp;
use std::convert::TryInto;
use std::mem::transmute_copy;

/// A nonce for a single AEAD opening or sealing operation.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// `Nonce` intentionally doesn't implement `Clone` to ensure that each one is
/// consumed at most once.
pub struct Nonce(pub(crate) [u8; NONCE_LEN]);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        let value: &[u8; NONCE_LEN] = value.try_into()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    fn as_ref(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl From<&[u8; NONCE_LEN]> for Nonce {
    fn from(bytes: &[u8; NONCE_LEN]) -> Self {
        Nonce(bytes.to_owned())
    }
}

impl From<&[u32; NONCE_LEN / 4]> for Nonce {
    fn from(values: &[u32; NONCE_LEN / 4]) -> Self {
        unsafe {
            let bytes: [u8; NONCE_LEN] = transmute_copy(values);
            Nonce(bytes)
        }
    }
}

impl From<BigEndian<u32>> for Nonce {
    fn from(number: BigEndian<u32>) -> Self {
        let nonce = [BigEndian::ZERO, BigEndian::ZERO, number];
        Nonce(*(nonce.as_byte_array()))
    }
}

impl From<LittleEndian<u32>> for Nonce {
    fn from(number: LittleEndian<u32>) -> Self {
        let nonce = [LittleEndian::ZERO, LittleEndian::ZERO, number];
        Nonce(*(nonce.as_byte_array()))
    }
}

impl From<BigEndian<u64>> for Nonce {
    fn from(number: BigEndian<u64>) -> Self {
        let most_sig_bytes = (u64::from(number) >> 32) as u32;
        let least_sig_bytes = u64::from(number) as u32;
        let nonce = [
            BigEndian::ZERO,
            BigEndian::from(most_sig_bytes),
            BigEndian::from(least_sig_bytes),
        ];
        Nonce(*(nonce.as_byte_array()))
    }
}

impl From<LittleEndian<u64>> for Nonce {
    fn from(number: LittleEndian<u64>) -> Self {
        let most_sig_bytes = (u64::from(number) >> 32) as u32;
        let least_sig_bytes = u64::from(number) as u32;

        let nonce = [
            LittleEndian::from(least_sig_bytes),
            LittleEndian::from(most_sig_bytes),
            LittleEndian::ZERO,
        ];
        Nonce(*(nonce.as_byte_array()))
    }
}

impl From<&[u8; IV_LEN]> for Nonce {
    fn from(bytes: &[u8; IV_LEN]) -> Self {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let bytes_start_index = 0;
        let nonce_start_index = 0;

        nonce_bytes[nonce_start_index..(NONCE_LEN + nonce_start_index)]
            .copy_from_slice(&bytes[bytes_start_index..(NONCE_LEN + bytes_start_index)]);
        Nonce(nonce_bytes)
    }
}

impl From<&[u8]> for Nonce {
    fn from(bytes: &[u8]) -> Self {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let iteration_count = cmp::min(NONCE_LEN, bytes.len());
        let bytes_start_index = bytes.len() - iteration_count; // Copy from end
        let nonce_start_index = NONCE_LEN - iteration_count; // Write to the end
        nonce_bytes[nonce_start_index..(NONCE_LEN + nonce_start_index)]
            .copy_from_slice(&bytes[bytes_start_index..(NONCE_LEN + bytes_start_index)]);
        Nonce(nonce_bytes)
    }
}

impl From<CounterBEu32> for Nonce {
    fn from(counter: CounterBEu32) -> Self {
        Nonce::from(counter.u32s.as_byte_array())
    }
}

impl From<CounterLEu32> for Nonce {
    fn from(counter: CounterLEu32) -> Self {
        Nonce::from(counter.u32s.as_byte_array())
    }
}

impl From<Iv> for Nonce {
    fn from(iv: Iv) -> Self {
        Nonce::from(&iv.into_bytes_less_safe())
    }
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;
