// Copyright 2015-2022 Brian Smith.
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

// SPDX-License-Identifier: Apache-2.0
// Modifications Copyright Amazon.com, Inc. or its affiliates. See GitHub history for details.

use crate::digest::{Algorithm, AlgorithmID};

pub const BLOCK_LEN: usize = 512 / 8;
pub const CHAINING_LEN: usize = 160 / 8;
pub const OUTPUT_LEN: usize = 160 / 8;

/// The length of the output of SHA-1, in bytes.
pub const SHA1_OUTPUT_LEN: usize = OUTPUT_LEN;

/// The length of the output of SHA-256, in bytes.
pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

/// The length of the output of SHA-384, in bytes.
pub const SHA384_OUTPUT_LEN: usize = 384 / 8;

/// The length of the output of SHA-512, in bytes.
pub const SHA512_OUTPUT_LEN: usize = 512 / 8;

/// The length of the output of SHA-512/256, in bytes.
pub const SHA512_256_OUTPUT_LEN: usize = 256 / 8;

/// The length of a block for SHA-512-based algorithms, in bytes.
const SHA512_BLOCK_LEN: usize = 1024 / 8;

/// SHA-1 and SHA-256 are limited to an input size of 2^64-1 bits.
const SHA256_MAX_INPUT_LEN: usize = u64::MAX as usize;

/// SHA-384, SHA-512, and SHA-512/256 are limited to an input size of 2^128-1 bits.
const SHA512_MAX_INPUT_LEN: usize = u128::MAX as usize;

/// SHA-1 as specified in [FIPS 180-4]. Deprecated.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    output_len: SHA1_OUTPUT_LEN,
    chaining_len: CHAINING_LEN,
    block_len: BLOCK_LEN,
    max_input_len: SHA256_MAX_INPUT_LEN,

    id: AlgorithmID::SHA1,
};

/// SHA-256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA256: Algorithm = Algorithm {
    output_len: SHA256_OUTPUT_LEN,
    chaining_len: SHA256_OUTPUT_LEN,
    block_len: 512 / 8,
    max_input_len: SHA256_MAX_INPUT_LEN,

    id: AlgorithmID::SHA256,
};

/// SHA-384 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA384: Algorithm = Algorithm {
    output_len: SHA384_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,
    max_input_len: SHA512_MAX_INPUT_LEN,

    id: AlgorithmID::SHA384,
};

/// SHA-512 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512: Algorithm = Algorithm {
    output_len: SHA512_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,
    max_input_len: SHA512_MAX_INPUT_LEN,

    id: AlgorithmID::SHA512,
};

/// SHA-512/256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512_256: Algorithm = Algorithm {
    output_len: SHA512_256_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,
    max_input_len: SHA512_MAX_INPUT_LEN,

    id: AlgorithmID::SHA512_256,
};
