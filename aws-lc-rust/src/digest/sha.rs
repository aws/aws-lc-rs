// Copyright 2015-2022 Brian Smith.
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::digest::{Algorithm, AlgorithmID};
use aws_lc::{NID_sha1, NID_sha256, NID_sha384, NID_sha512, NID_sha512_256};

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
#[allow(clippy::cast_possible_truncation)]
const SHA256_MAX_INPUT_LEN: u64 = u64::MAX;

/// SHA-384, SHA-512, and SHA-512/256 are limited to an input size of 2^128-1 bits according to the spec.
/// u64 is more than sufficient enough for practical usecases, so we limit the input length to 2^64-1 bits.
#[allow(clippy::cast_possible_truncation)]
const SHA512_MAX_INPUT_LEN: u64 = u64::MAX;

/// SHA-1 as specified in [FIPS 180-4]. Deprecated.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    output_len: SHA1_OUTPUT_LEN,
    chaining_len: CHAINING_LEN,
    block_len: BLOCK_LEN,
    max_input_len: SHA256_MAX_INPUT_LEN,

    one_shot_hash: sha1_digest,

    id: AlgorithmID::SHA1,

    hash_nid: NID_sha1,
};

/// SHA-256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA256: Algorithm = Algorithm {
    output_len: SHA256_OUTPUT_LEN,
    chaining_len: SHA256_OUTPUT_LEN,
    block_len: 512 / 8,
    max_input_len: SHA256_MAX_INPUT_LEN,

    one_shot_hash: sha256_digest,

    id: AlgorithmID::SHA256,

    hash_nid: NID_sha256,
};

/// SHA-384 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA384: Algorithm = Algorithm {
    output_len: SHA384_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,
    max_input_len: SHA512_MAX_INPUT_LEN,

    one_shot_hash: sha384_digest,

    id: AlgorithmID::SHA384,
    hash_nid: NID_sha384,
};

/// SHA-512 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512: Algorithm = Algorithm {
    output_len: SHA512_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,
    max_input_len: SHA512_MAX_INPUT_LEN,

    one_shot_hash: sha512_digest,

    id: AlgorithmID::SHA512,
    hash_nid: NID_sha512,
};

/// SHA-512/256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512_256: Algorithm = Algorithm {
    output_len: SHA512_256_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,
    max_input_len: SHA512_MAX_INPUT_LEN,

    one_shot_hash: sha512_256_digest,

    id: AlgorithmID::SHA512_256,
    hash_nid: NID_sha512_256,
};

fn sha1_digest(msg: &[u8], output: &mut [u8]) {
    unsafe {
        aws_lc::SHA1(msg.as_ptr(), msg.len(), output.as_mut_ptr());
    }
}

fn sha256_digest(msg: &[u8], output: &mut [u8]) {
    unsafe {
        aws_lc::SHA256(msg.as_ptr(), msg.len(), output.as_mut_ptr());
    }
}

fn sha384_digest(msg: &[u8], output: &mut [u8]) {
    unsafe {
        aws_lc::SHA384(msg.as_ptr(), msg.len(), output.as_mut_ptr());
    }
}

fn sha512_digest(msg: &[u8], output: &mut [u8]) {
    unsafe {
        aws_lc::SHA512(msg.as_ptr(), msg.len(), output.as_mut_ptr());
    }
}

fn sha512_256_digest(msg: &[u8], output: &mut [u8]) {
    unsafe {
        aws_lc::SHA512_256(msg.as_ptr(), msg.len(), output.as_mut_ptr());
    }
}
