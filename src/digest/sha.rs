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
use aws_lc_sys::SHA_CTX;
use std::ffi::c_void;
use std::mem;

pub const BLOCK_LEN: usize = 512 / 8;
pub const CHAINING_LEN: usize = 160 / 8;
pub const OUTPUT_LEN: usize = 160 / 8;

fn sha1_digest(msg: &mut [u8], msg_len: usize, output: &mut [u8]) {
    unsafe {
        // let ctx = aws_lc_sys::EVP_MD_CTX_new();
        // aws_lc_sys::EVP_DigestInit_ex(ctx, aws_lc_sys::EVP_sha1(), aws_lc_sys::ENGINE_new());

        let sha_ctx: &mut SHA_CTX = &mut SHA_CTX::default();
        aws_lc_sys::SHA1_Init(sha_ctx);
        // Cast mutable pointer as c_void to conform to AWS-LC's SHA APIs.
        aws_lc_sys::SHA1_Update(sha_ctx, msg.as_mut_ptr() as *mut _, msg_len);
        aws_lc_sys::SHA1_Final(output.as_mut_ptr(), sha_ctx);
        //aws_lc_sys::SHA1(msg.as_mut_ptr(), msg_len, output.as_mut_ptr());
    }
}

fn sha256_digest(msg: &mut [u8], msg_len: usize, output: &mut [u8]) {
    unsafe {
        aws_lc_sys::SHA256(msg.as_mut_ptr(), msg_len, output.as_mut_ptr());
    }
}

fn sha384_digest(msg: &mut [u8], msg_len: usize, output: &mut [u8]) {
    unsafe {
        aws_lc_sys::SHA384(msg.as_mut_ptr(), msg_len, output.as_mut_ptr());
    }
}

fn sha512_digest(msg: &mut [u8], msg_len: usize, output: &mut [u8]) {
    unsafe {
        aws_lc_sys::SHA512(msg.as_mut_ptr(), msg_len, output.as_mut_ptr());
    }
}

fn sha512_256_digest(msg: &mut [u8], msg_len: usize, output: &mut [u8]) {
    unsafe {
        aws_lc_sys::SHA512_256(msg.as_mut_ptr(), msg_len, output.as_mut_ptr());
    }
}

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

/// SHA-1 as specified in [FIPS 180-4]. Deprecated.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    output_len: SHA1_OUTPUT_LEN,
    chaining_len: CHAINING_LEN,
    block_len: BLOCK_LEN,

    hash: sha1_digest,

    id: AlgorithmID::SHA1,
};

/// SHA-256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA256: Algorithm = Algorithm {
    output_len: SHA256_OUTPUT_LEN,
    chaining_len: SHA256_OUTPUT_LEN,
    block_len: 512 / 8,

    hash: sha256_digest,

    id: AlgorithmID::SHA256,
};

/// SHA-384 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA384: Algorithm = Algorithm {
    output_len: SHA384_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,

    hash: sha384_digest,

    id: AlgorithmID::SHA384,
};

/// SHA-512 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512: Algorithm = Algorithm {
    output_len: SHA512_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,

    hash: sha512_digest,

    id: AlgorithmID::SHA512,
};

/// SHA-512/256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512_256: Algorithm = Algorithm {
    output_len: SHA512_256_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: SHA512_BLOCK_LEN,

    hash: sha512_256_digest,

    id: AlgorithmID::SHA512_256,
};
