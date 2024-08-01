// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! # Key-based Key Derivation Function (KBKDF) in Counter Mode
//!
//! [`kbkdf_ctr_hmac`] provides an implementation of KDF in Counter Mode using HMAC PRF specified in
//! [NIST SP 800-108r1-upd1](https://doi.org/10.6028/NIST.SP.800-108r1-upd1) section 4.1. Further details
//! regarding the implementation can be found on the accompanying function documentation.
//!
//! Key-based key derivation functions are used to derive additional keys from an existing cryptographic key.
//!
//! ##  Example: Usage with HMAC-SHA256 PRF
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::unstable::kdf::{kbkdf_ctr_hmac, KBKDF_CTR_HMAC_SHA256};
//!
//! const OUTPUT_KEY_LEN: usize = 16;
//!
//! let key: &[u8] = &[
//!     0x01, 0x85, 0xfb, 0x76, 0x61, 0xf6, 0xdd, 0x40, 0x8d, 0x98, 0x2f, 0x81, 0x0f, 0xcd, 0x50,
//!     0x04,
//! ];
//!
//! let info: &[u8] = &[
//!     0xc3, 0xf1, 0x71, 0x2a, 0x82, 0x61, 0x36, 0x43, 0xe0, 0xf7, 0x63, 0xa7, 0xa0, 0xa3, 0x15,
//!     0x88, 0xb6, 0xae, 0xd9, 0x50, 0x56, 0xdf, 0xc5, 0x12, 0x55, 0x0c, 0xf2, 0xd0, 0x0d, 0x68,
//!     0xa3, 0x2d,
//! ];
//!
//! let mut output_key = [0u8; OUTPUT_KEY_LEN];
//!
//! kbkdf_ctr_hmac(&KBKDF_CTR_HMAC_SHA256, key, info, &mut output_key)?;
//!
//! assert_eq!(
//!     output_key,
//!     [
//!         0xc6, 0x3f, 0x74, 0x7b, 0x67, 0xbe, 0x71, 0xf5, 0x7b, 0xa4, 0x56, 0x21, 0x17, 0xdd,
//!         0x29, 0x4
//!     ]
//! );
//!
//! # Ok(())
//! # }
//! ```
//!
//! ##  Example: Usage with HMAC-SHA256 PRF using NIST FixedInfo Construction
//!
//! ```
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::unstable::kdf::{kbkdf_ctr_hmac, KBKDF_CTR_HMAC_SHA256};
//!
//! const OUTPUT_KEY_LEN: usize = 16;
//!
//! let key: &[u8] = &[
//!     0x01, 0x85, 0xfb, 0x76, 0x61, 0xf6, 0xdd, 0x40, 0x8d, 0x98, 0x2f, 0x81, 0x0f, 0xcd, 0x50,
//!     0x04,
//! ];
//!
//! let label: &[u8] = b"KBKDF HMAC Counter Label";
//! let context: &[u8] = b"KBKDF HMAC Counter Context";
//!
//! let output_len_bits_be: [u8; 4] = {
//!     // Multiply `output_len` by eight to convert from bytes to bits
//!     // Convert value to a 32-bit big-endian representation
//!     let len: u32 = (OUTPUT_KEY_LEN * 8).try_into()?;
//!     len.to_be_bytes()
//! };
//!
//! // FixedInfo String: Label || 0x00 || Context || [L]
//! let mut info = Vec::<u8>::new();
//! info.extend_from_slice(label);
//! info.push(0x0);
//! info.extend_from_slice(context);
//! info.extend_from_slice(&output_len_bits_be);
//!
//! let mut output_key = [0u8; OUTPUT_KEY_LEN];
//!
//! kbkdf_ctr_hmac(&KBKDF_CTR_HMAC_SHA256, key, &info, &mut output_key)?;
//!
//! assert_eq!(
//!     output_key,
//!     [
//!         0xcd, 0xe0, 0x92, 0xc8, 0xfe, 0x96, 0x21, 0x51, 0x88, 0xd4, 0x3d, 0xe4, 0x6c, 0xf6,
//!         0x37, 0xcb
//!     ]
//! );
//!
//! # Ok(())
//! # }
//! ```
//! # Single-step Key Derivation Function (SSKDF)
//!
//! [`sskdf_digest`] and [`sskd_hmac`] provided implementations of a one-step key derivation function defined in
//! section 4 of [NIST SP 800-56Cr2](https://doi.org/10.6028/NIST.SP.800-56Cr2).
//!
//! These functions are used to derive keying material from a shared secret during a key establishment scheme.
//!
//! ## SSKDF using digest
//!
//! ```rust
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::unstable::kdf::{sskdf_digest, SSKDF_DIGEST_SHA256};
//!
//! const OUTPUT_KEY_LEN: usize = 16;
//!
//! let shared_secret: &[u8] = &[
//!     0x59, 0x09, 0x6b, 0x7b, 0xb7, 0x2b, 0x94, 0xc5, 0x55, 0x5c, 0x36, 0xc9, 0x76, 0x8f, 0xd8,
//!     0xe4, 0xed, 0x8f, 0x39, 0x5e, 0x78, 0x48, 0x5e, 0xb9, 0xf9, 0xdd, 0x43, 0x65, 0x55, 0x00,
//!     0xed, 0x7a,
//! ];
//!
//! let info: &[u8] = &[
//!     0x9b, 0xca, 0xd7, 0xe8, 0xee, 0xf7, 0xb2, 0x1a, 0x98, 0xff, 0x18, 0x60, 0x5c, 0x68, 0x16,
//!     0xbd,
//! ];
//!
//! let mut output_key = [0u8; OUTPUT_KEY_LEN];
//!
//! sskdf_digest(&SSKDF_DIGEST_SHA256, shared_secret, info, &mut output_key)?;
//!
//! assert_eq!(
//!     output_key,
//!     [
//!         0x21, 0x79, 0x35, 0x6c, 0xdc, 0x30, 0x1, 0xe6, 0x3f, 0x91, 0xb3, 0xc8, 0x10, 0x7, 0xba,
//!         0x31
//!     ]
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## SSKDF using HMAC
//!
//! ```rust
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use aws_lc_rs::unstable::kdf::{sskdf_hmac, SSKDF_HMAC_SHA256};
//!
//! const OUTPUT_KEY_LEN: usize = 16;
//!
//! let shared_secret: &[u8] = &[
//!     0x59, 0x09, 0x6b, 0x7b, 0xb7, 0x2b, 0x94, 0xc5, 0x55, 0x5c, 0x36, 0xc9, 0x76, 0x8f, 0xd8,
//!     0xe4, 0xed, 0x8f, 0x39, 0x5e, 0x78, 0x48, 0x5e, 0xb9, 0xf9, 0xdd, 0x43, 0x65, 0x55, 0x00,
//!     0xed, 0x7a,
//! ];
//!
//! let info: &[u8] = &[
//!     0x9b, 0xca, 0xd7, 0xe8, 0xee, 0xf7, 0xb2, 0x1a, 0x98, 0xff, 0x18, 0x60, 0x5c, 0x68, 0x16,
//!     0xbd,
//! ];
//!
//! let salt: &[u8] = &[
//!     0x2b, 0xc5, 0xf1, 0x6c, 0x48, 0x34, 0x72, 0xd8, 0xda, 0x53, 0xf6, 0xc3, 0x0f, 0x0a, 0xf4,
//!     0x02,
//! ];
//!
//! let mut output_key = [0u8; OUTPUT_KEY_LEN];
//!
//! sskdf_hmac(
//!     &SSKDF_HMAC_SHA256,
//!     shared_secret,
//!     info,
//!     salt,
//!     &mut output_key,
//! )?;
//!
//! assert_eq!(
//!     output_key,
//!     [
//!         0x4c, 0x36, 0x80, 0x2d, 0xf5, 0xd8, 0xd6, 0x1b, 0xd5, 0xc2, 0x4, 0x7e, 0x5, 0x5a, 0x6d,
//!         0xcb
//!     ]
//! );
//! # Ok(())
//! # }
//! ```

mod kbkdf;
mod sskdf;

pub use kbkdf::{
    kbkdf_ctr_hmac, KbkdfAlgorithmId, KbkdfCtrHmacAlgorithm, KBKDF_CTR_HMAC_SHA1,
    KBKDF_CTR_HMAC_SHA224, KBKDF_CTR_HMAC_SHA256, KBKDF_CTR_HMAC_SHA384, KBKDF_CTR_HMAC_SHA512,
};

pub use sskdf::{
    sskdf_digest, sskdf_hmac, SskdfAlgorithmId, SskdfDigestAlgorithm, SskdfHmacAlgorithm,
    SSKDF_DIGEST_SHA1, SSKDF_DIGEST_SHA224, SSKDF_DIGEST_SHA256, SSKDF_DIGEST_SHA384,
    SSKDF_DIGEST_SHA512, SSKDF_HMAC_SHA1, SSKDF_HMAC_SHA224, SSKDF_HMAC_SHA256, SSKDF_HMAC_SHA384,
    SSKDF_HMAC_SHA512,
};

#[cfg(test)]
mod tests {
    use crate::unstable::kdf::{
        kbkdf_ctr_hmac, sskdf_digest, sskdf_hmac, SskdfAlgorithmId, KBKDF_CTR_HMAC_SHA256,
        SSKDF_DIGEST_SHA1, SSKDF_DIGEST_SHA224, SSKDF_DIGEST_SHA256, SSKDF_DIGEST_SHA384,
        SSKDF_DIGEST_SHA512, SSKDF_HMAC_SHA1, SSKDF_HMAC_SHA224, SSKDF_HMAC_SHA256,
        SSKDF_HMAC_SHA384, SSKDF_HMAC_SHA512,
    };

    #[test]
    fn zero_length_output() {
        let mut output = vec![0u8; 0];
        assert!(sskdf_hmac(&SSKDF_HMAC_SHA256, &[0u8; 16], &[], &[], &mut output).is_err());
        assert!(sskdf_digest(&SSKDF_DIGEST_SHA256, &[0u8; 16], &[], &mut output).is_err());
        assert!(kbkdf_ctr_hmac(&KBKDF_CTR_HMAC_SHA256, &[0u8; 16], &[], &mut output).is_err());
    }

    #[test]
    fn zero_length_secret() {
        let mut output = vec![0u8; 16];
        assert!(sskdf_hmac(&SSKDF_HMAC_SHA256, &[], &[], &[], &mut output).is_err());
        assert!(sskdf_digest(&SSKDF_DIGEST_SHA256, &[], &[], &mut output).is_err());
        assert!(kbkdf_ctr_hmac(&KBKDF_CTR_HMAC_SHA256, &[], &[], &mut output).is_err());
    }

    macro_rules! test_id_and_debug {
        ($name:ident, $alg:expr, $expect:expr) => {
            #[test]
            fn $name() {
                let id = $alg.id();
                let expect = $expect;
                assert_eq!(id, expect);
                assert_eq!(format!("{id:?}"), format!("{expect:?}"));
            }
        };
    }

    test_id_and_debug!(
        sskdf_digest_sha1_id,
        SSKDF_DIGEST_SHA1,
        SskdfAlgorithmId::DigestSha1
    );
    test_id_and_debug!(
        sskdf_digest_sha224_id,
        SSKDF_DIGEST_SHA224,
        SskdfAlgorithmId::DigestSha224
    );
    test_id_and_debug!(
        sskdf_digest_sha256_id,
        SSKDF_DIGEST_SHA256,
        SskdfAlgorithmId::DigestSha256
    );
    test_id_and_debug!(
        sskdf_digest_sha384_id,
        SSKDF_DIGEST_SHA384,
        SskdfAlgorithmId::DigestSha384
    );
    test_id_and_debug!(
        sskdf_digest_sha512_id,
        SSKDF_DIGEST_SHA512,
        SskdfAlgorithmId::DigestSha512
    );

    test_id_and_debug!(
        sskdf_hmac_sha1_id,
        SSKDF_HMAC_SHA1,
        SskdfAlgorithmId::HmacSha1
    );
    test_id_and_debug!(
        sskdf_hmac_sha224_id,
        SSKDF_HMAC_SHA224,
        SskdfAlgorithmId::HmacSha224
    );
    test_id_and_debug!(
        sskdf_hmac_sha256_id,
        SSKDF_HMAC_SHA256,
        SskdfAlgorithmId::HmacSha256
    );
    test_id_and_debug!(
        sskdf_hmac_sha384_id,
        SSKDF_HMAC_SHA384,
        SskdfAlgorithmId::HmacSha384
    );
    test_id_and_debug!(
        sskdf_hmac_sha512_id,
        SSKDF_HMAC_SHA512,
        SskdfAlgorithmId::HmacSha512
    );
}
