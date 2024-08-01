// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(all(feature = "unstable", not(feature = "fips")))]

use std::error::Error;

use aws_lc_rs::{
    test, test_file,
    unstable::kdf::{
        kbkdf_ctr_hmac, sskdf_digest, sskdf_hmac, KbkdfCtrHmacAlgorithm, SskdfDigestAlgorithm,
        SskdfHmacAlgorithm, KBKDF_CTR_HMAC_SHA1, KBKDF_CTR_HMAC_SHA224, KBKDF_CTR_HMAC_SHA256,
        KBKDF_CTR_HMAC_SHA384, KBKDF_CTR_HMAC_SHA512, SSKDF_DIGEST_SHA1, SSKDF_DIGEST_SHA224,
        SSKDF_DIGEST_SHA256, SSKDF_DIGEST_SHA384, SSKDF_DIGEST_SHA512, SSKDF_HMAC_SHA1,
        SSKDF_HMAC_SHA224, SSKDF_HMAC_SHA256, SSKDF_HMAC_SHA384, SSKDF_HMAC_SHA512,
    },
};

#[derive(Clone, Copy)]
enum SskdfVariant {
    Digest,
    Hmac,
}

impl TryFrom<String> for SskdfVariant {
    type Error = Box<dyn Error>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "DIGEST" => Ok(SskdfVariant::Digest),
            "HMAC" => Ok(SskdfVariant::Hmac),
            _ => Err(format!("unsupported sskdf variant: {value:?}").into()),
        }
    }
}

#[derive(Clone, Copy)]
enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<String> for Hash {
    type Error = Box<dyn Error>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "SHA1" => Ok(Hash::Sha1),
            "SHA-224" => Ok(Hash::Sha224),
            "SHA-256" => Ok(Hash::Sha256),
            "SHA-384" => Ok(Hash::Sha384),
            "SHA-512" => Ok(Hash::Sha512),
            _ => Err(format!("unsupported hash: {value:?}").into()),
        }
    }
}

impl From<Hash> for &'static SskdfHmacAlgorithm {
    fn from(value: Hash) -> Self {
        match value {
            Hash::Sha1 => &SSKDF_HMAC_SHA1,
            Hash::Sha224 => &SSKDF_HMAC_SHA224,
            Hash::Sha256 => &SSKDF_HMAC_SHA256,
            Hash::Sha384 => &SSKDF_HMAC_SHA384,
            Hash::Sha512 => &SSKDF_HMAC_SHA512,
        }
    }
}

impl From<Hash> for &'static SskdfDigestAlgorithm {
    fn from(value: Hash) -> Self {
        match value {
            Hash::Sha1 => &SSKDF_DIGEST_SHA1,
            Hash::Sha224 => &SSKDF_DIGEST_SHA224,
            Hash::Sha256 => &SSKDF_DIGEST_SHA256,
            Hash::Sha384 => &SSKDF_DIGEST_SHA384,
            Hash::Sha512 => &SSKDF_DIGEST_SHA512,
        }
    }
}

impl From<Hash> for &'static KbkdfCtrHmacAlgorithm {
    fn from(value: Hash) -> Self {
        match value {
            Hash::Sha1 => &KBKDF_CTR_HMAC_SHA1,
            Hash::Sha224 => &KBKDF_CTR_HMAC_SHA224,
            Hash::Sha256 => &KBKDF_CTR_HMAC_SHA256,
            Hash::Sha384 => &KBKDF_CTR_HMAC_SHA384,
            Hash::Sha512 => &KBKDF_CTR_HMAC_SHA512,
        }
    }
}

#[test]
fn sskdf() {
    test::run(test_file!("data/sskdf.txt"), |_section, tc| {
        const EMPTY_SLICE: &[u8] = &[];

        let hash: Hash = tc.consume_string("HASH").try_into().unwrap();
        let variant: SskdfVariant = tc.consume_string("VARIANT").try_into().unwrap();

        let secret = tc.consume_bytes("SECRET");
        let info = tc.consume_optional_bytes("INFO");
        let salt = tc.consume_optional_bytes("SALT");
        let expect = tc.consume_bytes("EXPECT");

        let info = if let Some(v) = &info {
            v.as_slice()
        } else {
            EMPTY_SLICE
        };

        let salt = if let Some(v) = &salt {
            v.as_slice()
        } else {
            EMPTY_SLICE
        };

        match variant {
            SskdfVariant::Digest => {
                assert_sskdf_digest(hash.into(), &secret, info, &expect);
            }
            SskdfVariant::Hmac => assert_sskdf_hmac(hash.into(), &secret, info, salt, &expect),
        }

        Ok(())
    });
}

fn assert_sskdf_digest(
    algorithm: &'static SskdfDigestAlgorithm,
    secret: &[u8],
    info: &[u8],
    expect: &[u8],
) {
    let mut output = vec![0u8; expect.len()];
    sskdf_digest(algorithm, secret, info, output.as_mut_slice()).unwrap();
    assert_eq!(expect, output.as_slice());
}

fn assert_sskdf_hmac(
    algorithm: &'static SskdfHmacAlgorithm,
    secret: &[u8],
    info: &[u8],
    salt: &[u8],
    expect: &[u8],
) {
    let mut output = vec![0u8; expect.len()];
    sskdf_hmac(algorithm, secret, info, salt, output.as_mut_slice()).unwrap();
    assert_eq!(expect, output.as_slice());
}

#[test]
fn hkdf_ctr_hmac() {
    test::run(test_file!("data/kbkdf_counter.txt"), |_section, tc| {
        const EMPTY_SLICE: &[u8] = &[];

        let hash: Hash = tc.consume_string("HASH").try_into().unwrap();
        let secret = tc.consume_bytes("SECRET");
        let info = tc.consume_bytes("INFO");
        let expect = tc.consume_bytes("EXPECT");

        let mut output = vec![0u8; expect.len()];
        kbkdf_ctr_hmac(hash.into(), &secret, &info, output.as_mut_slice()).unwrap();
        assert_eq!(expect, output.as_slice());

        Ok(())
    });
}
