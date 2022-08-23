// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//use ring::{aead, error};
use aws_lc_ring_facade::{aead, error};

use aead::quic;

use hex::*;

pub fn from_hex(hex_str: &str) -> Vec<u8> {
    <Vec<u8>>::from_hex(hex_str).unwrap()
}

#[test]
fn test_quic_aes_128_gcm() -> Result<(), error::Unspecified> {
    let key_bytes = from_hex("e8904ecc2e37a6e4cc02271e319c804b");
    let sample = from_hex("13484ec85dc4d36349697c7d4ea1a159");
    let mask = from_hex("67387ebf3a");

    let key = quic::HeaderProtectionKey::new(&quic::AES_128, &key_bytes)?;

    assert_eq!(mask.as_ref(), key.new_mask(&sample)?);

    Ok(())
}
