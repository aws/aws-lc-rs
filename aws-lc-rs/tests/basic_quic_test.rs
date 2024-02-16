// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::aead;

use aead::quic;
use aws_lc_rs::test::from_dirty_hex;

#[test]
fn test_quic_aes_128_gcm() {
    let key_bytes = from_dirty_hex("e8904ecc2e37a6e4cc02271e319c804b");
    let sample = from_dirty_hex("13484ec85dc4d36349697c7d4ea1a159");
    let mask = from_dirty_hex("67387ebf3a");

    let key = quic::HeaderProtectionKey::new(&quic::AES_128, &key_bytes).unwrap();

    assert_eq!(mask.as_ref(), key.new_mask(&sample).unwrap());
}

#[test]
fn test_quic_aes_256_gcm() {
    let key_bytes =
        from_dirty_hex("85af7213814aec7b92ace6284a906643912ec8853d00d158a927b8697c7ff585");
    let sample = from_dirty_hex("82a0db90f4cee12fa4afeddb74396cf6");
    let mask = from_dirty_hex("670897adf5");

    let key = quic::HeaderProtectionKey::new(&quic::AES_256, &key_bytes).unwrap();

    assert_eq!(mask.as_ref(), key.new_mask(&sample).unwrap());
}

#[test]
fn test_quic_chacha20() {
    let key_bytes =
        from_dirty_hex("59bdff7a5bcdaacf319d99646c6273ad96687d2c74ace678f15a1c710675bb23");
    let sample = from_dirty_hex("215a7c1688b4ab7d830dcd052aef9f3c");
    let mask = from_dirty_hex("6409a6196d");

    let key = quic::HeaderProtectionKey::new(&quic::CHACHA20, &key_bytes).unwrap();

    assert_eq!(mask.as_ref(), key.new_mask(&sample).unwrap());
}
