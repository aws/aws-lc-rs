// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};
use aws_lc_rs::{hkdf, test};

#[test]
fn test_key_type_header_protection_key() {
    let key_bytes = test::from_dirty_hex(r"d480429666d48b400633921c5407d1d1");
    let info = test::from_dirty_hex(r"f0f1f2f3f4f5f6f7f8f9");
    let info_wrap = [info.as_slice()];
    let sample = test::from_dirty_hex(r"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");

    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &key_bytes);
    let okm = prk.expand(&info_wrap, &AES_128).unwrap();
    let hpk = HeaderProtectionKey::from(okm);
    assert_eq!(&AES_128, hpk.algorithm());
    assert_eq!(16, AES_128.key_len());
    assert_eq!(16, AES_128.sample_len());
    assert_eq!(32, AES_256.key_len());
    assert_eq!(16, AES_256.sample_len());
    assert_eq!(32, CHACHA20.key_len());
    assert_eq!(16, CHACHA20.sample_len());
    let mask = hpk.new_mask(&sample).unwrap();

    let ring_prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &key_bytes);
    let ring_okm = ring_prk
        .expand(&info_wrap, &ring::aead::quic::AES_128)
        .unwrap();
    let ring_hpk = ring::aead::quic::HeaderProtectionKey::from(ring_okm);
    let ring_mask = ring_hpk.new_mask(&sample).unwrap();
    assert_eq!(mask, ring_mask);
}
