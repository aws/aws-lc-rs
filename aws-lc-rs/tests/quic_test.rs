// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::aead::quic;
use aws_lc_rs::{test, test_file};

#[test]
fn quic_aes_128() {
    test_quic(&quic::AES_128, test_file!("data/quic_aes_128_tests.txt"));
}

#[test]
fn quic_aes_256() {
    test_quic(&quic::AES_256, test_file!("data/quic_aes_256_tests.txt"));
}

#[test]
fn quic_chacha20() {
    test_quic(&quic::CHACHA20, test_file!("data/quic_chacha20_tests.txt"));
}

fn test_quic(alg: &'static quic::Algorithm, test_file: test::File) {
    test_sample_len(alg);

    test::run(test_file, |section, test_case| {
        assert_eq!(section, "");
        let key_bytes = test_case.consume_bytes("KEY");
        let sample = test_case.consume_bytes("SAMPLE");
        let mask = test_case.consume_bytes("MASK");

        let key = quic::HeaderProtectionKey::new(alg, &key_bytes)?;

        assert_eq!(mask.as_ref(), key.new_mask(&sample)?);

        Ok(())
    });
}

#[allow(clippy::range_plus_one)]
fn test_sample_len(alg: &'static quic::Algorithm) {
    let key_len = alg.key_len();
    let key_data = vec![0u8; key_len];

    let key = quic::HeaderProtectionKey::new(alg, &key_data).unwrap();

    let sample_len = 16;
    let sample_data = vec![0u8; sample_len + 2];

    // Sample is the right size.
    assert!(key.new_mask(&sample_data[..sample_len]).is_ok());

    // Sample is one byte too small.
    assert!(key.new_mask(&sample_data[..(sample_len - 1)]).is_err());

    // Sample is one byte too big.
    assert!(key.new_mask(&sample_data[..(sample_len + 1)]).is_err());

    // Sample is empty.
    assert!(key.new_mask(&[]).is_err());
}
