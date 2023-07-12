// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::aead;

// Based on bugs found while testing against rustls.
// Specifically related to tls12 API tests: https://github.com/rustls/rustls/blob/main/rustls/tests/api.rs
#[test]
#[allow(clippy::unit_cmp)]
fn rustls_bug() {
    const KEY: &[u8] = &[
        239, 90, 253, 140, 117, 97, 1, 139, 56, 128, 152, 217, 106, 97, 87, 101, 79, 81, 29, 233,
        96, 98, 201, 110, 206, 250, 122, 166, 21, 134, 58, 249,
    ];
    const NONCE: [u8; 12] = [43, 177, 114, 110, 129, 186, 1, 92, 12, 167, 248, 103];
    const AAD: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16];
    const DATA: &[u8; 16] = &[
        20, 0, 0, 12, 92, 94, 146, 70, 164, 130, 7, 112, 227, 239, 243, 228,
    ];

    fn append(v: &mut Vec<u8>, extra: &[u8], data: &[u8], tag: &[u8]) {
        v.extend_from_slice(extra);
        v.extend_from_slice(data);
        v.extend_from_slice(tag);
    }

    let uk = aead::UnboundKey::new(&aead::AES_256_GCM, KEY).unwrap();
    let ring_uk = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, KEY).unwrap();

    let lsk = aead::LessSafeKey::new(uk);
    let ring_lsk = ring::aead::LessSafeKey::new(ring_uk);

    let mut enc_data: Vec<u8> = vec![];
    enc_data.extend_from_slice(&DATA[..]);
    let tag = lsk
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(NONCE),
            aead::Aad::from(AAD),
            &mut enc_data,
        )
        .unwrap();

    let mut ring_enc_data: Vec<u8> = vec![];
    ring_enc_data.extend_from_slice(&DATA[..]);
    let ring_tag = ring_lsk
        .seal_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(NONCE),
            ring::aead::Aad::from(AAD),
            &mut ring_enc_data,
        )
        .unwrap();

    assert_eq!(ring_tag.as_ref(), tag.as_ref());
    assert_eq!(ring_enc_data.as_slice(), enc_data.as_slice());

    let prefix_bytes: &[u8] = &NONCE[4..];

    let mut enc_data_tag_vec: Vec<u8> = vec![];
    append(&mut enc_data_tag_vec, prefix_bytes, &enc_data, tag.as_ref());

    let mut ring_enc_data_tag_vec: Vec<u8> = vec![];
    append(
        &mut ring_enc_data_tag_vec,
        prefix_bytes,
        &ring_enc_data,
        ring_tag.as_ref(),
    );

    assert_eq!(ring_enc_data_tag_vec, enc_data_tag_vec);

    let len = lsk
        .open_within(
            aead::Nonce::assume_unique_for_key(NONCE),
            aead::Aad::from(AAD),
            &mut enc_data_tag_vec[..],
            prefix_bytes.len()..,
        )
        .unwrap()
        .len();

    let ring_len = ring_lsk
        .open_within(
            ring::aead::Nonce::assume_unique_for_key(NONCE),
            ring::aead::Aad::from(AAD),
            &mut ring_enc_data_tag_vec[..],
            prefix_bytes.len()..,
        )
        .unwrap()
        .len();

    assert_eq!(
        ring_enc_data_tag_vec.truncate(ring_len),
        enc_data_tag_vec.truncate(len)
    );
}
