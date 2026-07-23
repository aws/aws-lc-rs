// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![forbid(unsafe_code)]

use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

/// A byte no algorithm here will produce for a whole buffer, so a buffer the cipher
/// never touched is distinguishable from one it filled.
const UNWRITTEN: u8 = 0xAA;

fn key_for(alg: &'static Algorithm) -> LessSafeKey {
    let key_bytes = vec![0x42u8; alg.key_len()];
    LessSafeKey::new(UnboundKey::new(alg, &key_bytes).unwrap())
}

fn nonce() -> Nonce {
    Nonce::assume_unique_for_key([0x24u8; 12])
}

/// A repeatable, non-uniform byte pattern, so a byte written at the wrong offset shows
/// up as a mismatch rather than being masked by a run of identical bytes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("i % 251 fits in a u8"))
        .collect()
}

#[test]
fn out_of_place_matches_in_place() {
    for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        for len in [0usize, 1, 15, 16, 17, 1024, 4096, 16384, 16385] {
            let plaintext = pattern(len);
            let aad = [0x17u8, 0x03, 0x03, 0x40, 0x11];

            // Reference: seal in place, tag returned separately.
            let mut in_place = plaintext.clone();
            let expected_tag = key_for(alg)
                .seal_in_place_separate_tag(nonce(), Aad::from(aad), &mut in_place)
                .unwrap();

            // Seal out of place, plaintext left alone.
            let mut ciphertext = vec![UNWRITTEN; len];
            let mut tag_out = vec![UNWRITTEN; alg.tag_len()];
            key_for(alg)
                .seal_out_of_place_scatter(
                    nonce(),
                    Aad::from(aad),
                    &plaintext,
                    &mut ciphertext,
                    &[],
                    &mut tag_out,
                )
                .unwrap();

            assert_eq!(ciphertext, in_place, "ciphertext differs at len={len}");
            assert_eq!(tag_out, expected_tag.as_ref(), "tag differs at len={len}");
            if len > 0 {
                assert_ne!(
                    ciphertext, plaintext,
                    "output should be encrypted at len={len}"
                );
            }
            assert_eq!(
                plaintext,
                pattern(len),
                "plaintext was mutated at len={len}"
            );
        }
    }
}

#[test]
fn out_of_place_roundtrips_through_open() {
    let alg = &AES_128_GCM;
    let plaintext = b"out-of-place sealing must still decrypt".to_vec();
    let aad = [1u8, 2, 3];

    let mut ciphertext = vec![UNWRITTEN; plaintext.len()];
    let mut tag_out = vec![UNWRITTEN; alg.tag_len()];
    key_for(alg)
        .seal_out_of_place_scatter(
            nonce(),
            Aad::from(aad),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag_out,
        )
        .unwrap();

    let mut sealed = ciphertext.clone();
    sealed.extend_from_slice(&tag_out);
    let opened = key_for(alg)
        .open_in_place(nonce(), Aad::from(aad), &mut sealed)
        .unwrap();
    assert_eq!(opened, &plaintext[..]);
}

#[test]
fn extra_in_is_encrypted_ahead_of_the_tag() {
    // `extra_in` exists for TLS 1.3's inner content-type byte, so it has to be
    // encrypted and authenticated, not merely copied out. Decrypting is what proves it.
    for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        let plaintext = pattern(1024);
        let extra_in = [23u8];
        let aad = [0x17u8, 0x03, 0x03, 0x04, 0x11];

        let mut ciphertext = vec![UNWRITTEN; plaintext.len()];
        let mut extra_and_tag = vec![UNWRITTEN; extra_in.len() + alg.tag_len()];
        key_for(alg)
            .seal_out_of_place_scatter(
                nonce(),
                Aad::from(aad),
                &plaintext,
                &mut ciphertext,
                &extra_in,
                &mut extra_and_tag,
            )
            .unwrap();

        assert_ne!(
            extra_and_tag[0], extra_in[0],
            "the extra_in byte must be encrypted, not copied"
        );

        let mut sealed = ciphertext.clone();
        sealed.extend_from_slice(&extra_and_tag);
        let opened = key_for(alg)
            .open_in_place(nonce(), Aad::from(aad), &mut sealed)
            .unwrap();
        assert_eq!(&opened[..plaintext.len()], &plaintext[..]);
        assert_eq!(opened[plaintext.len()], 23, "the extra_in byte round-trips");
    }
}

#[test]
fn a_recycled_output_buffer_leaves_no_stale_bytes() {
    // The caller-provided-buffer API is aimed at record layers that reuse one buffer per
    // record, so sealing into a buffer that still holds a previous record must overwrite
    // every byte it reports.
    let alg = &AES_128_GCM;
    let first = pattern(512);
    let second = vec![0u8; 512];

    let mut ciphertext = vec![UNWRITTEN; 512];
    let mut tag_out = vec![UNWRITTEN; alg.tag_len()];
    key_for(alg)
        .seal_out_of_place_scatter(
            nonce(),
            Aad::empty(),
            &first,
            &mut ciphertext,
            &[],
            &mut tag_out,
        )
        .unwrap();
    let first_ciphertext = ciphertext.clone();

    // Same buffer, different plaintext, different nonce.
    let nonce2 = Nonce::assume_unique_for_key([0x99u8; 12]);
    key_for(alg)
        .seal_out_of_place_scatter(
            nonce2,
            Aad::empty(),
            &second,
            &mut ciphertext,
            &[],
            &mut tag_out,
        )
        .unwrap();
    assert_ne!(
        ciphertext, first_ciphertext,
        "the second seal must overwrite the first record"
    );

    let mut sealed = ciphertext.clone();
    sealed.extend_from_slice(&tag_out);
    let nonce2 = Nonce::assume_unique_for_key([0x99u8; 12]);
    let opened = key_for(alg)
        .open_in_place(nonce2, Aad::empty(), &mut sealed)
        .unwrap();
    assert_eq!(opened, &second[..]);
}

#[test]
fn wrong_buffer_lengths_are_refused() {
    let alg = &AES_128_GCM;
    let plaintext = vec![0u8; 64];
    let mut tag = vec![0u8; alg.tag_len()];

    for ciphertext_len in [63usize, 65] {
        let mut ciphertext = vec![0u8; ciphertext_len];
        assert!(
            key_for(alg)
                .seal_out_of_place_scatter(
                    nonce(),
                    Aad::empty(),
                    &plaintext,
                    &mut ciphertext,
                    &[],
                    &mut tag
                )
                .is_err(),
            "a {ciphertext_len}-byte buffer for a 64-byte plaintext should be refused"
        );
    }

    let mut ct = vec![0u8; 64];
    for tag_len in [alg.tag_len() - 1, alg.tag_len() + 1] {
        let mut bad_tag = vec![0u8; tag_len];
        assert!(
            key_for(alg)
                .seal_out_of_place_scatter(
                    nonce(),
                    Aad::empty(),
                    &plaintext,
                    &mut ct,
                    &[],
                    &mut bad_tag
                )
                .is_err(),
            "a {tag_len}-byte tag buffer should be refused"
        );
    }
}

#[test]
fn a_length_mismatch_is_refused_before_the_output_is_touched() {
    // The length check happens in Rust, ahead of the AEAD, so the caller's buffer is
    // left exactly as it was. (A failure raised inside the AEAD scrubs it instead --
    // see the TLS tests, where a replayed nonce can produce one.)
    let alg = &AES_128_GCM;
    let plaintext = vec![0u8; 64];
    let mut ciphertext = vec![UNWRITTEN; 63];
    let mut tag = vec![UNWRITTEN; alg.tag_len()];

    assert!(key_for(alg)
        .seal_out_of_place_scatter(
            nonce(),
            Aad::empty(),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag
        )
        .is_err());
    assert!(
        ciphertext.iter().all(|&b| b == UNWRITTEN),
        "a length mismatch must not write to the output buffer"
    );
    assert!(
        tag.iter().all(|&b| b == UNWRITTEN),
        "a length mismatch must not write to the tag buffer"
    );
}
