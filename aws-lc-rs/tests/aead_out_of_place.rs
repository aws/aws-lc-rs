// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// Out-of-place sealing must be bit-identical to the in-place path, or it is not the
// same cipher and nothing downstream can trust it.
//
// This file is `#![forbid(unsafe_code)]`: sealing into uninitialised memory and using
// the result is meant to need no `unsafe` from the caller, and the compiler enforces
// that here rather than the claim being asserted in prose.
#![forbid(unsafe_code)]

use std::mem::MaybeUninit;

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
                .seal_separate_out_of_place(
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
    let plaintext = b"the fused path must still decrypt".to_vec();
    let aad = [1u8, 2, 3];

    let mut ciphertext = vec![UNWRITTEN; plaintext.len()];
    let mut tag_out = vec![UNWRITTEN; alg.tag_len()];
    key_for(alg)
        .seal_separate_out_of_place(
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
fn wrong_buffer_lengths_are_refused() {
    let alg = &AES_128_GCM;
    let plaintext = vec![0u8; 64];
    let mut tag = vec![0u8; alg.tag_len()];

    for ciphertext_len in [63usize, 65] {
        let mut ciphertext = vec![0u8; ciphertext_len];
        assert!(
            key_for(alg)
                .seal_separate_out_of_place(
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
                .seal_separate_out_of_place(
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
fn wrong_buffer_lengths_are_refused_on_the_uninit_path_too() {
    // The uninit path is the one writing into memory the caller has not initialised, so
    // its length check is the one whose absence would be a heap overflow rather than a
    // wrong answer. Cover it separately from the initialised path.
    let alg = &AES_128_GCM;
    let plaintext = vec![0u8; 64];

    for ciphertext_len in [63usize, 65] {
        let mut ciphertext = vec![MaybeUninit::<u8>::uninit(); ciphertext_len];
        let mut tag = vec![MaybeUninit::<u8>::uninit(); alg.tag_len()];
        assert!(
            key_for(alg)
                .seal_separate_out_of_place_uninit(
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

    for tag_len in [alg.tag_len() - 1, alg.tag_len() + 1] {
        let mut ciphertext = vec![MaybeUninit::<u8>::uninit(); 64];
        let mut bad_tag = vec![MaybeUninit::<u8>::uninit(); tag_len];
        assert!(
            key_for(alg)
                .seal_separate_out_of_place_uninit(
                    nonce(),
                    Aad::empty(),
                    &plaintext,
                    &mut ciphertext,
                    &[],
                    &mut bad_tag
                )
                .is_err(),
            "a {tag_len}-byte tag buffer should be refused"
        );
    }
}

#[test]
fn uninit_variant_matches_the_initialised_one() {
    for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        for len in [0usize, 1, 17, 1024, 16384] {
            let plaintext = pattern(len);
            let aad = [0x17u8, 0x03, 0x03, 0x40, 0x11];
            let extra_in = [23u8]; // a TLS 1.3 inner content type

            let mut ct_a = vec![UNWRITTEN; len];
            let mut tail_a = vec![UNWRITTEN; extra_in.len() + alg.tag_len()];
            key_for(alg)
                .seal_separate_out_of_place(
                    nonce(),
                    Aad::from(aad),
                    &plaintext,
                    &mut ct_a,
                    &extra_in,
                    &mut tail_a,
                )
                .unwrap();
            if len > 0 {
                assert_ne!(ct_a, plaintext, "output should be encrypted at len={len}");
            }

            let mut ct_b = vec![MaybeUninit::<u8>::uninit(); len];
            let mut tail_b = vec![MaybeUninit::<u8>::uninit(); extra_in.len() + alg.tag_len()];
            let (ct_b, tail_b) = key_for(alg)
                .seal_separate_out_of_place_uninit(
                    nonce(),
                    Aad::from(aad),
                    &plaintext,
                    &mut ct_b,
                    &extra_in,
                    &mut tail_b,
                )
                .unwrap();

            assert_eq!(ct_a, ct_b, "ciphertext differs at len={len}");
            assert_eq!(tail_a, tail_b, "extra+tag differs at len={len}");
        }
    }
}

#[test]
fn a_caller_with_an_uninit_array_gets_usable_slices_back() {
    const N: usize = 1024;
    let alg = &AES_128_GCM;
    let plaintext = pattern(N);

    // Never zeroed. The cipher is the only thing that writes here.
    let mut ct_buf = [MaybeUninit::<u8>::uninit(); N];
    let mut tail_buf = [MaybeUninit::<u8>::uninit(); 1 + 16];

    let (ciphertext, extra_and_tag) = key_for(alg)
        .seal_separate_out_of_place_uninit(
            nonce(),
            Aad::empty(),
            &plaintext,
            &mut ct_buf,
            &[23],
            &mut tail_buf,
        )
        .unwrap();

    // Both are plain `&mut [u8]` -- readable, writable, no assume_init in sight.
    assert_eq!(ciphertext.len(), N);
    assert_eq!(extra_and_tag.len(), 1 + alg.tag_len());
    assert_ne!(&ciphertext[..8], &plaintext[..8], "should be encrypted");

    // And they decrypt, which is the real proof the bytes were written.
    let mut sealed = ciphertext.to_vec();
    sealed.extend_from_slice(extra_and_tag);
    let opened = key_for(alg)
        .open_in_place(nonce(), Aad::empty(), &mut sealed)
        .unwrap();
    assert_eq!(&opened[..N], &plaintext[..]);
    assert_eq!(opened[N], 23, "the extra_in byte round-trips");
}

#[test]
fn append_writes_the_same_bytes_as_the_separate_form() {
    for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        for len in [0usize, 1, 17, 1024, 16384] {
            let plaintext = pattern(len);
            let aad = [0x17u8, 0x03, 0x03, 0x40, 0x11];
            let extra_in = [23u8]; // a TLS 1.3 inner content type

            let mut expected = vec![UNWRITTEN; len];
            let mut expected_tail = vec![UNWRITTEN; extra_in.len() + alg.tag_len()];
            key_for(alg)
                .seal_separate_out_of_place(
                    nonce(),
                    Aad::from(aad),
                    &plaintext,
                    &mut expected,
                    &extra_in,
                    &mut expected_tail,
                )
                .unwrap();
            expected.extend_from_slice(&expected_tail);

            let mut out = Vec::new();
            key_for(alg)
                .seal_out_of_place_append(nonce(), Aad::from(aad), &plaintext, &extra_in, &mut out)
                .unwrap();

            assert_eq!(out, expected, "appended output differs at len={len}");
        }
    }
}

#[test]
fn append_preserves_an_existing_prefix_and_reuses_capacity() {
    let alg = &AES_128_GCM;
    let plaintext = pattern(512);
    let header = [0x17u8, 0x03, 0x03, 0x02, 0x11]; // a TLS record header

    // A recycled buffer: filled by a previous, longer record and then truncated back to
    // just the header, so its spare capacity really does hold stale bytes. Building it
    // that way is the point -- sealing must overwrite every byte it reports, with no
    // stale byte surviving inside the region the caller is handed back.
    let mut out = vec![0xEEu8; 4096];
    out.truncate(0);
    out.extend_from_slice(&header);
    let capacity_before = out.capacity();

    key_for(alg)
        .seal_out_of_place_append(nonce(), Aad::empty(), &plaintext, &[23], &mut out)
        .unwrap();

    assert_eq!(&out[..header.len()], &header[..], "prefix was clobbered");
    assert_eq!(
        out.len(),
        header.len() + plaintext.len() + 1 + alg.tag_len()
    );
    assert_eq!(
        out.capacity(),
        capacity_before,
        "should have used the spare capacity rather than reallocating"
    );

    let mut sealed = out[header.len()..].to_vec();
    let opened = key_for(alg)
        .open_in_place(nonce(), Aad::empty(), &mut sealed)
        .unwrap();
    assert_eq!(&opened[..plaintext.len()], &plaintext[..]);
    assert_eq!(opened[plaintext.len()], 23, "the extra_in byte round-trips");
}
