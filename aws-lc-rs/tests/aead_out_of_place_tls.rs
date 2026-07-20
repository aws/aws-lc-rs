// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// TlsRecordSealingKey wraps different C constructions per protocol version and tracks a
// nonce counter across calls, so the out-of-place entry points need coverage of their
// own rather than inheriting it from the LessSafeKey tests.
//
// This file is `#![forbid(unsafe_code)]` for the same reason as aead_out_of_place.rs:
// the claim that these APIs need no caller-side `unsafe` is enforced, not asserted.
#![forbid(unsafe_code)]

use std::mem::MaybeUninit;

use aws_lc_rs::aead::{
    Aad, Algorithm, Nonce, TlsProtocolId, TlsRecordOpeningKey, TlsRecordSealingKey, AES_128_GCM,
    AES_256_GCM,
};

const KEY: [u8; 32] = [0x42u8; 32];

/// The AEAD algorithms and TLS versions `TlsRecordSealingKey` accepts. TLS 1.2 and
/// TLS 1.3 reach different C functions with different nonce handling, so every entry
/// point is exercised over the whole matrix rather than one representative cell.
const MATRIX: [(&Algorithm, TlsProtocolId); 4] = [
    (&AES_128_GCM, TlsProtocolId::TLS12),
    (&AES_128_GCM, TlsProtocolId::TLS13),
    (&AES_256_GCM, TlsProtocolId::TLS12),
    (&AES_256_GCM, TlsProtocolId::TLS13),
];

fn sealing_key(alg: &'static Algorithm, protocol: TlsProtocolId) -> TlsRecordSealingKey {
    TlsRecordSealingKey::new(alg, protocol, &KEY[..alg.key_len()]).unwrap()
}

fn opening_key(alg: &'static Algorithm, protocol: TlsProtocolId) -> TlsRecordOpeningKey {
    TlsRecordOpeningKey::new(alg, protocol, &KEY[..alg.key_len()]).unwrap()
}

fn nonce(counter: u32) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[8..].copy_from_slice(&counter.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

/// A repeatable, non-uniform byte pattern, so a byte written at the wrong offset shows
/// up as a mismatch rather than being masked by a run of identical bytes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("i % 251 fits in a u8"))
        .collect()
}

/// A byte no algorithm here will produce for a whole buffer, so a buffer the cipher
/// never touched is distinguishable from one it filled.
const UNWRITTEN: u8 = 0xAA;

#[test]
fn out_of_place_matches_in_place() {
    for (alg, protocol) in MATRIX {
        for len in [0usize, 1, 17, 1024, 16384] {
            let plaintext = pattern(len);
            let aad = [0x17u8, 0x03, 0x03, 0x40, 0x11];

            let mut in_place = plaintext.clone();
            let expected_tag = sealing_key(alg, protocol)
                .seal_in_place_separate_tag(nonce(1), Aad::from(aad), &mut in_place)
                .unwrap();

            let mut ciphertext = vec![UNWRITTEN; len];
            let mut tag_out = vec![UNWRITTEN; alg.tag_len()];
            sealing_key(alg, protocol)
                .seal_separate_out_of_place(
                    nonce(1),
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
fn uninit_variant_matches_the_initialised_one() {
    for (alg, protocol) in MATRIX {
        let plaintext = pattern(1024);
        let aad = [0x17u8, 0x03, 0x03, 0x04, 0x11];
        let extra_in = [23u8]; // a TLS 1.3 inner content type

        let mut ct_a = vec![UNWRITTEN; plaintext.len()];
        let mut tail_a = vec![UNWRITTEN; extra_in.len() + alg.tag_len()];
        sealing_key(alg, protocol)
            .seal_separate_out_of_place(
                nonce(7),
                Aad::from(aad),
                &plaintext,
                &mut ct_a,
                &extra_in,
                &mut tail_a,
            )
            .unwrap();
        assert_ne!(ct_a, plaintext, "output should be encrypted");

        let mut ct_b = vec![MaybeUninit::<u8>::uninit(); plaintext.len()];
        let mut tail_b = vec![MaybeUninit::<u8>::uninit(); extra_in.len() + alg.tag_len()];
        let (ct_b, tail_b) = sealing_key(alg, protocol)
            .seal_separate_out_of_place_uninit(
                nonce(7),
                Aad::from(aad),
                &plaintext,
                &mut ct_b,
                &extra_in,
                &mut tail_b,
            )
            .unwrap();

        assert_eq!(ct_a, ct_b);
        assert_eq!(tail_a, tail_b);
    }
}

#[test]
fn an_appended_record_decrypts_with_its_inner_content_type() {
    for (alg, protocol) in MATRIX {
        let plaintext = pattern(4096);
        let aad = [0x17u8, 0x03, 0x03, 0x10, 0x11];
        let extra_in = [23u8]; // a TLS 1.3 inner content type

        let mut record = Vec::new();
        sealing_key(alg, protocol)
            .seal_out_of_place_append(nonce(3), Aad::from(aad), &plaintext, &extra_in, &mut record)
            .unwrap();
        assert_eq!(
            record.len(),
            plaintext.len() + extra_in.len() + alg.tag_len()
        );

        let opened = opening_key(alg, protocol)
            .open_in_place(nonce(3), Aad::from(aad), &mut record)
            .unwrap();

        assert_eq!(&opened[..plaintext.len()], &plaintext[..]);
        assert_eq!(
            opened[plaintext.len()],
            23,
            "the extra_in byte must be encrypted and authenticated too"
        );
    }
}

#[test]
fn append_writes_the_same_bytes_as_the_separate_form() {
    for (alg, protocol) in MATRIX {
        let plaintext = pattern(4096);
        let aad = [0x17u8, 0x03, 0x03, 0x10, 0x11];
        let extra_in = [23u8];

        let mut expected = vec![UNWRITTEN; plaintext.len()];
        let mut expected_tail = vec![UNWRITTEN; extra_in.len() + alg.tag_len()];
        sealing_key(alg, protocol)
            .seal_separate_out_of_place(
                nonce(3),
                Aad::from(aad),
                &plaintext,
                &mut expected,
                &extra_in,
                &mut expected_tail,
            )
            .unwrap();
        expected.extend_from_slice(&expected_tail);

        let header = [0x17u8, 0x03, 0x03, 0x10, 0x11]; // a TLS record header
        let mut out = header.to_vec();
        sealing_key(alg, protocol)
            .seal_out_of_place_append(nonce(3), Aad::from(aad), &plaintext, &extra_in, &mut out)
            .unwrap();

        assert_eq!(&out[..header.len()], &header[..], "prefix was clobbered");
        assert_eq!(&out[header.len()..], &expected[..]);
    }
}

#[test]
fn the_out_of_place_path_shares_the_in_place_nonce_counter() {
    // The TLS constructions require monotonically increasing nonces per key. A caller
    // must not be able to replay a nonce by switching between the in-place and
    // out-of-place entry points, so the two have to advance one shared counter.
    for (alg, protocol) in MATRIX {
        let mut key = sealing_key(alg, protocol);
        let plaintext = pattern(32);

        let mut in_place = plaintext.clone();
        let _tag = key
            .seal_in_place_separate_tag(nonce(5), Aad::empty(), &mut in_place)
            .unwrap();

        let mut ciphertext = vec![UNWRITTEN; plaintext.len()];
        let mut tag_out = vec![UNWRITTEN; alg.tag_len()];
        assert!(
            key.seal_separate_out_of_place(
                nonce(5),
                Aad::empty(),
                &plaintext,
                &mut ciphertext,
                &[],
                &mut tag_out,
            )
            .is_err(),
            "replaying nonce 5 out-of-place after using it in-place must be refused"
        );

        // EVP_AEAD_CTX_seal_scatter scrubs the output buffers whenever it returns
        // failure, so that a caller who ignores the return value cannot transmit
        // whatever was there before. The buffers are therefore zeroed rather than left
        // at UNWRITTEN, and asserting that here keeps the scrub from being dropped
        // silently.
        assert!(
            ciphertext.iter().all(|&b| b == 0),
            "a refused seal must scrub the output buffer"
        );
        assert!(
            tag_out.iter().all(|&b| b == 0),
            "a refused seal must scrub the tag buffer"
        );

        // The appending entry point shares the same counter, so it must refuse the
        // replay too -- and must leave `out` exactly as it found it.
        let mut out = b"record header".to_vec();
        let len_before = out.len();
        assert!(
            key.seal_out_of_place_append(nonce(5), Aad::empty(), &plaintext, &[], &mut out)
                .is_err(),
            "replaying nonce 5 through the appending form must be refused"
        );
        assert_eq!(
            out.len(),
            len_before,
            "a refused append must not grow the output"
        );
        assert_eq!(
            &out[..],
            b"record header",
            "a refused append must not alter it"
        );

        // A higher nonce on the same key is still accepted, so the rejections above were
        // the counter doing its job rather than the key being poisoned.
        key.seal_separate_out_of_place(
            nonce(6),
            Aad::empty(),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag_out,
        )
        .unwrap();
    }
}

#[test]
fn wrong_buffer_lengths_are_refused() {
    let alg = &AES_128_GCM;
    let plaintext = vec![0u8; 64];
    let mut tag = vec![0u8; alg.tag_len()];

    for ciphertext_len in [63usize, 65] {
        let mut ciphertext = vec![0u8; ciphertext_len];
        assert!(
            sealing_key(alg, TlsProtocolId::TLS13)
                .seal_separate_out_of_place(
                    nonce(1),
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
            sealing_key(alg, TlsProtocolId::TLS13)
                .seal_separate_out_of_place(
                    nonce(1),
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
