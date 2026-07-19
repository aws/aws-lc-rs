// SPIKE: out-of-place sealing must be bit-identical to the in-place path, or it is
// not the same cipher and nothing downstream can trust it.
use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

fn key_for(alg: &'static Algorithm) -> LessSafeKey {
    let key_bytes = vec![0x42u8; alg.key_len()];
    LessSafeKey::new(UnboundKey::new(alg, &key_bytes).unwrap())
}

fn nonce() -> Nonce {
    Nonce::assume_unique_for_key([0x24u8; 12])
}

#[test]
fn out_of_place_matches_in_place() {
    for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        for len in [0usize, 1, 15, 16, 17, 1024, 4096, 16384, 16385] {
            let plaintext = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let aad = [0x17u8, 0x03, 0x03, 0x40, 0x11];

            // Reference: seal in place, tag returned separately.
            let mut in_place = plaintext.clone();
            let expected_tag = key_for(alg)
                .seal_in_place_separate_tag(nonce(), Aad::from(aad), &mut in_place)
                .unwrap();

            // Spike: seal out of place, plaintext left alone.
            let mut ciphertext = vec![0u8; len];
            let mut tag_out = vec![0u8; alg.tag_len()];
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

            let untouched = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            assert_eq!(plaintext, untouched, "plaintext was mutated at len={len}");
        }
    }
}

#[test]
fn out_of_place_roundtrips_through_open() {
    let alg = &AES_128_GCM;
    let plaintext = b"the fused path must still decrypt".to_vec();
    let aad = [1u8, 2, 3];

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag_out = vec![0u8; alg.tag_len()];
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

    let mut short = vec![0u8; 63];
    let mut tag = vec![0u8; alg.tag_len()];
    assert!(key_for(alg)
        .seal_separate_out_of_place(nonce(), Aad::empty(), &plaintext, &mut short, &[], &mut tag)
        .is_err());

    let mut ct = vec![0u8; 64];
    let mut bad_tag = vec![0u8; alg.tag_len() - 1];
    assert!(key_for(alg)
        .seal_separate_out_of_place(
            nonce(),
            Aad::empty(),
            &plaintext,
            &mut ct,
            &[],
            &mut bad_tag
        )
        .is_err());
}

#[test]
fn uninit_variant_matches_the_initialised_one() {
    use std::mem::MaybeUninit;

    for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        for len in [0usize, 1, 17, 1024, 16384] {
            let plaintext = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let aad = [0x17u8, 0x03, 0x03, 0x40, 0x11];
            let extra_in = [23u8]; // a TLS 1.3 inner content type

            let mut ct_a = vec![0u8; len];
            let mut tail_a = vec![0u8; extra_in.len() + alg.tag_len()];
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

            let mut ct_b = vec![MaybeUninit::<u8>::uninit(); len];
            let mut tail_b = vec![MaybeUninit::<u8>::uninit(); extra_in.len() + alg.tag_len()];
            key_for(alg)
                .seal_separate_out_of_place_uninit(
                    nonce(),
                    Aad::from(aad),
                    &plaintext,
                    &mut ct_b,
                    &extra_in,
                    &mut tail_b,
                )
                .unwrap();

            // SAFETY: the call above reports success, so it wrote every byte.
            let ct_b: Vec<u8> = ct_b.iter().map(|b| unsafe { b.assume_init() }).collect();
            let tail_b: Vec<u8> = tail_b.iter().map(|b| unsafe { b.assume_init() }).collect();

            assert_eq!(ct_a, ct_b, "ciphertext differs at len={len}");
            assert_eq!(tail_a, tail_b, "extra+tag differs at len={len}");
        }
    }
}
