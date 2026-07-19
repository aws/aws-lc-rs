// Does the returning signature let a caller avoid `unsafe` entirely?
//
// This whole file is `#![forbid(unsafe_code)]`, so if it compiles, a caller can seal
// into an uninitialised buffer and use the result without writing any unsafe.
#![forbid(unsafe_code)]

use std::mem::MaybeUninit;

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

fn key() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &[0x42; 16]).unwrap())
}

#[test]
fn caller_with_an_uninit_array_needs_no_unsafe() {
    const N: usize = 1024;
    let plaintext = [0x5au8; N];

    // Never zeroed. The cipher is the only thing that writes here.
    let mut ct_buf = [MaybeUninit::<u8>::uninit(); N];
    let mut tail_buf = [MaybeUninit::<u8>::uninit(); 1 + 16];

    let (ciphertext, extra_and_tag) = key()
        .seal_separate_out_of_place_uninit(
            Nonce::assume_unique_for_key([0x24; 12]),
            Aad::empty(),
            &plaintext,
            &mut ct_buf,
            &[23],
            &mut tail_buf,
        )
        .unwrap();

    // Both are plain `&mut [u8]` -- readable, writable, no assume_init in sight.
    assert_eq!(ciphertext.len(), N);
    assert_eq!(extra_and_tag.len(), 1 + 16);
    assert_ne!(&ciphertext[..8], &plaintext[..8], "should be encrypted");

    // And they decrypt, which is the real proof the bytes were written.
    let mut sealed = ciphertext.to_vec();
    sealed.extend_from_slice(extra_and_tag);
    let opened = key()
        .open_in_place(
            Nonce::assume_unique_for_key([0x24; 12]),
            Aad::empty(),
            &mut sealed,
        )
        .unwrap();
    assert_eq!(&opened[..N], &plaintext[..]);
    assert_eq!(opened[N], 23, "the extra_in byte round-trips");
}

#[test]
fn the_returned_length_is_the_evidence_a_vec_caller_needs() {
    // A Vec caller still needs one `unsafe` for set_len -- Vec's length invariant is
    // unsafe to assert no matter how the bytes got there. But it is no longer
    // justified by trusting the FFI: it is justified by the length of the slice the
    // call handed back. This test only checks the arithmetic that justification rests
    // on, so it stays unsafe-free.
    const N: usize = 4096;
    let plaintext = [0x11u8; N];
    let mut ct_buf = [MaybeUninit::<u8>::uninit(); N];
    let mut tail_buf = [MaybeUninit::<u8>::uninit(); 1 + 16];

    let (ciphertext, extra_and_tag) = key()
        .seal_separate_out_of_place_uninit(
            Nonce::assume_unique_for_key([0x01; 12]),
            Aad::empty(),
            &plaintext,
            &mut ct_buf,
            &[23],
            &mut tail_buf,
        )
        .unwrap();

    let written = ciphertext.len() + extra_and_tag.len();
    assert_eq!(written, N + 1 + AES_128_GCM.tag_len());
}
