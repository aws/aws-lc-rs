// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::test::from_hex;

use aws_lc_rs::aead;

#[test]
fn test_openssh() {
    let key_bytes: [u8; aead::chacha20_poly1305_openssh::KEY_LEN] =
        from_hex("247a041f6780baf0de3741aa4436024b6a5169b0eab8a090a291f5900bf566a54ac2c64c0f38cab14a143111bc39d1873013f52f2e92062e375c1a5378ad9b32").unwrap().try_into().unwrap();
    let plaintext = from_hex("000000100f000000000000000000000000000000").unwrap();
    let sequence_num = 94;
    let ciphertext = from_hex("c87186a24d89e672f37df98a95d0a0653e9f0fe4").unwrap();
    let expected_tag = from_hex("075bc727e855c8d487bb3060c42267cd").unwrap();

    let mut tag = [0u8; aead::chacha20_poly1305_openssh::TAG_LEN];
    let mut s_in_out = plaintext.clone();

    let s_key = aead::chacha20_poly1305_openssh::SealingKey::new(&key_bytes);
    s_key.seal_in_place(sequence_num, &mut s_in_out[..], &mut tag);
    assert_eq!(&ciphertext, &s_in_out);
    assert_eq!(&expected_tag, &tag);
    let o_key = aead::chacha20_poly1305_openssh::OpeningKey::new(&key_bytes);

    {
        let o_result = o_key.open_in_place(sequence_num, &mut s_in_out[..], &tag);
        assert_eq!(o_result, Ok(&plaintext[4..]));
    }
    assert_eq!(&s_in_out[..4], &ciphertext[..4]);
    assert_eq!(&s_in_out[4..], &plaintext[4..]);
}
