// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::rsa::{
    Pkcs1PrivateDecryptingKey, Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
};
use openssl::rsa::{Padding, Rsa};

#[test]
fn rsa2048_pkcs1_openssl_interop() {
    const PKCS8_PRIVATE_KEY: &[u8] =
        include_bytes!("../../aws-lc-rs/tests/data/rsa_test_private_key_2048.p8");
    const RSA_PRIVATE_KEY: &[u8] =
        include_bytes!("../../aws-lc-rs/tests/data/rsa_test_private_key_2048.der");
    const PUBLIC_KEY: &[u8] =
        include_bytes!("../../aws-lc-rs/tests/data/rsa_test_public_key_2048.x509");
    const MESSAGE: &[u8] = b"OpenSSL KAT";

    let aws_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("public key");
    let aws_public_key = Pkcs1PublicEncryptingKey::new(aws_public_key).expect("public key");

    let mut ciphertext = vec![0u8; aws_public_key.ciphertext_size()];
    let ciphertext: &[u8] = aws_public_key
        .encrypt(MESSAGE, &mut ciphertext)
        .expect("encrypted");

    assert_ne!(MESSAGE, ciphertext);

    let ossl_private_key = Rsa::private_key_from_der(RSA_PRIVATE_KEY).expect("private key");

    let mut message = vec![0u8; ossl_private_key.size().try_into().expect("usize cast")];
    let message_len = ossl_private_key
        .private_decrypt(ciphertext, &mut message, Padding::PKCS1)
        .expect("decrypted");
    let message: &[u8] = &message[0..message_len];

    assert_eq!(MESSAGE, message);

    let aws_private_key = PrivateDecryptingKey::from_pkcs8(PKCS8_PRIVATE_KEY).expect("private key");
    let aws_private_key = Pkcs1PrivateDecryptingKey::new(aws_private_key).expect("private key");
    let ossl_public_key = Rsa::public_key_from_der(PUBLIC_KEY).expect("public key");

    let mut ciphertext = vec![0u8; ossl_public_key.size().try_into().expect("usize cast")];
    let ciphertext_len = ossl_public_key
        .public_encrypt(MESSAGE, &mut ciphertext, Padding::PKCS1)
        .expect("encrypted");
    let ciphertext: &[u8] = &ciphertext[0..ciphertext_len];

    assert_ne!(MESSAGE, ciphertext);

    let mut plaintext = vec![0u8; aws_private_key.min_output_size()];
    let plaintext: &[u8] = aws_private_key
        .decrypt(ciphertext, &mut plaintext)
        .expect("decrypted");

    assert_eq!(MESSAGE, plaintext);
}
