// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

extern crate core;

use aws_lc_rs::{aead, error, test};

use aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
    AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use aws_lc_rs::test::from_hex;
use error::Unspecified;

struct NotANonce(Vec<u8>);

impl NotANonce {
    fn from(value: Vec<u8>) -> Self {
        NotANonce(value)
    }
}

impl NonceSequence for NotANonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce.copy_from_slice(&self.0[0..aead::NONCE_LEN]);
        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

struct AeadConfig {
    algorithm: &'static Algorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: String,
}

impl AeadConfig {
    fn new(algorithm: &'static Algorithm, key: &[u8], nonce: &[u8], aad: &str) -> AeadConfig {
        AeadConfig {
            algorithm,
            key: Vec::from(key),
            nonce: Vec::from(nonce),
            aad: String::from(aad),
        }
    }

    fn key(&self) -> UnboundKey {
        UnboundKey::new(self.algorithm, &self.key).unwrap()
    }
    fn aad(&self) -> Aad<String> {
        Aad::from(self.aad.clone())
    }
    fn nonce(&self) -> impl NonceSequence {
        NotANonce::from(self.nonce.clone())
    }
}

#[test]
fn test_aes_128_gcm() {
    let config = AeadConfig::new(
        &AES_128_GCM,
        &from_hex("d480429666d48b400633921c5407d1d1").unwrap(),
        &from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap(),
        std::str::from_utf8(&from_hex("").unwrap()).unwrap(),
    );
    let mut in_out = from_hex("").unwrap();
    test_aead_separate_in_place(&config, &mut in_out).unwrap();
    test_aead_append_within(&config, &in_out).unwrap();
}

#[test]
fn test_aes_256_gcm() {
    let config = AeadConfig::new(
        &AES_256_GCM,
        &from_hex("e5ac4a32c67e425ac4b143c83c6f161312a97d88d634afdf9f4da5bd35223f01").unwrap(),
        &from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap(),
        "123456789abcdef",
    );
    let mut in_out = from_hex("123456789abcdef0").unwrap();

    test_aead_separate_in_place(&config, &mut in_out).unwrap();
    test_aead_append_within(&config, &in_out).unwrap();
}

#[test]
fn test_chacha20_poly1305() {
    let config = AeadConfig::new(
        &CHACHA20_POLY1305,
        &from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap(),
        &from_hex("070000004041424344454647").unwrap(),
        "123456789abcdef",
    );
    let mut in_out = from_hex("123456789abcdef0").unwrap();

    #[cfg(feature = "alloc")]
    test_aead_separate_in_place(&config, &mut in_out).unwrap();
    test_aead_append_within(&config, &in_out).unwrap();
}

fn test_aead_separate_in_place(
    config: &AeadConfig,
    in_out: &mut Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut sealing_key = SealingKey::new(config.key(), config.nonce());
    let mut opening_key = OpeningKey::new(config.key(), config.nonce());

    println!("Sealing Key: {sealing_key:?}");
    println!("Opening Key: {opening_key:?}");

    let plaintext = in_out.clone();
    println!("Plaintext: {plaintext:?}");
    let tag = sealing_key
        .seal_in_place_separate_tag(config.aad(), in_out.as_mut_slice())
        .map_err(|x| x.to_string())?;

    let cipher_text = in_out.clone();
    println!("Ciphertext: {cipher_text:?}");
    if !plaintext.is_empty() {
        assert_ne!(plaintext, cipher_text);
    }
    println!("Tag: {:?}", tag.as_ref());

    in_out.extend(tag.as_ref());
    let result_plaintext = opening_key
        .open_in_place(config.aad(), in_out)
        .map_err(|x| x.to_string())?;

    assert_eq!(plaintext, result_plaintext);

    println!("Roundtrip: {result_plaintext:?}");

    Ok(Vec::from(result_plaintext))
}

fn test_aead_append_within(config: &AeadConfig, in_out: &[u8]) -> Result<Vec<u8>, String> {
    let mut sealing_key = SealingKey::new(config.key(), config.nonce());
    let mut opening_key = OpeningKey::new(config.key(), config.nonce());

    println!("Sealing Key: {sealing_key:?}");
    println!("Opening Key: {opening_key:?}");

    let plaintext = in_out.to_owned();
    println!("Plaintext: {plaintext:?}");
    let mut sized_in_out = in_out.to_vec();
    #[allow(deprecated)]
    sealing_key
        .seal_in_place(config.aad(), &mut sized_in_out)
        .map_err(|x| x.to_string())?;

    let (cipher_text, tag_value) = sized_in_out.split_at_mut(plaintext.len());

    if !plaintext.is_empty() {
        assert_ne!(plaintext, cipher_text);
    }
    println!("Ciphertext: {cipher_text:?}");
    println!("Tag: {tag_value:?}");

    let result_plaintext = opening_key
        .open_within(config.aad(), &mut sized_in_out, 0..)
        .map_err(|x| x.to_string())?;

    assert_eq!(plaintext, result_plaintext);

    println!("Roundtrip: {result_plaintext:?}");

    Ok(Vec::from(result_plaintext))
}

#[test]
fn test_types() {
    test::compile_time_assert_send::<Algorithm>();
    test::compile_time_assert_sync::<Algorithm>();
    test::compile_time_assert_eq::<Algorithm>();

    test::compile_time_assert_send::<SealingKey<NotANonce>>();
    test::compile_time_assert_sync::<SealingKey<NotANonce>>();

    test::compile_time_assert_send::<OpeningKey<NotANonce>>();
    test::compile_time_assert_sync::<OpeningKey<NotANonce>>();
}

/*
}}}

mod test_aead {
    test_aead!(ring);
    test_aead!(aws_lc_rs);
}
*/
