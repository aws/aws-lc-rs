// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};
use hex::*;

pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    <Vec<u8>>::from_hex(hex_str).map_err(|e| String::from("Oops"))
}

pub enum AeadAlgorithm {
    MY_AES_128_GCM,
    MY_AES_256_GCM,
    MY_CHACHA20_POLY1305,
}

pub struct AeadConfig {
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: String,
}

impl AeadConfig {
    pub fn new(algorithm: AeadAlgorithm, key: &[u8], nonce: &[u8], aad: &str) -> AeadConfig {
        AeadConfig {
            algorithm,
            key: Vec::from(key),
            nonce: Vec::from(nonce),
            aad: String::from(aad),
        }
    }
}

macro_rules! benchmark_aead
{( $pkg:ident ) =>
{
    paste::item! {
mod [<$pkg _benchmarks>]  {
    use criterion::black_box;
    use crate::AeadConfig;
    use $pkg::{aead, error, test};
    use aead::{
        Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, Tag, UnboundKey,
        AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
    };
    use error::Unspecified;
    use std::slice;

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

    fn algorithm(config: &crate::AeadConfig) ->  &'static aead::Algorithm {
        black_box(match &config.algorithm {
            MY_AES_128_GCM => &aead::AES_128_GCM,
            MY_AES_256_GCM => &aead::AES_256_GCM,
            MY_CHACHA20_POLY1305 => &aead::CHACHA20_POLY1305,
        })
    }

    fn key(config: &crate::AeadConfig) -> UnboundKey {
       black_box(UnboundKey::new(algorithm(config), &config.key).unwrap())
    }

    fn aad(config: &crate::AeadConfig) -> Aad<String> {
        black_box(Aad::from(config.aad.clone()))
    }

    fn nonce(config: &crate::AeadConfig) -> impl NonceSequence {
       black_box(NotANonce::from(config.nonce.clone()))
    }

    pub fn test_aead_separate_in_place( config: &AeadConfig, in_out: &mut Vec<u8> )  {
        let mut sealing_key = SealingKey::new(key(&config), nonce(&config));
        let mut opening_key = OpeningKey::new(key(&config), nonce(&config));

        let plaintext = in_out.clone();
        let tag = sealing_key
            .seal_in_place_separate_tag(aad(&config), in_out.as_mut_slice())
            .map_err(|x| x.to_string()).unwrap();

        let cipher_text = in_out.clone();
        let raw_tag = &tag as *const Tag as *const u8;
        let tag_value = unsafe { slice::from_raw_parts(raw_tag, 16) };

        in_out.extend(tag.as_ref());
        let result_plaintext = opening_key
            .open_in_place(aad(&config), in_out)
            .map_err(|x| x.to_string()).unwrap();
    }

    pub fn test_aead_append_within(config: &AeadConfig, in_out: &mut Vec<u8>) {
        let mut sealing_key = SealingKey::new(key(&config), nonce(&config));
        let mut opening_key = OpeningKey::new(key(&config), nonce(&config));

        let plaintext = in_out.clone();
        let mut sized_in_out = in_out.to_vec();
        sealing_key
            .seal_in_place_append_tag(aad(&config), &mut sized_in_out)
            .map_err(|x| x.to_string()).unwrap();

        let (cipher_text, tag_value) = sized_in_out.split_at_mut(plaintext.len());

        let result_plaintext = opening_key
            .open_within(aad(&config), &mut sized_in_out, 0..)
            .map_err(|x| x.to_string()).unwrap();
    }

}
}}}

benchmark_aead!(ring);
benchmark_aead!(aws_lc_ring_facade);

fn test_aes_128_gcm_small_separate(c: &mut Criterion) {
    let config = AeadConfig::new(
        AeadAlgorithm::MY_AES_128_GCM,
        &from_hex("d480429666d48b400633921c5407d1d1").unwrap(),
        &from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap(),
        "aad value",
    );
    let mut in_out = from_hex("0a2714aa7d").unwrap();
    c.bench_function("ring-AES_128_GCM-separate: small input", |b| {
        b.iter(|| {
            ring_benchmarks::test_aead_separate_in_place(&config, &mut in_out);
        })
    });
    c.bench_function("aws-lc-AES_128_GCM-separate: small input", |b| {
        b.iter(|| {
            aws_lc_ring_facade_benchmarks::test_aead_separate_in_place(&config, &mut in_out);
        })
    });
}

fn test_aes_128_gcm_small_append(c: &mut Criterion) {
    let config = AeadConfig::new(
        AeadAlgorithm::MY_AES_128_GCM,
        &from_hex("d480429666d48b400633921c5407d1d1").unwrap(),
        &from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap(),
        "aad value",
    );
    let mut in_out = from_hex("0a2714aa7d").unwrap();
    c.bench_function("ring-AES_128_GCM-append: small input", |b| {
        b.iter(|| {
            ring_benchmarks::test_aead_append_within(&config, &mut in_out);
        })
    });

    c.bench_function("aws-lc-AES_128_GCM-append: small input", |b| {
        b.iter(|| {
            aws_lc_ring_facade_benchmarks::test_aead_append_within(&config, &mut in_out);
        })
    });
}

criterion_group!(
    benches,
    test_aes_128_gcm_small_separate,
    test_aes_128_gcm_small_append
);
criterion_main!(benches);
