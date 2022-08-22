// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use paste::*;

pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err(String::from(
            "Hex string does not have an even number of digits",
        ));
    }

    let mut result = Vec::with_capacity(hex_str.len() / 2);
    for digits in hex_str.as_bytes().chunks(2) {
        let hi = from_hex_digit(digits[0])?;
        let lo = from_hex_digit(digits[1])?;
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

fn from_hex_digit(d: u8) -> Result<u8, String> {
    use core::ops::RangeInclusive;
    const DECIMAL: (u8, RangeInclusive<u8>) = (0, b'0'..=b'9');
    const HEX_LOWER: (u8, RangeInclusive<u8>) = (10, b'a'..=b'f');
    const HEX_UPPER: (u8, RangeInclusive<u8>) = (10, b'A'..=b'F');
    for (offset, range) in &[DECIMAL, HEX_LOWER, HEX_UPPER] {
        if range.contains(&d) {
            return Ok(d - range.start() + offset);
        }
    }
    Err(format!("Invalid hex digit '{}'", d as char))
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

    impl crate::AeadConfig {

        fn [<algorithm_ $pkg>] (&self) -> &'static aead::Algorithm {
            match &self.algorithm {
                MY_AES_128_GCM => &aead::AES_128_GCM,
                MY_AES_256_GCM => &aead::AES_256_GCM,
                MY_CHACHA20_POLY1305 => &aead::CHACHA20_POLY1305,
            }
        }

        fn [<key_ $pkg>] (&self) -> UnboundKey {
            UnboundKey::new(self.[<algorithm_ $pkg>](), &self.key).unwrap()
        }
        fn [<aad_ $pkg>] (&self) -> Aad<String> {
            Aad::from(self.aad.clone())
        }
        fn [<nonce_ $pkg>] (&self) -> impl NonceSequence {
            //RngNonce{}
            //NotANonce::new()
            NotANonce::from(self.nonce.clone())
        }
    }



    pub fn test_aead_separate_in_place( config: &AeadConfig, in_out: &mut Vec<u8> )  {
        let mut sealing_key = SealingKey::new(config.[<key_ $pkg>](), config.[<nonce_ $pkg>]());
        let mut opening_key = OpeningKey::new(config.[<key_ $pkg>](), config.[<nonce_ $pkg>]());

        let plaintext = in_out.clone();
        let tag = sealing_key
            .seal_in_place_separate_tag(config.[<aad_ $pkg>](), in_out.as_mut_slice())
            .map_err(|x| x.to_string()).unwrap();

        let cipher_text = in_out.clone();
        if !plaintext.is_empty() {
            assert_ne!(plaintext, cipher_text);
        }
        let raw_tag = &tag as *const Tag as *const u8;
        let tag_value = unsafe { slice::from_raw_parts(raw_tag, 16) };

        in_out.extend(tag.as_ref());
        let result_plaintext = opening_key
            .open_in_place(config.[<aad_ $pkg>](), in_out)
            .map_err(|x| x.to_string()).unwrap();
    }

    pub fn test_aead_append_within(config: &AeadConfig, in_out: &mut Vec<u8>) {
        let mut sealing_key = SealingKey::new(config.[<key_ $pkg>](), config.[<nonce_ $pkg>]());
        let mut opening_key = OpeningKey::new(config.[<key_ $pkg>](), config.[<nonce_ $pkg>]());


        let plaintext = in_out.clone();
        let mut sized_in_out = in_out.to_vec();
        sealing_key
            .seal_in_place_append_tag(config.[<aad_ $pkg>](), &mut sized_in_out)
            .map_err(|x| x.to_string()).unwrap();

        let (cipher_text, tag_value) = sized_in_out.split_at_mut(plaintext.len());

        if !plaintext.is_empty() {
            assert_ne!(plaintext, cipher_text);
        }

        let result_plaintext = opening_key
            .open_within(config.[<aad_ $pkg>](), &mut sized_in_out, 0..)
            .map_err(|x| x.to_string()).unwrap();
    }

}
}}}

benchmark_aead!(ring);
benchmark_aead!(aws_lc_ring_facade);

fn test_aes_128_gcm(c: &mut Criterion) {
    let config = AeadConfig::new(
        AeadAlgorithm::MY_AES_128_GCM,
        &from_hex("d480429666d48b400633921c5407d1d1").unwrap(),
        &from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap(),
        std::str::from_utf8(&from_hex("").unwrap()).unwrap(),
    );
    let mut in_out = from_hex("").unwrap();
    c.bench_function("rust-AES_128_GCM-separate: empty input", |b| {
        b.iter(|| {
            ring_benchmarks::test_aead_separate_in_place(&config, &mut in_out);
        })
    });
    c.bench_function("aws-lc-AES_128_GCM-separate: empty input", |b| {
        b.iter(|| {
            aws_lc_ring_facade_benchmarks::test_aead_separate_in_place(&config, &mut in_out);
        })
    });
    c.bench_function("rust-AES_128_GCM-append: empty input", |b| {
        b.iter(|| {
            ring_benchmarks::test_aead_append_within(&config, &mut in_out);
        })
    });
    c.bench_function("aws-lc-AES_128_GCM-append: empty input", |b| {
        b.iter(|| {
            aws_lc_ring_facade_benchmarks::test_aead_append_within(&config, &mut in_out);
        })
    });
}

criterion_group!(benches, test_aes_128_gcm);
criterion_main!(benches);
