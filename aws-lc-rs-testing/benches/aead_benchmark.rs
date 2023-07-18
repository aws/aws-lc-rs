// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};

#[derive(Debug)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

pub struct AeadConfig {
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: String,
    in_out: Vec<u8>,
}

impl AeadConfig {
    #[must_use]
    pub fn new(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &str,
        in_out: &[u8],
    ) -> AeadConfig {
        AeadConfig {
            algorithm,
            key: Vec::from(key),
            nonce: Vec::from(nonce),
            aad: String::from(aad),
            in_out: Vec::from(in_out),
        }
    }
}
macro_rules! benchmark_aead
{( $pkg:ident ) =>
{
    paste::item! {
mod [<$pkg _benchmarks>]  {

    use $pkg::{aead, error};

    use criterion::black_box;
    use crate::AeadConfig;
    use aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, Tag, UnboundKey,
    };
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

    fn algorithm(config: &crate::AeadConfig) ->  &'static aead::Algorithm {
        black_box(match &config.algorithm {
            crate::AeadAlgorithm::Aes128Gcm => &aead::AES_128_GCM,
            crate::AeadAlgorithm::Aes256Gcm => &aead::AES_256_GCM,
            crate::AeadAlgorithm::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
        })
    }

    fn key(config: &crate::AeadConfig) -> UnboundKey {
       black_box(UnboundKey::new(algorithm(config), &config.key).unwrap())
    }

    fn nonce(config: &crate::AeadConfig) -> impl NonceSequence {
       black_box(NotANonce::from(config.nonce.clone()))
    }

    pub fn aad(config: &crate::AeadConfig) -> Aad<String> {
        black_box(Aad::from(config.aad.clone()))
    }

    pub fn create_sealing_key(config: &AeadConfig) -> SealingKey<impl NonceSequence> {
        SealingKey::new(key(&config), nonce(&config))
    }

    pub fn create_opening_key(config: &AeadConfig) -> OpeningKey<impl NonceSequence> {
        OpeningKey::new(key(&config), nonce(&config))
    }


    pub fn seal_separate(sealing_key: &mut SealingKey<impl NonceSequence>, aad: Aad<String>, in_out: &mut [u8]) -> Tag {
       sealing_key
            .seal_in_place_separate_tag(aad, in_out)
            .map_err(|x| x.to_string()).unwrap()
    }

    pub fn seal_append(sealing_key: &mut SealingKey<impl NonceSequence>, aad: Aad<String>, in_out: &mut Vec<u8>) {
       sealing_key
            .seal_in_place_append_tag(aad, in_out)
            .map_err(|x| x.to_string()).unwrap()
    }

    pub fn open(opening_key: &mut OpeningKey<impl NonceSequence>, aad: Aad<String>, in_out: &mut [u8]) {
       opening_key
            .open_in_place(aad, in_out)
            .map_err(|x| x.to_string()).unwrap();
    }

}
}}}

benchmark_aead!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_aead!(ring);

fn test_aes_128_gcm(c: &mut Criterion) {
    test::run(
        test_file!("data/aead_aes_128_gcm_benchmarks.txt"),
        |_section, test_case| {
            let config = AeadConfig::new(
                AeadAlgorithm::Aes128Gcm,
                test_case.consume_bytes("KEY").as_slice(),
                test_case.consume_bytes("NONCE").as_slice(),
                test_case.consume_string("AD").as_str(),
                test_case.consume_bytes("IN").as_slice(),
            );
            test_aead_separate(c, &config);
            test_aead_append(c, &config);
            test_aead_open(c, &config);
            Ok(())
        },
    );
}

fn test_aes_256_gcm(c: &mut Criterion) {
    test::run(
        test_file!("data/aead_aes_256_gcm_benchmarks.txt"),
        |_section, test_case| {
            let config = AeadConfig::new(
                AeadAlgorithm::Aes256Gcm,
                test_case.consume_bytes("KEY").as_slice(),
                test_case.consume_bytes("NONCE").as_slice(),
                test_case.consume_string("AD").as_str(),
                test_case.consume_bytes("IN").as_slice(),
            );
            test_aead_separate(c, &config);
            test_aead_append(c, &config);
            test_aead_open(c, &config);
            Ok(())
        },
    );
}

fn test_chacha20(c: &mut Criterion) {
    test::run(
        test_file!("data/aead_chacha20_poly1305_benchmarks.txt"),
        |_section, test_case| {
            let config = AeadConfig::new(
                AeadAlgorithm::Chacha20Poly1305,
                test_case.consume_bytes("KEY").as_slice(),
                test_case.consume_bytes("NONCE").as_slice(),
                test_case.consume_string("AD").as_str(),
                test_case.consume_bytes("IN").as_slice(),
            );
            test_aead_separate(c, &config);
            test_aead_append(c, &config);
            test_aead_open(c, &config);
            Ok(())
        },
    );
}

fn test_aead_separate(c: &mut Criterion, config: &AeadConfig) {
    let mut in_out = config.in_out.clone();

    let bench_group_name = format!(
        "AEAD-{:?}-separate-{}-bytes",
        config.algorithm,
        in_out.len()
    );
    let mut group = c.benchmark_group(bench_group_name);

    let mut aws_sealing_key = aws_lc_rs_benchmarks::create_sealing_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let aws_aad = aws_lc_rs_benchmarks::aad(config);
            let _tag =
                aws_lc_rs_benchmarks::seal_separate(&mut aws_sealing_key, aws_aad, &mut in_out);
        });
    });

    #[cfg(feature = "ring-benchmarks")]
    {
        let mut ring_sealing_key = ring_benchmarks::create_sealing_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                let ring_aad = ring_benchmarks::aad(config);
                let _tag =
                    ring_benchmarks::seal_separate(&mut ring_sealing_key, ring_aad, &mut in_out);
            });
        });
    }
}

fn test_aead_append(c: &mut Criterion, config: &AeadConfig) {
    let in_out = config.in_out.clone();

    let bench_group_name = format!("AEAD-{:?}-append-{}-bytes", config.algorithm, in_out.len());
    let mut group = c.benchmark_group(bench_group_name);

    let mut aws_sealing_key = aws_lc_rs_benchmarks::create_sealing_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let mut aws_in_out = in_out.clone();
            let aws_aad = aws_lc_rs_benchmarks::aad(config);
            aws_lc_rs_benchmarks::seal_append(&mut aws_sealing_key, aws_aad, &mut aws_in_out);
        });
    });

    #[cfg(feature = "ring-benchmarks")]
    {
        let mut ring_sealing_key = ring_benchmarks::create_sealing_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                let mut ring_in_out = in_out.clone();
                let ring_aad = ring_benchmarks::aad(config);
                ring_benchmarks::seal_append(&mut ring_sealing_key, ring_aad, &mut ring_in_out);
            });
        });
    }
}

fn test_aead_open(c: &mut Criterion, config: &AeadConfig) {
    let mut in_out = config.in_out.clone();

    let aws_aad = aws_lc_rs_benchmarks::aad(config);
    let mut aws_sealing_key = aws_lc_rs_benchmarks::create_sealing_key(config);
    aws_lc_rs_benchmarks::seal_append(&mut aws_sealing_key, aws_aad, &mut in_out);

    let bench_group_name = format!("AEAD-{:?}-open-{}-bytes", config.algorithm, in_out.len());
    let mut group = c.benchmark_group(bench_group_name);

    let mut aws_opening_key = aws_lc_rs_benchmarks::create_opening_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let mut aws_in_out = in_out.clone();
            let aws_aad = aws_lc_rs_benchmarks::aad(config);
            aws_lc_rs_benchmarks::open(&mut aws_opening_key, aws_aad, &mut aws_in_out);
        });
    });

    #[cfg(feature = "ring-benchmarks")]
    {
        let mut ring_opening_key = ring_benchmarks::create_opening_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                let mut ring_in_out = in_out.clone();
                let ring_aad = ring_benchmarks::aad(config);
                ring_benchmarks::open(&mut ring_opening_key, ring_aad, &mut ring_in_out);
            });
        });
    }
}

criterion_group!(benches, test_aes_128_gcm, test_aes_256_gcm, test_chacha20,);
criterion_main!(benches);
