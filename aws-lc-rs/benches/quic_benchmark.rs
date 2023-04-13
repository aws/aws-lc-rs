// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};

#[derive(Debug)]
pub enum QuicAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

pub struct QuicConfig {
    algorithm: QuicAlgorithm,
    key: Vec<u8>,
    sample: Vec<u8>,
    description: String,
}

impl QuicConfig {
    #[must_use]
    pub fn new(
        algorithm: QuicAlgorithm,
        key: &[u8],
        sample: &[u8],
        description: &str,
    ) -> QuicConfig {
        QuicConfig {
            algorithm,
            key: Vec::from(key),
            sample: Vec::from(sample),
            description: String::from(description),
        }
    }
}
macro_rules! benchmark_quic
{( $pkg:ident ) =>
{
    paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::aead;
            use aead::quic;
            use criterion::black_box;

            fn algorithm(config: &crate::QuicConfig) -> &'static quic::Algorithm {
                black_box(match &config.algorithm {
                    crate::QuicAlgorithm::Aes128Gcm => &quic::AES_128,
                    crate::QuicAlgorithm::Aes256Gcm => &quic::AES_256,
                    crate::QuicAlgorithm::Chacha20 => &quic::CHACHA20,
                })
            }

            pub fn header_protection_key(config: &crate::QuicConfig) -> quic::HeaderProtectionKey {
                let algorithm = algorithm(config);
                quic::HeaderProtectionKey::new(algorithm, config.key.as_slice()).unwrap()
            }

            pub fn new_mask(key: &quic::HeaderProtectionKey, sample: &[u8]) {
                key.new_mask(sample).unwrap();
            }
        }
}}}

benchmark_quic!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_quic!(ring);

fn test_new_mask(c: &mut Criterion, config: &QuicConfig) {
    let sample = config.sample.as_slice();

    let bench_group_name = format!(
        "QUIC-{:?}-new-mask-{}-{}-bytes",
        config.algorithm,
        config.description,
        sample.len()
    );
    let mut group = c.benchmark_group(bench_group_name);

    let aws_key = aws_lc_rs_benchmarks::header_protection_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_rs_benchmarks::new_mask(&aws_key, sample);
        });
    });

    #[cfg(feature = "ring-benchmarks")]
    {
        let ring_key = ring_benchmarks::header_protection_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::new_mask(&ring_key, sample);
            });
        });
    }
}

fn test_aes_128(c: &mut Criterion) {
    test::run(
        test_file!("data/quic_aes_128_benchmarks.txt"),
        |_section, test_case| {
            let config = QuicConfig::new(
                QuicAlgorithm::Aes128Gcm,
                test_case.consume_bytes("KEY").as_slice(),
                test_case.consume_bytes("SAMPLE").as_slice(),
                test_case.consume_string("DESC").as_str(),
            );
            test_new_mask(c, &config);
            Ok(())
        },
    );
}
fn test_aes_256(c: &mut Criterion) {
    test::run(
        test_file!("data/quic_aes_256_benchmarks.txt"),
        |_section, test_case| {
            let config = QuicConfig::new(
                QuicAlgorithm::Aes256Gcm,
                test_case.consume_bytes("KEY").as_slice(),
                test_case.consume_bytes("SAMPLE").as_slice(),
                test_case.consume_string("DESC").as_str(),
            );
            test_new_mask(c, &config);
            Ok(())
        },
    );
}
fn test_chacha20(c: &mut Criterion) {
    test::run(
        test_file!("data/quic_chacha20_benchmarks.txt"),
        |_section, test_case| {
            let config = QuicConfig::new(
                QuicAlgorithm::Chacha20,
                test_case.consume_bytes("KEY").as_slice(),
                test_case.consume_bytes("SAMPLE").as_slice(),
                test_case.consume_string("DESC").as_str(),
            );
            test_new_mask(c, &config);
            Ok(())
        },
    );
}

criterion_group!(benches, test_aes_128, test_aes_256, test_chacha20);
criterion_main!(benches);
