// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};

#[derive(Debug)]
pub enum HMACAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

pub struct HMACConfig {
    algorithm: HMACAlgorithm,
    description: String,
}

impl HMACConfig {
    pub fn new(algorithm: HMACAlgorithm, description: &str) -> HMACConfig {
        HMACConfig {
            algorithm,
            description: String::from(description),
        }
    }
}

// For SHA-{256, 384, 512, 512-256}, aws-lc-ring-facade hmac::sign one-shot Rust functions
// are around 20% slower on 16 bit inputs when benchmarked against Ring. The performance for
// 256-16394 bit inputs quickly jumps up and is completely on par with Ring. For SHA-1, AWS-LC is
// consistently 1-2 times faster on all input lengths.
// For the one-shot hmac::sign, we do not use the corresponding one-shot HMAC function available in
// AWS-LC. This is because we've moved HMAC_CTX initialization into the key construction phase,
// which significantly improves our HMAC Rust performance. hmac::sign for both aws-lc-ring-facade
// and ring call Context::update/Context::sign under the hood, so the performance for one-shot vs
// incremental should be relatively the same.
macro_rules! benchmark_hmac {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{hmac, digest};

            use criterion::black_box;
            use crate::HMACConfig;


            pub fn algorithm(config: &crate::HMACConfig) ->  hmac::Algorithm {
                black_box(match &config.algorithm {
                    crate::HMACAlgorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                    crate::HMACAlgorithm::SHA256 => hmac::HMAC_SHA256,
                    crate::HMACAlgorithm::SHA384 => hmac::HMAC_SHA384,
                    crate::HMACAlgorithm::SHA512 => hmac::HMAC_SHA512,
                })
            }

            pub fn create_hmac_key(config: &HMACConfig) -> hmac::Key {
                let key_length = match &config.algorithm {
                    crate::HMACAlgorithm::SHA1 => digest::SHA1_OUTPUT_LEN,
                    crate::HMACAlgorithm::SHA256 => digest::SHA256_OUTPUT_LEN,
                    crate::HMACAlgorithm::SHA384 => digest::SHA384_OUTPUT_LEN,
                    crate::HMACAlgorithm::SHA512 => digest::SHA512_OUTPUT_LEN,
                };
                let key_val = vec![123u8; key_length];
                hmac::Key::new(algorithm(&config), &key_val)
            }

            pub fn create_longer_hmac_key(config: &HMACConfig) -> hmac::Key {
                let key_length = match &config.algorithm {
                    crate::HMACAlgorithm::SHA1 => digest::SHA1_OUTPUT_LEN,
                    crate::HMACAlgorithm::SHA256 => digest::SHA256_OUTPUT_LEN,
                    crate::HMACAlgorithm::SHA384 => digest::SHA384_OUTPUT_LEN,
                    crate::HMACAlgorithm::SHA512 => digest::SHA512_OUTPUT_LEN,
                };
                let key_val = vec![123u8; key_length + 1];
                hmac::Key::new(algorithm(&config), &key_val)
            }

            pub fn run_hmac_incremental(key: &hmac::Key, chunk: &[u8]) {
                let mut s_ctx = hmac::Context::with_key(&key);
                s_ctx.update(chunk);
                s_ctx.sign();
            }

            pub fn run_hmac_one_shot(key: &hmac::Key, chunk: &[u8]) {
                hmac::sign(&key, chunk);
            }
        }
        }
    };
}

benchmark_hmac!(ring);
benchmark_hmac!(aws_lc_ring_facade);

fn bench_hmac_sha1(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA1, "HMAC SHA1");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
    bench_hmac_longer_key(c, &config);
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA256, "HMAC SHA256");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
    bench_hmac_longer_key(c, &config);
}

fn bench_hmac_sha384(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA384, "HMAC SHA384");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
    bench_hmac_longer_key(c, &config);
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA512, "HMAC SHA512");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
    bench_hmac_longer_key(c, &config);
}

const G_CHUNK_LENGTHS: [usize; 5] = [16, 256, 1350, 8192, 16384];

// Benchmark hmac::sign one-shot API.
fn bench_hmac_one_shot(c: &mut Criterion, config: &HMACConfig) {
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![123u8; chunk_len];

        let bench_group_name = format!(
            "HMAC-{:?}: {} ({} bytes) [one-shot]",
            config.algorithm, config.description, chunk_len
        );
        let mut group = c.benchmark_group(bench_group_name);

        let aws_key = aws_lc_ring_facade_benchmarks::create_hmac_key(config);
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_ring_facade_benchmarks::run_hmac_one_shot(&aws_key, &chunk);
            })
        });

        let ring_key = ring_benchmarks::create_hmac_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::run_hmac_one_shot(&ring_key, &chunk);
            })
        });
    }
}

// Benchmark hmac::sign with keys longer than the block size. If a key is longer than the block
// length then it will be compressed using the digest algorithm.
fn bench_hmac_longer_key(c: &mut Criterion, config: &HMACConfig) {
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![123u8; chunk_len];

        let bench_group_name = format!(
            "HMAC-{:?}: {} ({} bytes) [long-key]",
            config.algorithm, config.description, chunk_len
        );
        let mut group = c.benchmark_group(bench_group_name);

        let aws_key = aws_lc_ring_facade_benchmarks::create_longer_hmac_key(config);
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_ring_facade_benchmarks::run_hmac_one_shot(&aws_key, &chunk);
            })
        });

        let ring_key = ring_benchmarks::create_longer_hmac_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::run_hmac_one_shot(&ring_key, &chunk);
            })
        });
    }
}

// Benchmark incremental hmac update/sign.
fn bench_hmac_incremental(c: &mut Criterion, config: &HMACConfig) {
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![123u8; chunk_len];

        let bench_group_name = format!(
            "HMAC-{:?}: {} ({} bytes) [update/finish]",
            config.algorithm, config.description, chunk_len
        );
        let mut group = c.benchmark_group(bench_group_name);

        let aws_key = aws_lc_ring_facade_benchmarks::create_hmac_key(config);
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_ring_facade_benchmarks::run_hmac_incremental(&aws_key, &chunk);
            })
        });

        let ring_key = ring_benchmarks::create_hmac_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::run_hmac_incremental(&ring_key, &chunk);
            })
        });
    }
}

criterion_group!(
    benches,
    bench_hmac_sha1,
    bench_hmac_sha256,
    bench_hmac_sha384,
    bench_hmac_sha512,
);

criterion_main!(benches);
