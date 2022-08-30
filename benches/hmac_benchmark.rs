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
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA256, "HMAC SHA256");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
}

fn bench_hmac_sha384(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA384, "HMAC SHA384");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let config = HMACConfig::new(HMACAlgorithm::SHA512, "HMAC SHA512");
    bench_hmac_one_shot(c, &config);
    bench_hmac_incremental(c, &config);
}

const G_CHUNK_LENGTHS: [usize; 5] = [16, 256, 1350, 8192, 16384];

// TODO: Run this benchmark on a linux ec2 instance.
fn bench_hmac_one_shot(c: &mut Criterion, config: &HMACConfig) {
    // Benchmark hmac::sign one-shot.
    //
    // For SHA-{256, 384, 512, 512-256}, aws-lc-ring-facade digest::digest one-shot Rust functions
    // are around 0.8-0.9 times slower on 16 bit inputs when benchmarked against Ring. The
    // performance on 256-16394 bit inputs is on par with Ring. For SHA-1, our one-shot APIs are
    // consistently 1-2 times faster around on all input lengths.
    // For the one-shot Rust API functions, we use the corresponding one-shot SHA functions
    // available in AWS-LC to save performance spent on additional memory allocation.
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![123u8; chunk_len];

        let aws_key = aws_lc_ring_facade_benchmarks::create_hmac_key(config);
        let aws_bench_name = format!(
            "aws-lc-{:?}: {} ({} bits) [one-shot]",
            config.algorithm, config.description, chunk_len
        );
        c.bench_function(&aws_bench_name, |b| {
            b.iter(|| {
                aws_lc_ring_facade_benchmarks::run_hmac_one_shot(&aws_key, &chunk);
            })
        });

        let ring_key = ring_benchmarks::create_hmac_key(config);
        let ring_bench_name = format!(
            "ring-{:?}: {} ({} bits) [one-shot]",
            config.algorithm, config.description, chunk_len
        );
        c.bench_function(&ring_bench_name, |b| {
            b.iter(|| {
                ring_benchmarks::run_hmac_one_shot(&ring_key, &chunk);
            })
        });
    }
}

fn bench_hmac_incremental(c: &mut Criterion, config: &HMACConfig) {
    // Benchmark incremental digest update/finish.
    //
    // For update/finish functions, we are consistently around 0.6 times slower on smaller
    // inputs against ring, while the difference drops off to around 1% slower on larger inputs
    // for SHA-{256, 384, 512, 512-256}. The same slower performance on smaller inputs also applies
    // for SHA-1, but the difference speeds up 2-3 times faster on larger inputs.
    // This difference is most likely caused by the additional memory allocation needed when
    // wielding the C `EVP_MD`/`EVP_MD_CTX` interfaces as mentioned in the original ring
    // implementation. Ring does the hashing block computations entirely in Rust.
    // https://github.com/briansmith/ring/blob/main/src/digest.rs#L21-L25
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![123u8; chunk_len];

        let aws_key = aws_lc_ring_facade_benchmarks::create_hmac_key(config);
        let aws_bench_name = format!(
            "aws-lc-{:?}: {} ({} bits) [update/finish]",
            config.algorithm, config.description, chunk_len
        );
        c.bench_function(&aws_bench_name, |b| {
            b.iter(|| {
                aws_lc_ring_facade_benchmarks::run_hmac_incremental(&aws_key, &chunk);
            })
        });

        let ring_key = ring_benchmarks::create_hmac_key(config);
        let ring_bench_name = format!(
            "ring-{:?}: {} ({} bits) [update/finish]",
            config.algorithm, config.description, chunk_len
        );
        c.bench_function(&ring_bench_name, |b| {
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
