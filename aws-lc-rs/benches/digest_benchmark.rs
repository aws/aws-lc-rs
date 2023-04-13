// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use criterion::{criterion_group, criterion_main, Criterion};

#[derive(Debug)]
pub enum DigestAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
}

pub struct DigestConfig {
    algorithm: DigestAlgorithm,
}

impl DigestConfig {
    #[must_use]
    pub fn new(algorithm: DigestAlgorithm) -> DigestConfig {
        DigestConfig { algorithm }
    }
}

macro_rules! benchmark_digest {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{digest};

            use criterion::black_box;
            use crate::DigestConfig;
            use digest::{Context, Digest};

            fn algorithm(config: &crate::DigestConfig) ->  &'static digest::Algorithm {
                black_box(match &config.algorithm {
                    crate::DigestAlgorithm::SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    crate::DigestAlgorithm::SHA256 => &digest::SHA256,
                    crate::DigestAlgorithm::SHA384 => &digest::SHA384,
                    crate::DigestAlgorithm::SHA512 => &digest::SHA512,
                    crate::DigestAlgorithm::SHA512_256 => &digest::SHA512_256
                })
            }

            pub fn run_digest_incremental(config: &DigestConfig, chunk: &[u8]) {
                let mut ctx = Context::new(algorithm(&config));
                ctx.update(&chunk);
                let _: Digest = ctx.finish();
            }

            #[allow(unused_must_use)]
            pub fn run_digest_one_shot(config: &DigestConfig, chunk: &[u8]) {
                digest::digest(algorithm(&config), &chunk);
            }
        }
        }
    };
}

benchmark_digest!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_digest!(ring);

fn bench_sha1(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA1);
    bench_digest_one_shot(c, &config);
    bench_digest_incremental(c, &config);
}

fn bench_sha256(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA256);
    bench_digest_one_shot(c, &config);
    bench_digest_incremental(c, &config);
}

fn bench_sha384(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA384);
    bench_digest_one_shot(c, &config);
    bench_digest_incremental(c, &config);
}

fn bench_sha512(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA512);
    bench_digest_one_shot(c, &config);
    bench_digest_incremental(c, &config);
}

fn bench_sha512_256(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA512_256);
    bench_digest_one_shot(c, &config);
    bench_digest_incremental(c, &config);
}

const G_CHUNK_LENGTHS: [usize; 5] = [16, 256, 1350, 8192, 16384];

fn bench_digest_one_shot(c: &mut Criterion, config: &DigestConfig) {
    // Benchmark digest::digest one-shot.
    //
    // For the one-shot Rust API functions, we use the corresponding one-shot SHA functions
    // available in *AWS-LC* to avoid the latency of additional memory allocation.
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![1u8; chunk_len];

        let bench_group_name =
            format!("DIGEST-{:?}-one-shot-{}-bytes", config.algorithm, chunk_len);
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_rs_benchmarks::run_digest_one_shot(config, &chunk);
            });
        });
        #[cfg(feature = "ring-benchmarks")]
        {
            group.bench_function("Ring", |b| {
                b.iter(|| {
                    ring_benchmarks::run_digest_one_shot(config, &chunk);
                });
            });
        }
    }
}

fn bench_digest_incremental(c: &mut Criterion, config: &DigestConfig) {
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
        let chunk = vec![1u8; chunk_len];

        let bench_group_name = format!(
            "DIGEST-{:?}-incremental-{}-bytes",
            config.algorithm, chunk_len
        );
        let mut group = c.benchmark_group(bench_group_name);

        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_rs_benchmarks::run_digest_incremental(config, &chunk);
            });
        });
        #[cfg(feature = "ring-benchmarks")]
        {
            group.bench_function("Ring", |b| {
                b.iter(|| {
                    ring_benchmarks::run_digest_incremental(config, &chunk);
                });
            });
        }
    }
}

criterion_group!(
    benches,
    bench_sha1,
    bench_sha256,
    bench_sha384,
    bench_sha512,
    bench_sha512_256
);

criterion_main!(benches);
