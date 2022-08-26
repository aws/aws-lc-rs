// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
    description: String,
}

impl DigestConfig {
    pub fn new(algorithm: DigestAlgorithm, description: &str) -> DigestConfig {
        DigestConfig {
            algorithm,
            description: String::from(description),
        }
    }
}

macro_rules! benchmark_digest {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{digest};

            use criterion::black_box;
            use crate::DigestConfig;
            use digest::Context;

            fn algorithm(config: &crate::DigestConfig) ->  &'static digest::Algorithm {
                black_box(match &config.algorithm {
                    crate::DigestAlgorithm::SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    crate::DigestAlgorithm::SHA256 => &digest::SHA256,
                    crate::DigestAlgorithm::SHA384 => &digest::SHA384,
                    crate::DigestAlgorithm::SHA512 => &digest::SHA512,
                    crate::DigestAlgorithm::SHA512_256 => &digest::SHA512_256
                })
            }

            pub fn run_digest(config: &DigestConfig, chunk_len: usize) {
                let chunk = vec![0u8; chunk_len];
                let mut ctx = Context::new(algorithm(&config));
                ctx.update(&chunk);
                ctx.finish();
            }
        }
        }
    };
}

benchmark_digest!(ring);
benchmark_digest!(aws_lc_ring_facade);

fn bench_sha1(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA1, "SHA1 Digest");
    bench_digest(c, &config);
}

fn bench_sha256(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA256, "SHA256 Digest");
    bench_digest(c, &config);
}

fn bench_sha384(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA384, "SHA384 Digest");
    bench_digest(c, &config);
}

fn bench_sha512(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA512, "SHA512 Digest");
    bench_digest(c, &config);
}

fn bench_sha512_256(c: &mut Criterion) {
    let config = DigestConfig::new(DigestAlgorithm::SHA512_256, "SHA512_256 Digest");
    bench_digest(c, &config);
}

fn bench_digest(c: &mut Criterion, config: &DigestConfig) {
    let g_chunk_lengths: Vec<usize> = vec![16, 256, 1350, 8192, 16384];

    // Run over the various chunk lengths.
    //
    // Current status is aws-lc-ring-facade is consistently around 0.6 times slower on smaller
    // inputs against ring, while the difference drops off to around 1% slower on larger inputs
    // for SHA-{256, 384, 512, 512-256}. The same slower performance on smaller inputs also applies
    // for SHA-1, but the difference speeds up 2-3 times faster on larger inputs.
    // This difference is most likely caused by the additional memory allocation needed when
    // wielding the C `EVP_MD`/`EVP_MD_CTX` interfaces as mentioned in the original ring
    // implementation. Ring does the hashing block computations entirely in Rust.
    // https://github.com/briansmith/ring/blob/main/src/digest.rs#L21-L25
    for chunk_len in g_chunk_lengths {
        let aws_bench_name = format!(
            "aws-lc-{:?}: {} ({} bytes)",
            config.algorithm, config.description, chunk_len
        );
        c.bench_function(&aws_bench_name, |b| {
            b.iter(|| {
                aws_lc_ring_facade_benchmarks::run_digest(config, chunk_len);
            })
        });

        let ring_bench_name = format!(
            "ring-{:?}: {} ({} bytes)",
            config.algorithm, config.description, chunk_len
        );
        c.bench_function(&ring_bench_name, |b| {
            b.iter(|| {
                ring_benchmarks::run_digest(config, chunk_len);
            })
        });
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
