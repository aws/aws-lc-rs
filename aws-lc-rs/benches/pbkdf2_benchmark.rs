// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use criterion::{criterion_group, criterion_main, Criterion};
use std::num::NonZeroU32;

#[derive(Debug)]
pub enum PBKDF2Algorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

pub struct PBKDF2Config {
    algorithm: PBKDF2Algorithm,
}

impl PBKDF2Config {
    #[must_use]
    pub fn new(algorithm: PBKDF2Algorithm) -> PBKDF2Config {
        PBKDF2Config { algorithm }
    }
}

macro_rules! benchmark_pbkdf2 {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::pbkdf2;

            use crate::PBKDF2Config;
            use criterion::black_box;
            use std::num::NonZeroU32;

            pub fn algorithm(config: &crate::PBKDF2Config) -> pbkdf2::Algorithm {
                black_box(match &config.algorithm {
                    crate::PBKDF2Algorithm::SHA1 => pbkdf2::PBKDF2_HMAC_SHA1,
                    crate::PBKDF2Algorithm::SHA256 => pbkdf2::PBKDF2_HMAC_SHA256,
                    crate::PBKDF2Algorithm::SHA384 => pbkdf2::PBKDF2_HMAC_SHA384,
                    crate::PBKDF2Algorithm::SHA512 => pbkdf2::PBKDF2_HMAC_SHA512,
                })
            }

            // pbkdf2::{derive, verify} are essentially the same operations being ran, so we only
            // need to benchmark one.
            // The length of the salt and secret input doesn't have any significant effects on the
            // speed of pbkdf2. The secret will be hashed to a digest, if longer than the block
            // size. The length of salt is normally 64 or 128 bits.
            // The number of iterations has a larger impact on performance, and running a large
            // number of iterations is important for pbkdf2 security.
            pub fn run_pbkdf2_derive(
                config: &PBKDF2Config,
                iterations: NonZeroU32,
                out: &mut [u8],
            ) {
                pbkdf2::derive(algorithm(&config), iterations, b"salt", b"password", out);
            }
        }
        }
    };
}

benchmark_pbkdf2!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_pbkdf2!(ring);

fn bench_pbkdf2_sha1(c: &mut Criterion) {
    let config = PBKDF2Config::new(PBKDF2Algorithm::SHA1);
    bench_pbkdf2(c, &config);
}

fn bench_pbkdf2_sha256(c: &mut Criterion) {
    let config = PBKDF2Config::new(PBKDF2Algorithm::SHA256);
    bench_pbkdf2(c, &config);
}

fn bench_pbkdf2_sha384(c: &mut Criterion) {
    let config = PBKDF2Config::new(PBKDF2Algorithm::SHA384);
    bench_pbkdf2(c, &config);
}

fn bench_pbkdf2_sha512(c: &mut Criterion) {
    let config = PBKDF2Config::new(PBKDF2Algorithm::SHA512);
    bench_pbkdf2(c, &config);
}

// The recommended number of iterations can go to the hundred thousands, but we only need a
// suitable number of iterations to capture our speed performance. The time to run pbkdf2 grows
// proportionally, according to the number of iterations.
const G_ITERATIONS: [u32; 4] = [6250, 12500, 25000, 50000];

fn bench_pbkdf2(c: &mut Criterion, config: &PBKDF2Config) {
    for &iterations in &G_ITERATIONS {
        let iter = NonZeroU32::new(iterations).unwrap();
        let bench_group_name = format!("PBKDF2-{:?}-{}-iterations", config.algorithm, iter);
        let mut group = c.benchmark_group(bench_group_name);

        let mut aws_out = vec![0u8; 64];
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_rs_benchmarks::run_pbkdf2_derive(config, iter, &mut aws_out);
            });
        });
        #[cfg(feature = "ring-benchmarks")]
        {
            let mut ring_out = vec![0u8; 64];
            group.bench_function("Ring", |b| {
                b.iter(|| {
                    ring_benchmarks::run_pbkdf2_derive(config, iter, &mut ring_out);
                });
            });
        }
    }
}

criterion_group!(
    benches,
    bench_pbkdf2_sha1,
    bench_pbkdf2_sha256,
    bench_pbkdf2_sha384,
    bench_pbkdf2_sha512,
);

criterion_main!(benches);
