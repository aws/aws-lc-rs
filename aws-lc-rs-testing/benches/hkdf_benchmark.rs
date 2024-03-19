// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use criterion::{criterion_group, criterion_main, Criterion};

#[derive(Debug)]
pub enum HKDFAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

pub struct HKDFConfig {
    algorithm: HKDFAlgorithm,
}

impl HKDFConfig {
    #[must_use]
    pub fn new(algorithm: HKDFAlgorithm) -> HKDFConfig {
        HKDFConfig { algorithm }
    }
}

// For the hkdf functions, we use the corresponding one-shot `HKDF_expand` and `HKDF_extract`
// functions available in *AWS-LC*.
macro_rules! benchmark_hkdf {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{hkdf, digest};

            use criterion::black_box;
            use crate::HKDFConfig;

            pub fn algorithm(config: &crate::HKDFConfig) ->  hkdf::Algorithm {
                black_box(match &config.algorithm {
                    crate::HKDFAlgorithm::SHA1 => hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
                    crate::HKDFAlgorithm::SHA256 => hkdf::HKDF_SHA256,
                    crate::HKDFAlgorithm::SHA384 => hkdf::HKDF_SHA384,
                    crate::HKDFAlgorithm::SHA512 => hkdf::HKDF_SHA512,
                })
            }

            /// `HKDF_extract` is essentially just HMAC under the hood.
            pub fn run_hkdf_extract(config: &HKDFConfig) -> hkdf::Prk {
                let salt = hkdf::Salt::new(algorithm(&config), &[]);
                salt.extract(&[])
            }

            /// The extracted PRK length we expand from will always be the output length of the
            /// used digest algorithm. The len defined for `My()` is only used to define length of
            /// the expected buffer output.
            pub fn run_hkdf_expand(prk: &hkdf::Prk, info_value: &[&[u8]]) {
                let _result: My<Vec<u8>> =
                    prk.expand(info_value, My(digest::MAX_OUTPUT_LEN)).unwrap().into();
            }

            /// Generic newtype wrapper that lets us implement traits for externally-defined
            /// types.
            #[derive(Debug, PartialEq)]
            struct My<T: core::fmt::Debug + PartialEq>(T);

            impl hkdf::KeyType for My<usize> {
                fn len(&self) -> usize {
                    self.0
                }
            }

            impl From<hkdf::Okm<'_, My<usize>>> for My<Vec<u8>> {
                fn from(okm: hkdf::Okm<My<usize>>) -> Self {
                    let mut r = vec![0u8; okm.len().0];
                    okm.fill(&mut r).unwrap();
                    Self(r)
                }
            }
        }
        }
    };
}

benchmark_hkdf!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_hkdf!(ring);

fn bench_hkdf_sha1(c: &mut Criterion) {
    let config = HKDFConfig::new(HKDFAlgorithm::SHA1);
    bench_hkdf(c, &config);
}

fn bench_hkdf_sha256(c: &mut Criterion) {
    let config = HKDFConfig::new(HKDFAlgorithm::SHA256);
    bench_hkdf(c, &config);
}

fn bench_hkdf_sha384(c: &mut Criterion) {
    let config = HKDFConfig::new(HKDFAlgorithm::SHA384);
    bench_hkdf(c, &config);
}

fn bench_hkdf_sha512(c: &mut Criterion) {
    let config = HKDFConfig::new(HKDFAlgorithm::SHA512);
    bench_hkdf(c, &config);
}

const G_CHUNK_LENGTHS: [usize; 4] = [16, 32, 64, 80];

fn bench_hkdf(c: &mut Criterion, config: &HKDFConfig) {
    for &chunk_len in &G_CHUNK_LENGTHS {
        let chunk = vec![1u8; chunk_len];
        let info_chunk: &[&[u8]] = &[&chunk];
        let bench_group_name = format!("HKDF-{:?}-{}-bytes", config.algorithm, chunk_len);
        let mut group = c.benchmark_group(bench_group_name);

        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                let aws_prk = aws_lc_rs_benchmarks::run_hkdf_extract(config);
                aws_lc_rs_benchmarks::run_hkdf_expand(&aws_prk, info_chunk);
            });
        });
        #[cfg(feature = "ring-benchmarks")]
        {
            group.bench_function("Ring", |b| {
                b.iter(|| {
                    let ring_prk = ring_benchmarks::run_hkdf_extract(config);
                    ring_benchmarks::run_hkdf_expand(&ring_prk, info_chunk);
                });
            });
        }
    }
}

criterion_group!(
    benches,
    bench_hkdf_sha1,
    bench_hkdf_sha256,
    bench_hkdf_sha384,
    bench_hkdf_sha512,
);

criterion_main!(benches);
