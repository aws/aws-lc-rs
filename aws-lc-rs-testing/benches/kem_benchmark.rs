// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    kem::PrivateKey,
    unstable::kem::{get_algorithm, AlgorithmId},
};
use criterion::{criterion_group, criterion_main, Criterion};

const UNSTABLE_ALGORITHMS: &[Option<&aws_lc_rs::kem::Algorithm<AlgorithmId>>] = &[
    get_algorithm(AlgorithmId::Kyber512_R3),
    get_algorithm(AlgorithmId::Kyber768_R3),
    get_algorithm(AlgorithmId::Kyber1024_R3),
];

fn bench_kem_keygen(c: &mut Criterion) {
    for ele in UNSTABLE_ALGORITHMS {
        let ele = ele.unwrap();
        let bench_group_name = format!("KEM/{:?}/keygen", ele.id());
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_rs::kem::PrivateKey::generate(ele).unwrap();
            });
        });
    }
}

fn bench_kem_encapsulate(c: &mut Criterion) {
    for ele in UNSTABLE_ALGORITHMS {
        let ele = ele.unwrap();
        let bench_group_name = format!("KEM/{:?}/encapsulate", ele.id());
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter_batched(
                || {
                    let private = PrivateKey::generate(ele).unwrap();
                    private.public_key().unwrap()
                },
                |key| key.encapsulate(),
                criterion::BatchSize::LargeInput,
            );
        });
    }
}

fn bench_kem_decapsulate(c: &mut Criterion) {
    for ele in UNSTABLE_ALGORITHMS {
        let ele = ele.unwrap();
        let bench_group_name = format!("KEM/{:?}/decapsulate", ele.id());
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter_batched(
                || {
                    let private = PrivateKey::generate(ele).unwrap();
                    let public = private.public_key().unwrap();
                    let (ciphertext, _) = public.encapsulate().unwrap();
                    (private, ciphertext)
                },
                |(key, ciphertext)| key.decapsulate(ciphertext).unwrap(),
                criterion::BatchSize::LargeInput,
            );
        });
    }
}

fn bench_kem(c: &mut Criterion) {
    bench_kem_keygen(c);
    bench_kem_encapsulate(c);
    bench_kem_decapsulate(c);
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
