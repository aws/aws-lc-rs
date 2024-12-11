// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    kem::DecapsulationKey,
    kem::{Algorithm, ML_KEM_1024, ML_KEM_512, ML_KEM_768},
};
use criterion::{criterion_group, criterion_main, Criterion};

const KEM_ALGORITHMS: &[Algorithm; 3] = &[ML_KEM_512, ML_KEM_768, ML_KEM_1024];

fn bench_kem_keygen(c: &mut Criterion) {
    for ele in KEM_ALGORITHMS {
        let bench_group_name = format!("KEM/{:?}/keygen", ele.id());
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                DecapsulationKey::generate(ele).unwrap();
            });
        });
    }
}

fn bench_kem_encapsulate(c: &mut Criterion) {
    for ele in KEM_ALGORITHMS {
        let bench_group_name = format!("KEM/{:?}/encapsulate", ele.id());
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter_batched(
                || {
                    let private = DecapsulationKey::generate(ele).unwrap();
                    private.encapsulation_key().unwrap()
                },
                |key| key.encapsulate(),
                criterion::BatchSize::LargeInput,
            );
        });
    }
}

fn bench_kem_decapsulate(c: &mut Criterion) {
    for ele in KEM_ALGORITHMS {
        let bench_group_name = format!("KEM/{:?}/decapsulate", ele.id());
        let mut group = c.benchmark_group(bench_group_name);
        group.bench_function("AWS-LC", |b| {
            b.iter_batched(
                || {
                    let private = DecapsulationKey::generate(ele).unwrap();
                    let public = private.encapsulation_key().unwrap();
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
