// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Algorithm {
    KYBER512_R3,
    KYBER768_R3,
    KYBER1024_R3,
}

impl From<&str> for Algorithm {
    fn from(value: &str) -> Self {
        match value {
            "KYBER512_R3" => Algorithm::KYBER512_R3,
            "KYBER768_R3" => Algorithm::KYBER768_R3,
            "KYBER1024_R3" => Algorithm::KYBER1024_R3,
            _ => panic!("Unrecognized algorithm: '{value}'"),
        }
    }
}

pub struct KemConfig {
    algorithm: Algorithm,
    public_key: Box<[u8]>,
    secret_key: Box<[u8]>,
    ciphertext: Box<[u8]>,
}

impl KemConfig {
    fn new(algorithm: &str, public_key: &[u8], secret_key: &[u8], ciphertext: &[u8]) -> Self {
        KemConfig {
            algorithm: Algorithm::from(algorithm),
            public_key: Vec::from(public_key).into(),
            secret_key: Vec::from(secret_key).into(),
            ciphertext: Vec::from(ciphertext).into(),
        }
    }
}

mod aws_lc_rs_benchmarks {

    use aws_lc_rs::kem;

    use crate::{Algorithm, KemConfig};
    use kem::{KemAlgorithm, KemPrivateKey, KemPublicKey, KYBER1024_R3, KYBER512_R3, KYBER768_R3};

    fn algorithm(config: &KemConfig) -> &'static KemAlgorithm {
        match config.algorithm {
            Algorithm::KYBER512_R3 => &KYBER512_R3,
            Algorithm::KYBER768_R3 => &KYBER768_R3,
            Algorithm::KYBER1024_R3 => &KYBER1024_R3,
        }
    }

    pub fn new_private_key(config: &KemConfig) -> KemPrivateKey {
        KemPrivateKey::new(algorithm(config), &config.secret_key).unwrap()
    }

    pub fn new_public_key(config: &KemConfig) -> KemPublicKey {
        KemPublicKey::new(algorithm(config), &config.public_key).unwrap()
    }

    pub fn keygen(config: &KemConfig) {
        let private_key = KemPrivateKey::generate(algorithm(config)).unwrap();
        let _public_key = private_key.compute_public_key().unwrap();
    }

    pub fn encapsulate(public_key: &KemPublicKey) {
        public_key
            .encapsulate((), |ct, ss| Ok((Vec::from(ct), Vec::from(ss))))
            .unwrap();
    }

    pub fn decapsulate(config: &KemConfig, secret_key: &KemPrivateKey) {
        let mut ciphertext = config.ciphertext.clone();
        secret_key
            .decapsulate(&mut ciphertext, (), |ss| Ok(Vec::from(ss)))
            .unwrap();
    }
}

fn bench_kem_keygen(c: &mut Criterion, config: &KemConfig) {
    let bench_group_name = format!("KEM-{:?}-keygen", config.algorithm);

    let mut group = c.benchmark_group(bench_group_name);

    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_rs_benchmarks::keygen(config);
        });
    });
}

fn bench_kem_encapsulate(c: &mut Criterion, config: &KemConfig) {
    let bench_group_name = format!("KEM-{:?}-encapsulate", config.algorithm);

    let mut group = c.benchmark_group(bench_group_name);

    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let public_key = aws_lc_rs_benchmarks::new_public_key(config);
            aws_lc_rs_benchmarks::encapsulate(&public_key);
        });
    });
}

fn bench_kem_decapsulate(c: &mut Criterion, config: &KemConfig) {
    let bench_group_name = format!("KEM-{:?}-decapsulate", config.algorithm);

    let mut group = c.benchmark_group(bench_group_name);

    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let private_key = aws_lc_rs_benchmarks::new_private_key(config);
            aws_lc_rs_benchmarks::decapsulate(config, &private_key);
        });
    });
}

fn bench_kem(c: &mut Criterion) {
    test::run(
        test_file!("data/kem_benchmarks.txt"),
        |_section, test_case| {
            let config = KemConfig::new(
                test_case.consume_string("algorithm").as_str(),
                test_case.consume_bytes("pk").as_slice(),
                test_case.consume_bytes("sk").as_slice(),
                test_case.consume_bytes("ct").as_slice(),
            );
            bench_kem_keygen(c, &config);
            bench_kem_encapsulate(c, &config);
            bench_kem_decapsulate(c, &config);
            Ok(())
        },
    );
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
