// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{test, test_file};
// use aws_lc_rs_benchmarks::{encapsulate, decapsulate};
use criterion::{criterion_group, criterion_main, Criterion};

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Algorithm {
    KYBER512_R3,
}

impl From<&str> for Algorithm {
    fn from(value: &str) -> Self {
        match value {
            "KYBER512_R3" => Algorithm::KYBER512_R3,
            _ => panic!("Unrecognized algorithm: '{value}'"),
        }
    }
}

pub struct KemConfig {
    algorithm: Algorithm,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

impl KemConfig {
    fn new(
        algorithm: &str,
        public_key: &[u8],
        secret_key: &[u8],
        ciphertext: &[u8],
        shared_secret: &[u8],
    ) -> Self {
        KemConfig {
            algorithm: Algorithm::from(algorithm),
            public_key: Vec::from(public_key),
            secret_key: Vec::from(secret_key),
            ciphertext: Vec::from(ciphertext),
            shared_secret: Vec::from(shared_secret),
        }
    }
}

macro_rules! benchmark_kem {
    ( $pkg:ident ) => {
        paste::item! {
                mod [<$pkg _benchmarks>]  {

                    use $pkg::{kem, test};

            use crate::{KemConfig, Algorithm};
            use kem::{KemPrivateKey, KemPublicKey, KemAlgorithm, KYBER512_R3};

            fn algorithm(config: &KemConfig) -> &'static KemAlgorithm {
                match config.algorithm {
                    Algorithm::KYBER512_R3 => &KYBER512_R3,
                }
            }

            pub fn new_private_key(config: &KemConfig) -> KemPrivateKey {
                KemPrivateKey::new(algorithm(config), &config.secret_key).unwrap()
            }

            pub fn new_public_key(config: &KemConfig) -> KemPublicKey {
                KemPublicKey::new(algorithm(config), &config.public_key).unwrap()
            }

            pub fn encapsulate(
                public_key: &KemPublicKey,
            ) {
                public_key.encapsulate((), |ct, ss| {
                    Ok((Vec::from(ct), Vec::from(ss)))
                }).unwrap();
            }

            pub fn decapsulate(
                config: &KemConfig,
                secret_key: &KemPrivateKey,
            ) {
                let mut ciphertext = config.ciphertext.clone();
                secret_key.decapsulate(&mut ciphertext, (), |ss| {
                    Ok((Vec::from(ss)))
                }).unwrap();
            }
        }
                }
    };
}

benchmark_kem!(aws_lc_rs);
// #[cfg(feature = "ring-benchmarks")]
// benchmark_agreement!(ring);

fn test_kem_keygen(c: &mut Criterion, config: &KemConfig) {
    let bench_group_name = format!("KEM-keygen-{:?}", config.algorithm);

    let mut group = c.benchmark_group(bench_group_name);

    // let aws_peer_public_key = aws_lc_rs_benchmarks::peer_public_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let private_key = aws_lc_rs_benchmarks::new_private_key(config);
            let public_key = aws_lc_rs_benchmarks::new_public_key(config);
            aws_lc_rs_benchmarks::encapsulate(&public_key);
        });
    });
}

fn test_kem_encapsulate(c: &mut Criterion, config: &KemConfig) {
    let bench_group_name = format!("KEM-encapsulate-{:?}", config.algorithm);

    let mut group = c.benchmark_group(bench_group_name);

    // let aws_peer_public_key = aws_lc_rs_benchmarks::peer_public_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            // let private_key = aws_lc_rs_benchmarks::new_private_key(config);
            let public_key = aws_lc_rs_benchmarks::new_public_key(config);
            aws_lc_rs_benchmarks::encapsulate(&public_key);
        });
    });
}

fn test_kem_decapsulate(c: &mut Criterion, config: &KemConfig) {
    let bench_group_name = format!("KEM-decapsulate-{:?}", config.algorithm);

    let mut group = c.benchmark_group(bench_group_name);

    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let private_key = aws_lc_rs_benchmarks::new_private_key(config);
            // let public_key = aws_lc_rs_benchmarks::new_public_key(config);
            aws_lc_rs_benchmarks::decapsulate(config, &private_key);
        });
    });
}

fn test_kem(c: &mut Criterion) {
    test::run(
        test_file!("data/kem_benchmarks.txt"),
        |_section, test_case| {
            let config = KemConfig::new(
                test_case.consume_string("algorithm").as_str(),
                test_case.consume_bytes("pk").as_slice(),
                test_case.consume_bytes("sk").as_slice(),
                test_case.consume_bytes("ct").as_slice(),
                test_case.consume_bytes("ss").as_slice(),
            );
            // test_kem_keygen(c, &config);
            test_kem_encapsulate(c, &config);
            test_kem_decapsulate(c, &config);
            Ok(())
        },
    );
}

criterion_group!(benches, test_kem);
criterion_main!(benches);
