/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 */

use aws_lc_ring_facade::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Ed25519Config {
    seed: Vec<u8>,
    public_key: Vec<u8>,
    msg: Vec<u8>,
    signature: Vec<u8>,
}

impl Ed25519Config {
    fn new(seed: &[u8], public_key: &[u8], msg: &[u8], signature: &[u8]) -> Ed25519Config {
        Ed25519Config {
            seed: Vec::from(seed),
            public_key: Vec::from(public_key),
            msg: Vec::from(msg),
            signature: Vec::from(signature),
        }
    }
}

macro_rules! benchmark_ed25519 {
    ( $pkg:ident ) => {
        paste::item! {
                mod [<$pkg _benchmarks>]  {

                    use $pkg::signature;

        /*
        #[allow(unused_imports, unused_variables, dead_code)]
        mod ring_benchmarks {
            use ring::{error, rand, signature};
        */

            use crate::Ed25519Config;
            use signature::{ED25519, Ed25519KeyPair, EdDSAParameters, VerificationAlgorithm};

            pub fn create_key_pair(config: &Ed25519Config) -> Ed25519KeyPair {
                Ed25519KeyPair::from_seed_and_public_key(&config.seed, &config.public_key)
                    .expect(&format!("Unable to build Ed25519KeyPair: {:?}", config))
            }

            pub fn sign(key_pair: &Ed25519KeyPair, msg: &[u8]) {
                key_pair.sign(msg);
            }

            pub fn verification() -> &'static EdDSAParameters {
                &ED25519
            }

            pub fn verify(
                verification_alg: &'static EdDSAParameters,
                public_key: &[u8],
                msg: &[u8],
                signature: &[u8],
            ) {
                let public_key = untrusted::Input::from(public_key);
                let msg = untrusted::Input::from(msg);
                let signature = untrusted::Input::from(signature);
                verification_alg
                    .verify(public_key, msg, signature)
                    .expect("verification failed");
            }
        }

        }
    };
}
benchmark_ed25519!(ring);
benchmark_ed25519!(aws_lc_ring_facade);

fn test_ed25519_sign(c: &mut Criterion, config: &Ed25519Config) {
    let bench_group_name = format!("ED25519-sign-{}-bytes", config.msg.len());
    let mut group = c.benchmark_group(bench_group_name);

    let aws_key_pair = aws_lc_ring_facade_benchmarks::create_key_pair(&config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_ring_facade_benchmarks::sign(&aws_key_pair, &config.msg);
        })
    });

    let ring_key_pair = ring_benchmarks::create_key_pair(&config);

    group.bench_function("Ring", |b| {
        b.iter(|| {
            ring_benchmarks::sign(&ring_key_pair, &config.msg);
        })
    });
}

fn test_ed25519_verify(c: &mut Criterion, config: &Ed25519Config) {
    let bench_group_name = format!("ED25519-verify-{}-bytes", config.msg.len());
    let mut group = c.benchmark_group(bench_group_name);
    let pub_key = config.public_key.as_slice();
    let sig = config.signature.as_slice();

    let aws_verification_alg = aws_lc_ring_facade_benchmarks::verification();
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_ring_facade_benchmarks::verify(aws_verification_alg, pub_key, &config.msg, &sig);
        })
    });

    let ring_verification_alg = ring_benchmarks::verification();

    group.bench_function("Ring", |b| {
        b.iter(|| {
            ring_benchmarks::verify(ring_verification_alg, pub_key, &config.msg, &sig);
        })
    });
}
fn test_ed25519(c: &mut Criterion) {
    test::run(
        test_file!("data/ed25519_benchmarks.txt"),
        |_section, test_case| {
            let config = Ed25519Config::new(
                test_case.consume_bytes("SEED").as_slice(),
                test_case.consume_bytes("PUB").as_slice(),
                test_case.consume_bytes("MESSAGE").as_slice(),
                test_case.consume_bytes("SIG").as_slice(),
            );
            test_ed25519_sign(c, &config);
            test_ed25519_verify(c, &config);
            Ok(())
        },
    );
}

criterion_group!(benches, test_ed25519);
criterion_main!(benches);
