// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Curve {
    X25519,
    P256,
    P384,
}

impl From<&str> for Curve {
    fn from(value: &str) -> Self {
        match value {
            "X25519" => Curve::X25519,
            "P-256" => Curve::P256,
            "P-384" => Curve::P384,
            _ => panic!("Unrecognized curve: '{value}'"),
        }
    }
}

pub struct AgreementConfig {
    curve: Curve,
    peer_pub: Vec<u8>,
    private: Vec<u8>,
}

impl AgreementConfig {
    fn new(curve: &str, peer_pub: &[u8], private: &[u8]) -> Self {
        AgreementConfig {
            curve: Curve::from(curve),
            peer_pub: Vec::from(peer_pub),
            private: Vec::from(private),
        }
    }
}

macro_rules! benchmark_agreement {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{agreement, test};

    use crate::{AgreementConfig, Curve};
    use agreement::{
        agree_ephemeral, Algorithm, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256, ECDH_P384,
        X25519,
    };

    fn algorithm(config: &AgreementConfig) -> &'static Algorithm {
        match config.curve {
            Curve::X25519 => &X25519,
            Curve::P256 => &ECDH_P256,
            Curve::P384 => &ECDH_P384,
        }
    }

    pub fn private_key(config: &AgreementConfig) -> EphemeralPrivateKey {
        let rng = test::rand::FixedSliceRandom {
            bytes: &config.private,
        };
        EphemeralPrivateKey::generate(algorithm(config), &rng).unwrap()
    }

    pub fn peer_public_key(config: &AgreementConfig) -> UnparsedPublicKey<Vec<u8>> {
        UnparsedPublicKey::new(algorithm(config), config.peer_pub.clone())
    }

    pub fn agreement(
        private_key: EphemeralPrivateKey,
        peer_public_key: &UnparsedPublicKey<Vec<u8>>,
    ) {
        agree_ephemeral(private_key, peer_public_key, (), |val| Ok(Vec::from(val))).unwrap();
    }
}
        }
    };
}

benchmark_agreement!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_agreement!(ring);

fn test_agree_ephemeral(c: &mut Criterion, config: &AgreementConfig) {
    let bench_group_name = format!("Agreement-{:?}", config.curve);

    let mut group = c.benchmark_group(bench_group_name);

    let aws_peer_public_key = aws_lc_rs_benchmarks::peer_public_key(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            let private_key = aws_lc_rs_benchmarks::private_key(config);
            aws_lc_rs_benchmarks::agreement(private_key, &aws_peer_public_key);
        });
    });
    #[cfg(feature = "ring-benchmarks")]
    {
        let ring_peer_public_key = ring_benchmarks::peer_public_key(config);
        group.bench_function("Ring", |b| {
            b.iter(|| {
                let private_key = ring_benchmarks::private_key(config);
                ring_benchmarks::agreement(private_key, &ring_peer_public_key);
            });
        });
    }
}

fn test_agreement(c: &mut Criterion) {
    test::run(
        test_file!("data/agreement_benchmarks.txt"),
        |_section, test_case| {
            let config = AgreementConfig::new(
                test_case.consume_string("Curve").as_str(),
                test_case.consume_bytes("PeerQ").as_slice(),
                test_case.consume_bytes("D").as_slice(),
            );
            test_agree_ephemeral(c, &config);
            Ok(())
        },
    );
}

criterion_group!(benches, test_agreement);
criterion_main!(benches);
