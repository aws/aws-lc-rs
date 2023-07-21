// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(deprecated, dead_code)]

use aws_lc_rs::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};

#[allow(dead_code)]
pub struct RsaConfig {
    padding: &'static RsaPadding,
    digest: &'static RsaDigest,
    key: Vec<u8>,
    msg: Vec<u8>,
    signature: Vec<u8>,
}

impl RsaConfig {
    fn new(padding: &str, digest: &str, key: &[u8], msg: &[u8], signature: &[u8]) -> RsaConfig {
        RsaConfig {
            padding: RsaPadding::from(padding),
            digest: RsaDigest::from(digest),
            key: Vec::from(key),
            msg: Vec::from(msg),
            signature: Vec::from(signature),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Debug)]
pub enum RsaPadding {
    PSS,
    PKCS1,
}
pub const PSS: RsaPadding = RsaPadding::PSS;
pub const PKCS1: RsaPadding = RsaPadding::PKCS1;

impl RsaPadding {
    fn from(value: &str) -> &'static Self {
        match value.trim() {
            "PSS" => &PSS,
            "PKCS1" => &PKCS1,
            _ => panic!("Unrecognized padding: '{value}'"),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Debug)]
pub enum RsaDigest {
    SHA256,
    SHA384,
    SHA512,
}
pub const SHA256: RsaDigest = RsaDigest::SHA256;
pub const SHA384: RsaDigest = RsaDigest::SHA384;
pub const SHA512: RsaDigest = RsaDigest::SHA512;

impl RsaDigest {
    fn from(value: &str) -> &'static Self {
        match value.trim() {
            "SHA256" => &SHA256,
            "SHA384" => &SHA384,
            "SHA512" => &SHA512,
            _ => panic!("Unrecognize padding: '{value}'"),
        }
    }
}

macro_rules! benchmark_rsa {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{signature, rand};

    use super::{RsaDigest, RsaPadding};
    use signature::{RsaKeyPair, RsaParameters, VerificationAlgorithm};

    pub fn create_key_pair(key: &[u8]) -> RsaKeyPair {
        RsaKeyPair::from_der(key).expect("Unable to parse key")
    }

    pub fn encoding(
        padding: &'static RsaPadding,
        digest: &'static RsaDigest,
    ) -> &'static dyn signature::RsaEncoding {
        match (padding, digest) {
            (&crate::PSS, &crate::SHA256) => &signature::RSA_PSS_SHA256,
            (&crate::PSS, &crate::SHA384) => &signature::RSA_PSS_SHA384,
            (&crate::PSS, &crate::SHA512) => &signature::RSA_PSS_SHA512,
            (&crate::PKCS1, &crate::SHA256) => &signature::RSA_PKCS1_SHA256,
            (&crate::PKCS1, &crate::SHA384) => &signature::RSA_PKCS1_SHA384,
            (&crate::PKCS1, &crate::SHA512) => &signature::RSA_PKCS1_SHA512,
        }
    }

    pub fn parameters(
        padding: &'static RsaPadding,
        digest: &'static RsaDigest,
    ) -> &'static RsaParameters {
        match (padding, digest) {
            (&crate::PSS, &crate::SHA256) => &signature::RSA_PSS_2048_8192_SHA256,
            (&crate::PSS, &crate::SHA384) => &signature::RSA_PSS_2048_8192_SHA384,
            (&crate::PSS, &crate::SHA512) => &signature::RSA_PSS_2048_8192_SHA512,
            (&crate::PKCS1, &crate::SHA256) => &signature::RSA_PKCS1_2048_8192_SHA256,
            (&crate::PKCS1, &crate::SHA384) => &signature::RSA_PKCS1_2048_8192_SHA384,
            (&crate::PKCS1, &crate::SHA512) => &signature::RSA_PKCS1_2048_8192_SHA512,
        }
    }

    pub fn get_rng() -> rand::SystemRandom {
        rand::SystemRandom::new()
    }

    pub fn sign(
        key_pair: &RsaKeyPair,
        rng: &dyn rand::SecureRandom,
        msg: &[u8],
        encoding: &'static dyn signature::RsaEncoding,
        signature: &mut [u8],
    ) {
        key_pair
            .sign(encoding, rng, msg, signature)
            .expect("signing failed");
    }

    pub fn verify(rsa_params: &RsaParameters, public_key: &[u8], msg: &[u8], signature: &[u8]) {
        let public_key = untrusted::Input::from(public_key);
        let msg = untrusted::Input::from(msg);
        let signature = untrusted::Input::from(signature);
        rsa_params.verify(public_key, msg, signature).unwrap()
    }
}

}
    };
}

benchmark_rsa!(aws_lc_rs);
#[cfg(feature = "ring-benchmarks")]
benchmark_rsa!(ring);

fn test_rsa_sign(c: &mut Criterion, config: &RsaConfig) {
    let mut buffer = [0u8; 2048];

    let bench_group_name = format!(
        "RSA-{}-{:?}-{:?}-sign-{}-bytes",
        config.key.len(),
        config.padding,
        config.digest,
        config.msg.len()
    );
    let mut group = c.benchmark_group(bench_group_name);
    let aws_rng = aws_lc_rs_benchmarks::get_rng();
    let aws_encoding = aws_lc_rs_benchmarks::encoding(config.padding, config.digest);
    let aws_key_pair = aws_lc_rs_benchmarks::create_key_pair(&config.key);
    let aws_sig = &mut buffer[0..aws_key_pair.public_modulus_len()];
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_rs_benchmarks::sign(&aws_key_pair, &aws_rng, &config.msg, aws_encoding, aws_sig);
        });
    });
    #[cfg(feature = "ring-benchmarks")]
    {
        let ring_rng = ring_benchmarks::get_rng();
        let ring_encoding = ring_benchmarks::encoding(config.padding, config.digest);
        let ring_key_pair = ring_benchmarks::create_key_pair(&config.key);
        let ring_sig = &mut buffer[0..ring_key_pair.public_modulus_len()];

        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::sign(
                    &ring_key_pair,
                    &ring_rng,
                    &config.msg,
                    ring_encoding,
                    ring_sig,
                );
            });
        });
    }
}

fn test_rsa_verify(c: &mut Criterion, config: &RsaConfig) {
    let bench_group_name = format!(
        "RSA-{}-{:?}-{:?}-verify-{}-bytes",
        config.key.len(),
        config.padding,
        config.digest,
        config.msg.len()
    );
    let mut group = c.benchmark_group(bench_group_name);
    {
        use aws_lc_rs::signature::KeyPair;
        let aws_params = aws_lc_rs_benchmarks::parameters(config.padding, config.digest);
        let aws_key_pair = aws_lc_rs_benchmarks::create_key_pair(&config.key);
        let aws_pub_key = aws_key_pair.public_key().as_ref();
        let aws_sig = config.signature.as_slice();

        group.bench_function("AWS-LC", |b| {
            b.iter(|| {
                aws_lc_rs_benchmarks::verify(aws_params, aws_pub_key, &config.msg, aws_sig);
            });
        });
    }
    #[cfg(feature = "ring-benchmarks")]
    {
        use ring::signature::KeyPair;
        let ring_params = ring_benchmarks::parameters(config.padding, config.digest);
        let ring_key_pair = ring_benchmarks::create_key_pair(&config.key);
        let ring_pub_key = ring_key_pair.public_key().as_ref();
        let ring_sig = config.signature.as_slice();

        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::verify(ring_params, ring_pub_key, &config.msg, ring_sig);
            });
        });
    }
}

fn test_rsa(c: &mut Criterion) {
    test::run(
        test_file!("data/rsa_benchmarks.txt"),
        |_section, test_case| {
            let config = RsaConfig::new(
                test_case.consume_string("Padding").as_str(),
                test_case.consume_string("Digest").as_str(),
                test_case.consume_bytes("Key").as_slice(),
                test_case.consume_bytes("Msg").as_slice(),
                test_case.consume_bytes("Sig").as_slice(),
            );
            test_rsa_sign(c, &config);
            test_rsa_verify(c, &config);
            Ok(())
        },
    );
}

criterion_group!(benches, test_rsa);
criterion_main!(benches);
