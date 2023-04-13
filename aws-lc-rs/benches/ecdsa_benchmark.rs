// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(deprecated, dead_code)]

#[cfg(feature = "ring-sig-verify")]
use aws_lc_rs::{test, test_file};
#[cfg(feature = "ring-sig-verify")]
use criterion::{criterion_group, criterion_main, Criterion};

#[allow(dead_code)]
#[derive(Debug)]
pub struct EcdsaConfig {
    curve: &'static EcdsaCurve,
    digest: &'static EcdsaDigest,
    format: &'static EcdsaFormat,
    msg: Vec<u8>,
    d: Vec<u8>,
    q: Vec<u8>,
    signature: Vec<u8>,
}

impl EcdsaConfig {
    #[cfg(feature = "ring-sig-verify")]
    fn new(
        curve: &str,
        digest: &str,
        format: &str,
        msg: &[u8],
        d: &[u8],
        q: &[u8],
        signature: &[u8],
    ) -> EcdsaConfig {
        EcdsaConfig {
            curve: EcdsaCurve::from(curve),
            digest: EcdsaDigest::from(digest),
            format: EcdsaFormat::from(format),
            d: Vec::from(d),
            q: Vec::from(q),
            msg: Vec::from(msg),
            signature: Vec::from(signature),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Debug)]
pub enum EcdsaFormat {
    FIXED,
    ASN1,
}
pub const FIXED: EcdsaFormat = EcdsaFormat::FIXED;
pub const ASN1: EcdsaFormat = EcdsaFormat::ASN1;

impl EcdsaFormat {
    #[cfg(feature = "ring-sig-verify")]
    fn from(value: &str) -> &'static Self {
        match value.trim() {
            "FIXED" => &FIXED,
            "ASN1" => &ASN1,
            _ => panic!("Unrecognized padding: '{value}'"),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Debug)]
pub enum EcdsaCurve {
    P256,
    P384,
}
pub const P256: EcdsaCurve = EcdsaCurve::P256;
pub const P384: EcdsaCurve = EcdsaCurve::P384;

impl EcdsaCurve {
    #[cfg(feature = "ring-sig-verify")]
    fn from(value: &str) -> &'static Self {
        match value.trim() {
            "P-256" => &P256,
            "P-384" => &P384,
            _ => panic!("Unrecognized padding: '{value}'"),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Debug)]
pub enum EcdsaDigest {
    SHA256,
    SHA384,
    SHA512,
}
pub const SHA256: EcdsaDigest = EcdsaDigest::SHA256;
pub const SHA384: EcdsaDigest = EcdsaDigest::SHA384;
pub const SHA512: EcdsaDigest = EcdsaDigest::SHA512;

impl EcdsaDigest {
    #[cfg(feature = "ring-sig-verify")]
    fn from(value: &str) -> &'static Self {
        match value.trim() {
            "SHA256" => &SHA256,
            "SHA384" => &SHA384,
            "SHA512" => &SHA512,
            _ => panic!("Unrecognize padding: '{value}'"),
        }
    }
}

#[cfg(feature = "ring-sig-verify")]
macro_rules! benchmark_ecdsa {
    ( $pkg:ident ) => {
        paste::item! {
        mod [<$pkg _benchmarks>]  {

            use $pkg::{rand, signature};

    use crate::{EcdsaConfig, EcdsaCurve, EcdsaDigest, EcdsaFormat};
    use signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, VerificationAlgorithm, EcdsaVerificationAlgorithm};

    pub fn create_key_pair(config: &EcdsaConfig) -> EcdsaKeyPair {
        let signing = signing(config.curve, config.digest, config.format);
        EcdsaKeyPair::from_private_key_and_public_key(signing, &config.d, &config.q)
            .expect(&format!("Unable to build EcdsaKeyPair: {:?}", config))
    }

    pub fn signing(
        curve: &'static EcdsaCurve,
        digest: &'static EcdsaDigest,
        format: &'static EcdsaFormat,
    ) -> &'static EcdsaSigningAlgorithm {
        match (curve, digest, format) {
            (&crate::P256, &crate::SHA256, &crate::FIXED) => {
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING
            }
            (&crate::P256, &crate::SHA256, &crate::ASN1) => {
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING
            }
            (&crate::P384, &crate::SHA384, &crate::FIXED) => {
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING
            }
            (&crate::P384, &crate::SHA384, &crate::ASN1) => {
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING
            }
            _ => panic!(
                "Unsupported signing parameters: {:?} {:?} {:?}",
                curve, digest, format
            ),
        }
    }

    pub fn verification(
        curve: &'static EcdsaCurve,
        digest: &'static EcdsaDigest,
        format: &'static EcdsaFormat,
    ) -> &'static signature::EcdsaVerificationAlgorithm {
        match (curve, digest, format) {
            (&crate::P256, &crate::SHA256, &crate::ASN1) => &signature::ECDSA_P256_SHA256_ASN1,
            (&crate::P256, &crate::SHA256, &crate::FIXED) => &signature::ECDSA_P256_SHA256_FIXED,
            (&crate::P256, &crate::SHA384, &crate::ASN1) => &signature::ECDSA_P256_SHA384_ASN1,
            (&crate::P384, &crate::SHA256, &crate::ASN1) => &signature::ECDSA_P384_SHA256_ASN1,
            (&crate::P384, &crate::SHA384, &crate::ASN1) => &signature::ECDSA_P384_SHA384_ASN1,
            (&crate::P384, &crate::SHA384, &crate::FIXED) => &signature::ECDSA_P384_SHA384_FIXED,
            _ => panic!(
                "Unsupported verification parameters: {:?} {:?} {:?}",
                curve, digest, format
            ),
        }
    }

    pub fn get_rng() -> rand::SystemRandom {
        rand::SystemRandom::new()
    }

    pub fn sign(key_pair: &EcdsaKeyPair, rng: &dyn rand::SecureRandom, msg: &[u8]) {
        key_pair.sign(rng, msg).expect("signing failed");
    }

    pub fn verify(
        verification_alg: &EcdsaVerificationAlgorithm,
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

#[cfg(feature = "ring-sig-verify")]
benchmark_ecdsa!(aws_lc_rs);

#[cfg(all(feature = "ring-sig-verify", feature = "ring-benchmarks"))]
benchmark_ecdsa!(ring);

#[cfg(feature = "ring-sig-verify")]
fn test_ecdsa_sign(c: &mut Criterion, config: &EcdsaConfig) {
    let bench_group_name = format!(
        "ECDSA-{}-{:?}-{:?}-{:?}-sign-{}-bytes",
        config.d.len(),
        config.curve,
        config.digest,
        config.format,
        config.msg.len()
    );
    let mut group = c.benchmark_group(bench_group_name);

    let aws_rng = aws_lc_rs_benchmarks::get_rng();
    let aws_key_pair = aws_lc_rs_benchmarks::create_key_pair(config);
    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_rs_benchmarks::sign(&aws_key_pair, &aws_rng, &config.msg);
        });
    });
    #[cfg(feature = "ring-benchmarks")]
    {
        let ring_rng = ring_benchmarks::get_rng();
        let ring_key_pair = ring_benchmarks::create_key_pair(config);

        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::sign(&ring_key_pair, &ring_rng, &config.msg);
            });
        });
    }
}

#[cfg(feature = "ring-sig-verify")]
fn test_ecdsa_verify(c: &mut Criterion, config: &EcdsaConfig) {
    let bench_group_name = format!(
        "ECDSA-{}-{:?}-{:?}-{:?}-verify-{}-bytes",
        config.d.len(),
        config.curve,
        config.digest,
        config.format,
        config.msg.len()
    );
    let mut group = c.benchmark_group(bench_group_name);
    let pub_key = config.q.as_slice();
    let sig = config.signature.as_slice();

    let aws_verification_alg =
        aws_lc_rs_benchmarks::verification(config.curve, config.digest, config.format);

    group.bench_function("AWS-LC", |b| {
        b.iter(|| {
            aws_lc_rs_benchmarks::verify(aws_verification_alg, pub_key, &config.msg, sig);
        });
    });
    #[cfg(feature = "ring-benchmarks")]
    {
        let ring_verification_alg =
            ring_benchmarks::verification(config.curve, config.digest, config.format);

        group.bench_function("Ring", |b| {
            b.iter(|| {
                ring_benchmarks::verify(ring_verification_alg, pub_key, &config.msg, sig);
            });
        });
    }
}
#[cfg(feature = "ring-sig-verify")]
fn test_ecdsa(c: &mut Criterion) {
    test::run(
        test_file!("data/ecdsa_benchmarks.txt"),
        |_section, test_case| {
            let config = EcdsaConfig::new(
                test_case.consume_string("Curve").as_str(),
                test_case.consume_string("Digest").as_str(),
                test_case.consume_string("Format").as_str(),
                test_case.consume_bytes("Msg").as_slice(),
                test_case.consume_bytes("d").as_slice(),
                test_case.consume_bytes("Q").as_slice(),
                test_case.consume_bytes("Sig").as_slice(),
            );
            test_ecdsa_sign(c, &config);
            test_ecdsa_verify(c, &config);
            Ok(())
        },
    );
}
#[cfg(feature = "ring-sig-verify")]
criterion_group!(benches, test_ecdsa);
#[cfg(feature = "ring-sig-verify")]
criterion_main!(benches);

#[cfg(not(feature = "ring-sig-verify"))]
fn main() {
    println!("This bench requires feature: ring-sig-verify");
}
