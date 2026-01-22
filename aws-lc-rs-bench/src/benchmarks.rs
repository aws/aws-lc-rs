// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Benchmark definitions for aws-lc-rs cryptographic operations.
//!
//! Each benchmark measures a specific cryptographic operation that represents
//! typical usage patterns. The benchmarks are designed to be deterministic
//! when run under Valgrind's callgrind tool.

use std::hint::black_box;

use aws_lc_rs::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
    AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN,
};
use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::digest::{self, Context as DigestContext};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256, HKDF_SHA384};
use aws_lc_rs::hmac::{self, Context as HmacContext};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING, ED25519,
};

/// A benchmark definition
pub struct Benchmark {
    pub name: String,
    pub description: String,
    pub func: Box<dyn Fn() + Send + Sync>,
}

impl Benchmark {
    pub fn new<F>(name: &str, description: &str, func: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            func: Box::new(func),
        }
    }
}

/// A simple nonce sequence for benchmarking
struct BenchNonceSequence {
    counter: u64,
}

impl BenchNonceSequence {
    fn new() -> Self {
        Self { counter: 0 }
    }
}

impl NonceSequence for BenchNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Returns all benchmarks to run
pub fn all_benchmarks() -> Vec<Benchmark> {
    let mut benchmarks = Vec::new();

    // AEAD benchmarks
    benchmarks.extend(aead_benchmarks());

    // Digest benchmarks
    benchmarks.extend(digest_benchmarks());

    // HMAC benchmarks
    benchmarks.extend(hmac_benchmarks());

    // HKDF benchmarks
    benchmarks.extend(hkdf_benchmarks());

    // Agreement (key exchange) benchmarks
    benchmarks.extend(agreement_benchmarks());

    // Signature benchmarks
    benchmarks.extend(signature_benchmarks());

    benchmarks
}

/// AEAD (Authenticated Encryption) benchmarks
fn aead_benchmarks() -> Vec<Benchmark> {
    vec![
        // AES-128-GCM
        Benchmark::new(
            "aead_aes_128_gcm_seal_16b",
            "AES-128-GCM seal 16 bytes",
            || {
                let key_bytes = [0u8; 16];
                let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
                let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
                let mut data = [0u8; 16];
                let aad = Aad::from(&[]);
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(aad, &mut data)
                        .unwrap(),
                );
            },
        ),
        Benchmark::new("aead_aes_128_gcm_seal_1kb", "AES-128-GCM seal 1 KB", || {
            let key_bytes = [0u8; 16];
            let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
            let mut data = vec![0u8; 1024];
            let aad = Aad::from(&[]);
            let _ = black_box(
                sealing_key
                    .seal_in_place_separate_tag(aad, &mut data)
                    .unwrap(),
            );
        }),
        Benchmark::new("aead_aes_128_gcm_seal_8kb", "AES-128-GCM seal 8 KB", || {
            let key_bytes = [0u8; 16];
            let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
            let mut data = vec![0u8; 8192];
            let aad = Aad::from(&[]);
            let _ = black_box(
                sealing_key
                    .seal_in_place_separate_tag(aad, &mut data)
                    .unwrap(),
            );
        }),
        Benchmark::new("aead_aes_128_gcm_open_1kb", "AES-128-GCM open 1 KB", || {
            let key_bytes = [0u8; 16];
            // First seal the data
            let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
            let mut data = vec![0u8; 1024];
            let aad = Aad::from(&[]);
            sealing_key
                .seal_in_place_append_tag(aad, &mut data)
                .unwrap();

            // Now open it
            let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let mut opening_key = OpeningKey::new(key, BenchNonceSequence::new());
            let aad = Aad::from(&[]);
            black_box(opening_key.open_in_place(aad, &mut data).unwrap());
        }),
        // AES-256-GCM
        Benchmark::new("aead_aes_256_gcm_seal_1kb", "AES-256-GCM seal 1 KB", || {
            let key_bytes = [0u8; 32];
            let key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
            let mut data = vec![0u8; 1024];
            let aad = Aad::from(&[]);
            let _ = black_box(
                sealing_key
                    .seal_in_place_separate_tag(aad, &mut data)
                    .unwrap(),
            );
        }),
        Benchmark::new("aead_aes_256_gcm_seal_8kb", "AES-256-GCM seal 8 KB", || {
            let key_bytes = [0u8; 32];
            let key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
            let mut data = vec![0u8; 8192];
            let aad = Aad::from(&[]);
            let _ = black_box(
                sealing_key
                    .seal_in_place_separate_tag(aad, &mut data)
                    .unwrap(),
            );
        }),
        // ChaCha20-Poly1305
        Benchmark::new(
            "aead_chacha20_poly1305_seal_1kb",
            "ChaCha20-Poly1305 seal 1 KB",
            || {
                let key_bytes = [0u8; 32];
                let key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
                let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
                let mut data = vec![0u8; 1024];
                let aad = Aad::from(&[]);
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(aad, &mut data)
                        .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "aead_chacha20_poly1305_seal_8kb",
            "ChaCha20-Poly1305 seal 8 KB",
            || {
                let key_bytes = [0u8; 32];
                let key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
                let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
                let mut data = vec![0u8; 8192];
                let aad = Aad::from(&[]);
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(aad, &mut data)
                        .unwrap(),
                );
            },
        ),
    ]
}

/// Digest (hashing) benchmarks
fn digest_benchmarks() -> Vec<Benchmark> {
    vec![
        Benchmark::new("digest_sha256_16b", "SHA-256 hash 16 bytes", || {
            let data = [0u8; 16];
            black_box(digest::digest(&digest::SHA256, &data));
        }),
        Benchmark::new("digest_sha256_256b", "SHA-256 hash 256 bytes", || {
            let data = [0u8; 256];
            black_box(digest::digest(&digest::SHA256, &data));
        }),
        Benchmark::new("digest_sha256_1kb", "SHA-256 hash 1 KB", || {
            let data = [0u8; 1024];
            black_box(digest::digest(&digest::SHA256, &data));
        }),
        Benchmark::new("digest_sha256_8kb", "SHA-256 hash 8 KB", || {
            let data = vec![0u8; 8192];
            black_box(digest::digest(&digest::SHA256, &data));
        }),
        Benchmark::new("digest_sha256_1mb", "SHA-256 hash 1 MB", || {
            let data = vec![0u8; 1024 * 1024];
            black_box(digest::digest(&digest::SHA256, &data));
        }),
        Benchmark::new("digest_sha384_1kb", "SHA-384 hash 1 KB", || {
            let data = [0u8; 1024];
            black_box(digest::digest(&digest::SHA384, &data));
        }),
        Benchmark::new("digest_sha512_1kb", "SHA-512 hash 1 KB", || {
            let data = [0u8; 1024];
            black_box(digest::digest(&digest::SHA512, &data));
        }),
        // Incremental hashing
        Benchmark::new(
            "digest_sha256_incremental_1kb",
            "SHA-256 incremental hash 1 KB (4 chunks)",
            || {
                let data = [0u8; 256];
                let mut ctx = DigestContext::new(&digest::SHA256);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                black_box(ctx.finish());
            },
        ),
    ]
}

/// HMAC benchmarks
fn hmac_benchmarks() -> Vec<Benchmark> {
    vec![
        Benchmark::new("hmac_sha256_16b", "HMAC-SHA256 16 bytes", || {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
            let data = [0u8; 16];
            black_box(hmac::sign(&key, &data));
        }),
        Benchmark::new("hmac_sha256_256b", "HMAC-SHA256 256 bytes", || {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
            let data = [0u8; 256];
            black_box(hmac::sign(&key, &data));
        }),
        Benchmark::new("hmac_sha256_1kb", "HMAC-SHA256 1 KB", || {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
            let data = [0u8; 1024];
            black_box(hmac::sign(&key, &data));
        }),
        Benchmark::new("hmac_sha384_1kb", "HMAC-SHA384 1 KB", || {
            let key = hmac::Key::new(hmac::HMAC_SHA384, &[0u8; 48]);
            let data = [0u8; 1024];
            black_box(hmac::sign(&key, &data));
        }),
        Benchmark::new("hmac_sha512_1kb", "HMAC-SHA512 1 KB", || {
            let key = hmac::Key::new(hmac::HMAC_SHA512, &[0u8; 64]);
            let data = [0u8; 1024];
            black_box(hmac::sign(&key, &data));
        }),
        // Incremental HMAC
        Benchmark::new(
            "hmac_sha256_incremental_1kb",
            "HMAC-SHA256 incremental 1 KB (4 chunks)",
            || {
                let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
                let data = [0u8; 256];
                let mut ctx = HmacContext::with_key(&key);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                black_box(ctx.sign());
            },
        ),
        // HMAC verify
        Benchmark::new("hmac_sha256_verify_1kb", "HMAC-SHA256 verify 1 KB", || {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
            let data = [0u8; 1024];
            let tag = hmac::sign(&key, &data);
            black_box(hmac::verify(&key, &data, tag.as_ref()).unwrap());
        }),
    ]
}

/// HKDF benchmarks
fn hkdf_benchmarks() -> Vec<Benchmark> {
    vec![
        Benchmark::new(
            "hkdf_sha256_derive_32b",
            "HKDF-SHA256 derive 32 bytes",
            || {
                let salt = Salt::new(HKDF_SHA256, &[0u8; 32]);
                let prk = salt.extract(&[0u8; 32]);
                let okm = prk.expand(&[b"info"], HkdfOutputLen(32)).unwrap();
                let mut out = [0u8; 32];
                black_box(okm.fill(&mut out).unwrap());
            },
        ),
        Benchmark::new(
            "hkdf_sha256_derive_64b",
            "HKDF-SHA256 derive 64 bytes",
            || {
                let salt = Salt::new(HKDF_SHA256, &[0u8; 32]);
                let prk = salt.extract(&[0u8; 32]);
                let okm = prk.expand(&[b"info"], HkdfOutputLen(64)).unwrap();
                let mut out = [0u8; 64];
                black_box(okm.fill(&mut out).unwrap());
            },
        ),
        Benchmark::new(
            "hkdf_sha384_derive_48b",
            "HKDF-SHA384 derive 48 bytes",
            || {
                let salt = Salt::new(HKDF_SHA384, &[0u8; 48]);
                let prk = salt.extract(&[0u8; 48]);
                let okm = prk.expand(&[b"info"], HkdfOutputLen(48)).unwrap();
                let mut out = [0u8; 48];
                black_box(okm.fill(&mut out).unwrap());
            },
        ),
    ]
}

/// HKDF output length wrapper
struct HkdfOutputLen(usize);

impl aws_lc_rs::hkdf::KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Agreement (key exchange) benchmarks
fn agreement_benchmarks() -> Vec<Benchmark> {
    vec![
        Benchmark::new("agreement_x25519_keygen", "X25519 key generation", || {
            let rng = SystemRandom::new();
            black_box(EphemeralPrivateKey::generate(&X25519, &rng).unwrap());
        }),
        Benchmark::new(
            "agreement_x25519_agree",
            "X25519 key agreement",
            move || {
                let rng = SystemRandom::new();
                // Generate both keys
                let my_private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
                let peer_private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
                let peer_public = peer_private.compute_public_key().unwrap();
                let peer_public_bytes = peer_public.as_ref();

                let peer_public = UnparsedPublicKey::new(&X25519, peer_public_bytes);
                black_box(
                    agreement::agree_ephemeral(my_private, &peer_public, (), |key| {
                        Ok(Vec::from(key))
                    })
                    .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "agreement_ecdh_p256_keygen",
            "ECDH P-256 key generation",
            || {
                let rng = SystemRandom::new();
                black_box(EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap());
            },
        ),
        Benchmark::new(
            "agreement_ecdh_p256_agree",
            "ECDH P-256 key agreement",
            move || {
                let rng = SystemRandom::new();
                let my_private =
                    EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
                let peer_private =
                    EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
                let peer_public = peer_private.compute_public_key().unwrap();
                let peer_public_bytes = peer_public.as_ref();

                let peer_public = UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_bytes);
                black_box(
                    agreement::agree_ephemeral(my_private, &peer_public, (), |key| {
                        Ok(Vec::from(key))
                    })
                    .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "agreement_ecdh_p384_keygen",
            "ECDH P-384 key generation",
            || {
                let rng = SystemRandom::new();
                black_box(EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap());
            },
        ),
        Benchmark::new(
            "agreement_ecdh_p384_agree",
            "ECDH P-384 key agreement",
            move || {
                let rng = SystemRandom::new();
                let my_private =
                    EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
                let peer_private =
                    EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
                let peer_public = peer_private.compute_public_key().unwrap();
                let peer_public_bytes = peer_public.as_ref();

                let peer_public = UnparsedPublicKey::new(&agreement::ECDH_P384, peer_public_bytes);
                black_box(
                    agreement::agree_ephemeral(my_private, &peer_public, (), |key| {
                        Ok(Vec::from(key))
                    })
                    .unwrap(),
                );
            },
        ),
    ]
}

/// Signature benchmarks
fn signature_benchmarks() -> Vec<Benchmark> {
    // Use existing test key from the repository for Ed25519
    const ED25519_PKCS8_V1: &[u8] = include_bytes!("test_data/ed25519_pkcs8_v1.der");

    // Use existing test key from the repository for ECDSA P-256
    const ECDSA_P256_PKCS8: &[u8] = include_bytes!("test_data/ecdsa_p256_pkcs8.der");

    // Use existing test key from the repository for RSA 2048
    const RSA_2048_PKCS8: &[u8] = include_bytes!("test_data/rsa_2048_pkcs8.der");

    let message = [0u8; 32];

    vec![
        // Ed25519
        Benchmark::new("signature_ed25519_keygen", "Ed25519 key generation", || {
            let rng = SystemRandom::new();
            let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            black_box(Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap());
        }),
        Benchmark::new(
            "signature_ed25519_sign",
            "Ed25519 sign 32 bytes",
            move || {
                let key_pair = Ed25519KeyPair::from_pkcs8(ED25519_PKCS8_V1).unwrap();
                black_box(key_pair.sign(&message));
            },
        ),
        Benchmark::new(
            "signature_ed25519_verify",
            "Ed25519 verify 32 bytes",
            move || {
                let key_pair = Ed25519KeyPair::from_pkcs8(ED25519_PKCS8_V1).unwrap();
                let sig = key_pair.sign(&message);
                let public_key = key_pair.public_key();
                let public_key = signature::UnparsedPublicKey::new(&ED25519, public_key.as_ref());
                black_box(public_key.verify(&message, sig.as_ref()).unwrap());
            },
        ),
        // ECDSA P-256
        Benchmark::new(
            "signature_ecdsa_p256_keygen",
            "ECDSA P-256 key generation",
            || {
                let rng = SystemRandom::new();
                let pkcs8_bytes =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
                black_box(
                    EcdsaKeyPair::from_pkcs8(
                        &ECDSA_P256_SHA256_FIXED_SIGNING,
                        pkcs8_bytes.as_ref(),
                    )
                    .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "signature_ecdsa_p256_sign",
            "ECDSA P-256 sign 32 bytes",
            move || {
                let rng = SystemRandom::new();
                let key_pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_PKCS8)
                        .unwrap();
                black_box(key_pair.sign(&rng, &message).unwrap());
            },
        ),
        Benchmark::new(
            "signature_ecdsa_p256_verify",
            "ECDSA P-256 verify 32 bytes",
            move || {
                let rng = SystemRandom::new();
                let key_pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_PKCS8)
                        .unwrap();
                let sig = key_pair.sign(&rng, &message).unwrap();
                let public_key = key_pair.public_key();
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_FIXED,
                    public_key.as_ref(),
                );
                black_box(public_key.verify(&message, sig.as_ref()).unwrap());
            },
        ),
        // ECDSA P-384 - generate key at runtime since we don't have a pre-generated one
        Benchmark::new(
            "signature_ecdsa_p384_keygen",
            "ECDSA P-384 key generation",
            || {
                let rng = SystemRandom::new();
                let pkcs8_bytes =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
                black_box(
                    EcdsaKeyPair::from_pkcs8(
                        &ECDSA_P384_SHA384_FIXED_SIGNING,
                        pkcs8_bytes.as_ref(),
                    )
                    .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "signature_ecdsa_p384_sign",
            "ECDSA P-384 sign 32 bytes",
            move || {
                let rng = SystemRandom::new();
                // Generate key at runtime
                let pkcs8_bytes =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                )
                .unwrap();
                black_box(key_pair.sign(&rng, &message).unwrap());
            },
        ),
        Benchmark::new(
            "signature_ecdsa_p384_verify",
            "ECDSA P-384 verify 32 bytes",
            move || {
                let rng = SystemRandom::new();
                // Generate key at runtime
                let pkcs8_bytes =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                )
                .unwrap();
                let sig = key_pair.sign(&rng, &message).unwrap();
                let public_key = key_pair.public_key();
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P384_SHA384_FIXED,
                    public_key.as_ref(),
                );
                black_box(public_key.verify(&message, sig.as_ref()).unwrap());
            },
        ),
        // RSA 2048
        Benchmark::new(
            "signature_rsa_2048_pkcs1_sign",
            "RSA-2048 PKCS#1 sign 32 bytes",
            move || {
                let rng = SystemRandom::new();
                let key_pair = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
                let mut sig = vec![0u8; key_pair.public_modulus_len()];
                black_box(
                    key_pair
                        .sign(&signature::RSA_PKCS1_SHA256, &rng, &message, &mut sig)
                        .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "signature_rsa_2048_pkcs1_verify",
            "RSA-2048 PKCS#1 verify 32 bytes",
            move || {
                let rng = SystemRandom::new();
                let key_pair = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
                let mut sig = vec![0u8; key_pair.public_modulus_len()];
                key_pair
                    .sign(&signature::RSA_PKCS1_SHA256, &rng, &message, &mut sig)
                    .unwrap();
                let public_key = key_pair.public_key();
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    public_key.as_ref(),
                );
                black_box(public_key.verify(&message, &sig).unwrap());
            },
        ),
        Benchmark::new(
            "signature_rsa_2048_pss_sign",
            "RSA-2048 PSS sign 32 bytes",
            move || {
                let rng = SystemRandom::new();
                let key_pair = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
                let mut sig = vec![0u8; key_pair.public_modulus_len()];
                black_box(
                    key_pair
                        .sign(&signature::RSA_PSS_SHA256, &rng, &message, &mut sig)
                        .unwrap(),
                );
            },
        ),
        Benchmark::new(
            "signature_rsa_2048_pss_verify",
            "RSA-2048 PSS verify 32 bytes",
            move || {
                let rng = SystemRandom::new();
                let key_pair = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
                let mut sig = vec![0u8; key_pair.public_modulus_len()];
                key_pair
                    .sign(&signature::RSA_PSS_SHA256, &rng, &message, &mut sig)
                    .unwrap();
                let public_key = key_pair.public_key();
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PSS_2048_8192_SHA256,
                    public_key.as_ref(),
                );
                black_box(public_key.verify(&message, &sig).unwrap());
            },
        ),
    ]
}
