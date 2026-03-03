// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Benchmark definitions for aws-lc-rs cryptographic operations.
//!
//! Each benchmark measures a specific cryptographic operation that represents
//! typical usage patterns. The benchmarks are designed to be deterministic
//! when run under Valgrind's callgrind tool.
//!
//! Setup steps (key creation, RNG initialization, etc.) are performed outside
//! the benchmark closure wherever possible, so that only the target operation
//! is measured. Dedicated key-creation benchmarks are provided for operations
//! whose setup cost was extracted.

use std::hint::black_box;

use aws_lc_rs::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
        AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN,
    },
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    digest::{self, Context as DigestContext},
    error::Unspecified,
    hkdf::{Salt, HKDF_SHA256, HKDF_SHA384},
    hmac::{self, Context as HmacContext},
    rand::SystemRandom,
    signature::{
        self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_FIXED_SIGNING, ED25519,
    },
};

/// A benchmark definition
pub struct Benchmark {
    pub name: String,
    pub description: String,
    pub func: Box<dyn FnMut() + Send>,
}

impl Benchmark {
    pub fn new<F>(name: &str, description: &str, func: F) -> Self
    where
        F: FnMut() + Send + 'static,
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
    let mut benchmarks = Vec::new();

    // --- Key creation benchmarks ---

    benchmarks.push(Benchmark::new(
        "aead_aes_128_gcm_key_create",
        "AES-128-GCM key creation",
        || {
            let key = UnboundKey::new(&AES_128_GCM, &[0u8; 16]).unwrap();
            black_box(SealingKey::new(key, BenchNonceSequence::new()));
        },
    ));

    benchmarks.push(Benchmark::new(
        "aead_aes_256_gcm_key_create",
        "AES-256-GCM key creation",
        || {
            let key = UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap();
            black_box(SealingKey::new(key, BenchNonceSequence::new()));
        },
    ));

    benchmarks.push(Benchmark::new(
        "aead_chacha20_poly1305_key_create",
        "ChaCha20-Poly1305 key creation",
        || {
            let key = UnboundKey::new(&CHACHA20_POLY1305, &[0u8; 32]).unwrap();
            black_box(SealingKey::new(key, BenchNonceSequence::new()));
        },
    ));

    // --- AES-128-GCM seal ---

    {
        let key = UnboundKey::new(&AES_128_GCM, &[0u8; 16]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = [0u8; 16];
        benchmarks.push(Benchmark::new(
            "aead_aes_128_gcm_seal_16b",
            "AES-128-GCM seal 16 bytes",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    {
        let key = UnboundKey::new(&AES_128_GCM, &[0u8; 16]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = vec![0u8; 1024];
        benchmarks.push(Benchmark::new(
            "aead_aes_128_gcm_seal_1kb",
            "AES-128-GCM seal 1 KB",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    {
        let key = UnboundKey::new(&AES_128_GCM, &[0u8; 16]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = vec![0u8; 8192];
        benchmarks.push(Benchmark::new(
            "aead_aes_128_gcm_seal_8kb",
            "AES-128-GCM seal 8 KB",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    // --- AES-128-GCM open ---

    {
        // Pre-seal the data outside the benchmark closure
        let key_bytes = [0u8; 16];
        let seal_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
        let mut sk = SealingKey::new(seal_key, BenchNonceSequence::new());
        let mut sealed_data = vec![0u8; 1024];
        sk.seal_in_place_append_tag(Aad::from(&[]), &mut sealed_data)
            .unwrap();

        // Key creation remains inside the closure because OpeningKey requires &mut self
        // and the nonce must match the sealed data. The key creation cost is measured
        // separately by the aead_aes_128_gcm_key_create benchmark.
        benchmarks.push(Benchmark::new(
            "aead_aes_128_gcm_open_1kb",
            "AES-128-GCM open 1 KB (includes key creation; see aead_aes_128_gcm_key_create)",
            move || {
                let mut data = sealed_data.clone();
                let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
                let mut opening_key = OpeningKey::new(key, BenchNonceSequence::new());
                black_box(
                    opening_key
                        .open_in_place(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    // --- AES-256-GCM seal ---

    {
        let key = UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = vec![0u8; 1024];
        benchmarks.push(Benchmark::new(
            "aead_aes_256_gcm_seal_1kb",
            "AES-256-GCM seal 1 KB",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    {
        let key = UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = vec![0u8; 8192];
        benchmarks.push(Benchmark::new(
            "aead_aes_256_gcm_seal_8kb",
            "AES-256-GCM seal 8 KB",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    // --- ChaCha20-Poly1305 seal ---

    {
        let key = UnboundKey::new(&CHACHA20_POLY1305, &[0u8; 32]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = vec![0u8; 1024];
        benchmarks.push(Benchmark::new(
            "aead_chacha20_poly1305_seal_1kb",
            "ChaCha20-Poly1305 seal 1 KB",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    {
        let key = UnboundKey::new(&CHACHA20_POLY1305, &[0u8; 32]).unwrap();
        let mut sealing_key = SealingKey::new(key, BenchNonceSequence::new());
        let mut data = vec![0u8; 8192];
        benchmarks.push(Benchmark::new(
            "aead_chacha20_poly1305_seal_8kb",
            "ChaCha20-Poly1305 seal 8 KB",
            move || {
                let _ = black_box(
                    sealing_key
                        .seal_in_place_separate_tag(Aad::from(&[]), &mut data)
                        .unwrap(),
                );
            },
        ));
    }

    benchmarks
}

/// Digest (hashing) benchmarks
fn digest_benchmarks() -> Vec<Benchmark> {
    let mut benchmarks = Vec::new();

    {
        let data = [0u8; 16];
        benchmarks.push(Benchmark::new(
            "digest_sha256_16b",
            "SHA-256 hash 16 bytes",
            move || {
                black_box(digest::digest(&digest::SHA256, &data));
            },
        ));
    }

    {
        let data = [0u8; 256];
        benchmarks.push(Benchmark::new(
            "digest_sha256_256b",
            "SHA-256 hash 256 bytes",
            move || {
                black_box(digest::digest(&digest::SHA256, &data));
            },
        ));
    }

    {
        let data = [0u8; 1024];
        benchmarks.push(Benchmark::new(
            "digest_sha256_1kb",
            "SHA-256 hash 1 KB",
            move || {
                black_box(digest::digest(&digest::SHA256, &data));
            },
        ));
    }

    {
        let data = vec![0u8; 8192];
        benchmarks.push(Benchmark::new(
            "digest_sha256_8kb",
            "SHA-256 hash 8 KB",
            move || {
                black_box(digest::digest(&digest::SHA256, &data));
            },
        ));
    }

    {
        let data = vec![0u8; 1024 * 1024];
        benchmarks.push(Benchmark::new(
            "digest_sha256_1mb",
            "SHA-256 hash 1 MB",
            move || {
                black_box(digest::digest(&digest::SHA256, &data));
            },
        ));
    }

    {
        let data = [0u8; 1024];
        benchmarks.push(Benchmark::new(
            "digest_sha384_1kb",
            "SHA-384 hash 1 KB",
            move || {
                black_box(digest::digest(&digest::SHA384, &data));
            },
        ));
    }

    {
        let data = [0u8; 1024];
        benchmarks.push(Benchmark::new(
            "digest_sha512_1kb",
            "SHA-512 hash 1 KB",
            move || {
                black_box(digest::digest(&digest::SHA512, &data));
            },
        ));
    }

    // Incremental hashing
    {
        let data = [0u8; 256];
        benchmarks.push(Benchmark::new(
            "digest_sha256_incremental_1kb",
            "SHA-256 incremental hash 1 KB (4 chunks)",
            move || {
                let mut ctx = DigestContext::new(&digest::SHA256);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                black_box(ctx.finish());
            },
        ));
    }

    benchmarks
}

/// HMAC benchmarks
fn hmac_benchmarks() -> Vec<Benchmark> {
    let mut benchmarks = Vec::new();

    // --- Key creation benchmarks ---

    benchmarks.push(Benchmark::new(
        "hmac_sha256_key_create",
        "HMAC-SHA256 key creation",
        || {
            black_box(hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]));
        },
    ));

    benchmarks.push(Benchmark::new(
        "hmac_sha384_key_create",
        "HMAC-SHA384 key creation",
        || {
            black_box(hmac::Key::new(hmac::HMAC_SHA384, &[0u8; 48]));
        },
    ));

    benchmarks.push(Benchmark::new(
        "hmac_sha512_key_create",
        "HMAC-SHA512 key creation",
        || {
            black_box(hmac::Key::new(hmac::HMAC_SHA512, &[0u8; 64]));
        },
    ));

    // --- HMAC sign ---

    {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        benchmarks.push(Benchmark::new(
            "hmac_sha256_16b",
            "HMAC-SHA256 16 bytes",
            move || {
                black_box(hmac::sign(&key, &[0u8; 16]));
            },
        ));
    }

    {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        benchmarks.push(Benchmark::new(
            "hmac_sha256_256b",
            "HMAC-SHA256 256 bytes",
            move || {
                black_box(hmac::sign(&key, &[0u8; 256]));
            },
        ));
    }

    {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        benchmarks.push(Benchmark::new(
            "hmac_sha256_1kb",
            "HMAC-SHA256 1 KB",
            move || {
                black_box(hmac::sign(&key, &[0u8; 1024]));
            },
        ));
    }

    {
        let key = hmac::Key::new(hmac::HMAC_SHA384, &[0u8; 48]);
        benchmarks.push(Benchmark::new(
            "hmac_sha384_1kb",
            "HMAC-SHA384 1 KB",
            move || {
                black_box(hmac::sign(&key, &[0u8; 1024]));
            },
        ));
    }

    {
        let key = hmac::Key::new(hmac::HMAC_SHA512, &[0u8; 64]);
        benchmarks.push(Benchmark::new(
            "hmac_sha512_1kb",
            "HMAC-SHA512 1 KB",
            move || {
                black_box(hmac::sign(&key, &[0u8; 1024]));
            },
        ));
    }

    // --- Incremental HMAC ---

    {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        benchmarks.push(Benchmark::new(
            "hmac_sha256_incremental_1kb",
            "HMAC-SHA256 incremental 1 KB (4 chunks)",
            move || {
                let data = [0u8; 256];
                let mut ctx = HmacContext::with_key(&key);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                ctx.update(&data);
                black_box(ctx.sign());
            },
        ));
    }

    // --- HMAC verify ---

    {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let data = [0u8; 1024];
        let tag = hmac::sign(&key, &data);
        let tag_bytes: Vec<u8> = tag.as_ref().to_vec();
        benchmarks.push(Benchmark::new(
            "hmac_sha256_verify_1kb",
            "HMAC-SHA256 verify 1 KB",
            move || {
                black_box(hmac::verify(&key, &data, tag_bytes.as_ref()).unwrap());
            },
        ));
    }

    benchmarks
}

/// HKDF benchmarks — measures full derivation pipeline (salt → extract → expand → fill)
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
    let mut benchmarks = Vec::new();

    // --- X25519 ---

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "agreement_x25519_keygen",
            "X25519 key generation",
            move || {
                black_box(EphemeralPrivateKey::generate(&X25519, &rng).unwrap());
            },
        ));
    }

    {
        let rng = SystemRandom::new();
        // Pre-generate peer public key outside the closure
        let peer_private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let peer_public_bytes: Vec<u8> =
            peer_private.compute_public_key().unwrap().as_ref().to_vec();
        let peer_public = UnparsedPublicKey::new(&X25519, peer_public_bytes);

        benchmarks.push(Benchmark::new(
            "agreement_x25519_agree",
            "X25519 key agreement (includes keygen; see agreement_x25519_keygen)",
            move || {
                // Own keygen is required because agree_ephemeral consumes the private key.
                // The keygen cost is measured separately by agreement_x25519_keygen.
                let my_private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
                black_box(
                    agreement::agree_ephemeral(my_private, &peer_public, (), |key| {
                        Ok(Vec::from(key))
                    })
                    .unwrap(),
                );
            },
        ));
    }

    // --- ECDH P-256 ---

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "agreement_ecdh_p256_keygen",
            "ECDH P-256 key generation",
            move || {
                black_box(EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap());
            },
        ));
    }

    {
        let rng = SystemRandom::new();
        let peer_private = EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let peer_public_bytes: Vec<u8> =
            peer_private.compute_public_key().unwrap().as_ref().to_vec();
        let peer_public = UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_bytes);

        benchmarks.push(Benchmark::new(
            "agreement_ecdh_p256_agree",
            "ECDH P-256 key agreement (includes keygen; see agreement_ecdh_p256_keygen)",
            move || {
                // Own keygen is required because agree_ephemeral consumes the private key.
                // The keygen cost is measured separately by agreement_ecdh_p256_keygen.
                let my_private =
                    EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
                black_box(
                    agreement::agree_ephemeral(my_private, &peer_public, (), |key| {
                        Ok(Vec::from(key))
                    })
                    .unwrap(),
                );
            },
        ));
    }

    // --- ECDH P-384 ---

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "agreement_ecdh_p384_keygen",
            "ECDH P-384 key generation",
            move || {
                black_box(EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap());
            },
        ));
    }

    {
        let rng = SystemRandom::new();
        let peer_private = EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
        let peer_public_bytes: Vec<u8> =
            peer_private.compute_public_key().unwrap().as_ref().to_vec();
        let peer_public = UnparsedPublicKey::new(&agreement::ECDH_P384, peer_public_bytes);

        benchmarks.push(Benchmark::new(
            "agreement_ecdh_p384_agree",
            "ECDH P-384 key agreement (includes keygen; see agreement_ecdh_p384_keygen)",
            move || {
                // Own keygen is required because agree_ephemeral consumes the private key.
                // The keygen cost is measured separately by agreement_ecdh_p384_keygen.
                let my_private =
                    EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
                black_box(
                    agreement::agree_ephemeral(my_private, &peer_public, (), |key| {
                        Ok(Vec::from(key))
                    })
                    .unwrap(),
                );
            },
        ));
    }

    benchmarks
}

/// Signature benchmarks
fn signature_benchmarks() -> Vec<Benchmark> {
    // Pre-generated test keys
    const ED25519_PKCS8_V1: &[u8] = include_bytes!("test_data/ed25519_pkcs8_v1.der");
    const ECDSA_P256_PKCS8: &[u8] = include_bytes!("test_data/ecdsa_p256_pkcs8.der");
    const RSA_2048_PKCS8: &[u8] = include_bytes!("test_data/rsa_2048_pkcs8.der");

    let mut benchmarks = Vec::new();

    let rng = SystemRandom::new();
    let message = [0u8; 32];

    // --- Ed25519 setup ---
    let ed25519_sign_key = Ed25519KeyPair::from_pkcs8(ED25519_PKCS8_V1).unwrap();
    let ed25519_verify_setup = Ed25519KeyPair::from_pkcs8(ED25519_PKCS8_V1).unwrap();
    let ed25519_sig_bytes: Vec<u8> = ed25519_verify_setup.sign(&message).as_ref().to_vec();
    let ed25519_pub_bytes: Vec<u8> = ed25519_verify_setup.public_key().as_ref().to_vec();

    // --- ECDSA P-256 setup ---
    let ecdsa_p256_sign_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_PKCS8).unwrap();
    let ecdsa_p256_verify_setup =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_PKCS8).unwrap();
    let ecdsa_p256_sig_bytes: Vec<u8> = ecdsa_p256_verify_setup
        .sign(&rng, &message)
        .unwrap()
        .as_ref()
        .to_vec();
    let ecdsa_p256_pub_bytes: Vec<u8> = ecdsa_p256_verify_setup.public_key().as_ref().to_vec();

    // --- ECDSA P-384 setup (generate key at setup time) ---
    let p384_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let p384_pkcs8_bytes: Vec<u8> = p384_pkcs8.as_ref().to_vec();
    let ecdsa_p384_sign_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &p384_pkcs8_bytes).unwrap();
    let ecdsa_p384_verify_setup =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &p384_pkcs8_bytes).unwrap();
    let ecdsa_p384_sig_bytes: Vec<u8> = ecdsa_p384_verify_setup
        .sign(&rng, &message)
        .unwrap()
        .as_ref()
        .to_vec();
    let ecdsa_p384_pub_bytes: Vec<u8> = ecdsa_p384_verify_setup.public_key().as_ref().to_vec();
    let p384_pkcs8_for_bench = p384_pkcs8_bytes;

    // --- RSA-2048 setup ---
    let rsa_pkcs1_sign_key = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
    let rsa_modulus_len = rsa_pkcs1_sign_key.public_modulus_len();

    let rsa_pkcs1_verify_setup = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
    let mut rsa_pkcs1_sig_buf = vec![0u8; rsa_modulus_len];
    rsa_pkcs1_verify_setup
        .sign(
            &signature::RSA_PKCS1_SHA256,
            &rng,
            &message,
            &mut rsa_pkcs1_sig_buf,
        )
        .unwrap();
    let rsa_pkcs1_sig_bytes = rsa_pkcs1_sig_buf;
    let rsa_pkcs1_pub_bytes: Vec<u8> = rsa_pkcs1_verify_setup.public_key().as_ref().to_vec();

    let rsa_pss_sign_key = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
    let rsa_pss_verify_setup = RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap();
    let mut rsa_pss_sig_buf = vec![0u8; rsa_modulus_len];
    rsa_pss_verify_setup
        .sign(
            &signature::RSA_PSS_SHA256,
            &rng,
            &message,
            &mut rsa_pss_sig_buf,
        )
        .unwrap();
    let rsa_pss_sig_bytes = rsa_pss_sig_buf;
    let rsa_pss_pub_bytes: Vec<u8> = rsa_pss_verify_setup.public_key().as_ref().to_vec();

    // === Ed25519 ===

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "signature_ed25519_keygen",
            "Ed25519 key pair generation (PKCS#8)",
            move || {
                black_box(Ed25519KeyPair::generate_pkcs8(&rng).unwrap());
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_ed25519_from_pkcs8",
        "Ed25519 parse key from PKCS#8",
        || {
            black_box(Ed25519KeyPair::from_pkcs8(ED25519_PKCS8_V1).unwrap());
        },
    ));

    benchmarks.push(Benchmark::new(
        "signature_ed25519_sign",
        "Ed25519 sign 32 bytes",
        move || {
            black_box(ed25519_sign_key.sign(&message));
        },
    ));

    benchmarks.push(Benchmark::new(
        "signature_ed25519_verify",
        "Ed25519 verify 32 bytes",
        move || {
            let public_key = signature::UnparsedPublicKey::new(&ED25519, &ed25519_pub_bytes);
            black_box(public_key.verify(&message, &ed25519_sig_bytes).unwrap());
        },
    ));

    // === ECDSA P-256 ===

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "signature_ecdsa_p256_keygen",
            "ECDSA P-256 key pair generation (PKCS#8)",
            move || {
                black_box(
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap(),
                );
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_ecdsa_p256_from_pkcs8",
        "ECDSA P-256 parse key from PKCS#8",
        || {
            black_box(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_PKCS8)
                    .unwrap(),
            );
        },
    ));

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "signature_ecdsa_p256_sign",
            "ECDSA P-256 sign 32 bytes",
            move || {
                black_box(ecdsa_p256_sign_key.sign(&rng, &message).unwrap());
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_ecdsa_p256_verify",
        "ECDSA P-256 verify 32 bytes",
        move || {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_FIXED,
                &ecdsa_p256_pub_bytes,
            );
            black_box(public_key.verify(&message, &ecdsa_p256_sig_bytes).unwrap());
        },
    ));

    // === ECDSA P-384 ===

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "signature_ecdsa_p384_keygen",
            "ECDSA P-384 key pair generation (PKCS#8)",
            move || {
                black_box(
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap(),
                );
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_ecdsa_p384_from_pkcs8",
        "ECDSA P-384 parse key from PKCS#8",
        move || {
            black_box(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &p384_pkcs8_for_bench)
                    .unwrap(),
            );
        },
    ));

    {
        let rng = SystemRandom::new();
        benchmarks.push(Benchmark::new(
            "signature_ecdsa_p384_sign",
            "ECDSA P-384 sign 32 bytes",
            move || {
                black_box(ecdsa_p384_sign_key.sign(&rng, &message).unwrap());
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_ecdsa_p384_verify",
        "ECDSA P-384 verify 32 bytes",
        move || {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_FIXED,
                &ecdsa_p384_pub_bytes,
            );
            black_box(public_key.verify(&message, &ecdsa_p384_sig_bytes).unwrap());
        },
    ));

    // === RSA-2048 ===

    benchmarks.push(Benchmark::new(
        "signature_rsa_2048_from_pkcs8",
        "RSA-2048 parse key from PKCS#8",
        || {
            black_box(RsaKeyPair::from_pkcs8(RSA_2048_PKCS8).unwrap());
        },
    ));

    {
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; rsa_modulus_len];
        benchmarks.push(Benchmark::new(
            "signature_rsa_2048_pkcs1_sign",
            "RSA-2048 PKCS#1 sign 32 bytes",
            move || {
                black_box(
                    rsa_pkcs1_sign_key
                        .sign(&signature::RSA_PKCS1_SHA256, &rng, &message, &mut sig)
                        .unwrap(),
                );
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_rsa_2048_pkcs1_verify",
        "RSA-2048 PKCS#1 verify 32 bytes",
        move || {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                &rsa_pkcs1_pub_bytes,
            );
            black_box(public_key.verify(&message, &rsa_pkcs1_sig_bytes).unwrap());
        },
    ));

    {
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; rsa_modulus_len];
        benchmarks.push(Benchmark::new(
            "signature_rsa_2048_pss_sign",
            "RSA-2048 PSS sign 32 bytes",
            move || {
                black_box(
                    rsa_pss_sign_key
                        .sign(&signature::RSA_PSS_SHA256, &rng, &message, &mut sig)
                        .unwrap(),
                );
            },
        ));
    }

    benchmarks.push(Benchmark::new(
        "signature_rsa_2048_pss_verify",
        "RSA-2048 PSS verify 32 bytes",
        move || {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PSS_2048_8192_SHA256,
                &rsa_pss_pub_bytes,
            );
            black_box(public_key.verify(&message, &rsa_pss_sig_bytes).unwrap());
        },
    ));

    benchmarks
}
