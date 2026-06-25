// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Minimal crypto surface binary for size measurement.
//!
//! Exercises SHA-256, AES-256-GCM, and ECDSA-P256 — the same surface used in
//! the binary-size investigation. The accumulator prevents dead-code
//! elimination from stripping the crypto operations.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};

fn main() {
    let mut acc: u64 = 0;

    // SHA-256
    for i in 0u64..100 {
        let d = digest::digest(&digest::SHA256, &i.to_le_bytes());
        acc = acc.wrapping_add(u64::from(d.as_ref()[0]));
    }

    // AES-256-GCM
    let key_bytes = [0x42u8; 32];
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    let mut buf = b"hello world!!!!X".to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .unwrap();
    acc = acc.wrapping_add(u64::from(buf[0]));

    // ECDSA P-256
    let rng = SystemRandom::new();
    let alg: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
    let sig = kp.sign(&rng, b"test message").unwrap();
    let pub_key = kp.public_key();
    let peer_pub_key =
        aws_lc_rs::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pub_key.as_ref());
    peer_pub_key.verify(b"test message", sig.as_ref()).unwrap();
    acc = acc.wrapping_add(u64::from(sig.as_ref()[0]));

    println!("acc={acc}");
}
