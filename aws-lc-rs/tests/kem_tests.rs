// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::kem::{PrivateKey, PublicKey, KYBER1024_R3, KYBER512_R3, KYBER768_R3};

#[test]
fn test_kem_e2e() {
    for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
        let priv_key = PrivateKey::generate(algorithm).unwrap();
        assert_eq!(priv_key.algorithm(), algorithm);

        let pub_key = priv_key.public_key().unwrap();

        let (alice_ciphertext, alice_secret) =
            pub_key.encapsulate().expect("encapsulate successful");

        let bob_secret = priv_key
            .decapsulate(alice_ciphertext)
            .expect("decapsulate successful");

        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
    }
}

#[test]
fn test_serialized_kem_e2e() {
    for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
        let priv_key = PrivateKey::generate(algorithm).unwrap();
        assert_eq!(priv_key.algorithm(), algorithm);

        // Generate private key bytes to possibly save for later
        let privkey_raw_bytes = priv_key.as_ref();

        let pub_key = priv_key.public_key().unwrap();

        // Generate public key bytes to send to bob
        let pub_key_bytes = pub_key.as_ref();

        let retrieved_pub_key = PublicKey::new(algorithm, pub_key_bytes).unwrap();
        let (ciphertext, bob_secret) = retrieved_pub_key
            .encapsulate()
            .expect("encapsulate successful");

        // Retrieve private key from stored raw bytes
        let retrieved_priv_key = PrivateKey::new(algorithm, privkey_raw_bytes).unwrap();

        let alice_secret = retrieved_priv_key
            .decapsulate(ciphertext)
            .expect("encapsulate successful");

        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
    }
}
