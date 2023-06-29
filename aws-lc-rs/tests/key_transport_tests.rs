// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::key_transport::*;

#[test]
fn test_kem_kyber512() {
    let priv_key = KemPrivateKey::generate(KemAlgorithm::KYBER512_R3).unwrap();
    assert_eq!(priv_key.algorithm(), &KemAlgorithm::KYBER512_R3);

    let pub_key = priv_key.compute_public_key().unwrap();

    let mut ciphertext: Vec<u8> = vec![];
    let mut alice_shared_secret: Vec<u8> = vec![];

    let alice_result = pub_key.encapsulate(|ct, ss| {
        ciphertext.extend_from_slice(ct);
        alice_shared_secret.extend_from_slice(ss);
        Ok(())
    });
    assert_eq!(alice_result, Ok(()));

    let mut bob_shared_secret: Vec<u8> = vec![];

    let bob_result = priv_key.decapsulate(&mut ciphertext, |ss| {
        bob_shared_secret.extend_from_slice(ss);
        Ok(())
    });
    assert_eq!(bob_result, Ok(()));
    assert_eq!(alice_shared_secret, bob_shared_secret);
}

#[test]
fn test_serialized_kem_kyber512() {
    let priv_key = KemPrivateKey::generate(KemAlgorithm::KYBER512_R3).unwrap();
    assert_eq!(priv_key.algorithm(), &KemAlgorithm::KYBER512_R3);

    // Generate private key bytes to possibly save for later
    let privkey_raw_bytes = priv_key.get_raw_bytes();

    let pub_key = priv_key.compute_public_key().unwrap();

    // Generate public key bytes to send to bob
    let pub_key_bytes = pub_key.get_raw_bytes();

    let mut ciphertext: Vec<u8> = vec![];
    let mut bob_shared_secret: Vec<u8> = vec![];

    let retrieved_pub_key = KemPublicKey::from_raw_bytes(KemAlgorithm::KYBER512_R3, pub_key_bytes).unwrap();
    let bob_result = retrieved_pub_key.encapsulate(|ct, ss| {
        ciphertext.extend_from_slice(ct);
        bob_shared_secret.extend_from_slice(ss);
        Ok(())
    });
    assert_eq!(bob_result, Ok(()));

    let mut alice_shared_secret: Vec<u8> = vec![];

    // Retrieve private key from stored raw bytes
    let retrieved_priv_key = KemPrivateKey::from_raw_bytes(KemAlgorithm::KYBER512_R3, privkey_raw_bytes).unwrap();
    
    let alice_result = retrieved_priv_key.decapsulate(&mut ciphertext, |ss| {
        alice_shared_secret.extend_from_slice(ss);
        Ok(())
    });
    assert_eq!(alice_result, Ok(()));
    assert_eq!(alice_shared_secret, bob_shared_secret);
}