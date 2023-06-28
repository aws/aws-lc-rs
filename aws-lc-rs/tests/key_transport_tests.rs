// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::env;
use aws_lc_rs::key_transport::*;

#[test]
fn test_agreement_kyber512() {
    // Debugging
    env::set_var("RUST_BACKTRACE", "1");

    let priv_key = KemPrivateKey::generate(Algorithm::KYBER512_R3).unwrap();
    assert_eq!(priv_key.algorithm(), &Algorithm::KYBER512_R3);

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
fn test_serialized_agreement_kyber512() {

}