// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

extern crate alloc;

use aws_lc_rs::{agreement, rand};

#[test]
fn agree_ephemeral_e2e() {
    let rng = rand::SystemRandom::new();

    for algorithm in [
        &agreement::ECDH_P256,
        &agreement::ECDH_P384,
        &agreement::ECDH_P521,
        &agreement::X25519,
    ] {
        let alice_private_key = agreement::EphemeralPrivateKey::generate(algorithm, &rng).unwrap();
        let alice_public_key = alice_private_key.compute_public_key().unwrap();

        let bob_private_key = agreement::EphemeralPrivateKey::generate(algorithm, &rng).unwrap();
        let bob_public_key = bob_private_key.compute_public_key().unwrap();

        let alice_shared_secret = {
            let mut secret: Vec<u8> = vec![];

            agreement::agree_ephemeral(
                alice_private_key,
                &agreement::UnparsedPublicKey::new(algorithm, bob_public_key),
                ring::error::Unspecified,
                |value| {
                    secret.extend_from_slice(value);
                    Ok(())
                },
            )
            .unwrap();

            secret
        };

        let bob_shared_secret = {
            let mut secret: Vec<u8> = vec![];

            agreement::agree_ephemeral(
                bob_private_key,
                &agreement::UnparsedPublicKey::new(algorithm, alice_public_key),
                ring::error::Unspecified,
                |value| {
                    secret.extend_from_slice(value);
                    Ok(())
                },
            )
            .unwrap();

            secret
        };

        assert_eq!(alice_shared_secret.as_slice(), bob_shared_secret.as_slice());
    }
}
