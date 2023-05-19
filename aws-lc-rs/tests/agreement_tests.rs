// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

extern crate alloc;

use aws_lc_rs::{agreement, error, rand, test};

#[test]
fn test_agreement_ecdh_x25519_rfc_iterated() {
    fn expect_iterated_x25519(
        expected_result: &str,
        range: core::ops::Range<usize>,
        k: &mut Vec<u8>,
        u: &mut Vec<u8>,
    ) {
        for _ in range {
            let new_k = x25519(k, u);
            *u = k.clone();
            *k = new_k;
        }
        assert_eq!(&h(expected_result), k);
    }

    let mut k = h("0900000000000000000000000000000000000000000000000000000000000000");
    let mut u = k.clone();

    expect_iterated_x25519(
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        0..1,
        &mut k,
        &mut u,
    );
    expect_iterated_x25519(
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        1..1_000,
        &mut k,
        &mut u,
    );

    // The spec gives a test vector for 1,000,000 iterations but it takes
    // too long to do 1,000,000 iterations by default right now. This
    // 10,000 iteration vector is self-computed.
    expect_iterated_x25519(
        "2c125a20f639d504a7703d2e223c79a79de48c4ee8c23379aa19a62ecd211815",
        1_000..10_000,
        &mut k,
        &mut u,
    );

    if cfg!(feature = "slow_tests") {
        expect_iterated_x25519(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            10_000..1_000_000,
            &mut k,
            &mut u,
        );
    }
}

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

fn x25519(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    x25519_(private_key, public_key).unwrap()
}

fn x25519_(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, error::Unspecified> {
    let rng = test::rand::FixedSliceRandom { bytes: private_key };
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
    let public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, public_key);
    agreement::agree_ephemeral(
        private_key,
        &public_key,
        error::Unspecified,
        |agreed_value| Ok(Vec::from(agreed_value)),
    )
}

fn h(s: &str) -> Vec<u8> {
    match test::from_hex(s) {
        Ok(v) => v,
        Err(msg) => {
            panic!("{msg} in {s}");
        }
    }
}
