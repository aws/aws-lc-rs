// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::hmac::sign;
use aws_lc_rs::{digest, hmac, test, test_file};

#[test]
fn hmac_tests() {
    test::run(test_file!("data/hmac_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = test_case.consume_digest_alg("HMAC");
        let key_value = test_case.consume_bytes("Key");
        let mut input = test_case.consume_bytes("Input");
        let output = test_case.consume_bytes("Output");

        let algorithm = {
            let Some(digest_alg) = digest_alg else {
                return Ok(());
            };
            if digest_alg == &digest::SHA1_FOR_LEGACY_USE_ONLY {
                hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY
            } else if digest_alg == &digest::SHA224 {
                hmac::HMAC_SHA224
            } else if digest_alg == &digest::SHA256 {
                hmac::HMAC_SHA256
            } else if digest_alg == &digest::SHA384 {
                hmac::HMAC_SHA384
            } else if digest_alg == &digest::SHA512 {
                hmac::HMAC_SHA512
            } else {
                unreachable!()
            }
        };

        hmac_test_case_inner(algorithm, &key_value[..], &input[..], &output[..], true);

        // Tamper with the input and check that verification fails.
        if input.is_empty() {
            input.push(0);
        } else {
            input[0] ^= 1;
        }

        hmac_test_case_inner(algorithm, &key_value[..], &input[..], &output[..], false);

        Ok(())
    });
}

fn hmac_test_case_inner(
    algorithm: hmac::Algorithm,
    key_value: &[u8],
    input: &[u8],
    output: &[u8],
    is_ok: bool,
) {
    let key = hmac::Key::new(algorithm, key_value);

    // One-shot API.
    {
        let signature = sign(&key, input);
        assert_eq!(is_ok, signature.as_ref() == output);
        assert_eq!(is_ok, hmac::verify(&key, input, output).is_ok());
    }

    // Multi-part API, one single part.
    {
        let mut s_ctx = hmac::Context::with_key(&key);
        s_ctx.update(input);
        let signature = s_ctx.sign();
        assert_eq!(is_ok, signature.as_ref() == output);
    }

    // Multi-part API, byte by byte.
    {
        let mut ctx = hmac::Context::with_key(&key);
        for b in input {
            ctx.update(&[*b]);
        }
        let signature = ctx.sign();
        assert_eq!(is_ok, signature.as_ref() == output);
    }
}

#[test]
fn hmac_debug() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0; 32]);
    assert_eq!("Key { algorithm: SHA256 }", format!("{:?}", &key));

    let ctx = hmac::Context::with_key(&key);
    assert_eq!("Context { algorithm: SHA256 }", format!("{:?}", &ctx));

    assert_eq!("Algorithm(SHA256)", format!("{:?}", hmac::HMAC_SHA256));
}

#[test]
fn hmac_traits() {
    test::compile_time_assert_send::<hmac::Key>();
    test::compile_time_assert_sync::<hmac::Key>();
}

#[test]
fn hmac_thread_safeness() {
    use std::thread;
    lazy_static::lazy_static! {
        static ref SECRET_KEY: hmac::Key = hmac::Key::new(hmac::HMAC_SHA256, b"this is a test!");
        static ref MSG: Vec<u8> = vec![1u8; 256];
    }

    let signature = sign(&SECRET_KEY, &MSG);

    let mut join_handles = Vec::new();
    for _ in 1..100 {
        let join_handle = thread::spawn(|| {
            let signature = sign(&SECRET_KEY, &MSG);
            for _ in 1..100 {
                let my_signature = sign(&SECRET_KEY, &MSG);
                assert_eq!(signature.as_ref(), my_signature.as_ref());
            }
            signature
        });
        join_handles.push(join_handle);
    }
    for handle in join_handles {
        let thread_signature = handle.join().unwrap();
        assert_eq!(thread_signature.as_ref(), signature.as_ref());
    }
}
