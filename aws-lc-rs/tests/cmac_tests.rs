// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{cmac, test, test_file};

#[test]
fn cavp_cmac_aes128_tests() {
    test::run(
        test_file!("data/cavp_aes128_cmac_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let _count = test_case.consume_usize("Count");
            let _klen = test_case.consume_usize("Klen");
            let mlen = test_case.consume_usize("Mlen");
            let tlen = test_case.consume_usize("Tlen");
            let key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let mac = test_case.consume_bytes("Mac");
            let result = test_case.consume_string("Result");

            let input = if mlen == 0 { Vec::new() } else { msg };
            let should_pass = result.starts_with('P');

            let cmac_key = cmac::Key::new(cmac::AES_128, &key).unwrap();
            let signature = cmac::sign(&cmac_key, &input).unwrap();

            // Truncate to tlen
            let truncated_sig =
                &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];

            if should_pass {
                assert_eq!(truncated_sig, &mac);
            } else {
                assert_ne!(truncated_sig, &mac);
            }

            Ok(())
        },
    );
}

#[test]
fn cavp_cmac_aes192_tests() {
    test::run(
        test_file!("data/cavp_aes192_cmac_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let _count = test_case.consume_usize("Count");
            let _klen = test_case.consume_usize("Klen");
            let mlen = test_case.consume_usize("Mlen");
            let tlen = test_case.consume_usize("Tlen");
            let key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let mac = test_case.consume_bytes("Mac");
            let result = test_case.consume_string("Result");

            let input = if mlen == 0 { Vec::new() } else { msg };
            let should_pass = result.starts_with('P');

            let cmac_key = cmac::Key::new(cmac::AES_192, &key).unwrap();
            let signature = cmac::sign(&cmac_key, &input).unwrap();

            // Truncate to tlen
            let truncated_sig =
                &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];

            if should_pass {
                assert_eq!(truncated_sig, &mac);
            } else {
                assert_ne!(truncated_sig, &mac);
            }

            Ok(())
        },
    );
}

#[test]
fn cavp_cmac_aes256_tests() {
    test::run(
        test_file!("data/cavp_aes256_cmac_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let _count = test_case.consume_usize("Count");
            let _klen = test_case.consume_usize("Klen");
            let mlen = test_case.consume_usize("Mlen");
            let tlen = test_case.consume_usize("Tlen");
            let key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let mac = test_case.consume_bytes("Mac");
            let result = test_case.consume_string("Result");

            let input = if mlen == 0 { Vec::new() } else { msg };
            let should_pass = result.starts_with('P');

            let cmac_key = cmac::Key::new(cmac::AES_256, &key).unwrap();
            let signature = cmac::sign(&cmac_key, &input).unwrap();

            // Truncate to tlen
            let truncated_sig =
                &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];

            if should_pass {
                assert_eq!(truncated_sig, &mac);
            } else {
                assert_ne!(truncated_sig, &mac);
            }

            Ok(())
        },
    );
}

#[test]
fn cavp_cmac_3des_tests() {
    test::run(
        test_file!("data/cavp_3des_cmac_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let _count = test_case.consume_usize("Count");
            let _klen = test_case.consume_usize("Klen");
            let mlen = test_case.consume_usize("Mlen");
            let tlen = test_case.consume_usize("Tlen");
            let key1 = test_case.consume_bytes("Key1");
            let key2 = test_case.consume_bytes("Key2");
            let key3 = test_case.consume_bytes("Key3");
            let msg = test_case.consume_bytes("Msg");
            let mac = test_case.consume_bytes("Mac");
            let result = test_case.consume_string("Result");

            // Combine 3DES keys
            let mut combined_key = key1;
            combined_key.extend(key2);
            combined_key.extend(key3);

            let input = if mlen == 0 { Vec::new() } else { msg };
            let should_pass = result.starts_with('P');

            let cmac_key = cmac::Key::new(cmac::TDES_FOR_LEGACY_USE_ONLY, &combined_key).unwrap();
            let signature = cmac::sign(&cmac_key, &input).unwrap();

            // Truncate to tlen
            let truncated_sig =
                &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];

            if should_pass {
                assert_eq!(truncated_sig, &mac);
            } else {
                assert_ne!(truncated_sig, &mac);
            }
            Ok(())
        },
    );
}

#[test]
fn test_sign_to_buffer_basic() {
    // Test sign_to_buffer with all algorithms
    for algorithm in &[
        cmac::AES_128,
        cmac::AES_192,
        cmac::AES_256,
        cmac::TDES_FOR_LEGACY_USE_ONLY,
    ] {
        let key = cmac::Key::generate(*algorithm).unwrap();
        let data = b"test data for sign_to_buffer";

        // Test with exact size buffer
        let mut output = vec![0u8; algorithm.tag_len()];
        let result = cmac::sign_to_buffer(&key, data, &mut output).unwrap();

        assert_eq!(result.len(), algorithm.tag_len());

        // Verify result matches the standard sign function
        let tag = cmac::sign(&key, data).unwrap();
        assert_eq!(result, tag.as_ref());
    }
}

#[test]
fn test_sign_to_buffer_large_buffer() {
    // Test that sign_to_buffer works with buffers larger than needed
    let key = cmac::Key::generate(cmac::AES_256).unwrap();
    let data = b"sample data";

    let mut large_buffer = vec![0u8; 128]; // Much larger than needed
    let result = cmac::sign_to_buffer(&key, data, &mut large_buffer).unwrap();

    // Should only use the required bytes
    assert_eq!(result.len(), cmac::AES_256.tag_len());

    // Verify correctness
    let tag = cmac::sign(&key, data).unwrap();
    assert_eq!(result, tag.as_ref());
}

#[test]
fn test_sign_to_buffer_too_small() {
    // Test that sign_to_buffer fails with insufficient buffer size
    let key = cmac::Key::generate(cmac::AES_128).unwrap();
    let data = b"test";

    let mut small_buffer = vec![0u8; cmac::AES_128.tag_len() - 1];
    let result = cmac::sign_to_buffer(&key, data, &mut small_buffer);

    assert!(result.is_err());
}

#[test]
fn test_sign_to_buffer_empty_data() {
    // Test sign_to_buffer with empty data
    let key = cmac::Key::generate(cmac::AES_128).unwrap();
    let data = b"";

    let mut output = vec![0u8; cmac::AES_128.tag_len()];
    let result = cmac::sign_to_buffer(&key, data, &mut output).unwrap();

    // Verify it matches standard sign with empty data
    let tag = cmac::sign(&key, data).unwrap();
    assert_eq!(result, tag.as_ref());
}

#[test]
fn test_context_verify_basic() {
    // Test Context::verify with valid tag
    for algorithm in &[
        cmac::AES_128,
        cmac::AES_192,
        cmac::AES_256,
        cmac::TDES_FOR_LEGACY_USE_ONLY,
    ] {
        let key = cmac::Key::generate(*algorithm).unwrap();
        let data = b"data to verify";

        // Generate valid tag
        let tag = cmac::sign(&key, data).unwrap();

        // Verify using Context::verify
        let mut ctx = cmac::Context::with_key(&key);
        ctx.update(data).unwrap();
        assert!(ctx.verify(tag.as_ref()).is_ok());
    }
}

#[test]
fn test_context_verify_invalid_tag() {
    // Test Context::verify with invalid tag
    let key = cmac::Key::generate(cmac::AES_256).unwrap();
    let data = b"test data";

    let mut ctx = cmac::Context::with_key(&key);
    ctx.update(data).unwrap();

    // Use wrong tag
    let wrong_tag = vec![0u8; cmac::AES_256.tag_len()];
    assert!(ctx.verify(&wrong_tag).is_err());
}

#[test]
fn test_context_verify_multipart() {
    // Test Context::verify with multi-part update
    let key = cmac::Key::generate(cmac::AES_256).unwrap();
    let parts = ["hello", ", ", "world"];

    // Create expected tag from full message
    let mut full_msg = Vec::new();
    for part in &parts {
        full_msg.extend_from_slice(part.as_bytes());
    }
    let expected_tag = cmac::sign(&key, &full_msg).unwrap();

    // Verify using multi-part context
    let mut ctx = cmac::Context::with_key(&key);
    for part in &parts {
        ctx.update(part.as_bytes()).unwrap();
    }
    assert!(ctx.verify(expected_tag.as_ref()).is_ok());
}

#[test]
fn test_context_verify_wrong_data() {
    // Test that Context::verify fails when data doesn't match
    let key = cmac::Key::generate(cmac::AES_128).unwrap();
    let correct_data = b"correct data";
    let wrong_data = b"wrong data";

    // Generate tag for correct data
    let tag = cmac::sign(&key, correct_data).unwrap();

    // Try to verify with wrong data
    let mut ctx = cmac::Context::with_key(&key);
    ctx.update(wrong_data).unwrap();
    assert!(ctx.verify(tag.as_ref()).is_err());
}

#[test]
fn test_context_verify_empty_data() {
    // Test Context::verify with empty data
    let key = cmac::Key::generate(cmac::AES_128).unwrap();
    let data = b"";

    let tag = cmac::sign(&key, data).unwrap();

    let ctx = cmac::Context::with_key(&key);
    // No update calls - empty data
    assert!(ctx.verify(tag.as_ref()).is_ok());
}

#[test]
fn test_verify_function_basic() {
    // Test module-level verify function
    let key = cmac::Key::generate(cmac::AES_256).unwrap();
    let data = b"verify function test";

    let tag = cmac::sign(&key, data).unwrap();

    // Should succeed with correct tag
    assert!(cmac::verify(&key, data, tag.as_ref()).is_ok());

    // Should fail with wrong tag
    let wrong_tag = vec![0u8; cmac::AES_256.tag_len()];
    assert!(cmac::verify(&key, data, &wrong_tag).is_err());

    // Should fail with wrong data
    assert!(cmac::verify(&key, b"wrong data", tag.as_ref()).is_err());
}

#[test]
fn test_sign_to_buffer_vs_sign() {
    // Verify that sign_to_buffer produces identical results to sign
    let key = cmac::Key::generate(cmac::AES_192).unwrap();
    let test_cases = vec![
        b"".as_ref(),
        b"a",
        b"short",
        b"a longer message for testing",
        b"message with\nnewlines\nand\ttabs",
    ];

    for data in test_cases {
        let tag = cmac::sign(&key, data).unwrap();

        let mut output = vec![0u8; cmac::AES_192.tag_len()];
        let buffer_result = cmac::sign_to_buffer(&key, data, &mut output).unwrap();

        assert_eq!(tag.as_ref(), buffer_result);
    }
}
