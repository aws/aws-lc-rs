use aws_lc_rs::{cmac, test, test_file};

#[test]
fn cavp_cmac_aes128_tests() {
    test::run(test_file!("data/cavp_aes128_cmac_tests.txt"), |section, test_case| {
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
        let truncated_sig = &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];
        
        if should_pass {
            assert_eq!(truncated_sig, &mac);
        } else {
            assert_ne!(truncated_sig, &mac);
        }
        
        Ok(())
    });
}

#[test]
fn cavp_cmac_aes192_tests() {
    test::run(test_file!("data/cavp_aes192_cmac_tests.txt"), |section, test_case| {
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
        let truncated_sig = &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];
        
        if should_pass {
            assert_eq!(truncated_sig, &mac);
        } else {
            assert_ne!(truncated_sig, &mac);
        }
        
        Ok(())
    });
}

#[test]
fn cavp_cmac_aes256_tests() {
    test::run(test_file!("data/cavp_aes256_cmac_tests.txt"), |section, test_case| {
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
        let truncated_sig = &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];
        
        if should_pass {
            assert_eq!(truncated_sig, &mac);
        } else {
            assert_ne!(truncated_sig, &mac);
        }
        
        Ok(())
    });
}

#[test]
fn cavp_cmac_3des_tests() {
    test::run(test_file!("data/cavp_3des_cmac_tests.txt"), |section, test_case| {
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
        let truncated_sig = &signature.as_ref()[..std::cmp::min(signature.as_ref().len(), tlen)];
        
        if should_pass {
            assert_eq!(truncated_sig, &mac);
        } else {
            assert_ne!(truncated_sig, &mac);
        }
        Ok(())
    });
}