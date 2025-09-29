use aws_lc_rs::cmac::sign;
use aws_lc_rs::{cmac, test, test_file};

#[test]
fn cmac_tests() {
    test::run(test_file!("data/cmac_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let cipher_name = test_case.consume_string("CMAC");
        let key_value = test_case.consume_bytes("Key");
        let mut input = test_case.consume_bytes("Input");
        let output = test_case.consume_bytes("Output");

        let algorithm = match cipher_name.as_str() {
            "AES-128" => cmac::AES_128,
            "AES-192" => cmac::AES_192,
            "AES-256" => cmac::AES_256,
            "TDES" => cmac::TDES_FOR_LEGACY_USE_ONLY,
            _ => return Ok(()),
        };

        cmac_test_case_inner(algorithm, &key_value[..], &input[..], &output[..], true);

        // Tamper with the input and check that verification fails.
        if input.is_empty() {
            input.push(0);
        } else {
            input[0] ^= 1;
        }

        cmac_test_case_inner(algorithm, &key_value[..], &input[..], &output[..], false);

        Ok(())
    });
}

fn cmac_test_case_inner(
    algorithm: cmac::Algorithm,
    key_value: &[u8],
    input: &[u8],
    output: &[u8],
    is_ok: bool,
) {
    let key = cmac::Key::new(algorithm, key_value);

    // One-shot API.
    {
        let signature = sign(&key, input);
        println!("One-shot signature: {}", hex::encode(signature.as_ref()));
        println!("expected: {:?}", output);
        assert_eq!(is_ok, signature.as_ref() == output);
        assert_eq!(is_ok, cmac::verify(&key, input, output).is_ok());
    }

    // Multi-part API, one single part.
    {
        let mut s_ctx = cmac::Context::with_key(&key);
        s_ctx.update(input);
        let signature = s_ctx.sign();
        assert_eq!(is_ok, signature.as_ref() == output);
    }

    // Multi-part API, byte by byte.
    {
        let mut ctx = cmac::Context::with_key(&key);
        for b in input {
            ctx.update(&[*b]);
        }
        let signature = ctx.sign();
        assert_eq!(is_ok, signature.as_ref() == output);
    }
}

#[test]
fn cmac_debug() {
    let key = cmac::Key::new(cmac::AES_128, &[0; 16]);
    assert_eq!("Key { algorithm: Algorithm { name: \"AES_128\", key_len: 16, tag_len: 16 } }", format!("{:?}", &key));

    let ctx = cmac::Context::with_key(&key);
    assert_eq!("Context { algorithm: Algorithm { name: \"AES_128\", key_len: 16, tag_len: 16 } }", format!("{:?}", &ctx));

    assert_eq!("Algorithm { name: \"AES_128\", key_len: 16, tag_len: 16 }", format!("{:?}", cmac::AES_128));
}

#[test]
fn cmac_traits() {
    test::compile_time_assert_send::<cmac::Key>();
    test::compile_time_assert_sync::<cmac::Key>();
}

#[test]
fn cmac_thread_safeness() {
    use std::thread;
    lazy_static::lazy_static! {
        static ref SECRET_KEY: cmac::Key = cmac::Key::new(cmac::AES_128, &[0x2b; 16]);
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


