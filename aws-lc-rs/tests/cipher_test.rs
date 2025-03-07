// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, OperatingMode,
    PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, StreamingDecryptingKey,
    StreamingEncryptingKey, UnboundCipherKey, AES_128, AES_192, AES_256,
};
use aws_lc_rs::iv::{FixedLength, IV_LEN_128_BIT};
use aws_lc_rs::test::from_hex;
use concat_idents::concat_idents;

fn step_encrypt(
    mut encrypting_key: StreamingEncryptingKey,
    plaintext: &[u8],
    step: usize,
) -> (Box<[u8]>, DecryptionContext) {
    let alg = encrypting_key.algorithm();
    let mode = encrypting_key.mode();
    let n = plaintext.len();
    let mut ciphertext = vec![0u8; n + alg.block_len()];

    let mut in_idx: usize = 0;
    let mut out_idx: usize = 0;
    loop {
        let mut in_end = in_idx + step;
        if in_end > n {
            in_end = n;
        }
        let out_end = out_idx + (in_end - in_idx) + alg.block_len();
        let output = encrypting_key
            .update(
                &plaintext[in_idx..in_end],
                &mut ciphertext[out_idx..out_end],
            )
            .unwrap();
        in_idx += step;
        out_idx += output.written().len();
        if in_idx >= n {
            break;
        }
    }
    let out_end = out_idx + alg.block_len();
    let (decrypt_iv, output) = encrypting_key
        .finish(&mut ciphertext[out_idx..out_end])
        .unwrap();
    let outlen = output.written().len();
    ciphertext.truncate(out_idx + outlen);
    match mode {
        OperatingMode::CBC | OperatingMode::ECB => {
            assert!(ciphertext.len() > plaintext.len());
            assert!(ciphertext.len() <= plaintext.len() + alg.block_len());
        }
        OperatingMode::CTR | OperatingMode::CFB128 => {
            assert_eq!(ciphertext.len(), plaintext.len());
        }
        _ => panic!("Unknown cipher mode"),
    }

    (ciphertext.into_boxed_slice(), decrypt_iv)
}

fn step_decrypt(
    mut decrypting_key: StreamingDecryptingKey,
    ciphertext: &[u8],
    step: usize,
) -> Box<[u8]> {
    let alg = decrypting_key.algorithm();
    let mode = decrypting_key.mode();
    let n = ciphertext.len();
    let mut plaintext = vec![0u8; n + alg.block_len()];

    let mut in_idx: usize = 0;
    let mut out_idx: usize = 0;
    loop {
        let mut in_end = in_idx + step;
        if in_end > n {
            in_end = n;
        }
        let out_end = out_idx + (in_end - in_idx) + alg.block_len();
        let output = decrypting_key
            .update(
                &ciphertext[in_idx..in_end],
                &mut plaintext[out_idx..out_end],
            )
            .unwrap();
        in_idx += step;
        out_idx += output.written().len();
        if in_idx >= n {
            break;
        }
    }
    let out_end = out_idx + alg.block_len();
    let output = decrypting_key
        .finish(&mut plaintext[out_idx..out_end])
        .unwrap();
    let outlen = output.written().len();
    plaintext.truncate(out_idx + outlen);
    match mode {
        OperatingMode::CBC | OperatingMode::ECB => {
            assert!(ciphertext.len() > plaintext.len());
            assert!(ciphertext.len() <= plaintext.len() + alg.block_len());
        }
        OperatingMode::CTR | OperatingMode::CFB128 => {
            assert_eq!(ciphertext.len(), plaintext.len());
        }
        _ => panic!("Unknown cipher mode"),
    }
    plaintext.into_boxed_slice()
}

macro_rules! streaming_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal, $from_step:literal, $to_step:literal) => {
        concat_idents!( test_name = $name, _streaming {
        #[test]
        fn test_name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();

            for step in ($from_step..=$to_step) {
                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
                let encrypting_key = StreamingEncryptingKey::$constructor(unbound_key).unwrap();

                let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                    let decrypting_key =
                        StreamingDecryptingKey::$constructor(unbound_key2, decrypt_ctx).unwrap();

                let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                assert_eq!(input.as_slice(), plaintext.as_ref());
            }
        }
        });
    };
}

macro_rules! streaming_ecb_pkcs7_rt {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal, $from_step:literal, $to_step:literal) => {
        concat_idents!( test_name = $name, _streaming {
        #[test]
        fn test_name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();

            for step in ($from_step..=$to_step) {
                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
                let encrypting_key = StreamingEncryptingKey::ecb_pkcs7(unbound_key).unwrap();

                let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                    let decrypting_key =
                        StreamingDecryptingKey::ecb_pkcs7(unbound_key2, decrypt_ctx).unwrap();

                let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                assert_eq!(input.as_slice(), plaintext.as_ref());
            }
        }
        });
    };
}

macro_rules! streaming_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
        concat_idents!( test_name = $name, _streaming {
        #[test]
        fn test_name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();
            let iv = from_hex($iv).unwrap();

            for step in ($from_step..=$to_step) {
                let ec = EncryptionContext::Iv128(
                    FixedLength::<IV_LEN_128_BIT>::try_from(iv.as_slice()).unwrap(),
                );
                concat_idents!( less_safe_constructor = less_safe_, $constructor {
                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
                    let encrypting_key = StreamingEncryptingKey::less_safe_constructor(unbound_key, ec).unwrap();
                });
                let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                assert_eq!(expected_ciphertext.as_slice(), ciphertext.as_ref());

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                    let decrypting_key =
                        StreamingDecryptingKey::$constructor(unbound_key2, decrypt_ctx).unwrap();

                let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                assert_eq!(input.as_slice(), plaintext.as_ref());
            }
        }
        });
    };
}

macro_rules! streaming_ecb_pkcs7_kat {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
        concat_idents!( test_name = $name, _streaming {
        #[test]
        fn test_name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            for step in ($from_step..=$to_step) {
                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
                    let encrypting_key = StreamingEncryptingKey::ecb_pkcs7(unbound_key).unwrap();

                let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                assert_eq!(expected_ciphertext.as_slice(), ciphertext.as_ref());

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                    let decrypting_key =
                        StreamingDecryptingKey::ecb_pkcs7(unbound_key2, decrypt_ctx).unwrap();

                let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                assert_eq!(input.as_slice(), plaintext.as_ref());
            }
        }
        });
    };
}

macro_rules! padded_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let iv = from_hex($iv).unwrap();
            let fixed_iv = FixedLength::try_from(iv.as_slice()).unwrap();
            let context = EncryptionContext::Iv128(fixed_iv);

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = PaddedBlockEncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(&mut in_out, context)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out.as_slice());

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = PaddedBlockDecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        streaming_cipher_kat!(
            $name,
            $alg,
            $mode,
            $constructor,
            $key,
            $iv,
            $plaintext,
            $ciphertext,
            2,
            9
        );
    };
}

macro_rules! padded_ecb_pkcs7_kat {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = PaddedBlockEncryptingKey::ecb_pkcs7(unbound_key).unwrap();
            assert_eq!(OperatingMode::ECB, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(&mut in_out, EncryptionContext::None)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out.as_slice());

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = PaddedBlockDecryptingKey::ecb_pkcs7(unbound_key2).unwrap();
            assert_eq!(OperatingMode::ECB, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        streaming_ecb_pkcs7_kat!($name, $alg, $key, $plaintext, $ciphertext, 2, 9);
    };
}

macro_rules! cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let iv = from_hex($iv).unwrap();
            let fixed_iv = FixedLength::try_from(iv.as_slice()).unwrap();
            let context = EncryptionContext::Iv128(fixed_iv);

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = EncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(in_out.as_mut_slice(), context)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out);

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = DecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        streaming_cipher_kat!(
            $name,
            $alg,
            $mode,
            $constructor,
            $key,
            $iv,
            $plaintext,
            $ciphertext,
            2,
            9
        );
    };
}

macro_rules! ecb_kat {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = EncryptingKey::ecb(unbound_key).unwrap();
            assert_eq!(OperatingMode::ECB, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(in_out.as_mut_slice(), EncryptionContext::None)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out);

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = DecryptingKey::ecb(unbound_key2).unwrap();
            assert_eq!(OperatingMode::ECB, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }
    };
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = EncryptingKey::ecb(unbound_key).unwrap();
            assert_eq!(OperatingMode::ECB, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            encrypting_key
                .less_safe_encrypt(in_out.as_mut_slice(), EncryptionContext::None)
                .expect_err("expected encryption failure");
        }
    };
}

macro_rules! padded_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = PaddedBlockEncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key.encrypt(&mut in_out).unwrap();

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = PaddedBlockDecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        streaming_cipher_rt!($name, $alg, $mode, $constructor, $key, $plaintext, 2, 9);
    };
}

macro_rules! cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = EncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key.encrypt(in_out.as_mut_slice()).unwrap();

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = DecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }
        streaming_cipher_rt!($name, $alg, $mode, $constructor, $key, $plaintext, 2, 9);
    };
}

macro_rules! ecb_rt {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = EncryptingKey::ecb(unbound_key).unwrap();
            assert_eq!(OperatingMode::ECB, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key.encrypt(in_out.as_mut_slice()).unwrap();

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = DecryptingKey::ecb(unbound_key2).unwrap();
            assert_eq!(OperatingMode::ECB, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }
    };
}

macro_rules! padded_ecb_pkcs7_rt {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = PaddedBlockEncryptingKey::ecb_pkcs7(unbound_key).unwrap();
            assert_eq!(OperatingMode::ECB, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key.encrypt(&mut in_out).unwrap();

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = PaddedBlockDecryptingKey::ecb_pkcs7(unbound_key2).unwrap();
            assert_eq!(OperatingMode::ECB, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        streaming_ecb_pkcs7_rt!($name, $alg, $key, $plaintext, 2, 9);
    };
}

padded_cipher_kat!(
    test_kat_aes_128_cbc_16_bytes,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "000102030405060708090a0b0c0d0e0f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "69c4e0d86a7b0430d8cdb78070b4c55a9e978e6d16b086570ef794ef97984232"
);

padded_cipher_kat!(
    test_kat_aes_192_cbc_16_bytes,
    &AES_192,
    OperatingMode::CBC,
    cbc_pkcs7,
    "e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "fc7f57e545e92c0a0b364c3086d49bf0f1a1a203743fbd8af828af46edca074d"
);

padded_cipher_kat!(
    test_kat_aes_256_cbc_15_bytes,
    &AES_256,
    OperatingMode::CBC,
    cbc_pkcs7,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddee",
    "2ddfb635a651a43f582997966840ca0c"
);

cipher_kat!(
    test_kat_aes_128_ctr_16_bytes,
    &AES_128,
    OperatingMode::CTR,
    ctr,
    "000102030405060708090a0b0c0d0e0f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "c6b01904c3da3df5e7d62bd96d153686"
);

cipher_kat!(
    test_kat_aes_192_ctr_16_bytes,
    &AES_192,
    OperatingMode::CTR,
    ctr,
    "cd62376d5ebb414917f0c78f05266433dc9192a1ec943300",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "7f7d07cc05d0e31633fb59df5e34d2d6"
);

cipher_kat!(
    test_kat_aes_256_ctr_15_bytes,
    &AES_256,
    OperatingMode::CTR,
    ctr,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddee",
    "f28122856e1cf9a7216a30d111f399"
);

cipher_kat!(
    test_kat_aes_128_ctr_15_bytes,
    &AES_128,
    OperatingMode::CTR,
    ctr,
    "244828580821c1652582c76e34d299f5",
    "093145d5af233f46072a5eb5adc11aa1",
    "3ee38cec171e6cf466bf0df98aa0e1",
    "bd7d928f60e3422d96b3f8cd614eb2"
);

cipher_kat!(
    test_kat_aes_192_ctr_15_bytes,
    &AES_192,
    OperatingMode::CTR,
    ctr,
    "25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce",
    "ffffffffffffffffffffffffffffff80",
    "3ee38cec171e6cf466bf0df98aa0e1",
    "56caf80166f076dfee89adc73b71e5"
);

cipher_kat!(
    test_kat_aes_256_ctr_15_bytes_2,
    &AES_256,
    OperatingMode::CTR,
    ctr,
    "0857db8240ea459bdf660b4cced66d1f2d3734ff2de7b81e92740e65e7cc6a1d",
    "f028ecb053f801102d11fccc9d303a27",
    "eca7285d19f3c20e295378460e8729",
    "b5098e5e788de6ac2f2098eb2fc6f8"
);

padded_cipher_kat!(
    test_kat_aes_128_cbc_15_bytes,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "053304bb3899e1d99db9d29343ea782d",
    "b5313560244a4822c46c2a0c9d0cf7fd",
    "a3e4c990356c01f320043c3d8d6f43",
    "ad96993f248bd6a29760ec7ccda95ee1"
);

padded_cipher_kat!(
    test_kat_aes_192_cbc_15_bytes,
    &AES_192,
    OperatingMode::CBC,
    cbc_pkcs7,
    "7001c487cc3e572cfc92f4d0e697d982e8856fdcc957da40",
    "b5313560244a4822c46c2a0c9d0cf7fd",
    "a3e4c990356c01f320043c3d8d6f43",
    "33549957df6ff5cf32ca59b42298f4d5"
);

padded_cipher_kat!(
    test_kat_aes_128_cbc_16_bytes_2,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "95af71f1c63e4a1d0b0b1a27fb978283",
    "89e40797dca70197ff87d3dbb0ef2802",
    "aece7b5e3c3df1ffc9802d2dfe296dc7",
    "301b5dab49fb11e919d0d39970d06739301919743304f23f3cbc67d28564b25b"
);

padded_cipher_kat!(
    test_kat_aes_256_cbc_16_bytes,
    &AES_256,
    OperatingMode::CBC,
    cbc_pkcs7,
    "d4a8206dcae01242f9db79a4ecfe277d0f7bb8ccbafd8f9809adb39f35aa9b41",
    "24f6076548fb9d93c8f7ed9f6e661ef9",
    "a39c1fdf77ea3e1f18178c0ec237c70a",
    "f1af484830a149ee0387b854d65fe87ca0e62efc1c8e6909d4b9ab8666470453"
);

padded_cipher_rt!(
    test_rt_aes_128_cbc_16_bytes,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "000102030405060708090a0b0c0d0e0f",
    "00112233445566778899aabbccddeeff"
);

padded_cipher_rt!(
    test_rt_aes_192_cbc_16_bytes,
    &AES_192,
    OperatingMode::CBC,
    cbc_pkcs7,
    "d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3",
    "00112233445566778899aabbccddeeff"
);

padded_cipher_rt!(
    test_rt_aes_256_cbc_15_bytes,
    &AES_256,
    OperatingMode::CBC,
    cbc_pkcs7,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "00112233445566778899aabbccddee"
);

cipher_rt!(
    test_rt_aes_128_ctr_16_bytes,
    &AES_128,
    OperatingMode::CTR,
    ctr,
    "000102030405060708090a0b0c0d0e0f",
    "00112233445566778899aabbccddeeff"
);

cipher_rt!(
    test_rt_aes_192_ctr_16_bytes,
    &AES_192,
    OperatingMode::CTR,
    ctr,
    "982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93",
    "00112233445566778899aabbccddeeff"
);

cipher_rt!(
    test_rt_aes_128_ctr_17_bytes,
    &AES_128,
    OperatingMode::CTR,
    ctr,
    "000102030405060708090a0b0c0d0e0f",
    "00112233445566778899aabbccddeeff01"
);

cipher_rt!(
    test_rt_aes_192_ctr_17_bytes,
    &AES_192,
    OperatingMode::CTR,
    ctr,
    "98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9",
    "00112233445566778899aabbccddeeff01"
);

cipher_rt!(
    test_rt_aes_256_ctr_15_bytes,
    &AES_256,
    OperatingMode::CTR,
    ctr,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "00112233445566778899aabbccddee"
);

cipher_rt!(
    test_rt_aes_128_ctr_15_bytes,
    &AES_128,
    OperatingMode::CTR,
    ctr,
    "244828580821c1652582c76e34d299f5",
    "3ee38cec171e6cf466bf0df98aa0e1"
);

cipher_rt!(
    test_rt_aes_192_ctr_15_bytes,
    &AES_192,
    OperatingMode::CTR,
    ctr,
    "b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35",
    "3ee38cec171e6cf466bf0df98aa0e1"
);

cipher_rt!(
    test_rt_aes_256_ctr_15_bytes_2,
    &AES_256,
    OperatingMode::CTR,
    ctr,
    "0857db8240ea459bdf660b4cced66d1f2d3734ff2de7b81e92740e65e7cc6a1d",
    "eca7285d19f3c20e295378460e8729"
);

cipher_rt!(
    test_rt_aes_256_ctr_17_bytes,
    &AES_256,
    OperatingMode::CTR,
    ctr,
    "0857db8240ea459bdf660b4cced66d1f2d3734ff2de7b81e92740e65e7cc6a1d",
    "eca7285d19f3c20e295378460e872934"
);

padded_cipher_rt!(
    test_rt_aes_128_cbc_15_bytes,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "053304bb3899e1d99db9d29343ea782d",
    "a3e4c990356c01f320043c3d8d6f43"
);

padded_cipher_rt!(
    test_rt_aes_192_cbc_15_bytes,
    &AES_192,
    OperatingMode::CBC,
    cbc_pkcs7,
    "45899367c3132849763073c435a9288a766c8b9ec2308516",
    "a3e4c990356c01f320043c3d8d6f43"
);

padded_cipher_rt!(
    test_rt_aes_128_cbc_16_bytes_2,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "95af71f1c63e4a1d0b0b1a27fb978283",
    "aece7b5e3c3df1ffc9802d2dfe296dc7"
);

padded_cipher_rt!(
    test_rt_128_cbc_17_bytes,
    &AES_128,
    OperatingMode::CBC,
    cbc_pkcs7,
    "95af71f1c63e4a1d0b0b1a27fb978283",
    "aece7b5e3c3df1ffc9802d2dfe296dc734"
);

padded_cipher_rt!(
    test_rt_192_cbc_17_bytes,
    &AES_192,
    OperatingMode::CBC,
    cbc_pkcs7,
    "ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e",
    "aece7b5e3c3df1ffc9802d2dfe296dc734"
);

padded_cipher_rt!(
    test_rt_aes_256_cbc_16_bytes,
    &AES_256,
    OperatingMode::CBC,
    cbc_pkcs7,
    "d4a8206dcae01242f9db79a4ecfe277d0f7bb8ccbafd8f9809adb39f35aa9b41",
    "a39c1fdf77ea3e1f18178c0ec237c70a"
);

padded_cipher_rt!(
    test_rt_aes_256_cbc_17_bytes,
    &AES_256,
    OperatingMode::CBC,
    cbc_pkcs7,
    "d4a8206dcae01242f9db79a4ecfe277d0f7bb8ccbafd8f9809adb39f35aa9b41",
    "a39c1fdf77ea3e1f18178c0ec237c70a34"
);

padded_ecb_pkcs7_kat!(
    test_kat_aes_128_ecb_pkcs7_16_bytes,
    &AES_128,
    "4da1ed87937836de98836433b11eb5a7",
    "61f17a594bd5b55ae3fa8efaae6e83d6",
    "e5e18734e84530de94b1636d938e5d6f6b4027b4321685a9195b4ddbf25530bf"
);

padded_ecb_pkcs7_kat!(
    test_kat_aes_192_ecb_pkcs7_16_bytes,
    &AES_192,
    "d077a03bd8a38973928ccafe4a9d2f455130bd0af5ae46a9",
    "61f17a594bd5b55ae3fa8efaae6e83d6",
    "2379bbaa72d82275688301f5cb6ac1898c1ea2c8cd120dc19cdefcc3d477fce4"
);

padded_ecb_pkcs7_kat!(
    test_kat_aes_128_ecb_pkcs7_15_bytes,
    &AES_128,
    "50f0fb9c8bfcedd0424a4932fdb4578d",
    "4badb333837326d75406a0cd6149f0",
    "593a39d148e106ebc4a429b97b5033bc"
);

padded_ecb_pkcs7_kat!(
    test_kat_aes_192_ecb_pkcs7_15_bytes,
    &AES_192,
    "d184c36cf0dddfec39e654195006022237871a47c33d3198",
    "4badb333837326d75406a0cd6149f0",
    "45f7cea9d1d21ade4fc31ff0c4ebf4c7"
);

padded_ecb_pkcs7_kat!(
    test_kat_aes_256_ecb_pkcs7_16_bytes,
    &AES_256,
    "13b2cc03ba601f45b7b1927a7b8566abfae0d97220cb7d5193725ab12e1b23ac",
    "6a3867fbd39bd3345df4aec929c8843a",
    "615c152b5655499a1d94993e9c220a7e9430ed4d48f2c5b408878beed2c90cf7"
);

padded_ecb_pkcs7_kat!(
    test_kat_aes_256_ecb_pkcs7_15_bytes,
    &AES_256,
    "f636aefc30bfe19e7fda3ea399be6529f102b965523719e7e717648ec8451c86",
    "8d6e85663f99f22bb293582f81ae45",
    "f6dc9e368d2cdf6a2e97a022876eb9f2"
);

ecb_kat!(
    test_kat_aes_128_ecb_16_bytes,
    &AES_128,
    "f8efb984d9e813c96a79020bdfbb6032",
    "c4a500e39307dbe7727b5b3a36660f70",
    "1eea416d959f747da26d48d2df11d205"
);

ecb_kat!(
    test_kat_aes_192_ecb_16_bytes,
    &AES_192,
    "4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080",
    "c4a500e39307dbe7727b5b3a36660f70",
    "1f021658980c025396455f7bb7e01d07"
);

ecb_kat!(
    test_kat_aes_128_ecb_15_bytes,
    &AES_128,
    "f8efb984d9e813c96a79020bdfbb6032",
    "c4a500e39307dbe7727b5b3a36660f"
);

ecb_kat!(
    test_kat_aes_192_ecb_15_bytes,
    &AES_192,
    "c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72",
    "c4a500e39307dbe7727b5b3a36660f"
);

ecb_kat!(
    test_kat_aes_256_ecb_16_bytes,
    &AES_256,
    "d3c9173cbfc65d0e2b6f43ae57c2a6550b756f487bbb7b6404efec69aa74d411",
    "109082176cf2a9488b0cd887386bb84a",
    "c8c9fece9883b26c0ca58e610493a318"
);

ecb_kat!(
    test_kat_aes_256_ecb_15_bytes,
    &AES_256,
    "d3c9173cbfc65d0e2b6f43ae57c2a6550b756f487bbb7b6404efec69aa74d411",
    "109082176cf2a9488b0cd887386bb8"
);

ecb_rt!(
    test_rt_aes_128_16_bytes,
    &AES_128,
    "9dfb64e0d2b94ba6df41ef5f72413cb1",
    "81c7241bbbf37d9b50e5072858fc498d"
);

ecb_rt!(
    test_rt_aes_192_16_bytes,
    &AES_192,
    "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd",
    "81c7241bbbf37d9b50e5072858fc498d"
);

ecb_rt!(
    test_rt_aes_256_16_bytes,
    &AES_256,
    "e6be82de1addbf40550abad4b613b2e77dd498ecaeff5251d4773fcfa00cc1f4",
    "eb80cab07da4d9ce53c27903dd070b28"
);

padded_ecb_pkcs7_rt!(
    test_rt_aes_128_ecb_pkcs7_16_bytes,
    &AES_128,
    "c6fcad04ac45dc5801277484279396c0",
    "e6a32546cb537cf589ac65aac84815ae"
);

padded_ecb_pkcs7_rt!(
    test_rt_aes_192_ecb_pkcs7_16_bytes,
    &AES_192,
    "15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29",
    "e6a32546cb537cf589ac65aac84815ae"
);

padded_ecb_pkcs7_rt!(
    test_rt_aes_128_ecb_pkcs7_15_bytes,
    &AES_128,
    "41647c63411930c483be063ca890472e",
    "6194b065db9003381c0c736130188e"
);

padded_ecb_pkcs7_rt!(
    test_rt_aes_192_ecb_pkcs7_15_bytes,
    &AES_192,
    "a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c",
    "6194b065db9003381c0c736130188e"
);

padded_ecb_pkcs7_rt!(
    test_rt_aes_256_ecb_pkcs7_16_bytes,
    &AES_256,
    "c0b52e26961ec041bcea9b3d066c42ea97023a7cfb3e1f3b2e3a8a6427284a47",
    "10420ee900c0045bde1218e17008bdb0"
);

padded_ecb_pkcs7_rt!(
    test_rt_aes_256_ecb_pkcs7_15_bytes,
    &AES_256,
    "48c8511ea06d6b4f594870cdf30fd60e7a88eee09f62d7c359e26e475292ec64",
    "9ac8559493ee5274ae9ca03a47618d"
);

cipher_kat!(
    test_kat_aes_128_cfb128_16_bytes,
    &AES_128,
    OperatingMode::CFB128,
    cfb128,
    "679816318e2f095262ee93c4552490a2",
    "dd41c2fb73e61bdc02da6c70eb5ac729",
    "6a841482cf079c4a4b8c59b6c6bda6a4",
    "0cebe979ac61df66bb190bf9ed22e363"
);

cipher_kat!(
    test_kat_aes_128_cfb128_15_bytes,
    &AES_128,
    OperatingMode::CFB128,
    cfb128,
    "27d4285e8315857653833f63b0bcc034",
    "bbdeef0d1837c33971f04eb0a8cde0a2",
    "750cf377093fb05f84875a240154f7",
    "187a9d7d922afa9f3294ad12669df1"
);

cipher_kat!(
    test_kat_aes_192_cfb128_16_bytes,
    &AES_192,
    OperatingMode::CFB128,
    cfb128,
    "cd62376d5ebb414917f0c78f05266433dc9192a1ec943300",
    "dd41c2fb73e61bdc02da6c70eb5ac729",
    "6a841482cf079c4a4b8c59b6c6bda6a4",
    "35f27d6902d635ac4f664e2367fcd686"
);

cipher_kat!(
    test_kat_aes_192_cfb128_15_bytes,
    &AES_192,
    OperatingMode::CFB128,
    cfb128,
    "502a6ab36984af268bf423c7f509205207fc1552af4a91e5",
    "bbdeef0d1837c33971f04eb0a8cde0a2",
    "750cf377093fb05f84875a240154f7",
    "6c650820cd06ca89aa96c07e16e717"
);

cipher_kat!(
    test_kat_aes_256_cfb128_16_bytes,
    &AES_256,
    OperatingMode::CFB128,
    cfb128,
    "c7faca2e29734b069d19c0e95b9a93efa2512925ccebba8622fb321a93d50cd0",
    "6f5aad20a97c694b0e0c93457f81b5c8",
    "2bc1196172ca0bad4a349198f8abd925",
    "21e1e308bfec28a24520a963aa0f4c57"
);

cipher_kat!(
    test_kat_aes_256_cfb128_15_bytes,
    &AES_256,
    OperatingMode::CFB128,
    cfb128,
    "8ac86dfe6fa15d71c5c5c4a88ae182fd3a1636818f6a8bcd62c85a599329649c",
    "f1b6b55e908d39b769968ae6c3c05c4f",
    "9c1675a95f573b4504e6bc5275d0df",
    "b8e816bd9e74adebdacf9036cbda41"
);
