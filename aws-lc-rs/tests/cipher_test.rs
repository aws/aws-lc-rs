// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::cipher::{
    Algorithm, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, OperatingMode,
    PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, StreamingDecryptingKey,
    StreamingEncryptingKey, UnboundCipherKey, AES_128, AES_192, AES_256,
};
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
use aws_lc_rs::cipher::{
    DES_EDE3_FOR_LEGACY_USE_ONLY, DES_EDE_FOR_LEGACY_USE_ONLY, DES_FOR_LEGACY_USE_ONLY,
};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::iv::{FixedLength, IV_LEN_128_BIT};
use aws_lc_rs::test;
use aws_lc_rs::test::from_hex;
use paste::paste;

// NOTE: these helpers hand `update` one byte MORE than its documented minimum
// (`in_len + block_len`), so they cover the generous-buffer path and are not
// output-bounds tests. Overrun coverage lives in the `cipher::streaming` unit
// tests, which canary the bytes past each output slice.
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
        OperatingMode::CTR
        | OperatingMode::CFB128
        | OperatingMode::CFB8
        | OperatingMode::CFB1
        | OperatingMode::OFB => {
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
        OperatingMode::CTR
        | OperatingMode::CFB128
        | OperatingMode::CFB8
        | OperatingMode::CFB1
        | OperatingMode::OFB => {
            assert_eq!(ciphertext.len(), plaintext.len());
        }
        _ => panic!("Unknown cipher mode"),
    }
    plaintext.into_boxed_slice()
}

macro_rules! streaming_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        fn [<$name _streaming>]() {
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
        }
    };
}

macro_rules! streaming_ecb_pkcs7_rt {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        fn [<$name _streaming>]() {
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
        }
    };
}

macro_rules! streaming_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        fn [<$name _streaming>]() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();
            let iv = from_hex($iv).unwrap();

            for step in ($from_step..=$to_step) {
                let ec = EncryptionContext::Iv128(
                    FixedLength::<IV_LEN_128_BIT>::try_from(iv.as_slice()).unwrap(),
                );

                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
                    let encrypting_key = StreamingEncryptingKey::[<less_safe_ $constructor>](unbound_key, ec).unwrap();

                let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                assert_eq!(expected_ciphertext.as_slice(), ciphertext.as_ref());

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                    let decrypting_key =
                        StreamingDecryptingKey::$constructor(unbound_key2, decrypt_ctx).unwrap();

                let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                assert_eq!(input.as_slice(), plaintext.as_ref());
            }
        }
        }
    };
}

macro_rules! streaming_ecb_pkcs7_kat {
    ($name:ident, $alg:expr, $key:literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        fn [<$name _streaming>]() {
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
        }
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
        unpadded_cipher_kat!(
            $name,
            $alg,
            $mode,
            $constructor,
            $key,
            $iv,
            $plaintext,
            $ciphertext
        );

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

macro_rules! unpadded_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let context = if $iv.len() == 0 {
                EncryptionContext::None
            } else {
                let iv = from_hex($iv).unwrap();
                let fixed_iv = FixedLength::try_from(iv.as_slice()).unwrap();
                EncryptionContext::Iv128(fixed_iv)
            };

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
    };

    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal) => {
        #[test]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();

            let context = if $iv.len() == 0 {
                EncryptionContext::None
            } else {
                let iv = from_hex($iv).unwrap();
                let fixed_iv = FixedLength::try_from(iv.as_slice()).unwrap();
                EncryptionContext::Iv128(fixed_iv)
            };

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

            let encrypting_key = EncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            encrypting_key
                .less_safe_encrypt(in_out.as_mut_slice(), context)
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

unpadded_cipher_kat!(
    test_kat_aes_128_ecb_16_bytes,
    &AES_128,
    OperatingMode::ECB,
    ecb,
    "f8efb984d9e813c96a79020bdfbb6032",
    "", // ECB does not have an IV
    "c4a500e39307dbe7727b5b3a36660f70",
    "1eea416d959f747da26d48d2df11d205"
);

unpadded_cipher_kat!(
    test_kat_aes_192_ecb_16_bytes,
    &AES_192,
    OperatingMode::ECB,
    ecb,
    "4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080",
    "", // ECB does not have an IV
    "c4a500e39307dbe7727b5b3a36660f70",
    "1f021658980c025396455f7bb7e01d07"
);

unpadded_cipher_kat!(
    test_kat_aes_128_ecb_15_bytes,
    &AES_128,
    OperatingMode::ECB,
    ecb,
    "f8efb984d9e813c96a79020bdfbb6032",
    "", // ECB does not have an IV
    "c4a500e39307dbe7727b5b3a36660f"
);

unpadded_cipher_kat!(
    test_kat_aes_192_ecb_15_bytes,
    &AES_192,
    OperatingMode::ECB,
    ecb,
    "c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72",
    "", // ECB does not have an IV
    "c4a500e39307dbe7727b5b3a36660f"
);

unpadded_cipher_kat!(
    test_kat_aes_256_ecb_16_bytes,
    &AES_256,
    OperatingMode::ECB,
    ecb,
    "d3c9173cbfc65d0e2b6f43ae57c2a6550b756f487bbb7b6404efec69aa74d411",
    "", // ECB does not have an IV
    "109082176cf2a9488b0cd887386bb84a",
    "c8c9fece9883b26c0ca58e610493a318"
);

unpadded_cipher_kat!(
    test_kat_aes_256_ecb_15_bytes,
    &AES_256,
    OperatingMode::ECB,
    ecb,
    "d3c9173cbfc65d0e2b6f43ae57c2a6550b756f487bbb7b6404efec69aa74d411",
    "", // ECB does not have an IV
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

unpadded_cipher_kat!(
    test_kat_aes_128_cbc_16_bytes_raw,
    &AES_128,
    OperatingMode::CBC,
    cbc,
    "000102030405060708090a0b0c0d0e0f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);

unpadded_cipher_kat!(
    test_kat_aes_192_cbc_16_bytes_raw,
    &AES_192,
    OperatingMode::CBC,
    cbc,
    "e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "fc7f57e545e92c0a0b364c3086d49bf0"
);

unpadded_cipher_kat!(
    test_kat_aes_256_cbc_16_bytes_raw,
    &AES_256,
    OperatingMode::CBC,
    cbc,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "8ea2b7ca516745bfeafc49904b496089"
);

unpadded_cipher_kat!(
    test_kat_aes_128_cbc_15_bytes_raw,
    &AES_128,
    OperatingMode::CBC,
    cbc,
    "000102030405060708090a0b0c0d0e0f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddee"
);

unpadded_cipher_kat!(
    test_kat_aes_192_cbc_15_bytes_raw,
    &AES_192,
    OperatingMode::CBC,
    cbc,
    "e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddee"
);

unpadded_cipher_kat!(
    test_kat_aes_256_cbc_15_bytes_raw,
    &AES_256,
    OperatingMode::CBC,
    cbc,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddee"
);

#[cfg(feature = "legacy-des")]
macro_rules! des_streaming_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, ecb_pkcs7, $key:literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        #[allow(deprecated)]
        fn [<$name _streaming>]() {
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
        }
    };

    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv:literal, $plaintext:literal, $ciphertext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        #[allow(deprecated)]
        fn [<$name _streaming>]() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();
            let iv = from_hex($iv).unwrap();

            for step in ($from_step..=$to_step) {
                let iv_arr: [u8; 8] = iv.clone().try_into().unwrap();
                let ec = EncryptionContext::Iv64(FixedLength::from(iv_arr));

                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
                let encrypting_key = StreamingEncryptingKey::[<less_safe_ $constructor>](unbound_key, ec).unwrap();

                let (ciphertext, decrypt_ctx) = step_encrypt(encrypting_key, &input, step);

                assert_eq!(expected_ciphertext.as_slice(), ciphertext.as_ref());

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                let decrypting_key =
                    StreamingDecryptingKey::$constructor(unbound_key2, decrypt_ctx).unwrap();

                let plaintext = step_decrypt(decrypting_key, &ciphertext, step);
                assert_eq!(input.as_slice(), plaintext.as_ref());
            }
        }
        }
    };
}

#[cfg(feature = "legacy-des")]
macro_rules! des_streaming_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal, $from_step:literal, $to_step:literal) => {
        paste! {
        #[test]
        #[allow(deprecated)]
        fn [<$name _streaming>]() {
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
        }
    };
}

#[cfg(feature = "legacy-des")]
macro_rules! des_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv:literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        #[allow(deprecated)]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let enc_ctx = if $iv.len() == 0 {
                EncryptionContext::None
            } else {
                let iv_arr: [u8; 8] = from_hex($iv).unwrap().try_into().unwrap();
                EncryptionContext::Iv64(FixedLength::from(iv_arr))
            };

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
            let encrypting_key = EncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(&mut in_out, enc_ctx)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out.as_slice());

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = DecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }
    };

    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv:literal, $plaintext:literal) => {
        #[test]
        #[allow(deprecated)]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();

            let enc_ctx = if $iv.len() == 0 {
                EncryptionContext::None
            } else {
                let iv_arr: [u8; 8] = from_hex($iv).unwrap().try_into().unwrap();
                EncryptionContext::Iv64(FixedLength::from(iv_arr))
            };

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
            let encrypting_key = EncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            encrypting_key
                .less_safe_encrypt(in_out.as_mut_slice(), enc_ctx)
                .expect_err("expected encryption failure");
        }
    };
}

#[cfg(feature = "legacy-des")]
macro_rules! des_padded_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, ecb_pkcs7, $key:literal, $iv:literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        #[allow(deprecated)]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
            let encrypting_key = PaddedBlockEncryptingKey::ecb_pkcs7(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(&mut in_out, EncryptionContext::None)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out.as_slice());

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = PaddedBlockDecryptingKey::ecb_pkcs7(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        des_streaming_cipher_kat!(
            $name,
            $alg,
            $mode,
            ecb_pkcs7,
            $key,
            $plaintext,
            $ciphertext,
            2,
            9
        );
    };

    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv:literal, $plaintext:literal, $ciphertext:literal) => {
        #[test]
        #[allow(deprecated)]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();
            let expected_ciphertext = from_hex($ciphertext).unwrap();

            let enc_ctx = if $iv.len() == 0 {
                EncryptionContext::None
            } else {
                let iv_arr: [u8; 8] = from_hex($iv).unwrap().try_into().unwrap();
                EncryptionContext::Iv64(FixedLength::from(iv_arr))
            };

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
            let encrypting_key = PaddedBlockEncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key
                .less_safe_encrypt(&mut in_out, enc_ctx)
                .unwrap();
            assert_eq!(expected_ciphertext.as_slice(), in_out.as_slice());

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = PaddedBlockDecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }

        des_streaming_cipher_kat!(
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

#[cfg(feature = "legacy-des")]
macro_rules! des_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal) => {
        #[test]
        #[allow(deprecated)]
        fn $name() {
            let key = from_hex($key).unwrap();
            let input = from_hex($plaintext).unwrap();

            let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();
            let encrypting_key = EncryptingKey::$constructor(unbound_key).unwrap();
            assert_eq!($mode, encrypting_key.mode());
            assert_eq!($alg, encrypting_key.algorithm());
            let mut in_out = input.clone();
            let context = encrypting_key.encrypt(in_out.as_mut_slice()).unwrap();
            assert_ne!(input.as_slice(), in_out.as_slice());

            let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
            let decrypting_key = DecryptingKey::$constructor(unbound_key2).unwrap();
            assert_eq!($mode, decrypting_key.mode());
            assert_eq!($alg, decrypting_key.algorithm());
            let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
            assert_eq!(input.as_slice(), plaintext);
        }
    };
}

#[cfg(feature = "legacy-des")]
macro_rules! des_padded_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal) => {
        #[test]
        #[allow(deprecated)]
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

        des_streaming_cipher_rt!($name, $alg, $mode, $constructor, $key, $plaintext, 2, 9);
    };
}

// The following Triple DES (2TDEA/3TDEA) KAT vectors are from the NIST SP 800-38A
// TDES example values:
// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
// The 2TDEA key is the first 16 bytes of the 3TDEA key.
// PKCS#7-padded variants are not from NIST; their ciphertexts were computed
// by applying PKCS#7 padding to the NIST plaintext before encryption.
//
// The single-DES KAT vectors below share the same key prefix, IV and plaintext
// as the TDES vectors for convenience but are not from NIST (SP 800-38A has no
// single-DES examples). Their ciphertexts were verified against an independent
// DES implementation.
#[cfg(feature = "legacy-des")]
des_cipher_rt!(
    test_rt_des_cbc_32_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_cipher_rt!(
    test_rt_des_ecb_32_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

// NIST SP 800-38A, Appendix F.
// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf>

// Source: F.4.1
cipher_kat!(
    test_kat_aes_128_ofb_16_bytes,
    &AES_128,
    OperatingMode::OFB,
    ofb,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172a",
    "3b3fd92eb72dad20333449f8e83cfb4a"
);

// Source: F.4.3
cipher_kat!(
    test_kat_aes_192_ofb_16_bytes,
    &AES_192,
    OperatingMode::OFB,
    ofb,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172a",
    "cdc80d6fddf18cab34c25909c99a4174"
);

// Source: F.4.5
cipher_kat!(
    test_kat_aes_256_ofb_16_bytes,
    &AES_256,
    OperatingMode::OFB,
    ofb,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172a",
    "dc7e84bfda79164b7ecd8486985d3860"
);

// Source: F.4.1, all four blocks
cipher_kat!(
    test_kat_aes_128_ofb_64_bytes,
    &AES_128,
    OperatingMode::OFB,
    ofb,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"
);

// Source: F.4.3, all four blocks
cipher_kat!(
    test_kat_aes_192_ofb_64_bytes,
    &AES_192,
    OperatingMode::OFB,
    ofb,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a"
);

// Source: F.4.5, all four blocks
cipher_kat!(
    test_kat_aes_256_ofb_64_bytes,
    &AES_256,
    OperatingMode::OFB,
    ofb,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484"
);

// Source: F.3.7, via AWS-LC cfb_test.cc
cipher_kat!(
    test_kat_aes_128_cfb8_18_bytes,
    &AES_128,
    OperatingMode::CFB8,
    cfb8,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d",
    "3b79424c9c0dd436bace9e0ed4586a4f32b9"
);

// Source: F.3.9, via AWS-LC cfb_test.cc
cipher_kat!(
    test_kat_aes_192_cfb8_18_bytes,
    &AES_192,
    OperatingMode::CFB8,
    cfb8,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d",
    "cda2521ef0a905ca44cd057cbf0d47a0678a"
);

// Source: F.3.11, via AWS-LC cfb_test.cc
cipher_kat!(
    test_kat_aes_256_cfb8_18_bytes,
    &AES_256,
    OperatingMode::CFB8,
    cfb8,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d",
    "dc1f1a8520a64db55fcc8ac554844e889700"
);

// Source: F.3.1, via AWS-LC cfb_test.cc
cipher_kat!(
    test_kat_aes_128_cfb1_2_bytes,
    &AES_128,
    OperatingMode::CFB1,
    cfb1,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1",
    "68b3"
);

// Source: F.3.3, via AWS-LC cfb_test.cc
cipher_kat!(
    test_kat_aes_192_cfb1_2_bytes,
    &AES_192,
    OperatingMode::CFB1,
    cfb1,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1",
    "9359"
);

// Source: F.3.5, via AWS-LC cfb_test.cc
cipher_kat!(
    test_kat_aes_256_cfb1_2_bytes,
    &AES_256,
    OperatingMode::CFB1,
    cfb1,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1",
    "9029"
);

// Source: F.3.1, via AWS-LC cfb_test.cc
streaming_cipher_kat!(
    test_kat_aes_128_cfb1_2_bytes_step1,
    &AES_128,
    OperatingMode::CFB1,
    cfb1,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1",
    "68b3",
    1,
    1
);

// Source: F.3.3, via AWS-LC cfb_test.cc
streaming_cipher_kat!(
    test_kat_aes_192_cfb1_2_bytes_step1,
    &AES_192,
    OperatingMode::CFB1,
    cfb1,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1",
    "9359",
    1,
    1
);

// Source: F.3.5, via AWS-LC cfb_test.cc
streaming_cipher_kat!(
    test_kat_aes_256_cfb1_2_bytes_step1,
    &AES_256,
    OperatingMode::CFB1,
    cfb1,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1",
    "9029",
    1,
    1
);

cipher_rt!(
    test_rt_aes_128_cfb8_5_bytes,
    &AES_128,
    OperatingMode::CFB8,
    cfb8,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "6bc1bee22e"
);

cipher_rt!(
    test_rt_aes_256_cfb8_5_bytes,
    &AES_256,
    OperatingMode::CFB8,
    cfb8,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "6bc1bee22e"
);

cipher_rt!(
    test_rt_aes_128_cfb8_20_bytes,
    &AES_128,
    OperatingMode::CFB8,
    cfb8,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "6bc1bee22e409f96e93d7e117393172aae2d8a57"
);

cipher_rt!(
    test_rt_aes_256_cfb8_20_bytes,
    &AES_256,
    OperatingMode::CFB8,
    cfb8,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "6bc1bee22e409f96e93d7e117393172aae2d8a57"
);

cipher_rt!(
    test_rt_aes_128_cfb1_5_bytes,
    &AES_128,
    OperatingMode::CFB1,
    cfb1,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "6bc1bee22e"
);

cipher_rt!(
    test_rt_aes_256_cfb1_5_bytes,
    &AES_256,
    OperatingMode::CFB1,
    cfb1,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "6bc1bee22e"
);

cipher_rt!(
    test_rt_aes_128_cfb1_20_bytes,
    &AES_128,
    OperatingMode::CFB1,
    cfb1,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "6bc1bee22e409f96e93d7e117393172aae2d8a57"
);

cipher_rt!(
    test_rt_aes_256_cfb1_20_bytes,
    &AES_256,
    OperatingMode::CFB1,
    cfb1,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "6bc1bee22e409f96e93d7e117393172aae2d8a57"
);

cipher_rt!(
    test_rt_aes_128_ofb_17_bytes,
    &AES_128,
    OperatingMode::OFB,
    ofb,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "6bc1bee22e409f96e93d7e117393172aae"
);

cipher_rt!(
    test_rt_aes_256_ofb_17_bytes,
    &AES_256,
    OperatingMode::OFB,
    ofb,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "6bc1bee22e409f96e93d7e117393172aae"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_cbc_32_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "2d121f90fcf68631ed788fcfe31a62dffa784891fa512ef928ea856d934257c6"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ecb_32_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "7277a00dc1c1c36b2256338b7a9f36ef6e511022cfebec489a4a53a1c7d22e5b"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_cbc_31_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ecb_31_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_rt!(
    test_rt_des_cbc_pkcs7_31_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc_pkcs7,
    "0123456789abcdef",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_rt!(
    test_rt_des_ecb_pkcs7_31_bytes,
    &DES_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb_pkcs7,
    "0123456789abcdef",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
// The four weak and twelve semi-weak keys in odd parity (SP 800-67r2, section 3.3.2).
const DES_WEAK_AND_SEMI_WEAK_KEYS: [&str; 16] = [
    "0101010101010101",
    "fefefefefefefefe",
    "1f1f1f1f0e0e0e0e",
    "e0e0e0e0f1f1f1f1",
    "01fe01fe01fe01fe",
    "fe01fe01fe01fe01",
    "1fe01fe00ef10ef1",
    "e01fe01ff10ef10e",
    "01e001e001f101f1",
    "e001e001f101f101",
    "1ffe1ffe0efe0efe",
    "fe1ffe1ffe0efe0e",
    "011f011f010e010e",
    "1f011f010e010e01",
    "e0fee0fef1fef1fe",
    "fee0fee0fef1fef1",
];

#[cfg(feature = "legacy-des")]
fn des_test_subkeys() -> [[u8; 8]; 3] {
    ["0123456789abcdef", "23456789abcdef01", "456789abcdef0123"]
        .map(|key| from_hex(key).unwrap().try_into().unwrap())
}

#[cfg(feature = "legacy-des")]
fn des_parity_variant(mut key: [u8; 8], mask: u8) -> [u8; 8] {
    for (index, byte) in key.iter_mut().enumerate() {
        *byte ^= (mask >> index) & 1;
    }
    key
}

#[cfg(feature = "legacy-des")]
fn des_key_parity_variant(key_bytes: &[u8], mask: u8, variant_position: usize) -> Vec<u8> {
    let subkey_count = key_bytes.len() / 8;
    let mut variant = key_bytes.to_vec();
    for (position, subkey) in variant.chunks_exact_mut(8).enumerate() {
        if position == variant_position || variant_position == subkey_count {
            let key = (&*subkey).try_into().unwrap();
            subkey.copy_from_slice(&des_parity_variant(key, mask));
        }
    }
    variant
}

#[cfg(feature = "legacy-des")]
fn assert_des_key_validation(
    algorithm: &'static Algorithm,
    key_bytes: &[u8],
    encryption_should_accept: bool,
) {
    let unbound = || {
        UnboundCipherKey::new(algorithm, key_bytes)
            .expect("UnboundCipherKey must defer DES weak-key and subkey-distinctness checks")
    };
    for (path, accepted) in [
        (
            "unpadded CBC encrypt",
            EncryptingKey::cbc(unbound()).is_ok(),
        ),
        (
            "unpadded ECB encrypt",
            EncryptingKey::ecb(unbound()).is_ok(),
        ),
        (
            "padded CBC encrypt",
            PaddedBlockEncryptingKey::cbc_pkcs7(unbound()).is_ok(),
        ),
        (
            "padded ECB encrypt",
            PaddedBlockEncryptingKey::ecb_pkcs7(unbound()).is_ok(),
        ),
        (
            "streaming CBC encrypt",
            StreamingEncryptingKey::less_safe_cbc_pkcs7(
                unbound(),
                EncryptionContext::Iv64(FixedLength::from([0u8; 8])),
            )
            .is_ok(),
        ),
        (
            "streaming ECB encrypt",
            StreamingEncryptingKey::ecb_pkcs7(unbound()).is_ok(),
        ),
    ] {
        assert_eq!(
            accepted, encryption_should_accept,
            "{algorithm:?}, key {key_bytes:02x?}, {path}"
        );
    }

    // Decryption must remain available for legacy weak and degenerate keys.
    for (path, accepted) in [
        (
            "unpadded CBC decrypt",
            DecryptingKey::cbc(unbound()).is_ok(),
        ),
        (
            "unpadded ECB decrypt",
            DecryptingKey::ecb(unbound()).is_ok(),
        ),
        (
            "padded CBC decrypt",
            PaddedBlockDecryptingKey::cbc_pkcs7(unbound()).is_ok(),
        ),
        (
            "padded ECB decrypt",
            PaddedBlockDecryptingKey::ecb_pkcs7(unbound()).is_ok(),
        ),
        (
            "ISO10126 CBC decrypt",
            PaddedBlockDecryptingKey::cbc_iso10126(unbound()).is_ok(),
        ),
        (
            "streaming CBC decrypt",
            StreamingDecryptingKey::cbc_pkcs7(
                unbound(),
                DecryptionContext::Iv64(FixedLength::from([0u8; 8])),
            )
            .is_ok(),
        ),
        (
            "streaming ECB decrypt",
            StreamingDecryptingKey::ecb_pkcs7(unbound(), DecryptionContext::None).is_ok(),
        ),
    ] {
        assert!(accepted, "{algorithm:?}, key {key_bytes:02x?}, {path}");
    }
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_weak_keys_rejected() {
    for hex_key in DES_WEAK_AND_SEMI_WEAK_KEYS {
        let weak_key = from_hex(hex_key).unwrap().try_into().unwrap();
        for mask in 0..=u8::MAX {
            assert_des_key_validation(
                &DES_FOR_LEGACY_USE_ONLY,
                &des_parity_variant(weak_key, mask),
                false,
            );
        }
    }
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_ede_weak_subkeys_rejected() {
    let valid_subkeys = des_test_subkeys();
    for (algorithm, subkey_count) in [
        (&DES_EDE_FOR_LEGACY_USE_ONLY, 2),
        (&DES_EDE3_FOR_LEGACY_USE_ONLY, 3),
    ] {
        for hex_key in DES_WEAK_AND_SEMI_WEAK_KEYS {
            let weak_key = from_hex(hex_key).unwrap().try_into().unwrap();
            for position in 0..subkey_count {
                for mask in 0..=u8::MAX {
                    let mut subkeys = valid_subkeys;
                    subkeys[position] = des_parity_variant(weak_key, mask);
                    let key_bytes = subkeys[..subkey_count].concat();
                    assert_des_key_validation(algorithm, &key_bytes, false);
                }
            }
        }
    }
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_ede_rejects_k1_equals_k2() {
    // 2TDEA degenerates to single DES even when K1 and K2 differ in parity bits.
    let k1 = des_test_subkeys()[0];
    for mask in 0..=u8::MAX {
        let k2 = des_parity_variant(k1, mask);
        for subkeys in [[k1, k2], [k2, k1]] {
            assert_des_key_validation(&DES_EDE_FOR_LEGACY_USE_ONLY, &subkeys.concat(), false);
        }
    }
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_ede3_rejects_pairwise_equal_keys() {
    let valid_subkeys = des_test_subkeys();
    for mask in 0..=u8::MAX {
        // K1 == K3 reduces to 2TDEA, so that pair must also be checked.
        for (first, second) in [(0, 1), (0, 2), (1, 2)] {
            let mut subkeys = valid_subkeys;
            subkeys[second] = des_parity_variant(subkeys[first], mask);
            assert_des_key_validation(&DES_EDE3_FOR_LEGACY_USE_ONLY, &subkeys.concat(), false);

            subkeys.swap(first, second);
            assert_des_key_validation(&DES_EDE3_FOR_LEGACY_USE_ONLY, &subkeys.concat(), false);
        }

        let k1 = valid_subkeys[0];
        let subkeys = [
            k1,
            des_parity_variant(k1, mask),
            des_parity_variant(k1, mask.rotate_left(1)),
        ];
        assert_des_key_validation(&DES_EDE3_FOR_LEGACY_USE_ONLY, &subkeys.concat(), false);
    }
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_parity_variants_accepted() {
    let valid_subkeys = des_test_subkeys();
    let plaintext =
        from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();
    for (algorithm, subkey_count, ciphertext_hex) in [
        (
            &DES_FOR_LEGACY_USE_ONLY,
            1,
            "7277a00dc1c1c36b2256338b7a9f36ef6e511022cfebec489a4a53a1c7d22e5b",
        ),
        (
            &DES_EDE_FOR_LEGACY_USE_ONLY,
            2,
            "06ede3d82884090aff322c19f0518486730576972a666e58b6c88cf107340d3d",
        ),
        (
            &DES_EDE3_FOR_LEGACY_USE_ONLY,
            3,
            "714772f339841d34267fcc4bd2949cc3ee11c22a576a303876183f99c0b6de87",
        ),
    ] {
        let expected_ciphertext = from_hex(ciphertext_hex).unwrap();
        let base_key = valid_subkeys[..subkey_count].concat();
        for mask in 0..=u8::MAX {
            // Change each subkey alone, then all subkeys together.
            for variant_position in 0..=subkey_count {
                let key_bytes = des_key_parity_variant(&base_key, mask, variant_position);
                assert_des_key_validation(algorithm, &key_bytes, true);

                let unbound = UnboundCipherKey::new(algorithm, &key_bytes).unwrap();
                let encrypting_key = EncryptingKey::ecb(unbound).unwrap();
                let mut in_out = plaintext.clone();
                let context = encrypting_key.encrypt(&mut in_out).unwrap();
                assert_eq!(
                    expected_ciphertext, in_out,
                    "{algorithm:?}, key {key_bytes:02x?} must have the same ECB ciphertext"
                );

                let unbound = UnboundCipherKey::new(algorithm, &key_bytes).unwrap();
                let decrypting_key = DecryptingKey::ecb(unbound).unwrap();
                assert_eq!(
                    plaintext.as_slice(),
                    decrypting_key.decrypt(&mut in_out, context).unwrap(),
                    "{algorithm:?}, key {key_bytes:02x?} must decrypt the same ECB ciphertext"
                );
            }
        }
    }
}

#[cfg(feature = "legacy-des")]
const DES_DECRYPTION_PLAINTEXT: [u8; 8] = *b"DES test";

#[cfg(feature = "legacy-des")]
const DES_DECRYPTION_IV: [u8; 8] = [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17];

#[cfg(feature = "legacy-des")]
fn des_test_decryption_context(mode: OperatingMode) -> DecryptionContext {
    match mode {
        OperatingMode::CBC => DecryptionContext::Iv64(FixedLength::from(DES_DECRYPTION_IV)),
        OperatingMode::ECB => DecryptionContext::None,
        _ => panic!("unsupported DES fixture mode"),
    }
}

#[cfg(feature = "legacy-des")]
fn assert_des_legacy_decryption(
    algorithm: &'static Algorithm,
    key_bytes: &[u8],
    ciphertexts: &[Vec<u8>; 3],
) {
    let [cbc_pkcs7, ecb_pkcs7, cbc_iso10126] = ciphertexts;
    let unbound = || UnboundCipherKey::new(algorithm, key_bytes).unwrap();
    for (mode, ciphertext) in [
        (OperatingMode::CBC, cbc_pkcs7),
        (OperatingMode::ECB, ecb_pkcs7),
    ] {
        let context = || des_test_decryption_context(mode);
        let unpadded = if mode == OperatingMode::CBC {
            DecryptingKey::cbc(unbound())
        } else {
            DecryptingKey::ecb(unbound())
        }
        .unwrap();
        let mut in_out = ciphertext[..DES_DECRYPTION_PLAINTEXT.len()].to_vec();
        assert_eq!(
            DES_DECRYPTION_PLAINTEXT.as_slice(),
            unpadded.decrypt(&mut in_out, context()).unwrap(),
            "{algorithm:?}, key {key_bytes:02x?}, unpadded {mode:?}"
        );

        let padded = if mode == OperatingMode::CBC {
            PaddedBlockDecryptingKey::cbc_pkcs7(unbound())
        } else {
            PaddedBlockDecryptingKey::ecb_pkcs7(unbound())
        }
        .unwrap();
        let mut in_out = ciphertext.clone();
        assert_eq!(
            DES_DECRYPTION_PLAINTEXT.as_slice(),
            padded.decrypt(&mut in_out, context()).unwrap(),
            "{algorithm:?}, key {key_bytes:02x?}, padded {mode:?}"
        );

        let streaming = if mode == OperatingMode::CBC {
            StreamingDecryptingKey::cbc_pkcs7(unbound(), context())
        } else {
            StreamingDecryptingKey::ecb_pkcs7(unbound(), context())
        }
        .unwrap();
        assert_eq!(
            DES_DECRYPTION_PLAINTEXT.as_slice(),
            step_decrypt(streaming, ciphertext, 3).as_ref(),
            "{algorithm:?}, key {key_bytes:02x?}, streaming {mode:?}"
        );
    }

    let iso10126 = PaddedBlockDecryptingKey::cbc_iso10126(unbound()).unwrap();
    for ciphertext in [cbc_pkcs7, cbc_iso10126] {
        let mut in_out = ciphertext.clone();
        assert_eq!(
            DES_DECRYPTION_PLAINTEXT.as_slice(),
            iso10126
                .decrypt(&mut in_out, des_test_decryption_context(OperatingMode::CBC))
                .unwrap(),
            "{algorithm:?}, key {key_bytes:02x?}, ISO10126 CBC"
        );
    }
}

// Weak, semi-weak, and degenerate DES keys with known ciphertexts.
// Generated with OpenSSL 3.5.9 using the default and legacy providers:
// openssl enc -<des|des-ede|des-ede3>-<cbc|ecb> -provider default
//   -provider legacy -nosalt -K KEY [-iv f69f2445df4f9b17]
// Plaintext is 4445532074657374 ("DES test"). Each fixture contains CBC
// PKCS#7, ECB PKCS#7, then CBC ISO10126 ciphertext. The latter encrypts
// 4445532074657374a1b2c3d4e5f60708 with -nopad (nonuniform padding).
// The first block of each PKCS#7 ciphertext is also the unpadded fixture.
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
const DES_LEGACY_KEY_FIXTURES: &[(&Algorithm, &str, [&str; 3])] = &[
    // DES weak key.
    (
        &DES_FOR_LEGACY_USE_ONLY,
        "0101010101010101",
        [
            "370e5fde6401df68a314e621a1edb5db",
            "3b0c2665c89c7ea67e422822773666c0",
            "370e5fde6401df68814fa47589c8b6b8",
        ],
    ),
    // DES semi-weak key.
    (
        &DES_FOR_LEGACY_USE_ONLY,
        "01fe01fe01fe01fe",
        [
            "13ec4012f5dd1b23e59ea106bd64e72a",
            "e235ecd549b7ae7705aa0cf305fecae6",
            "13ec4012f5dd1b23aa196891bb792784",
        ],
    ),
    // 2TDEA weak subkey K1.
    (
        &DES_EDE_FOR_LEGACY_USE_ONLY,
        "010101010101010123456789abcdef01",
        [
            "9ba619eee0d9700dbfa9c008fe31a8b9",
            "5c1be11367f9beca2a63be4fe0e55a2e",
            "9ba619eee0d9700d1196281fd80803cc",
        ],
    ),
    // 2TDEA weak subkey K2.
    (
        &DES_EDE_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef0101010101010101",
        [
            "4abbdea814f458c8c73916ec6fb66395",
            "14f4c730d3a763c75ced66355b27466f",
            "4abbdea814f458c8684ef15f3326c9df",
        ],
    ),
    // 3TDEA weak subkey K1.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "010101010101010123456789abcdef01456789abcdef0123",
        [
            "9766b0a05e09aac80bd556399c9f23c1",
            "41300804f9cf03847ec4c52a307e1637",
            "9766b0a05e09aac8a5c740762cbb7a57",
        ],
    ),
    // 3TDEA weak subkey K2.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef0101010101010101456789abcdef0123",
        [
            "2a32e2bd6ef15c6f1c6f8528d75464e2",
            "1ab84f5977880e0e28a90b068e120f81",
            "2a32e2bd6ef15c6f6756dbe6aca59911",
        ],
    ),
    // 3TDEA weak subkey K3.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef23456789abcdef010101010101010101",
        [
            "26834c529e1222e230e641363254b25c",
            "cc6bb8616c943129449455390145518f",
            "26834c529e1222e2fa0ab4eb62deca1c",
        ],
    ),
    // 2TDEA semi-weak subkey K1.
    (
        &DES_EDE_FOR_LEGACY_USE_ONLY,
        "01fe01fe01fe01fe23456789abcdef01",
        [
            "0d3233a576c0b3435b3619f96e26a2e6",
            "da16f6b793c42db71b9df4fdb24714df",
            "0d3233a576c0b343c37a56f6feefa232",
        ],
    ),
    // 2TDEA semi-weak subkey K2.
    (
        &DES_EDE_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef01fe01fe01fe01fe",
        [
            "445bb392ecaf1b8643f414458f52661f",
            "06fc4725590ad01db78ca9e5c90788a6",
            "445bb392ecaf1b86ed68ce0c8bc70bc8",
        ],
    ),
    // 3TDEA semi-weak subkey K1.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "01fe01fe01fe01fe23456789abcdef01456789abcdef0123",
        [
            "747e2668482aedf646ae951f294f4292",
            "fd80324e9996e715bc18279ea09da454",
            "747e2668482aedf6f51133b7bc9092d4",
        ],
    ),
    // 3TDEA semi-weak subkey K2.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef01fe01fe01fe01fe456789abcdef0123",
        [
            "54dd578faf4ba21f6d99ab6bad011f60",
            "464e09d5517f94fa94b5a3371def126c",
            "54dd578faf4ba21f1da3ac508276bc5d",
        ],
    ),
    // 3TDEA semi-weak subkey K3.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef23456789abcdef0101fe01fe01fe01fe",
        [
            "1bbe6a88f62dc93d2ddd9acc60af784b",
            "612ab62bdfcb48477e4b2794961de7bf",
            "1bbe6a88f62dc93d5fdf97b9a8d1276b",
        ],
    ),
    // 2TDEA K1 == K2.
    (
        &DES_EDE_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef0123456789abcdef",
        [
            "06ba8888c9f78471791d4d42192595c1",
            "b0c0454b0a5025ce086f9a1d74c94d4e",
            "06ba8888c9f78471067bc2d8f8192f7e",
        ],
    ),
    // 3TDEA K1 == K2.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef0123456789abcdef456789abcdef0123",
        [
            "9d4a0a218d15315d3358306b4334241c",
            "366330165ebefbb3042cd660fded50fc",
            "9d4a0a218d15315d7b0f50b8440e8dfe",
        ],
    ),
    // 3TDEA K1 == K3.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef23456789abcdef010123456789abcdef",
        [
            "80647273f24dc75e31a0aab909db63fc",
            "46f8c3cb9fbc0a685db28100613ac225",
            "80647273f24dc75ee16e919962e3242c",
        ],
    ),
    // 3TDEA K2 == K3.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef23456789abcdef0123456789abcdef01",
        [
            "06ba8888c9f78471791d4d42192595c1",
            "b0c0454b0a5025ce086f9a1d74c94d4e",
            "06ba8888c9f78471067bc2d8f8192f7e",
        ],
    ),
    // 3TDEA all subkeys equal.
    (
        &DES_EDE3_FOR_LEGACY_USE_ONLY,
        "0123456789abcdef0123456789abcdef0123456789abcdef",
        [
            "06ba8888c9f78471791d4d42192595c1",
            "b0c0454b0a5025ce086f9a1d74c94d4e",
            "06ba8888c9f78471067bc2d8f8192f7e",
        ],
    ),
];

#[test]
#[cfg(feature = "legacy-des")]
fn test_des_legacy_keys_decrypt_known_ciphertexts() {
    for &(algorithm, key_hex, ciphertext_hex) in DES_LEGACY_KEY_FIXTURES {
        let base_key = from_hex(key_hex).unwrap();
        let subkey_count = base_key.len() / 8;
        let ciphertexts = ciphertext_hex.map(|hex| from_hex(hex).unwrap());
        for mask in 0..=u8::MAX {
            for variant_position in 0..=subkey_count {
                let key_bytes = des_key_parity_variant(&base_key, mask, variant_position);
                assert_des_legacy_decryption(algorithm, &key_bytes, &ciphertexts);
            }
        }
    }
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_unsupported_modes_rejected() {
    for (alg, key_hex) in [
        (&DES_FOR_LEGACY_USE_ONLY, "0123456789abcdef"),
        (
            &DES_EDE_FOR_LEGACY_USE_ONLY,
            "0123456789abcdef23456789abcdef01",
        ),
        (
            &DES_EDE3_FOR_LEGACY_USE_ONLY,
            "0123456789abcdef23456789abcdef01456789abcdef0123",
        ),
    ] {
        let key_bytes = from_hex(key_hex).unwrap();

        // CTR must be rejected
        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        EncryptingKey::ctr(unbound).expect_err("DES + CTR should be rejected");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        DecryptingKey::ctr(unbound).expect_err("DES + CTR should be rejected (decrypt)");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        assert!(
            StreamingEncryptingKey::ctr(unbound).is_err(),
            "DES + CTR should be rejected (streaming encrypt)"
        );

        // CFB128 must be rejected
        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        EncryptingKey::cfb128(unbound).expect_err("DES + CFB128 should be rejected");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        DecryptingKey::cfb128(unbound).expect_err("DES + CFB128 should be rejected (decrypt)");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        assert!(
            StreamingEncryptingKey::cfb128(unbound).is_err(),
            "DES + CFB128 should be rejected (streaming encrypt)"
        );

        // CFB8 must be rejected
        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        EncryptingKey::cfb8(unbound).expect_err("DES + CFB8 should be rejected");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        DecryptingKey::cfb8(unbound).expect_err("DES + CFB8 should be rejected (decrypt)");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        assert!(
            StreamingEncryptingKey::cfb8(unbound).is_err(),
            "DES + CFB8 should be rejected (streaming encrypt)"
        );

        // CFB1 must be rejected
        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        EncryptingKey::cfb1(unbound).expect_err("DES + CFB1 should be rejected");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        DecryptingKey::cfb1(unbound).expect_err("DES + CFB1 should be rejected (decrypt)");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        assert!(
            StreamingEncryptingKey::cfb1(unbound).is_err(),
            "DES + CFB1 should be rejected (streaming encrypt)"
        );

        // OFB must be rejected
        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        EncryptingKey::ofb(unbound).expect_err("DES + OFB should be rejected");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        DecryptingKey::ofb(unbound).expect_err("DES + OFB should be rejected (decrypt)");

        let unbound = UnboundCipherKey::new(alg, &key_bytes).unwrap();
        assert!(
            StreamingEncryptingKey::ofb(unbound).is_err(),
            "DES + OFB should be rejected (streaming encrypt)"
        );
    }
}

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede_cbc_32_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef23456789abcdef01",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "7401ce1eab6d003caff84bf47b36cc2154f0238f9ffecd8f6acf118392b45581"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede3_cbc_32_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "2079c3d53aa763e193b79e2569ab5262516570481f25b50f73c0bda85c8e0da7"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede_ecb_32_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef23456789abcdef01",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "06ede3d82884090aff322c19f0518486730576972a666e58b6c88cf107340d3d"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede3_ecb_32_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "714772f339841d34267fcc4bd2949cc3ee11c22a576a303876183f99c0b6de87"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede_cbc_31_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef23456789abcdef01",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede3_cbc_31_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede_ecb_31_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef23456789abcdef01",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e"
);

#[cfg(feature = "legacy-des")]
des_cipher_kat!(
    test_kat_des_ede3_ecb_31_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e"
);

#[cfg(feature = "legacy-des")]
des_cipher_rt!(
    test_rt_des_ede_cbc_32_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef23456789abcdef01",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_cipher_rt!(
    test_rt_des_ede3_cbc_32_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_cipher_rt!(
    test_rt_des_ede_ecb_32_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef23456789abcdef01",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_cipher_rt!(
    test_rt_des_ede3_ecb_32_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_kat!(
    test_kat_des_ede_cbc_pkcs7_32_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc_pkcs7,
    "0123456789abcdef23456789abcdef01",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "7401ce1eab6d003caff84bf47b36cc2154f0238f9ffecd8f6acf118392b45581dcb0d2607c9dd8a3"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_kat!(
    test_kat_des_ede3_cbc_pkcs7_32_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc_pkcs7,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "f69f2445df4f9b17",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "2079c3d53aa763e193b79e2569ab5262516570481f25b50f73c0bda85c8e0da733830d1a78387028"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_kat!(
    test_kat_des_ede_ecb_pkcs7_32_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb_pkcs7,
    "0123456789abcdef23456789abcdef01",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "06ede3d82884090aff322c19f0518486730576972a666e58b6c88cf107340d3d5db28100613ac225"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_kat!(
    test_kat_des_ede3_ecb_pkcs7_32_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb_pkcs7,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
    "714772f339841d34267fcc4bd2949cc3ee11c22a576a303876183f99c0b6de87832846b52f9e213d"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_rt!(
    test_rt_des_ede_cbc_pkcs7_31_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc_pkcs7,
    "0123456789abcdef23456789abcdef01",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_rt!(
    test_rt_des_ede3_cbc_pkcs7_31_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::CBC,
    cbc_pkcs7,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_rt!(
    test_rt_des_ede_ecb_pkcs7_31_bytes,
    &DES_EDE_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb_pkcs7,
    "0123456789abcdef23456789abcdef01",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[cfg(feature = "legacy-des")]
des_padded_cipher_rt!(
    test_rt_des_ede3_ecb_pkcs7_31_bytes,
    &DES_EDE3_FOR_LEGACY_USE_ONLY,
    OperatingMode::ECB,
    ecb_pkcs7,
    "0123456789abcdef23456789abcdef01456789abcdef0123",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
);

#[test]
fn test_streaming_cipher_traits() {
    test::compile_time_assert_send::<StreamingEncryptingKey>();
    test::compile_time_assert_send::<StreamingDecryptingKey>();
}

type DecryptingKeyConstructor = fn(UnboundCipherKey) -> Result<DecryptingKey, Unspecified>;
type DecryptionContextConstructor = fn() -> DecryptionContext;

/// Asserts that `DecryptingKey::decrypt` returns an error, rather than panicking,
/// for every `DecryptionContext` variant except `valid_context`. The valid
/// variant must be accepted, so the check cannot pass by rejecting everything.
fn assert_decrypt_validates_context(
    algorithm: &'static Algorithm,
    key_bytes: &[u8],
    modes: &[(DecryptingKeyConstructor, &str)],
) {
    let contexts: &[(&str, DecryptionContextConstructor)] = &[
        ("None", || DecryptionContext::None),
        ("Iv128", || {
            DecryptionContext::Iv128(FixedLength::from([0u8; IV_LEN_128_BIT]))
        }),
        #[cfg(feature = "legacy-des")]
        ("Iv64", || {
            DecryptionContext::Iv64(FixedLength::from([0u8; 8]))
        }),
    ];
    for &(new_key, valid_context) in modes {
        let key = new_key(UnboundCipherKey::new(algorithm, key_bytes).unwrap()).unwrap();
        for &(context_name, new_context) in contexts {
            let mut in_out = vec![0u8; algorithm.block_len()];
            let result = key.decrypt(&mut in_out, new_context());
            assert_eq!(
                result.is_ok(),
                context_name == valid_context,
                "{algorithm:?} {:?} decrypt with {context_name} context",
                key.mode(),
            );
        }
    }
}

#[test]
fn test_decrypt_rejects_mismatched_context() {
    assert_decrypt_validates_context(
        &AES_128,
        &from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        &[
            (DecryptingKey::cbc, "Iv128"),
            (DecryptingKey::ctr, "Iv128"),
            (DecryptingKey::cfb128, "Iv128"),
            (DecryptingKey::ecb, "None"),
        ],
    );
}

#[test]
#[cfg(feature = "legacy-des")]
#[allow(deprecated)]
fn test_des_decrypt_rejects_mismatched_context() {
    for (algorithm, key_hex) in [
        (&DES_FOR_LEGACY_USE_ONLY, "0123456789abcdef"),
        (
            &DES_EDE_FOR_LEGACY_USE_ONLY,
            "0123456789abcdef23456789abcdef01",
        ),
        (
            &DES_EDE3_FOR_LEGACY_USE_ONLY,
            "0123456789abcdef23456789abcdef01456789abcdef0123",
        ),
    ] {
        assert_decrypt_validates_context(
            algorithm,
            &from_hex(key_hex).unwrap(),
            &[(DecryptingKey::cbc, "Iv64"), (DecryptingKey::ecb, "None")],
        );
    }
}
