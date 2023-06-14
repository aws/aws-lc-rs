// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::cipher::{
    CipherContext, DecryptingKey, EncryptingKey, OperatingMode, PaddedBlockDecryptingKey,
    PaddedBlockEncryptingKey, UnboundCipherKey, AES_128, AES_256,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::test::from_hex;

macro_rules! padded_cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
        paste::item! {
            #[test]
            fn $name() {
                let key = from_hex($key).unwrap();
                let input = from_hex($plaintext).unwrap();
                let expected_ciphertext = from_hex($ciphertext).unwrap();

                let iv = from_hex($iv).unwrap();
                let fixed_iv = FixedLength::try_from(iv.as_slice()).unwrap();
                let context = CipherContext::Iv128(fixed_iv);

                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

                let encrypting_key =
                    PaddedBlockEncryptingKey::$constructor(unbound_key).unwrap();
                assert_eq!($mode, encrypting_key.mode());
                assert_eq!($alg, encrypting_key.algorithm());
                let mut in_out = input.clone();
                let context = encrypting_key.less_safe_encrypt(&mut in_out, context).unwrap();
                assert_eq!(expected_ciphertext.as_slice(), in_out.as_slice());

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                let decrypting_key =
                    PaddedBlockDecryptingKey::$constructor(unbound_key2).unwrap();
                assert_eq!($mode, decrypting_key.mode());
                assert_eq!($alg, decrypting_key.algorithm());
                let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        }
    };
}

macro_rules! cipher_kat {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $iv: literal, $plaintext:literal, $ciphertext:literal) => {
        paste::item! {
            #[test]
            fn $name() {
                let key = from_hex($key).unwrap();
                let input = from_hex($plaintext).unwrap();
                let expected_ciphertext = from_hex($ciphertext).unwrap();

                let iv = from_hex($iv).unwrap();
                let fixed_iv = FixedLength::try_from(iv.as_slice()).unwrap();
                let context = CipherContext::Iv128(fixed_iv);

                let unbound_key = UnboundCipherKey::new($alg, &key).unwrap();

                let encrypting_key =
                    EncryptingKey::$constructor(unbound_key).unwrap();
                assert_eq!($mode, encrypting_key.mode());
                assert_eq!($alg, encrypting_key.algorithm());
                let mut in_out = input.clone();
                let context = encrypting_key.less_safe_encrypt(in_out.as_mut_slice(), context).unwrap();
                assert_eq!(expected_ciphertext.as_slice(), in_out);

                let unbound_key2 = UnboundCipherKey::new($alg, &key).unwrap();
                let decrypting_key =
                    DecryptingKey::$constructor(unbound_key2).unwrap();
                assert_eq!($mode, decrypting_key.mode());
                assert_eq!($alg, decrypting_key.algorithm());
                let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        }
    };
}

macro_rules! padded_cipher_rt {
    ($name:ident, $alg:expr, $mode:expr, $constructor:ident, $key:literal, $plaintext:literal) => {
        paste::item! {
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
                let decrypting_key =
                    PaddedBlockDecryptingKey::$constructor(unbound_key2).unwrap();
                assert_eq!($mode, decrypting_key.mode());
                assert_eq!($alg, decrypting_key.algorithm());
                let plaintext = decrypting_key.decrypt(&mut in_out, context).unwrap();
                assert_eq!(input.as_slice(), plaintext);
            }
        }
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
    test_rt_aes_128_ctr_17_bytes,
    &AES_128,
    OperatingMode::CTR,
    ctr,
    "000102030405060708090a0b0c0d0e0f",
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
