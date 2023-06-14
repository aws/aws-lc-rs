use aws_lc_rs::cipher::{
    CipherContext, DecryptingKey, EncryptingKey, OperatingMode, PaddedBlockDecryptingKey,
    PaddedBlockEncryptingKey, UnboundCipherKey, AES_128, AES_256,
};
use aws_lc_rs::{test, test_file};
use criterion::{criterion_group, criterion_main, Criterion};
use openssl::symm::Cipher;

macro_rules! openssl_bench {
    ($group:ident, $openssl: expr, $key:ident, $iv:ident, $data:ident) => {
        $group.bench_function("OpenSSL", |b| {
            b.iter(|| {
                use openssl::symm::{decrypt, encrypt};
                let data = encrypt($openssl, &$key, Some(&$iv), &$data).unwrap();
                let _ = decrypt($openssl, &$key, Some(&$iv), data.as_ref()).unwrap();
            })
        });
    };
}

macro_rules! benchmark_padded {
    ($fn:ident, $test:literal, $file:literal, $awslc:expr, $mode:expr, $openssl:expr) => {
        fn $fn(c: &mut Criterion) {
            test::run(test_file!($file), |_section, test_case| {
                let key_bytes = test_case.consume_bytes("KEY");
                let iv = test_case.consume_bytes("IV");
                let data = test_case.consume_bytes("IN");

                let mut group = c.benchmark_group(format!("{}-{}-bytes", $test, data.len()));

                group.bench_function("AWS-LC", |b| {
                    b.iter(|| {
                        let key = UnboundCipherKey::new($awslc, &key_bytes).unwrap();
                        let iv: CipherContext =
                            CipherContext::Iv128(iv.as_slice().try_into().unwrap());

                        let encrypt_key = match $mode {
                            OperatingMode::CBC => PaddedBlockEncryptingKey::cbc_pkcs7(key),
                            _ => unreachable!(),
                        }
                        .unwrap();

                        let mut in_out = Vec::from(data.as_slice());
                        let context = encrypt_key.less_safe_encrypt(&mut in_out, iv).unwrap();

                        let key = UnboundCipherKey::new($awslc, &key_bytes).unwrap();

                        let decrypt_key = match $mode {
                            OperatingMode::CBC => PaddedBlockDecryptingKey::cbc_pkcs7(key),
                            _ => unreachable!(),
                        }
                        .unwrap();

                        let _ = decrypt_key.decrypt(&mut in_out, context).unwrap();
                    })
                });

                openssl_bench!(group, $openssl, key_bytes, iv, data);

                Ok(())
            });
        }
    };
}

macro_rules! benchmark_unpadded {
    ($fn:ident, $test:literal, $file:literal, $awslc:expr, $mode:expr, $openssl:expr) => {
        fn $fn(c: &mut Criterion) {
            test::run(test_file!($file), |_section, test_case| {
                let key_bytes = test_case.consume_bytes("KEY");
                let iv = test_case.consume_bytes("IV");
                let data = test_case.consume_bytes("IN");

                let mut group = c.benchmark_group(format!("{}-{}-bytes", $test, data.len()));

                group.bench_function("AWS-LC", |b| {
                    b.iter(|| {
                        let key = UnboundCipherKey::new($awslc, &key_bytes).unwrap();
                        let iv: CipherContext =
                            CipherContext::Iv128(iv.as_slice().try_into().unwrap());

                        let encrypt_key = match $mode {
                            OperatingMode::CTR => EncryptingKey::ctr(key),
                            _ => unreachable!(),
                        }
                        .unwrap();

                        let mut in_out = Vec::from(data.as_slice());
                        let context = encrypt_key.less_safe_encrypt(&mut in_out, iv).unwrap();

                        let key = UnboundCipherKey::new($awslc, &key_bytes).unwrap();

                        let decrypt_key = match $mode {
                            OperatingMode::CTR => DecryptingKey::ctr(key),
                            _ => unreachable!(),
                        }
                        .unwrap();

                        let _ = decrypt_key.decrypt(&mut in_out, context).unwrap();
                    })
                });

                openssl_bench!(group, $openssl, key_bytes, iv, data);

                Ok(())
            });
        }
    };
}

benchmark_unpadded!(
    test_aes_128_ctr,
    "AES-128-CTR",
    "data/cipher_aes_128_ctr.txt",
    &AES_128,
    OperatingMode::CTR,
    Cipher::aes_128_ctr()
);

benchmark_unpadded!(
    test_aes_256_ctr,
    "AES-256-CTR",
    "data/cipher_aes_256_ctr.txt",
    &AES_256,
    OperatingMode::CTR,
    Cipher::aes_256_ctr()
);

benchmark_padded!(
    test_aes_128_cbc,
    "AES-128-CBC",
    "data/cipher_aes_128_cbc.txt",
    &AES_128,
    OperatingMode::CBC,
    Cipher::aes_128_cbc()
);

benchmark_padded!(
    test_aes_256_cbc,
    "AES-256-CBC",
    "data/cipher_aes_256_cbc.txt",
    &AES_256,
    OperatingMode::CBC,
    Cipher::aes_256_cbc()
);

criterion_group!(
    benches,
    test_aes_128_ctr,
    test_aes_128_cbc,
    test_aes_256_ctr,
    test_aes_256_cbc
);
criterion_main!(benches);
