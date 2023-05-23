use aws_lc_rs::{
    cipher::{
        LessSafeCipherKey, AES_128_CBC_PKCS7_PADDING, AES_128_CTR, AES_256_CBC_PKCS7_PADDING,
        AES_256_CTR,
    },
    iv::NonceIV,
    test, test_file,
};
use criterion::{criterion_group, criterion_main, Criterion};
use openssl::symm::Cipher;

macro_rules! benchmark {
    ($fn:ident, $test:literal, $file:literal, $awslc:expr, $openssl:expr) => {
        fn $fn(c: &mut Criterion) {
            test::run(test_file!($file), |_section, test_case| {
                let key = test_case.consume_bytes("KEY");
                let iv = test_case.consume_bytes("IV");
                let data = test_case.consume_bytes("IN");

                let mut group = c.benchmark_group(format!("{}-{}-bytes", $test, data.len()));

                group.bench_function("AWS-LC", |b| {
                    b.iter(|| {
                        let key = LessSafeCipherKey::new($awslc, &key).unwrap();
                        let iv: NonceIV = iv.as_slice().try_into().unwrap();
                        let mut in_out = Vec::from(data.as_slice());
                        let iv = key.encrypt(iv, &mut in_out).unwrap();
                        let _ = key.decrypt(iv, &mut in_out).unwrap();
                    })
                });

                group.bench_function("OpenSSL", |b| {
                    b.iter(|| {
                        use openssl::symm::{decrypt, encrypt};
                        let data = encrypt($openssl, &key, Some(&iv), &data).unwrap();
                        let _ = decrypt($openssl, &key, Some(&iv), data.as_ref()).unwrap();
                    })
                });

                Ok(())
            });
        }
    };
}

benchmark!(
    test_aes_128_ctr,
    "AES-128-CTR",
    "data/cipher_aes_128_ctr.txt",
    &AES_128_CTR,
    Cipher::aes_128_ctr()
);

benchmark!(
    test_aes_256_ctr,
    "AES-256-CTR",
    "data/cipher_aes_256_ctr.txt",
    &AES_256_CTR,
    Cipher::aes_256_ctr()
);

benchmark!(
    test_aes_128_cbc,
    "AES-128-CBC",
    "data/cipher_aes_128_cbc.txt",
    &AES_128_CBC_PKCS7_PADDING,
    Cipher::aes_128_cbc()
);

benchmark!(
    test_aes_256_cbc,
    "AES-256-CBC",
    "data/cipher_aes_256_cbc.txt",
    &AES_256_CBC_PKCS7_PADDING,
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
