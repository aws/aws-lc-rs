use aws_lc_rs::{
    cipher::{LessSafeCipherKey, AES_128_CTR},
    iv::NonceIV,
    test, test_file,
};
use criterion::{criterion_group, criterion_main, Criterion};

fn test_aes_128_ctr(c: &mut Criterion) {
    test::run(
        test_file!("data/cipher_aes_128_ctr.txt"),
        |_section, test_case| {
            let key = test_case.consume_bytes("KEY");
            let iv = test_case.consume_bytes("IV");
            let data = test_case.consume_bytes("IN");

            let mut group = c.benchmark_group(format!("AES-128-CTR-{}-bytes", data.len()));

            group.bench_function("AWS-LC", |b| {
                b.iter(|| {
                    let key = LessSafeCipherKey::new(&AES_128_CTR, &key).unwrap();
                    let iv: NonceIV = iv.as_slice().try_into().unwrap();
                    let mut in_out = Vec::from(data.as_slice());
                    let iv = key.encrypt(iv, &mut in_out).unwrap();
                    let _ = key.decrypt(iv, &mut in_out).unwrap();
                })
            });

            group.bench_function("openssl", |b| {
                b.iter(|| {
                    use openssl::symm::{decrypt, encrypt, Cipher};
                    let data = encrypt(Cipher::aes_128_ctr(), &key, Some(&iv), &data).unwrap();
                    let _ = decrypt(Cipher::aes_128_ctr(), &key, Some(&iv), data.as_ref()).unwrap();
                })
            });

            Ok(())
        },
    );
}

criterion_group!(benches, test_aes_128_ctr);
criterion_main!(benches);
