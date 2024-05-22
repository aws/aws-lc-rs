// Copyright 2015 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{aead, cipher, digest, error, hkdf, hmac, test, test_file};

#[test]
fn hkdf_tests() {
    test::run(test_file!("data/hkdf_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let alg = {
            let digest_alg = test_case
                .consume_digest_alg("Hash")
                .ok_or(error::Unspecified)?;
            if digest_alg == &digest::SHA256 {
                hkdf::HKDF_SHA256
            } else {
                // TODO: add test vectors for other algorithms
                panic!("unsupported algorithm: {digest_alg:?}");
            }
        };
        let secret = test_case.consume_bytes("IKM");
        let salt = test_case.consume_bytes("salt");
        let info = test_case.consume_bytes("info");
        test_case.consume_bytes("PRK");
        let expected_out = test_case.consume_bytes("OKM");

        let salt = hkdf::Salt::new(alg, &salt);

        // TODO: test multi-part info, especially with empty parts.
        let My(out) = salt
            .extract(&secret)
            .expand(&[&info], My(expected_out.len()))
            .unwrap()
            .into();
        assert_eq!(out, expected_out);

        Ok(())
    });
}

#[test]
fn hkdf_output_len_tests() {
    for &alg in &[hkdf::HKDF_SHA256, hkdf::HKDF_SHA384, hkdf::HKDF_SHA512] {
        const MAX_BLOCKS: usize = 255;

        let salt = hkdf::Salt::new(alg, &[]);
        let prk = salt.extract(&[]); // TODO: enforce minimum length.

        {
            // Test zero length.
            let okm = prk.expand(&[b"info"], My(0)).unwrap();
            let result: My<Vec<u8>> = okm.into();
            assert_eq!(&result.0, &[]);
        }

        let max_out_len = MAX_BLOCKS * alg.hmac_algorithm().digest_algorithm().output_len;

        {
            // Test maximum length output succeeds.
            let okm = prk.expand(&[b"info"], My(max_out_len)).unwrap();
            let result: My<Vec<u8>> = okm.into();
            assert_eq!(result.0.len(), max_out_len);
        }

        {
            // Test too-large output fails.
            assert!(prk.expand(&[b"info"], My(max_out_len + 1)).is_err());
        }

        {
            // Test length mismatch (smaller).
            let okm = prk.expand(&[b"info"], My(2)).unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(okm.fill(&mut buf), Err(error::Unspecified));
        }

        {
            // Test length mismatch (larger).
            let okm = prk.expand(&[b"info"], My(2)).unwrap();
            let mut buf = [0u8; 3];
            assert_eq!(okm.fill(&mut buf), Err(error::Unspecified));
        }

        {
            // Control for above two tests.
            let okm = prk.expand(&[b"info"], My(2)).unwrap();
            let mut buf = [0u8; 2];
            assert_eq!(okm.fill(&mut buf), Ok(()));
        }
    }
}

#[test]
fn hkdf_info_len_tests() {
    for &alg in &[hkdf::HKDF_SHA256, hkdf::HKDF_SHA384, hkdf::HKDF_SHA512] {
        for info_length in (50..300).step_by(7) {
            let salt = hkdf::Salt::new(alg, &[]);
            let prk = salt.extract(&[]); // TODO: enforce minimum length.
            let info = vec![1u8; info_length];
            let info = &[info.as_slice()];

            {
                let okm = prk.expand(info, My(2)).unwrap();
                let mut buf = [0u8; 2];
                assert_eq!(okm.fill(&mut buf), Ok(()));
            }
        }
    }
}

#[test]
/// Try creating various key types via HKDF.
fn hkdf_key_types() {
    for &alg in &[
        hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        hkdf::HKDF_SHA256,
        hkdf::HKDF_SHA384,
        hkdf::HKDF_SHA512,
    ] {
        let salt = hkdf::Salt::new(alg, &[]);
        let prk = salt.extract(&[]);
        let okm = prk.expand(&[b"info"], alg.hmac_algorithm()).unwrap();
        let hmac_key = hmac::Key::from(okm);
        assert_eq!(hmac_key.algorithm(), alg.hmac_algorithm());

        let okm = prk.expand(&[b"info"], alg).unwrap();
        let hkdf_salt_key = hkdf::Salt::from(okm);
        assert_eq!(hkdf_salt_key.algorithm(), alg);

        let okm = prk.expand(&[b"info"], alg).unwrap();
        let _hkdf_prk_key = hkdf::Prk::from(okm);

        for aead_alg in [
            &aead::AES_256_GCM,
            &aead::AES_128_GCM,
            &aead::CHACHA20_POLY1305,
        ] {
            let okm = prk.expand(&[b"info"], aead_alg).unwrap();
            let _aead_prk_key = aead::UnboundKey::from(okm);
        }

        for cipher_alg in [&cipher::AES_256, &cipher::AES_128] {
            let okm = prk.expand(&[b"info"], cipher_alg).unwrap();
            let _aes_prk_key = cipher::UnboundCipherKey::from(okm);
        }
    }
}

#[test]
fn hkdf_clone_tests() {
    for &alg in &[
        hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        hkdf::HKDF_SHA256,
        hkdf::HKDF_SHA384,
        hkdf::HKDF_SHA512,
    ] {
        // Coverage sanity check.
        assert_eq!(alg.clone(), alg);

        // Only using this API to construct a simple PRK.
        let prk = hkdf::Prk::new_less_safe(alg, &[0; 32]);
        let result: My<Vec<u8>> = prk
            .expand(&[b"info"], My(digest::MAX_OUTPUT_LEN))
            .unwrap()
            .into();

        let prk_clone = prk.clone();
        let result_2: My<Vec<u8>> = prk_clone
            .expand(&[b"info"], My(digest::MAX_OUTPUT_LEN))
            .unwrap()
            .into();
        assert_eq!(result, result_2);
    }
}

#[test]
fn hkdf_thread_safeness() {
    use std::thread;

    lazy_static::lazy_static! {
        /// Compute the Initial salt once, as the seed is constant
        static ref SECRET_KEY: hkdf::Salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"this is a test!");
    }

    // Compute the OKM, so we have something to compare to.
    let okm: My<Vec<u8>> = SECRET_KEY
        .extract(b"secret")
        .expand(&[b"info"], My(digest::MAX_OUTPUT_LEN))
        .unwrap()
        .into();

    let mut join_handles = Vec::new();
    for _ in 1..100 {
        let join_handle = thread::spawn(|| {
            let okm = SECRET_KEY
                .extract(b"secret")
                .expand(&[b"info"], My(digest::MAX_OUTPUT_LEN))
                .unwrap()
                .into();
            okm
        });
        join_handles.push(join_handle);
    }
    for handle in join_handles {
        let thread_okm: My<Vec<u8>> = handle.join().unwrap();
        assert_eq!(thread_okm, okm);
    }
}

/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.
#[derive(Debug, PartialEq)]
struct My<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for My<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, My<usize>>> for My<Vec<u8>> {
    fn from(okm: hkdf::Okm<My<usize>>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        Self(r)
    }
}
