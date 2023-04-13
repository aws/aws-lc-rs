// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    rand::{self, SecureRandom as _},
    test,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn test_system_random_lengths() {
    const LINUX_LIMIT: usize = 256;
    const WEB_LIMIT: usize = 65536;

    // Test that `fill` succeeds for various interesting lengths. `256` and
    // multiples thereof are interesting because that's an edge case for
    // `getrandom` on Linux.
    let lengths = [
        0,
        1,
        2,
        3,
        96,
        LINUX_LIMIT - 1,
        LINUX_LIMIT,
        LINUX_LIMIT + 1,
        LINUX_LIMIT * 2,
        511,
        512,
        513,
        4096,
        WEB_LIMIT - 1,
        WEB_LIMIT,
        WEB_LIMIT + 1,
        WEB_LIMIT * 2,
    ];

    for len in &lengths {
        let mut buf = vec![0; *len];

        let rng = rand::SystemRandom::new();
        assert!(rng.fill(&mut buf).is_ok());

        // If `len` < 96 then there's a big chance of false positives, but
        // otherwise the likelihood of a false positive is so too low to
        // worry about.
        if *len >= 96 {
            assert!(buf.iter().any(|x| *x != 0));
        }
    }
}

#[test]
fn test_system_random_traits() {
    test::compile_time_assert_clone::<rand::SystemRandom>();
    test::compile_time_assert_send::<rand::SystemRandom>();

    assert_eq!(
        "SystemRandom(())",
        format!("{:?}", rand::SystemRandom::new())
    );
}
