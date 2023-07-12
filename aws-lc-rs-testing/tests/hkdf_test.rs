// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::hkdf::{Prk, Salt, HKDF_SHA256};

#[test]
fn rustls_test() {
    const INFO1: &[&[u8]] = &[
        &[0, 32],
        &[13],
        &[116, 108, 115, 49, 51, 32],
        &[100, 101, 114, 105, 118, 101, 100],
        &[32],
        &[
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
    ];

    const INFO2: &[&[u8]] = &[
        &[0, 32],
        &[18],
        &[116, 108, 115, 49, 51, 32],
        &[99, 32, 104, 115, 32, 116, 114, 97, 102, 102, 105, 99],
        &[32],
        &[
            236, 20, 122, 6, 222, 163, 200, 132, 108, 2, 178, 35, 142, 65, 189, 220, 157, 137, 249,
            174, 161, 123, 94, 253, 77, 116, 130, 175, 117, 136, 28, 10,
        ],
    ];
    /*
            const SEED: &[u8] = &[
                51, 173, 10, 28, 96, 126, 192, 59, 9, 230, 205, 152, 147, 104, 12, 226, 16, 173, 243,
                0, 170, 31, 38, 96, 225, 178, 46, 16, 241, 112, 249, 42,
            ];

            const SECRET: &[u8] = &[
                231, 184, 254, 248, 144, 59, 82, 12, 185, 161, 137, 113, 182, 157, 212, 93, 202, 83,
                206, 47, 18, 191, 59, 239, 147, 21, 227, 18, 113, 223, 75, 64,
            ];
    */
    let salt = Salt::new(HKDF_SHA256, &[0u8; 32]);
    let prk = salt.extract(&[0u8; 32]);
    let okm = prk.expand(INFO1, HKDF_SHA256).unwrap();
    let okm2 = prk.expand(INFO2, HKDF_SHA256).unwrap();

    let mut output1 = [0u8; 32];
    okm.fill(&mut output1).expect("test failed");
    let mut output2 = [0u8; 32];
    okm2.fill(&mut output2).expect("test failed");

    println!("AWS-LC Result: {output1:?}");
    println!("AWS-LC Result: {output2:?}");

    let ring_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[0u8; 32]);
    let ring_prk = ring_salt.extract(&[0u8; 32]);
    let ring_okm = ring_prk.expand(INFO1, ring::hkdf::HKDF_SHA256).unwrap();
    let ring_okm2 = ring_prk.expand(INFO2, ring::hkdf::HKDF_SHA256).unwrap();

    let mut ring_output1 = [0u8; 32];
    ring_okm.fill(&mut ring_output1).expect("test failed");
    let mut ring_output2 = [0u8; 32];
    ring_okm2.fill(&mut ring_output2).expect("test failed");

    println!("ring Result: {ring_output1:?}");
    println!("ring Result: {ring_output2:?}");

    assert_eq!(ring_output1, output1);
    assert_eq!(ring_output2, output2);
}

#[test]
fn okm_to_salt() {
    const SALT: &[u8; 32] = &[
        29, 113, 120, 243, 11, 202, 39, 222, 206, 81, 163, 184, 122, 153, 52, 192, 98, 195, 240,
        32, 34, 19, 160, 128, 178, 111, 97, 232, 113, 101, 221, 143,
    ];
    const SECRET1: &[u8; 32] = &[
        157, 191, 36, 107, 110, 131, 193, 6, 175, 226, 193, 3, 168, 133, 165, 181, 65, 120, 194,
        152, 31, 92, 37, 191, 73, 222, 41, 112, 207, 236, 196, 174,
    ];
    const SECRET2: &[u8; 32] = &[
        224, 63, 67, 213, 224, 104, 58, 50, 88, 209, 237, 46, 232, 170, 253, 41, 19, 19, 60, 235,
        221, 215, 226, 154, 99, 234, 27, 43, 176, 174, 101, 21,
    ];
    const INFO1: &[&[u8]] = &[
        &[
            2, 130, 61, 83, 192, 248, 63, 60, 211, 73, 169, 66, 101, 160, 196, 212, 250, 113,
        ],
        &[
            80, 46, 248, 123, 78, 204, 171, 178, 67, 204, 96, 27, 131, 24,
        ],
    ];
    const INFO2: &[&[u8]] = &[
        &[
            34, 34, 23, 86, 156, 162, 231, 236, 148, 170, 84, 187, 88, 86, 15, 165, 95, 109,
        ],
        &[243, 251, 232, 90, 98, 26, 78, 75, 114, 115, 9, 72, 183, 193],
    ];

    let alg = HKDF_SHA256;
    let salt = Salt::new(alg, SALT);
    let prk = salt.extract(SECRET1);
    let okm = prk.expand(INFO1, alg).unwrap();
    let okm_salt: Salt = okm.into();
    let prk2 = okm_salt.extract(SECRET2);
    let okm2 = prk2.expand(INFO2, alg).unwrap();

    let mut output = [0u8; 32];
    okm2.fill(&mut output).expect("test failed");

    println!("AWS-LC: {output:?}");

    let ring_alg = ring::hkdf::HKDF_SHA256;
    let ring_salt = ring::hkdf::Salt::new(ring_alg, SALT);
    let ring_prk = ring_salt.extract(SECRET1);
    let ring_okm = ring_prk.expand(INFO1, ring_alg).unwrap();
    let ring_okm_salt: ring::hkdf::Salt = ring_okm.into();
    let ring_prk2 = ring_okm_salt.extract(SECRET2);
    let ring_okm2 = ring_prk2.expand(INFO2, ring_alg).unwrap();

    let mut ring_output = [0u8; 32];
    ring_okm2.fill(&mut ring_output).expect("test failed");

    println!("ring: {ring_output:?}");

    assert_eq!(ring_output, output);
    assert_eq!(
        output,
        [
            29, 148, 69, 177, 104, 16, 168, 31, 95, 217, 120, 105, 45, 141, 225, 36, 142, 230, 151,
            143, 240, 12, 41, 129, 143, 119, 94, 221, 132, 167, 236, 243
        ]
    );
}

#[test]
fn okm_to_prk() {
    const SALT: &[u8; 32] = &[
        29, 113, 120, 243, 11, 202, 39, 222, 206, 81, 163, 184, 122, 153, 52, 192, 98, 195, 240,
        32, 34, 19, 160, 128, 178, 111, 97, 232, 113, 101, 221, 143,
    ];
    const SECRET1: &[u8; 32] = &[
        157, 191, 36, 107, 110, 131, 193, 6, 175, 226, 193, 3, 168, 133, 165, 181, 65, 120, 194,
        152, 31, 92, 37, 191, 73, 222, 41, 112, 207, 236, 196, 174,
    ];

    const INFO1: &[&[u8]] = &[
        &[
            2, 130, 61, 83, 192, 248, 63, 60, 211, 73, 169, 66, 101, 160, 196, 212, 250, 113,
        ],
        &[
            80, 46, 248, 123, 78, 204, 171, 178, 67, 204, 96, 27, 131, 24,
        ],
    ];
    const INFO2: &[&[u8]] = &[
        &[
            34, 34, 23, 86, 156, 162, 231, 236, 148, 170, 84, 187, 88, 86, 15, 165, 95, 109,
        ],
        &[243, 251, 232, 90, 98, 26, 78, 75, 114, 115, 9, 72, 183, 193],
    ];

    let alg = HKDF_SHA256;
    let salt = Salt::new(alg, SALT);
    let prk = salt.extract(SECRET1);
    let okm = prk.expand(INFO1, alg).unwrap();
    let prk2 = Prk::from(okm);
    let okm2 = prk2.expand(INFO2, alg).unwrap();

    let mut output = [0u8; 32];
    okm2.fill(&mut output).expect("test failed");

    println!("AWS-LC: {output:?}");

    let ring_alg = ring::hkdf::HKDF_SHA256;
    let ring_salt = ring::hkdf::Salt::new(ring_alg, SALT);
    let ring_prk = ring_salt.extract(SECRET1);
    let ring_okm = ring_prk.expand(INFO1, ring_alg).unwrap();
    let ring_prk2 = ring::hkdf::Prk::from(ring_okm);
    let ring_okm2 = ring_prk2.expand(INFO2, ring_alg).unwrap();

    let mut ring_output = [0u8; 32];
    ring_okm2.fill(&mut ring_output).expect("test failed");

    println!("ring: {ring_output:?}");

    assert_eq!(ring_output, output);
    assert_eq!(
        output,
        [
            89, 74, 29, 169, 83, 186, 156, 217, 15, 130, 215, 15, 245, 57, 91, 192, 227, 195, 106,
            0, 10, 225, 34, 200, 10, 198, 253, 171, 44, 32, 192, 249
        ]
    );
}
