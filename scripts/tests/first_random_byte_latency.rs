#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[dependencies]
aws-lc-rs = { path = "../../aws-lc-rs", default-features = false, features = ["aws-lc-sys"] }
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::time::Instant;

fn main() {
    let mut byte_array: [u8; 1] = [0];
    let start = Instant::now();
    assert!(aws_lc_rs::rand::fill(&mut byte_array).is_ok());
    let duration = start.elapsed();
    println!("{}", duration.as_millis());
}
