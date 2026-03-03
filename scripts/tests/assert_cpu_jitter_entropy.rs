#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[dependencies]
aws-lc-rs = { path = "../../aws-lc-rs" }
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

fn main() {
    println!("Checking for CPU Jitter Entropy");
    assert!(aws_lc_rs::try_fips_cpu_jitter_entropy().is_ok());
    println!("CPU Jitter Entropy Success");
}
