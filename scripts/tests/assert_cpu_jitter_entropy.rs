#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[dependencies]
aws-lc-rs = { version = "1", path = "../../aws-lc-rs", default-features = false, features = ["fips"] }
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

fn main()  {
    println!("Checking for CPU Jitter Entropy");
    aws_lc_rs::fips_cpu_jitter_entropy();
    println!("CPU Jitter Entropy Success");
}
