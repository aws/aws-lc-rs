// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::env;

fn main() {
    let mutually_exclusives_count = [cfg!(feature = "non-fips"), cfg!(feature = "fips")]
        .iter()
        .filter(|x| **x)
        .count();

    if mutually_exclusives_count > 1 {
        eprint!("fips and non-fips are mutually exclusive crate features.");
        std::process::exit(1);
    }

    // This appears asymmetric, but it reflects the `cfg` statements in lib.rs that
    // require `aws-lc-sys` to be present when "fips" is not enabled.
    let at_least_one_count = [cfg!(feature = "aws-lc-sys"), cfg!(feature = "fips")]
        .iter()
        .filter(|x| **x)
        .count();

    if at_least_one_count < 1 {
        eprint!(
            "one of the following features must be specified: \
        aws-lc-sys, non-fips, or fips."
        );
        std::process::exit(1);
    }

    // For PQ KEM KATs we need to enable a private aws-lc API.
    // If AWS_LC_RUST_PRIVATE_INTERNALS=1 is set and bingen is enabled then enable our
    // configuration to allow the tests to be built and enabled.
    // Additionally these APIs are not thread safe. So force tests to run single threaded.
    if env::var("AWS_LC_RUST_PRIVATE_INTERNALS")
        .unwrap_or("0".into())
        .eq("1")
        && cfg!(feature = "bindgen")
    {
        println!("cargo:rustc-cfg=private_api");
        println!("cargo:rustc-env=RUST_TEST_THREADS=1");
    }
}
