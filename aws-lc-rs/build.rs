// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

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
}
