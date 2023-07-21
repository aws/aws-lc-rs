#!/usr/bin/env -S cargo +nightly -Zscript
//! Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//! SPDX-License-Identifier: Apache-2.0 OR ISC
//! ```cargo
//! [dependencies]
//! clap = { version = "4.2.2", features = ["derive"] }
//! regex = "1.7.3"
//! semver = "1.0.17"
//! ```

use clap::Parser;

#[derive(Parser)]
#[command(about)]
struct Args {
    tags: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let input: Vec<String> = args.tags;

    // Modified regex from https://semver.org/
    let re = regex::Regex::new(
        r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
    ).unwrap();

    let mut tags: Vec<semver::Version> = input
        .into_iter()
        .filter(|t| re.is_match(t))
        .map(|t| semver::Version::parse(t.strip_prefix("v").unwrap()).unwrap())
        .collect();

    tags.sort();

    let latest = tags.pop().unwrap();

    println!("v{latest}")
}
