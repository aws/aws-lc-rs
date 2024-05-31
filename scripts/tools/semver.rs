#!/usr/bin/env -S cargo +nightly-2024-05-22 -Zscript
---cargo
[dependencies]
clap = { version = "4", features = ["derive"] }
regex = "1"
semver = "1"
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use clap::{Parser, Subcommand};
use regex::Regex;
use std::error::Error;

#[derive(Parser)]
#[command(about)]
struct Args {
    #[command(subcommand)]
    release: Release,
}

#[derive(Subcommand, Clone)]
enum Release {
    Main { tags: Vec<String> },
    FipsV2 { tags: Vec<String> },
}

// regex from https://semver.org/
const SEMVER: &str = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$";

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let latest = match args.release {
        Release::Main { tags } => get_latest_main(tags)?,
        Release::FipsV2 { tags } => get_latest_fips(tags, 2)?,
    };

    println!("{latest}");
    Ok(())
}

fn get_latest_main(tags: Vec<String>) -> Result<String, Box<dyn Error>> {
    let re = Regex::new(SEMVER)?;
    let mut tags: Vec<semver::Version> = tags
        .into_iter()
        .filter(|t| t.starts_with("v"))
        .map(|t| String::from(t.strip_prefix("v").expect("prefix must be present")))
        .filter(|t| re.is_match(t))
        .map(|t| semver::Version::parse(&t).expect("semver parse must not fail"))
        .collect();

    tags.sort();

    let latest = tags.pop().ok_or("latest tag not found")?;

    Ok(format!("v{latest}"))
}

fn get_latest_fips(tags: Vec<String>, major: u64) -> Result<String, Box<dyn Error>> {
    const FIPS_TAG_PREFIX: &str = "AWS-LC-FIPS-";

    let re = Regex::new(SEMVER)?;

    let mut tags: Vec<semver::Version> = tags
        .into_iter()
        .filter(|t| t.starts_with(FIPS_TAG_PREFIX))
        .map(|t| {
            String::from(
                t.strip_prefix(FIPS_TAG_PREFIX)
                    .expect("prefix must be present"),
            )
        })
        .filter(|t| re.is_match(t))
        .map(|t| semver::Version::parse(&t).unwrap())
        .filter(|t| t.major == major)
        .collect();

    tags.sort();

    let latest = tags.pop().ok_or("latest tag not found")?;

    Ok(format!("{FIPS_TAG_PREFIX}{latest}"))
}
