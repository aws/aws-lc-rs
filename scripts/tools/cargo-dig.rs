#!/usr/bin/env -S cargo +nightly-2024-05-22 -Zscript
---cargo
[dependencies]
toml = "0.8"
clap = { version = "4", features = ["derive"] }
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use clap::Parser;
use std::fs::read_to_string;
use toml::Table;

#[derive(Parser)]
#[command(about)]
struct Args {
    cargo_file_path: Option<String>,
    #[arg(short = 'v', long = "version")]
    version: bool,
    #[arg(short = 'n', long = "name")]
    name: bool,
}

fn main() {
    let args = Args::parse();

    let content = read_to_string(args.cargo_file_path.unwrap_or("Cargo.toml".to_string()))
        .expect("failed to read file");

    let table = content.parse::<Table>().unwrap();

    let package = table["package"].as_table().unwrap();
    if args.name || !(args.version || args.name) {
        println!("{}", package["name"].as_str().unwrap());
    } else {
        println!("{}", package["version"].as_str().unwrap());
    };
}
