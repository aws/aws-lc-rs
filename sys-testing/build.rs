// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use toml_edit::Document;

fn main() {
    if cfg!(all(feature = "aws-lc-sys", feature = "aws-lc-fips-sys")) {
        panic!("only one sys crate can be built at a time")
    } else if cfg!(feature = "aws-lc-sys") {
        let aws_lc_sys_links = get_package_links_property("../aws-lc-sys/Cargo.toml");
        build_and_link(aws_lc_sys_links.as_ref(), "aws_lc_sys");
        return;
    } else if cfg!(feature = "aws-lc-fips-sys") {
        let aws_lc_fips_sys_links = get_package_links_property("../aws-lc-fips-sys/Cargo.toml");
        build_and_link(aws_lc_fips_sys_links.as_ref(), "aws_lc_fips");
        return;
    }
    panic!(
        "select a sys crate for testing using --features aws-lc-sys or --features aws-lc-fips-sys"
    )
}

fn build_and_link(links: &str, target_name: &str) {
    // ensure that the include path is exported and set up correctly
    cc::Build::new()
        .include(env(format!("DEP_{}_INCLUDE", links.to_uppercase())))
        .file("src/testing.c")
        .compile(target_name);

    // ensure the libcrypto artifact is linked
    println!("cargo:rustc-link-lib={links}_crypto");
}

fn get_package_links_property(cargo_toml_path: &str) -> String {
    let cargo_toml = std::fs::read_to_string(cargo_toml_path).unwrap();
    let cargo_toml = cargo_toml.parse::<Document>().unwrap();

    let links = cargo_toml["package"]["links"].as_str().unwrap();

    String::from(links)
}

fn env<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    println!("cargo:rerun-if-env-changed={s}");
    std::env::var(s).unwrap_or_else(|_| panic!("missing env var {s}"))
}
