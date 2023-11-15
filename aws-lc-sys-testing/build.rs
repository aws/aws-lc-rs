// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use toml_edit::Document;

fn main() {
    let cargo_toml = std::fs::read_to_string("../aws-lc-sys/Cargo.toml").unwrap();
    let cargo_toml = cargo_toml.parse::<Document>().unwrap();

    let links = cargo_toml["package"]["links"].as_str().unwrap();

    // ensure that the include path is exported and set up correctly
    cc::Build::new()
        .include(env(format!("DEP_{}_INCLUDE", links.to_uppercase())))
        .file("src/testing.c")
        .compile("aws_ls_sys_testing");

    // ensure the libcrypto artifact is linked
    println!("cargo:rustc-link-lib={}_crypto", links);
}

fn env<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    println!("cargo:rerun-if-env-changed={s}");
    std::env::var(s).unwrap_or_else(|_| panic!("missing env var {s}"))
}
