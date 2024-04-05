// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use toml_edit::DocumentMut;

fn main() {
    let mut deps = vec![];

    macro_rules! select_dep {
        ($dep:literal) => {
            if cfg!(feature = $dep) {
                deps.push($dep);
            }
        };
    }

    select_dep!("aws-lc-rs");
    select_dep!("aws-lc-sys");
    select_dep!("aws-lc-fips-sys");

    assert_eq!(
        deps.len(),
        1,
        "exactly one dependency is allowed at a time, got {deps:?}"
    );

    let dep = deps.pop().unwrap();
    let dep_links = get_package_links_property(&format!("../{dep}/Cargo.toml"));
    let dep_snake_case = dep.replace('-', "_");
    build_and_link(dep_links.as_ref(), &dep_snake_case);
}

fn build_and_link(links: &str, target_name: &str) {
    // ensure that the include path is exported and set up correctly
    cc::Build::new()
        .include(env(format!("DEP_{}_INCLUDE", links.to_uppercase())))
        .file("src/testing.c")
        .compile(&format!("testing_{target_name}"));

    // make sure the root was exported
    let root = env(format!("DEP_{}_ROOT", links.to_uppercase()));
    println!("cargo:rustc-link-search={root}");

    // ensure the libcrypto artifact is linked
    let libcrypto = env(format!("DEP_{}_LIBCRYPTO", links.to_uppercase()));
    println!("cargo:rustc-link-lib={libcrypto}");
}

fn get_package_links_property(cargo_toml_path: &str) -> String {
    let cargo_toml = std::fs::read_to_string(cargo_toml_path).unwrap();
    let cargo_toml = cargo_toml.parse::<DocumentMut>().unwrap();

    let links = cargo_toml["package"]["links"].as_str().unwrap();

    String::from(links)
}

fn env<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    println!("cargo:rerun-if-env-changed={s}");
    std::env::var(s).unwrap_or_else(|_| panic!("missing env var {s}"))
}
