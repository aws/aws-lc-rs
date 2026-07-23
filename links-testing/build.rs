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
    let links = links.to_uppercase();

    // ensure that the include path is exported and set up correctly
    cc::Build::new()
        .include(env(format!("DEP_{links}_INCLUDE")))
        .file("src/testing.c")
        .compile(&format!("testing_{target_name}"));

    // make sure the root was exported
    let root = env(format!("DEP_{links}_ROOT"));
    println!("cargo:rustc-link-search={root}");

    // ensure the libcrypto artifact is linked
    let libcrypto = env(format!("DEP_{links}_LIBCRYPTO"));
    println!("cargo:rustc-link-lib={libcrypto}");

    // ensure downstream native builds receive the exact artifact location
    let libdir = std::path::PathBuf::from(env(format!("DEP_{links}_LIBDIR")));
    let libcrypto_path = std::path::PathBuf::from(env(format!("DEP_{links}_LIBCRYPTO_PATH")));
    assert!(
        libdir.is_dir(),
        "exported libdir does not exist: {libdir:?}"
    );
    assert!(
        libcrypto_path.is_file(),
        "exported libcrypto path does not exist: {libcrypto_path:?}"
    );
    assert_eq!(libcrypto_path.parent(), Some(libdir.as_path()));

    let link_kind = env(format!("DEP_{links}_LINK_KIND"));
    assert!(matches!(link_kind.as_str(), "static" | "dylib"));
    if link_kind == "static" {
        // a static artifact must be an archive (`.a`) or MSVC library (`.lib`)
        let extension = libcrypto_path.extension().and_then(|e| e.to_str());
        assert!(
            matches!(extension, Some("a" | "lib")),
            "unexpected static libcrypto artifact: {libcrypto_path:?}"
        );
    }

    // when libssl is built, its exact artifact location must be exported too
    if optional_env(format!("DEP_{links}_LIBSSL")).is_some() {
        let libssl_path = std::path::PathBuf::from(env(format!("DEP_{links}_LIBSSL_PATH")));
        assert!(
            libssl_path.is_file(),
            "exported libssl path does not exist: {libssl_path:?}"
        );
        assert_eq!(libssl_path.parent(), Some(libdir.as_path()));
    }
}

fn get_package_links_property(cargo_toml_path: &str) -> String {
    let cargo_toml = std::fs::read_to_string(cargo_toml_path).unwrap();
    let cargo_toml = cargo_toml.parse::<DocumentMut>().unwrap();

    let links = cargo_toml["package"]["links"].as_str().unwrap();

    String::from(links)
}

fn env<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    optional_env(s).unwrap_or_else(|| panic!("missing env var {s}"))
}

fn optional_env<S: AsRef<str>>(s: S) -> Option<String> {
    let s = s.as_ref();
    println!("cargo:rerun-if-env-changed={s}");
    std::env::var(s).ok()
}
