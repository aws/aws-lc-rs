// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::path::Path;
use std::{env, fs};

/// AWS-LC functions that aws-lc-rs only uses when the sys crate's bindings declare them, because
/// some supported configurations lack them (for example, a system-installed AWS-LC below the
/// release that added the function).
///
/// For each function declared by the bindings the sys crate compiles, `build.rs` sets
/// `cfg(aws_lc_has = "<function name>")`. The `cfg` is unset when that cannot be determined
/// (such as with a sys crate that does not export its `bindings` path), so code gated on it
/// must have a fallback.
const OPTIONAL_AWS_LC_FUNCTIONS: &[&str] = &["EVP_PKEY_get_private_seed"];

fn main() {
    let has_mutually_exclusive_features = cfg!(feature = "non-fips") && cfg!(feature = "fips");
    assert!(
        !has_mutually_exclusive_features,
        "`fips` and `non-fips` are mutually exclusive crate features."
    );

    println!("cargo:rustc-check-cfg=cfg(aws_lc_rs_docsrs)");
    println!("cargo:rustc-check-cfg=cfg(disable_slow_tests)");
    println!("cargo:rustc-check-cfg=cfg(dev_tests_only)");
    if let Ok(disable) = env::var("AWS_LC_RS_DISABLE_SLOW_TESTS") {
        if disable == "1" {
            println!("cargo:warning=### Slow tests will be disabled! ###");
            println!("cargo:rustc-cfg=disable_slow_tests");
        } else {
            println!("cargo:warning=### Slow tests are enabled: {disable}! ###");
        }
    }
    println!("cargo:rerun-if-env-changed=AWS_LC_RS_DISABLE_SLOW_TESTS");

    let mut enable_dev_test_only = None;
    if cfg!(feature = "dev-tests-only") {
        enable_dev_test_only = Some(true);
    }
    // Environment variable can override
    if let Ok(dev_tests) = env::var("AWS_LC_RS_DEV_TESTS_ONLY") {
        println!("cargo:warning=### AWS_LC_RS_DEV_TESTS_ONLY: '{dev_tests}' ###");
        enable_dev_test_only = Some(dev_tests == "1");
    }
    println!("cargo:rerun-if-env-changed=AWS_LC_RS_DEV_TESTS_ONLY");

    if let Some(dev_test_only) = enable_dev_test_only {
        if dev_test_only {
            let profile = env::var("PROFILE").unwrap();
            if !profile.contains("dev") && !profile.contains("debug") && !profile.contains("test") {
                println!("cargo:warning=### PROFILE: '{profile}' ###");
                panic!("dev-tests-only feature only allowed for dev profile builds");
            }
            println!("cargo:warning=### Enabling public testing functions! ###");
            println!("cargo:rustc-cfg=dev_tests_only");
        } else {
            println!("cargo:warning=### AWS_LC_RS_DEV_TESTS_ONLY: Public testing functions not enabled! ###");
        }
    }

    // This appears asymmetric, but it reflects the `cfg` statements in lib.rs that
    // require `aws-lc-sys` to be present when "fips" is not enabled.
    // if `fips` is enabled, then use that
    let sys_crate = if cfg!(feature = "fips") {
        "aws-lc-fips-sys"
    } else if cfg!(feature = "aws-lc-sys") {
        "aws-lc-sys"
    } else {
        panic!(
            "one of the following features must be specified: `aws-lc-sys`, `non-fips`, or `fips`."
        );
    };

    // When using static CRT on Windows MSVC, ignore missing PDB file warnings
    // The static CRT libraries reference PDB files from Microsoft's build servers
    // which are not available during linking
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && env::var("CARGO_CFG_TARGET_FEATURE")
            .is_ok_and(|features| features.contains("crt-static"))
    {
        println!("cargo:rustc-link-arg=/ignore:4099");
    }

    let selected = export_sys_vars(sys_crate);
    emit_optional_function_cfgs(&selected);
}

/// Emits `cfg(aws_lc_has = "...")` for each of `OPTIONAL_AWS_LC_FUNCTIONS` declared by the
/// bindings that the sys crate exports as `bindings`.
fn emit_optional_function_cfgs(selected: &str) {
    let values: Vec<String> = OPTIONAL_AWS_LC_FUNCTIONS
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect();
    println!(
        "cargo:rustc-check-cfg=cfg(aws_lc_has, values({}))",
        values.join(", ")
    );

    let var = format!("{selected}BINDINGS");
    println!("cargo:rerun-if-env-changed={var}");
    // Older sys crates do not export their bindings path; every optional function is then
    // treated as unavailable.
    let Some(path) = env::var_os(&var) else {
        return;
    };
    let path = Path::new(&path);
    println!("cargo:rerun-if-changed={}", path.display());
    let bindings = match fs::read_to_string(path) {
        Ok(bindings) => bindings,
        Err(err) => {
            println!(
                "cargo:warning=Unable to read AWS-LC bindings {}: {err}",
                path.display()
            );
            return;
        }
    };

    for name in OPTIONAL_AWS_LC_FUNCTIONS {
        if declares_function(&bindings, name) {
            println!("cargo:rustc-cfg=aws_lc_has=\"{name}\"");
        }
    }
}

/// Whether `bindings` declares the function `name`. bindgen writes the declaration as
/// `fn NAME(` when its output is formatted (by rustfmt or prettyplease) and as `fn NAME (`
/// when it is not.
fn declares_function(bindings: &str, name: &str) -> bool {
    [format!(" fn {name}("), format!(" fn {name} (")]
        .iter()
        .any(|pattern| bindings.contains(pattern.as_str()))
}

/// Re-exports the selected sys crate's metadata, returning its `DEP_*` variable prefix.
fn export_sys_vars(sys_crate: &str) -> String {
    let prefix = if sys_crate == "aws-lc-fips-sys" {
        "DEP_AWS_LC_FIPS_"
    } else {
        "DEP_AWS_LC_"
    };

    let mut selected = String::default();
    let mut candidates = vec![];

    // search through the DEP vars and find the selected sys crate version
    for (name, value) in std::env::vars() {
        // if we've selected a prefix then we can go straight to exporting it
        if !selected.is_empty() {
            try_export_var(&selected, &name, &value);
            continue;
        }

        // we're still looking for a selected prefix
        if let Some(version) = name.strip_prefix(prefix) {
            if let Some(version) = version.strip_suffix("_INCLUDE") {
                // we've found the selected version so update it and export it
                selected = format!("{prefix}{version}_");
                try_export_var(&selected, &name, &value);
            } else {
                // it started with the expected prefix, but we don't know what the version is yet
                // so save it for later
                candidates.push((name, value));
            }
        }
    }

    assert!(!selected.is_empty(), "missing {prefix} include");

    // process all of the remaining candidates
    for (name, value) in candidates {
        try_export_var(&selected, &name, &value);
    }

    selected
}

fn try_export_var(selected: &str, name: &str, value: &str) {
    assert!(!selected.is_empty(), "missing selected prefix");

    if let Some(var) = name.strip_prefix(selected) {
        eprintln!("cargo:rerun-if-env-changed={name}");
        let var = var.to_lowercase();
        println!("cargo:{var}={value}");
    }
}
