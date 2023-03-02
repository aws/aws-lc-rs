/* Copyright (c) 2022, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// SPDX-License-Identifier: Apache-2.0 OR ISC
// Modifications Copyright Amazon.com, Inc. or its affiliates. See GitHub history for details.

#[cfg(feature = "bindgen")]
use std::default::Default;
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(feature = "bindgen")]
mod bindgen;

pub(crate) fn get_aws_lc_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("aws-lc").join("include")
}

pub(crate) fn get_rust_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("include")
}

pub(crate) fn get_generated_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("generated-include")
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputLib {
    RustWrapper,
    Crypto,
    Ssl,
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputLibType {
    Static,
    Dynamic,
}

impl OutputLibType {
    fn rust_lib_type(&self) -> &str {
        match self {
            OutputLibType::Static => "static",
            OutputLibType::Dynamic => "dylib",
        }
    }
}

impl OutputLib {
    fn libname(self, prefix: Option<&str>) -> String {
        format!(
            "{}{}",
            if let Some(pfix) = prefix { pfix } else { "" },
            match self {
                OutputLib::Crypto => "crypto",
                OutputLib::Ssl => "ssl",
                OutputLib::RustWrapper => {
                    "rust_wrapper"
                }
            }
        )
    }

    fn locate_dir(self, path: &Path) -> PathBuf {
        match self {
            OutputLib::RustWrapper => path.join("build").join(get_platform_output_path()),
            OutputLib::Crypto | OutputLib::Ssl => path
                .join("build")
                .join("aws-lc")
                .join(self.libname(None))
                .join(get_platform_output_path()),
        }
    }
}

fn get_platform_output_path() -> PathBuf {
    PathBuf::new()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn prefix_string() -> String {
    format!("aws_lc_{}", VERSION.to_string().replace('.', "_"))
}

#[cfg(feature = "bindgen")]
fn target_platform_prefix(name: &str) -> String {
    format!("{}_{}_{}", env::consts::OS, env::consts::ARCH, name)
}

fn test_command(executable: &OsStr, args: &[&OsStr]) -> bool {
    if let Ok(output) = Command::new(executable).args(args).output() {
        return output.status.success();
    }
    false
}

fn find_cmake_command() -> Option<&'static OsStr> {
    if test_command("cmake3".as_ref(), &["--version".as_ref()]) {
        Some("cmake3".as_ref())
    } else if test_command("cmake".as_ref(), &["--version".as_ref()]) {
        Some("cmake".as_ref())
    } else {
        None
    }
}

fn get_cmake_config(manifest_dir: &PathBuf) -> cmake::Config {
    cmake::Config::new(manifest_dir)
}

fn prepare_cmake_build(manifest_dir: &PathBuf, build_prefix: Option<&str>) -> cmake::Config {
    let mut cmake_cfg = get_cmake_config(manifest_dir);

    let opt_level = env::var("OPT_LEVEL").unwrap_or_else(|_| "0".to_string());
    if opt_level.ne("0") {
        if opt_level.eq("1") || opt_level.eq("2") {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
        } else {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "release");
        }
    }

    if let Some(symbol_prefix) = build_prefix {
        cmake_cfg.define("BORINGSSL_PREFIX", symbol_prefix);
        let include_path = manifest_dir.join("generated-include");
        cmake_cfg.define(
            "BORINGSSL_PREFIX_HEADERS",
            include_path.display().to_string(),
        );
    }

    // Build flags that minimize our crate size.
    cmake_cfg.define("BUILD_TESTING", "OFF");
    cmake_cfg.define("BUILD_LIBSSL", "ON");
    // Build flags that minimize our dependencies.
    cmake_cfg.define("DISABLE_PERL", "ON");
    cmake_cfg.define("DISABLE_GO", "ON");

    if cfg!(feature = "asan") {
        env::set_var("CC", "/usr/bin/clang");
        env::set_var("CXX", "/usr/bin/clang++");
        env::set_var("ASM", "/usr/bin/clang");

        cmake_cfg.define("ASAN", "1");
    }

    cmake_cfg
}

fn build_rust_wrapper(manifest_dir: &PathBuf) -> PathBuf {
    prepare_cmake_build(manifest_dir, Some(&prefix_string())).build()
}

#[cfg(feature = "bindgen")]
fn generate_bindings(manifest_dir: &PathBuf, prefix: &str, bindings_path: &PathBuf) {
    let options = bindgen::BindingOptions {
        build_prefix: Some(&prefix),
        include_ssl: cfg!(feature = "ssl"),
        disable_prelude: true,
        ..Default::default()
    };

    let bindings =
        bindgen::generate_bindings(&manifest_dir, options).expect("Unable to generate bindings.");

    bindings
        .write(Box::new(std::fs::File::create(&bindings_path).unwrap()))
        .expect("written bindings");
}

#[cfg(feature = "bindgen")]
fn generate_src_bindings(manifest_dir: &PathBuf, prefix: &str, src_bindings_path: &PathBuf) {
    bindgen::generate_bindings(
        &manifest_dir,
        bindgen::BindingOptions {
            build_prefix: Some(&prefix),
            include_ssl: false,
            ..Default::default()
        },
    )
    .expect("Unable to generate bindings.")
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto"))))
    .expect("write bindings");

    bindgen::generate_bindings(
        &manifest_dir,
        bindgen::BindingOptions {
            build_prefix: Some(&prefix),
            include_ssl: true,
            ..Default::default()
        },
    )
    .expect("Unable to generate bindings.")
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto_ssl"))))
    .expect("write bindings");
}

fn emit_rustc_cfg(cfg: &str) {
    println!("cargo:rustc-cfg={cfg}");
}

macro_rules! cfg_bindgen_platform {
    ($binding:ident, $os:literal, $arch:literal, $additional:expr) => {
        let $binding = {
            (cfg!(all(target_os = $os, target_arch = $arch)) && $additional)
                .then(|| {
                    emit_rustc_cfg(concat!($os, "_", $arch));
                    true
                })
                .unwrap_or(false)
        };
    };
}

fn main() {
    use crate::OutputLib::{Crypto, RustWrapper, Ssl};
    use crate::OutputLibType::Static;

    let is_bindgen_enabled = cfg!(feature = "bindgen");

    let is_internal_generate = env::var("AWS_LC_RUST_INTERNAL_BINDGEN")
        .unwrap_or_else(|_| String::from("0"))
        .eq("1");

    let pregenerated = !is_bindgen_enabled || is_internal_generate;

    cfg_bindgen_platform!(linux_x86, "linux", "x86", pregenerated);
    cfg_bindgen_platform!(linux_x86_64, "linux", "x86_64", pregenerated);
    cfg_bindgen_platform!(linux_aarch64, "linux", "aarch64", pregenerated);
    cfg_bindgen_platform!(macos_x86_64, "macos", "x86_64", pregenerated);

    if !(linux_x86 || linux_x86_64 || linux_aarch64 || macos_x86_64) {
        emit_rustc_cfg("not_pregenerated");
    }

    let mut missing_dependency = false;

    if let Some(cmake_cmd) = find_cmake_command() {
        env::set_var("CMAKE", cmake_cmd);
    } else {
        eprintln!("Missing dependency: cmake");
        missing_dependency = true;
    };

    assert!(
        !missing_dependency,
        "Required build dependency is missing. Halting build."
    );

    let manifest_dir = env::current_dir().unwrap();
    let manifest_dir = dunce::canonicalize(Path::new(&manifest_dir)).unwrap();
    let prefix = prefix_string();

    let artifact_output = build_rust_wrapper(&manifest_dir);

    if is_internal_generate {
        #[cfg(feature = "bindgen")]
        {
            let src_bindings_path = Path::new(&manifest_dir).join("src");
            generate_src_bindings(&manifest_dir, &prefix, &src_bindings_path);
        }
    } else {
        #[cfg(feature = "bindgen")]
        {
            let gen_bindings_path = Path::new(&env::var("OUT_DIR").unwrap()).join("bindings.rs");
            generate_bindings(&manifest_dir, &prefix, &gen_bindings_path);
        }
    }

    println!(
        "cargo:rustc-link-search=native={}",
        Crypto.locate_dir(&artifact_output).display()
    );

    println!(
        "cargo:rustc-link-lib={}={}",
        Static.rust_lib_type(),
        Crypto.libname(Some(&prefix))
    );

    if cfg!(feature = "ssl") {
        println!(
            "cargo:rustc-link-search=native={}",
            Ssl.locate_dir(&artifact_output).display()
        );

        println!(
            "cargo:rustc-link-lib={}={}",
            Static.rust_lib_type(),
            Ssl.libname(Some(&prefix))
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        RustWrapper.locate_dir(&artifact_output).display()
    );
    println!(
        "cargo:rustc-link-lib={}={}",
        Static.rust_lib_type(),
        RustWrapper.libname(Some(&prefix))
    );

    for include_path in vec![
        get_rust_include_path(&manifest_dir),
        get_generated_include_path(&manifest_dir),
        get_aws_lc_include_path(&manifest_dir),
    ] {
        println!("cargo:include={}", include_path.display());
    }

    println!("cargo:rerun-if-changed=builder/");
}
