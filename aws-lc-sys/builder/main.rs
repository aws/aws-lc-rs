// Copyright (c) 2022, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use cmake_builder::CmakeBuilder;

#[cfg(any(
    feature = "bindgen",
    not(any(
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    ))
))]
mod bindgen;
mod cmake_builder;

pub(crate) fn get_aws_lc_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("aws-lc").join("include")
}

pub(crate) fn get_rust_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("include")
}

pub(crate) fn get_generated_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("generated-include")
}

pub(crate) fn get_aws_lc_sys_includes_path() -> Option<Vec<PathBuf>> {
    env::var("AWS_LC_SYS_INCLUDES")
        .map(|colon_delim_paths| colon_delim_paths.split(':').map(PathBuf::from).collect())
        .ok()
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

impl Default for OutputLibType {
    fn default() -> Self {
        if let Ok(build_type) = env::var("AWS_LC_SYS_STATIC") {
            eprintln!("AWS_LC_SYS_STATIC={build_type}");
            // If the environment variable is set, we ignore every other factor.
            let build_type = build_type.to_lowercase();
            if build_type.starts_with('0')
                || build_type.starts_with('n')
                || build_type.starts_with("off")
            {
                // Only dynamic if the value is set and is a "negative" value
                return OutputLibType::Dynamic;
            }
        }
        OutputLibType::Static
    }
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
    fn libname(self, prefix: &Option<String>) -> String {
        let name = match self {
            OutputLib::Crypto => "crypto",
            OutputLib::Ssl => "ssl",
            OutputLib::RustWrapper => "rust_wrapper",
        };
        if let Some(prefix) = prefix {
            format!("{prefix}_{name}")
        } else {
            name.to_string()
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn prefix_string() -> String {
    format!("aws_lc_{}", VERSION.to_string().replace('.', "_"))
}

#[cfg(feature = "bindgen")]
fn target_platform_prefix(name: &str) -> String {
    format!("{}_{}_{}", env::consts::OS, env::consts::ARCH, name)
}

pub(crate) struct TestCommandResult {
    #[allow(dead_code)]
    output: Box<str>,
    status: bool,
}

fn test_command(executable: &OsStr, args: &[&OsStr]) -> TestCommandResult {
    if let Ok(result) = Command::new(executable).args(args).output() {
        let output = String::from_utf8(result.stdout)
            .unwrap_or_default()
            .into_boxed_str();
        return TestCommandResult {
            output,
            status: result.status.success(),
        };
    }
    TestCommandResult {
        output: String::new().into_boxed_str(),
        status: false,
    }
}

#[cfg(any(
    feature = "bindgen",
    not(any(
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    ))
))]
fn generate_bindings(manifest_dir: &Path, prefix: &str, bindings_path: &PathBuf) {
    let options = bindgen::BindingOptions {
        build_prefix: prefix,
        include_ssl: cfg!(feature = "ssl"),
        disable_prelude: true,
    };

    let bindings = bindgen::generate_bindings(manifest_dir, &options);

    bindings
        .write(Box::new(std::fs::File::create(bindings_path).unwrap()))
        .expect("written bindings");
}

#[cfg(feature = "bindgen")]
fn generate_src_bindings(manifest_dir: &Path, prefix: &str, src_bindings_path: &Path) {
    bindgen::generate_bindings(
        manifest_dir,
        &bindgen::BindingOptions {
            build_prefix: prefix,
            include_ssl: false,
            ..Default::default()
        },
    )
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto"))))
    .expect("write bindings");

    bindgen::generate_bindings(
        manifest_dir,
        &bindgen::BindingOptions {
            build_prefix: prefix,
            include_ssl: true,
            ..Default::default()
        },
    )
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto_ssl"))))
    .expect("write bindings");
}

fn emit_rustc_cfg(cfg: &str) {
    println!("cargo:rustc-cfg={cfg}");
}

fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").unwrap()
}

fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").unwrap()
}

fn target_env() -> String {
    env::var("CARGO_CFG_TARGET_ENV").unwrap()
}

fn target_vendor() -> String {
    env::var("CARGO_CFG_TARGET_VENDOR").unwrap()
}

fn target() -> String {
    env::var("TARGET").unwrap()
}

macro_rules! cfg_bindgen_platform {
    ($binding:ident, $os:literal, $arch:literal, $env:literal, $additional:expr) => {
        let $binding = {
            (target_os() == $os && target_arch() == $arch && target_env() == $env && $additional)
                .then(|| {
                    emit_rustc_cfg(concat!($os, "_", $arch));
                    true
                })
                .unwrap_or(false)
        };
    };
}

trait Builder {
    fn check_dependencies(&self) -> Result<(), String>;
    fn build(&self) -> Result<(), String>;
}

fn main() {
    let mut is_bindgen_required = cfg!(feature = "bindgen");
    let output_lib_type = OutputLibType::default();

    let is_internal_generate = env::var("AWS_LC_RUST_INTERNAL_BINDGEN")
        .unwrap_or_else(|_| String::from("0"))
        .eq("1");

    let pregenerated = !is_bindgen_required || is_internal_generate;

    cfg_bindgen_platform!(linux_x86, "linux", "x86", "gnu", pregenerated);
    cfg_bindgen_platform!(linux_x86_64, "linux", "x86_64", "gnu", pregenerated);
    cfg_bindgen_platform!(linux_aarch64, "linux", "aarch64", "gnu", pregenerated);
    cfg_bindgen_platform!(macos_x86_64, "macos", "x86_64", "", pregenerated);

    if !(linux_x86 || linux_x86_64 || linux_aarch64 || macos_x86_64) {
        emit_rustc_cfg("use_bindgen_generated");
        is_bindgen_required = true;
    }

    let manifest_dir = env::current_dir().unwrap();
    let manifest_dir = dunce::canonicalize(Path::new(&manifest_dir)).unwrap();
    let prefix = prefix_string();
    let out_dir_str = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(out_dir_str.as_str()).to_path_buf();

    let builder = CmakeBuilder::new(
        manifest_dir.clone(),
        out_dir.clone(),
        Some(prefix.clone()),
        output_lib_type,
    );

    builder.check_dependencies().unwrap();

    #[allow(unused_assignments)]
    let mut bindings_available = false;
    if is_internal_generate {
        #[cfg(feature = "bindgen")]
        {
            let src_bindings_path = Path::new(&manifest_dir).join("src");
            generate_src_bindings(&manifest_dir, &prefix, &src_bindings_path);
            bindings_available = true;
        }
    } else if is_bindgen_required {
        #[cfg(any(
            feature = "bindgen",
            not(any(
                all(target_os = "macos", target_arch = "x86_64"),
                all(target_os = "linux", target_arch = "x86"),
                all(target_os = "linux", target_arch = "x86_64"),
                all(target_os = "linux", target_arch = "aarch64")
            ))
        ))]
        {
            let gen_bindings_path = Path::new(&env::var("OUT_DIR").unwrap()).join("bindings.rs");
            generate_bindings(&manifest_dir, &prefix, &gen_bindings_path);
            bindings_available = true;
        }
    } else {
        bindings_available = true;
    }

    assert!(
        bindings_available,
        "aws-lc-sys build failed. Please enable the 'bindgen' feature on aws-lc-rs or aws-lc-sys"
    );
    builder.build().unwrap();

    println!(
        "cargo:include={}",
        setup_include_paths(&out_dir, &manifest_dir).display()
    );

    println!("cargo:rerun-if-changed=builder/");
    println!("cargo:rerun-if-changed=aws-lc/");
    println!("cargo:rerun-if-env-changed=AWS_LC_SYS_STATIC");
}

fn setup_include_paths(out_dir: &Path, manifest_dir: &Path) -> PathBuf {
    let mut include_paths = vec![
        get_rust_include_path(manifest_dir),
        get_generated_include_path(manifest_dir),
        get_aws_lc_include_path(manifest_dir),
    ];

    if let Some(extra_paths) = get_aws_lc_sys_includes_path() {
        include_paths.extend(extra_paths);
    }

    let include_dir = out_dir.join("include");
    std::fs::create_dir_all(&include_dir).unwrap();

    // iterate over all of the include paths and copy them into the final output
    for path in include_paths {
        for child in std::fs::read_dir(path).into_iter().flatten().flatten() {
            if child.file_type().map_or(false, |t| t.is_file()) {
                let _ = std::fs::copy(
                    child.path(),
                    include_dir.join(child.path().file_name().unwrap()),
                );
                continue;
            }

            // prefer the earliest paths
            let options = fs_extra::dir::CopyOptions::new()
                .skip_exist(true)
                .copy_inside(true);
            let _ = fs_extra::dir::copy(child.path(), &include_dir, &options);
        }
    }

    include_dir
}
