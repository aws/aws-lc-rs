// Copyright (c) 2022, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#[cfg(feature = "bindgen")]
use std::default::Default;
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(any(
    feature = "bindgen",
    not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    ))
))]
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

pub(crate) fn get_aws_lc_fips_sys_includes_path() -> Option<Vec<PathBuf>> {
    env::var("AWS_LC_FIPS_SYS_INCLUDES")
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
        let build_type_result = env::var("AWS_LC_FIPS_SYS_STATIC");
        if let Ok(build_type) = build_type_result {
            eprintln!("AWS_LC_FIPS_SYS_STATIC={build_type}");
            // If the environment variable is set, we ignore every other factor.
            let build_type = build_type.to_lowercase();
            if build_type.starts_with('0')
                || build_type.starts_with('n')
                || build_type.starts_with("off")
            {
                // Only dynamic if the value is set and is a "negative" value
                return OutputLibType::Dynamic;
            }

            return OutputLibType::Static;
        }

        if target_os() == "linux" && (target_arch() == "x86_64" || target_arch() == "aarch64") {
            OutputLibType::Static
        } else {
            OutputLibType::Dynamic
        }
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
    fn libname(self, prefix: Option<&str>) -> String {
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

fn artifact_output_dir(path: &Path) -> PathBuf {
    path.join("build")
        .join("artifacts")
        .join(get_platform_output_path())
}

fn get_platform_output_path() -> PathBuf {
    PathBuf::new()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn prefix_string() -> String {
    format!("aws_lc_fips_{}", VERSION.to_string().replace('.', "_"))
}

fn test_perl_command() -> bool {
    test_command("perl".as_ref(), &["--version".as_ref()])
}

fn test_go_command() -> bool {
    test_command("go".as_ref(), &["version".as_ref()])
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

fn prepare_cmake_build(manifest_dir: &PathBuf, build_prefix: String) -> cmake::Config {
    let mut cmake_cfg = get_cmake_config(manifest_dir);

    if OutputLibType::default() == OutputLibType::Dynamic {
        cmake_cfg.define("BUILD_SHARED_LIBS", "1");
    } else {
        cmake_cfg.define("BUILD_SHARED_LIBS", "0");
    }

    let opt_level = env::var("OPT_LEVEL").unwrap_or_else(|_| "0".to_string());
    if opt_level.ne("0") {
        if opt_level.eq("1") || opt_level.eq("2") {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
        } else {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "release");
        }
    }

    cmake_cfg.define("BORINGSSL_PREFIX", build_prefix);
    let include_path = manifest_dir.join("generated-include");
    cmake_cfg.define(
        "BORINGSSL_PREFIX_HEADERS",
        include_path.display().to_string(),
    );

    // Build flags that minimize our crate size.
    cmake_cfg.define("BUILD_TESTING", "OFF");
    if cfg!(feature = "ssl") {
        cmake_cfg.define("BUILD_LIBSSL", "ON");
    } else {
        cmake_cfg.define("BUILD_LIBSSL", "OFF");
    }
    cmake_cfg.define("FIPS", "1");

    if cfg!(feature = "asan") {
        env::set_var("CC", "/usr/bin/clang");
        env::set_var("CXX", "/usr/bin/clang++");
        env::set_var("ASM", "/usr/bin/clang");

        cmake_cfg.define("ASAN", "1");
    }

    cmake_cfg
}

fn build_rust_wrapper(manifest_dir: &PathBuf) -> PathBuf {
    prepare_cmake_build(manifest_dir, prefix_string() + "_")
        .configure_arg("--no-warn-unused-cli")
        .build()
}

#[cfg(any(
    feature = "bindgen",
    not(any(
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

#[allow(unused)]
fn target_vendor() -> String {
    env::var("CARGO_CFG_TARGET_VENDOR").unwrap()
}

#[allow(unused)]
fn target() -> String {
    env::var("TARGET").unwrap()
}

macro_rules! cfg_bindgen_platform {
    ($binding:ident, $os:literal, $arch:literal, $additional:expr) => {
        let $binding = {
            (target_os() == $os && target_arch() == $arch && $additional)
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

    let output_lib_type = OutputLibType::default();

    let mut is_bindgen_required = cfg!(feature = "bindgen");

    let is_internal_generate = env::var("AWS_LC_RUST_INTERNAL_BINDGEN")
        .unwrap_or_else(|_| String::from("0"))
        .eq("1");

    let pregenerated = !is_bindgen_required || is_internal_generate;

    cfg_bindgen_platform!(linux_x86_64, "linux", "x86_64", pregenerated);
    cfg_bindgen_platform!(linux_aarch64, "linux", "aarch64", pregenerated);

    if !(linux_x86_64 || linux_aarch64) {
        emit_rustc_cfg("use_bindgen_generated");
        is_bindgen_required = true;
    }

    check_dependencies();

    let manifest_dir = env::current_dir().unwrap();
    let manifest_dir = dunce::canonicalize(Path::new(&manifest_dir)).unwrap();
    let prefix = prefix_string();

    let out_dir = build_rust_wrapper(&manifest_dir);

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
        "aws-lc-fip-sys build failed. Please enable the 'bindgen' feature on aws-lc-rs or aws-lc-fips-sys"
    );

    println!(
        "cargo:rustc-link-search=native={}",
        artifact_output_dir(&out_dir).display()
    );

    println!(
        "cargo:rustc-link-lib={}={}",
        output_lib_type.rust_lib_type(),
        Crypto.libname(Some(&prefix))
    );

    if cfg!(feature = "ssl") {
        println!(
            "cargo:rustc-link-lib={}={}",
            output_lib_type.rust_lib_type(),
            Ssl.libname(Some(&prefix))
        );
    }

    println!(
        "cargo:rustc-link-lib={}={}",
        output_lib_type.rust_lib_type(),
        RustWrapper.libname(Some(&prefix))
    );

    println!(
        "cargo:include={}",
        setup_include_paths(&out_dir, &manifest_dir).display()
    );

    println!("cargo:rerun-if-changed=builder/");
    println!("cargo:rerun-if-changed=aws-lc/");
    println!("cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC");
}

fn check_dependencies() {
    let mut missing_dependency = false;
    if !test_go_command() {
        eprintln!("Missing dependency: Go is required for FIPS.");
        missing_dependency = true;
    }
    if !test_perl_command() {
        eprintln!("Missing dependency: perl is required for FIPS.");
        missing_dependency = true;
    }
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
}

fn setup_include_paths(out_dir: &Path, manifest_dir: &Path) -> PathBuf {
    let mut include_paths = vec![
        get_rust_include_path(manifest_dir),
        get_generated_include_path(manifest_dir),
        get_aws_lc_include_path(manifest_dir),
    ];

    if let Some(extra_paths) = get_aws_lc_fips_sys_includes_path() {
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
