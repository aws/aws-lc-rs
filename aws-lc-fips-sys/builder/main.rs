// Copyright (c) 2022, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use cmake_builder::CmakeBuilder;

#[cfg(any(
    feature = "bindgen",
    not(any(
        target = "aarch64-apple-darwin",
        target = "x86_64-apple-darwin",
        target = "aarch64-unknown-linux-gnu",
        target = "x86_64-unknown-linux-gnu",
        target = "aarch64-unknown-linux-musl",
        target = "x86_64-unknown-linux-musl"
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

pub(crate) fn get_aws_lc_fips_sys_includes_path() -> Option<Vec<PathBuf>> {
    option_env("AWS_LC_FIPS_SYS_INCLUDES")
        .map(|colon_delim_paths| colon_delim_paths.split(':').map(PathBuf::from).collect())
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

fn cargo_env<N: AsRef<str>>(name: N) -> String {
    let name = name.as_ref();
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name:?}"))
}
fn option_env<N: AsRef<str>>(name: N) -> Option<String> {
    let name = name.as_ref();
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok()
}

fn env_var_to_bool(name: &str) -> Option<bool> {
    let build_type_result = option_env(name);
    if let Some(env_var_value) = build_type_result {
        eprintln!("{name}={env_var_value}");
        // If the environment variable is set, we ignore every other factor.
        let env_var_value = env_var_value.to_lowercase();
        if env_var_value.starts_with('0')
            || env_var_value.starts_with('n')
            || env_var_value.starts_with("off")
        {
            Some(false)
        } else {
            // Otherwise, if the variable is set, assume true
            Some(true)
        }
    } else {
        None
    }
}

impl Default for OutputLibType {
    fn default() -> Self {
        if let Some(stc_lib) = env_var_to_bool("AWS_LC_FIPS_SYS_STATIC") {
            if stc_lib {
                OutputLibType::Static
            } else {
                OutputLibType::Dynamic
            }
        } else if target_os() == "linux"
            && (target_arch() == "x86_64" || target_arch() == "aarch64")
        {
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
    format!("aws_lc_fips_{}", VERSION.to_string().replace('.', "_"))
}

#[cfg(feature = "bindgen")]
fn target_platform_prefix(name: &str) -> String {
    format!("{}_{}", target().replace('-', "_"), name)
}

pub(crate) struct TestCommandResult {
    output: Box<str>,
    status: bool,
    executed: bool,
}

fn test_command(executable: &OsStr, args: &[&OsStr]) -> TestCommandResult {
    if let Ok(result) = Command::new(executable).args(args).output() {
        let output = String::from_utf8(result.stdout)
            .unwrap_or_default()
            .into_boxed_str();
        return TestCommandResult {
            output,
            status: result.status.success(),
            executed: true,
        };
    }
    TestCommandResult {
        output: String::new().into_boxed_str(),
        status: false,
        executed: false,
    }
}

#[cfg(any(
    feature = "bindgen",
    not(any(
        target = "aarch64-apple-darwin",
        target = "x86_64-apple-darwin",
        target = "aarch64-unknown-linux-gnu",
        target = "x86_64-unknown-linux-gnu",
        target = "aarch64-unknown-linux-musl",
        target = "x86_64-unknown-linux-musl"
    ))
))]
fn generate_bindings(manifest_dir: &Path, prefix: Option<String>, bindings_path: &PathBuf) {
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
fn generate_src_bindings(manifest_dir: &Path, prefix: Option<String>, src_bindings_path: &Path) {
    bindgen::generate_bindings(
        manifest_dir,
        &bindgen::BindingOptions {
            build_prefix: prefix.clone(),
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
    let cfg = cfg.replace('-', "_");
    println!("cargo:rustc-cfg={cfg}");
}

fn target_os() -> String {
    cargo_env("CARGO_CFG_TARGET_OS")
}

fn target_arch() -> String {
    cargo_env("CARGO_CFG_TARGET_ARCH")
}

#[allow(unused)]
fn target_env() -> String {
    cargo_env("CARGO_CFG_TARGET_ENV")
}

#[allow(unused)]
fn target_vendor() -> String {
    cargo_env("CARGO_CFG_TARGET_VENDOR")
}

#[allow(unused)]
fn target() -> String {
    cargo_env("TARGET")
}

fn out_dir() -> PathBuf {
    PathBuf::from(cargo_env("OUT_DIR"))
}

fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap()
}

macro_rules! cfg_bindgen_platform {
    ($binding:ident, $target:literal, $additional:expr) => {
        let $binding = {
            (target() == $target && $additional)
                .then(|| {
                    emit_rustc_cfg(&$target.replace('-', "_"));
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

#[allow(clippy::too_many_lines)]
fn main() {
    let is_internal_no_prefix =
        env_var_to_bool("AWS_LC_FIPS_SYS_INTERNAL_NO_PREFIX").unwrap_or(false);
    let is_internal_generate = env_var_to_bool("AWS_LC_RUST_INTERNAL_BINDGEN").unwrap_or(false);
    let mut is_bindgen_required =
        is_internal_no_prefix || is_internal_generate || cfg!(feature = "bindgen");

    let pregenerated = !is_bindgen_required || is_internal_generate;

    cfg_bindgen_platform!(
        x86_64_unknown_linux_gnu,
        "x86_64-unknown-linux-gnu",
        pregenerated
    );
    cfg_bindgen_platform!(
        aarch64_unknown_linux_gnu,
        "aarch64-unknown-linux-gnu",
        pregenerated
    );
    cfg_bindgen_platform!(
        x86_64_unknown_linux_musl,
        "x86_64-unknown-linux-musl",
        pregenerated
    );
    cfg_bindgen_platform!(
        aarch64_unknown_linux_musl,
        "aarch64-unknown-linux-musl",
        pregenerated
    );
    cfg_bindgen_platform!(x86_64_apple_darwin, "x86_64-apple-darwin", pregenerated);
    cfg_bindgen_platform!(aarch64_apple_darwin, "aarch64-apple-darwin", pregenerated);

    if !(x86_64_unknown_linux_gnu
        || aarch64_unknown_linux_gnu
        || x86_64_unknown_linux_musl
        || aarch64_unknown_linux_musl
        || x86_64_apple_darwin
        || aarch64_apple_darwin)
    {
        is_bindgen_required = true;
    }

    let manifest_dir = current_dir();
    let manifest_dir = dunce::canonicalize(Path::new(&manifest_dir)).unwrap();
    let prefix_str = prefix_string();
    let prefix = if is_internal_no_prefix {
        None
    } else {
        Some(prefix_str)
    };

    let builder = CmakeBuilder::new(
        manifest_dir.clone(),
        out_dir(),
        prefix.clone(),
        OutputLibType::default(),
    );

    builder.check_dependencies().unwrap();

    #[allow(unused_assignments)]
    let mut bindings_available = false;
    if is_internal_generate {
        #[cfg(feature = "bindgen")]
        {
            let src_bindings_path = Path::new(&manifest_dir).join("src");
            generate_src_bindings(&manifest_dir, prefix, &src_bindings_path);
            bindings_available = true;
        }
    } else if is_bindgen_required {
        #[cfg(any(
            feature = "bindgen",
            not(any(
                target = "aarch64-apple-darwin",
                target = "x86_64-apple-darwin",
                target = "aarch64-unknown-linux-gnu",
                target = "x86_64-unknown-linux-gnu",
                target = "aarch64-unknown-linux-musl",
                target = "x86_64-unknown-linux-musl"
            ))
        ))]
        {
            let gen_bindings_path = out_dir().join("bindings.rs");
            generate_bindings(&manifest_dir, prefix, &gen_bindings_path);
            emit_rustc_cfg("use_bindgen_generated");
            bindings_available = true;
        }
    } else {
        bindings_available = true;
    }

    assert!(
        bindings_available,
        "aws-lc-fips-sys build failed. Please enable the 'bindgen' feature on aws-lc-rs or aws-lc-fips-sys.\
        For more information, see the aws-lc-rs User Guide: https://aws.github.io/aws-lc-rs/index.html"
    );
    builder.build().unwrap();

    println!(
        "cargo:include={}",
        setup_include_paths(&out_dir(), &manifest_dir).display()
    );

    // export the artifact names
    println!("cargo:libcrypto={}_crypto", prefix_string());
    if cfg!(feature = "ssl") {
        println!("cargo:libssl={}_ssl", prefix_string());
    }

    println!("cargo:rerun-if-changed=builder/");
    println!("cargo:rerun-if-changed=aws-lc/");
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

    // iterate over all the include paths and copy them into the final output
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
