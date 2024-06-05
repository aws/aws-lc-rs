// Copyright (c) 2022, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use cc_builder::CcBuilder;
use cmake_builder::CmakeBuilder;

#[cfg(any(
    feature = "bindgen",
    not(any(
        all(
            any(target_arch = "x86_64", target_arch = "aarch64"),
            any(target_os = "linux", target_os = "macos"),
            any(target_env = "gnu", target_env = "musl", target_env = "")
        ),
        all(target_arch = "x86", target_os = "linux", target_env = "gnu")
    ))
))]
mod bindgen;
mod cc_builder;
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
    option_env("AWS_LC_SYS_INCLUDES")
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
        if Some(false) == env_var_to_bool("AWS_LC_SYS_STATIC") {
            // Only dynamic if the value is set and is a "negative" value
            OutputLibType::Dynamic
        } else {
            OutputLibType::Static
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
    format!("aws_lc_{}", VERSION.to_string().replace('.', "_"))
}

#[cfg(feature = "bindgen")]
fn target_platform_prefix(name: &str) -> String {
    format!("{}_{}", target().replace('-', "_"), name)
}

pub(crate) struct TestCommandResult {
    #[allow(dead_code)]
    stderr: Box<str>,
    #[allow(dead_code)]
    stdout: Box<str>,
    executed: bool,
    status: bool,
}

const MAX_CMD_OUTPUT_SIZE: usize = 1 << 12;
fn execute_command(executable: &OsStr, args: &[&OsStr]) -> TestCommandResult {
    if let Ok(mut result) = Command::new(executable).args(args).output() {
        result.stderr.truncate(MAX_CMD_OUTPUT_SIZE);
        let stderr = String::from_utf8(result.stderr)
            .unwrap_or_default()
            .into_boxed_str();
        result.stdout.truncate(MAX_CMD_OUTPUT_SIZE);
        let stdout = String::from_utf8(result.stdout)
            .unwrap_or_default()
            .into_boxed_str();
        return TestCommandResult {
            stderr,
            stdout,
            executed: true,
            status: result.status.success(),
        };
    }
    TestCommandResult {
        stderr: String::new().into_boxed_str(),
        stdout: String::new().into_boxed_str(),
        executed: false,
        status: false,
    }
}

#[cfg(any(
    feature = "bindgen",
    not(any(
        all(
            any(target_arch = "x86_64", target_arch = "aarch64"),
            any(target_os = "linux", target_os = "macos"),
            any(target_env = "gnu", target_env = "musl", target_env = "")
        ),
        all(target_arch = "x86", target_os = "linux", target_env = "gnu")
    ))
))]
fn generate_bindings(manifest_dir: &Path, prefix: &Option<String>, bindings_path: &PathBuf) {
    let options = BindingOptions {
        build_prefix: prefix.clone(),
        include_ssl: cfg!(feature = "ssl"),
        disable_prelude: true,
    };

    let bindings = bindgen::generate_bindings(manifest_dir, &options);

    bindings
        .write(Box::new(std::fs::File::create(bindings_path).unwrap()))
        .expect("written bindings");
}

#[cfg(feature = "bindgen")]
fn generate_src_bindings(manifest_dir: &Path, prefix: &Option<String>, src_bindings_path: &Path) {
    bindgen::generate_bindings(
        manifest_dir,
        &BindingOptions {
            build_prefix: prefix.clone(),
            include_ssl: false,
            ..Default::default()
        },
    )
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto"))))
    .expect("write bindings");

    bindgen::generate_bindings(
        manifest_dir,
        &BindingOptions {
            build_prefix: prefix.clone(),
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

fn emit_warning(message: &str) {
    println!("cargo:warning={message}");
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

fn target_vendor() -> String {
    cargo_env("CARGO_CFG_TARGET_VENDOR")
}

fn target() -> String {
    cargo_env("TARGET")
}

#[allow(unused)]
fn target_underscored() -> String {
    target().replace('-', "_")
}

fn out_dir() -> PathBuf {
    PathBuf::from(cargo_env("OUT_DIR"))
}

fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap()
}

fn get_builder(prefix: &Option<String>, manifest_dir: &Path, out_dir: &Path) -> Box<dyn Builder> {
    let cmake_builder_builder = || {
        Box::new(CmakeBuilder::new(
            manifest_dir.to_path_buf(),
            out_dir.to_path_buf(),
            prefix.clone(),
            OutputLibType::default(),
        ))
    };

    let cc_builder_builder = || {
        Box::new(CcBuilder::new(
            manifest_dir.to_path_buf(),
            out_dir.to_path_buf(),
            prefix.clone(),
            OutputLibType::default(),
        ))
    };

    if let Some(val) = env_var_to_bool("AWS_LC_SYS_CMAKE_BUILDER") {
        let builder: Box<dyn Builder> = if val {
            cmake_builder_builder()
        } else {
            cc_builder_builder()
        };
        builder.check_dependencies().unwrap();
        return builder;
    } else if is_no_asm() {
        let builder = cmake_builder_builder();
        builder.check_dependencies().unwrap();
        return builder;
    } else if !is_bindgen_required() {
        let cc_builder = cc_builder_builder();
        if cc_builder.check_dependencies().is_ok() {
            return cc_builder;
        }
    }
    let cmake_builder = cmake_builder_builder();
    cmake_builder.check_dependencies().unwrap();
    cmake_builder
}

trait Builder {
    fn check_dependencies(&self) -> Result<(), String>;
    fn build(&self) -> Result<(), String>;
}

static mut PREGENERATED: bool = false;
static mut AWS_LC_SYS_NO_PREFIX: bool = false;
static mut AWS_LC_SYS_INTERNAL_BINDGEN: bool = false;
static mut AWS_LC_SYS_EXTERNAL_BINDGEN: bool = false;
static mut AWS_LC_SYS_NO_ASM: bool = false;

fn initialize() {
    unsafe {
        AWS_LC_SYS_NO_PREFIX = env_var_to_bool("AWS_LC_SYS_NO_PREFIX").unwrap_or(false);
        AWS_LC_SYS_INTERNAL_BINDGEN =
            env_var_to_bool("AWS_LC_SYS_INTERNAL_BINDGEN").unwrap_or(false);
        AWS_LC_SYS_EXTERNAL_BINDGEN =
            env_var_to_bool("AWS_LC_SYS_EXTERNAL_BINDGEN").unwrap_or(false);
        AWS_LC_SYS_NO_ASM = env_var_to_bool("AWS_LC_SYS_NO_ASM").unwrap_or(false);
    }

    if !is_external_bindgen() && (is_internal_bindgen() || !has_bindgen_feature()) {
        let target = target();
        let supported_platform = match target.as_str() {
            "i686-unknown-linux-gnu"
            | "x86_64-unknown-linux-gnu"
            | "aarch64-unknown-linux-gnu"
            | "x86_64-unknown-linux-musl"
            | "aarch64-unknown-linux-musl"
            | "x86_64-apple-darwin"
            | "aarch64-apple-darwin" => Some(target),
            _ => None,
        };
        if let Some(platform) = supported_platform {
            emit_rustc_cfg(platform.as_str());
            unsafe {
                PREGENERATED = true;
            }
        }
    }
}

fn is_bindgen_required() -> bool {
    is_no_prefix()
        || is_internal_bindgen()
        || is_external_bindgen()
        || has_bindgen_feature()
        || !has_pregenerated()
}

fn is_no_prefix() -> bool {
    unsafe { AWS_LC_SYS_NO_PREFIX }
}

fn is_internal_bindgen() -> bool {
    unsafe { AWS_LC_SYS_INTERNAL_BINDGEN }
}

fn is_external_bindgen() -> bool {
    unsafe { AWS_LC_SYS_EXTERNAL_BINDGEN }
}

fn is_no_asm() -> bool {
    unsafe { AWS_LC_SYS_NO_ASM }
}

fn has_bindgen_feature() -> bool {
    cfg!(feature = "bindgen")
}

fn has_pregenerated() -> bool {
    unsafe { PREGENERATED }
}

fn prepare_cargo_cfg() {
    // This is supported in Rust >= 1.77.0
    // Also remove `#![allow(unexpected_cfgs)]` from src/lib.rs
    /*
    println!("cargo::rustc-check-cfg=cfg(use_bindgen_generated)");
    println!("cargo::rustc-check-cfg=cfg(i686_unknown_linux_gnu)");
    println!("cargo::rustc-check-cfg=cfg(x86_64_unknown_linux_gnu)");
    println!("cargo::rustc-check-cfg=cfg(aarch64_unknown_linux_gnu)");
    println!("cargo::rustc-check-cfg=cfg(x86_64_unknown_linux_musl)");
    println!("cargo::rustc-check-cfg=cfg(aarch64_unknown_linux_musl)");
    println!("cargo::rustc-check-cfg=cfg(x86_64_apple_darwin)");
    println!("cargo::rustc-check-cfg=cfg(aarch64_apple_darwin)");
     */
}

fn main() {
    initialize();
    prepare_cargo_cfg();

    let manifest_dir = current_dir();
    let manifest_dir = dunce::canonicalize(Path::new(&manifest_dir)).unwrap();
    let prefix_str = prefix_string();
    let prefix = if is_no_prefix() {
        None
    } else {
        Some(prefix_str)
    };

    let builder = get_builder(&prefix, &manifest_dir, &out_dir());

    builder.check_dependencies().unwrap();

    #[allow(unused_assignments)]
    let mut bindings_available = false;
    if is_internal_bindgen() {
        #[cfg(feature = "bindgen")]
        {
            emit_warning(&format!("Generating src bindings. Platform: {}", target()));
            let src_bindings_path = Path::new(&manifest_dir).join("src");
            generate_src_bindings(&manifest_dir, &prefix, &src_bindings_path);
            bindings_available = true;
        }
    } else if is_bindgen_required() {
        #[cfg(any(
            feature = "bindgen",
            not(any(
                all(
                    any(target_arch = "x86_64", target_arch = "aarch64"),
                    any(target_os = "linux", target_os = "macos"),
                    any(target_env = "gnu", target_env = "musl", target_env = "")
                ),
                all(target_arch = "x86", target_os = "linux", target_env = "gnu")
            ))
        ))]
        if !is_external_bindgen() {
            emit_warning(&format!(
                "Generating bindings - internal bindgen. Platform: {}",
                target()
            ));
            let gen_bindings_path = out_dir().join("bindings.rs");
            generate_bindings(&manifest_dir, &prefix, &gen_bindings_path);
            emit_rustc_cfg("use_bindgen_generated");
            bindings_available = true;
        }
    } else {
        bindings_available = true;
    }

    if !bindings_available && !cfg!(feature = "ssl") {
        emit_warning(&format!(
            "Generating bindings - external bindgen. Platform: {}",
            target()
        ));
        let gen_bindings_path = out_dir().join("bindings.rs");
        let result = invoke_external_bindgen(&manifest_dir, &prefix, &gen_bindings_path);
        match result {
            Ok(()) => {
                emit_rustc_cfg("use_bindgen_generated");
                bindings_available = true;
            }
            Err(msg) => eprintln!("Failure invoking external bindgen! {msg}"),
        }
    }

    assert!(
        bindings_available,
        "aws-lc-sys build failed. Please enable the 'bindgen' feature on aws-lc-rs or aws-lc-sys.\
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

    if let Some(extra_paths) = get_aws_lc_sys_includes_path() {
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

#[derive(Default)]
#[allow(dead_code)]
pub(crate) struct BindingOptions {
    pub build_prefix: Option<String>,
    pub include_ssl: bool,
    pub disable_prelude: bool,
}

fn invoke_external_bindgen(
    manifest_dir: &Path,
    prefix: &Option<String>,
    gen_bindings_path: &Path,
) -> Result<(), String> {
    let result = execute_command("bindgen".as_ref(), &["--version".as_ref()]);
    if !result.status {
        if !result.executed {
            eprintln!(
                "Consider installing the bindgen-cli: \
            `cargo install --force --locked bindgen-cli`\
            \n\
            See our User Guide for more information about bindgen:\
            https://aws.github.io/aws-lc-rs/index.html"
            );
        }
        return Err("External bindgen command failed.".to_string());
    }
    let options = BindingOptions {
        build_prefix: None,
        include_ssl: false,
        disable_prelude: true,
    };

    let clang_args = prepare_clang_args(manifest_dir, &options);
    let header = get_rust_include_path(manifest_dir)
        .join("rust_wrapper.h")
        .display()
        .to_string();

    let sym_prefix: String;
    let mut bindgen_params = vec![];
    if let Some(prefix_str) = prefix {
        sym_prefix = if target_os().to_lowercase() == "macos" || target_os().to_lowercase() == "ios"
        {
            format!("_{prefix_str}_")
        } else {
            format!("{prefix_str}_")
        };
        bindgen_params.extend(vec!["--prefix-link-name", sym_prefix.as_str()]);
    }

    // These flags needs to be kept in sync with the setup in bindgen::prepare_bindings_builder
    // If `bindgen-cli` makes backwards incompatible changes, we will update the parameters below
    // to conform with the most recent release. We will guide consumers to likewise use the
    // latest version of bindgen-cli.
    bindgen_params.extend(vec![
        "--rust-target",
        r"1.59",
        "--with-derive-default",
        "--with-derive-eq",
        "--allowlist-file",
        r".*(/|\\)openssl(/|\\)[^/\\]+\.h",
        "--allowlist-file",
        r".*(/|\\)rust_wrapper\.h",
        "--rustified-enum",
        r"point_conversion_form_t",
        "--default-macro-constant-type",
        r"signed",
        "--formatter",
        r"rustfmt",
        "--output",
        gen_bindings_path.to_str().unwrap(),
        "--raw-line",
        COPYRIGHT,
        header.as_str(),
        "--",
    ]);
    clang_args
        .iter()
        .for_each(|x| bindgen_params.push(x.as_str()));
    let cmd_params: Vec<OsString> = bindgen_params.iter().map(OsString::from).collect();
    let cmd_params: Vec<&OsStr> = cmd_params.iter().map(OsString::as_os_str).collect();

    let result = execute_command("bindgen".as_ref(), cmd_params.as_ref());
    if !result.status {
        return Err(format!(
            "\n\n\
            bindgen-PARAMS: {}\n\
            bindgen-STDOUT: {}\n\
            bindgen-STDERR: {}",
            bindgen_params.join(" "),
            result.stdout.as_ref(),
            result.stderr.as_ref()
        ));
    }
    Ok(())
}

fn add_header_include_path(args: &mut Vec<String>, path: String) {
    args.push("-I".to_string());
    args.push(path);
}

fn prepare_clang_args(manifest_dir: &Path, options: &BindingOptions) -> Vec<String> {
    let mut clang_args: Vec<String> = Vec::new();

    add_header_include_path(
        &mut clang_args,
        get_rust_include_path(manifest_dir).display().to_string(),
    );

    if options.build_prefix.is_some() {
        // NOTE: It's possible that the prefix embedded in the header files doesn't match the prefix
        // specified. This only happens when the version number as changed in Cargo.toml, but the
        // new headers have not yet been generated.
        add_header_include_path(
            &mut clang_args,
            get_generated_include_path(manifest_dir)
                .display()
                .to_string(),
        );
    }

    add_header_include_path(
        &mut clang_args,
        get_aws_lc_include_path(manifest_dir).display().to_string(),
    );

    if let Some(include_paths) = get_aws_lc_sys_includes_path() {
        for path in include_paths {
            add_header_include_path(&mut clang_args, path.display().to_string());
        }
    }

    clang_args
}

const COPYRIGHT: &str = r"
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
";
