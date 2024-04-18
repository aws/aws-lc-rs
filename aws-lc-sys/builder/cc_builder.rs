// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// NOTE: This module is intended to produce an equivalent "libcrypto" static library to the one
// produced by the CMake. Changes to CMake relating to compiler checks and/or special build flags
// may require modifications to the logic in this module.

mod aarch64_apple_darwin;
mod aarch64_unknown_linux_gnu;
mod aarch64_unknown_linux_musl;
mod i686_unknown_linux_gnu;
mod x86_64_apple_darwin;
mod x86_64_unknown_linux_gnu;
mod x86_64_unknown_linux_musl;

use crate::{
    cargo_env, env_var_to_bool, execute_command, out_dir, target, target_arch, target_os,
    target_vendor, OutputLibType,
};
use std::path::PathBuf;

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use std::fs;

pub(crate) struct Library {
    name: &'static str,
    flags: &'static [&'static str],
    sources: &'static [&'static str],
}

#[allow(non_camel_case_types)]
enum PlatformConfig {
    aarch64_apple_darwin,
    aarch64_unknown_linux_gnu,
    aarch64_unknown_linux_musl,
    x86_64_apple_darwin,
    x86_64_unknown_linux_gnu,
    x86_64_unknown_linux_musl,
    i686_unknown_linux_gnu,
}

impl PlatformConfig {
    fn libcrypto(&self) -> Library {
        match self {
            PlatformConfig::aarch64_apple_darwin => aarch64_apple_darwin::CRYPTO_LIBRARY,
            PlatformConfig::aarch64_unknown_linux_gnu => aarch64_unknown_linux_gnu::CRYPTO_LIBRARY,
            PlatformConfig::aarch64_unknown_linux_musl => {
                aarch64_unknown_linux_musl::CRYPTO_LIBRARY
            }
            PlatformConfig::x86_64_apple_darwin => x86_64_apple_darwin::CRYPTO_LIBRARY,
            PlatformConfig::x86_64_unknown_linux_gnu => x86_64_unknown_linux_gnu::CRYPTO_LIBRARY,
            PlatformConfig::x86_64_unknown_linux_musl => x86_64_unknown_linux_musl::CRYPTO_LIBRARY,
            PlatformConfig::i686_unknown_linux_gnu => i686_unknown_linux_gnu::CRYPTO_LIBRARY,
        }
    }

    fn default_for(target: &str) -> Option<Self> {
        println!("default_for Target: '{target}'");
        match target {
            "aarch64-apple-darwin" => Some(PlatformConfig::aarch64_apple_darwin),
            "aarch64-unknown-linux-gnu" => Some(PlatformConfig::aarch64_unknown_linux_gnu),
            "aarch64-unknown-linux-musl" => Some(PlatformConfig::aarch64_unknown_linux_musl),
            "x86_64-apple-darwin" => Some(PlatformConfig::x86_64_apple_darwin),
            "x86_64-unknown-linux-gnu" => Some(PlatformConfig::x86_64_unknown_linux_gnu),
            "x86_64-unknown-linux-musl" => Some(PlatformConfig::x86_64_unknown_linux_musl),
            "i686-unknown-linux-gnu" => Some(PlatformConfig::i686_unknown_linux_gnu),
            _ => None,
        }
    }
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self::default_for(&target()).unwrap()
    }
}

impl CcBuilder {
    pub(crate) fn new(
        manifest_dir: PathBuf,
        out_dir: PathBuf,
        build_prefix: Option<String>,
        output_lib_type: OutputLibType,
    ) -> Self {
        Self {
            manifest_dir,
            out_dir,
            build_prefix,
            output_lib_type,
        }
    }

    fn create_builder(&self) -> cc::Build {
        let mut cc_build = cc::Build::default();
        cc_build
            .out_dir(&self.out_dir)
            .flag("-std=c99")
            .flag("-Wno-unused-parameter")
            .cpp(false)
            .shared_flag(false)
            .static_flag(true);
        if target_os() == "linux" {
            cc_build.define("_XOPEN_SOURCE", "700").flag("-lpthread");
        }
        if let Some(prefix) = &self.build_prefix {
            cc_build
                .define("BORINGSSL_IMPLEMENTATION", "1")
                .define("BORINGSSL_PREFIX", prefix.as_str());
        }
        self.add_includes(&mut cc_build);
        cc_build
    }

    fn add_includes(&self, cc_build: &mut cc::Build) {
        cc_build
            .include(self.manifest_dir.join("include"))
            .include(self.manifest_dir.join("generated-include"))
            .include(self.manifest_dir.join("aws-lc").join("include"))
            .include(
                self.manifest_dir
                    .join("aws-lc")
                    .join("third_party")
                    .join("s2n-bignum")
                    .join("include"),
            );
    }

    fn add_all_files(&self, lib: &Library, cc_build: &mut cc::Build) {
        use core::str::FromStr;
        cc_build.file(PathBuf::from_str("rust_wrapper.c").unwrap());

        for source in lib.sources {
            let source_path = self.manifest_dir.join("aws-lc").join(source);
            let is_asm = std::path::Path::new(source)
                .extension()
                .map_or(false, |ext| ext.eq("S"));
            if is_asm && target_vendor() == "apple" && target_arch() == "aarch64" {
                let mut cc_preprocessor = self.create_builder();
                cc_preprocessor.file(source_path);
                let preprocessed_asm = String::from_utf8(cc_preprocessor.expand()).unwrap();
                let preprocessed_asm = preprocessed_asm.replace(';', "\n\t");
                let asm_output_path = self.out_dir.join(source);
                fs::create_dir_all(asm_output_path.parent().unwrap()).unwrap();
                fs::write(asm_output_path.clone(), preprocessed_asm).unwrap();
                cc_build.file(asm_output_path);
            } else {
                cc_build.file(source_path);
            }
        }
    }

    fn build_library(&self, lib: &Library) {
        let mut cc_build = self.create_builder();

        self.add_all_files(lib, &mut cc_build);

        for flag in lib.flags {
            cc_build.flag(flag);
        }
        self.compiler_checks(&mut cc_build);

        if let Some(prefix) = &self.build_prefix {
            cc_build.compile(format!("{}_crypto", prefix.as_str()).as_str());
        } else {
            cc_build.compile(lib.name);
        }
    }

    // This performs basic checks of compiler capabilities and sets an appropriate flag on success.
    // This should be kept in alignment with the checks performed by AWS-LC's CMake build.
    // See: https://github.com/search?q=repo%3Aaws%2Faws-lc%20check_compiler&type=code
    fn compiler_check(&self, cc_build: &mut cc::Build, basename: &str, flag: &str) {
        let output_path = self.out_dir.join(format!("{basename}.o"));
        if let Ok(()) = cc::Build::default()
            .file(
                self.manifest_dir
                    .join("aws-lc")
                    .join("tests")
                    .join("compiler_features_tests")
                    .join(format!("{basename}.c")),
            )
            .flag("-Wno-unused-parameter")
            .warnings_into_errors(true)
            .try_compile(output_path.as_os_str().to_str().unwrap())
        {
            cc_build.define(flag, "1");
        }
        let _ = fs::remove_file(output_path);
    }

    // This checks whether the compiler contains a critical bug that causes `memcmp` to erroneously
    // consider two regions of memory to be equal when they're not.
    // See GCC bug report: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189
    // This should be kept in alignment with the same check performed by the CMake build.
    // See: https://github.com/search?q=repo%3Aaws%2Faws-lc%20check_run&type=code
    fn memcmp_check(&self) {
        let basename = "memcmp_invalid_stripped_check";
        let exec_path = out_dir().join(basename);
        let memcmp_build = cc::Build::default();
        let memcmp_compiler = memcmp_build.get_compiler();
        let mut memcmp_compile_args = Vec::from(memcmp_compiler.args());
        memcmp_compile_args.push(
            self.manifest_dir
                .join("aws-lc")
                .join("tests")
                .join("compiler_features_tests")
                .join(format!("{basename}.c"))
                .into_os_string(),
        );
        memcmp_compile_args.push("-Wno-unused-parameter".into());
        memcmp_compile_args.push("-o".into());
        memcmp_compile_args.push(exec_path.clone().into_os_string());
        let memcmp_args: Vec<_> = memcmp_compile_args
            .iter()
            .map(std::ffi::OsString::as_os_str)
            .collect();
        let memcmp_compile_result =
            execute_command(memcmp_compiler.path().as_os_str(), memcmp_args.as_slice());
        assert!(
            memcmp_compile_result.status,
            "COMPILER: {:?}\
            ARGS: {:?}\
            EXECUTED: {}\
            ERROR: {}\
            OUTPUT: {}\
            Failed to compile {basename}
            ",
            memcmp_compiler.path(),
            memcmp_args.as_slice(),
            memcmp_compile_result.executed,
            memcmp_compile_result.stderr,
            memcmp_compile_result.stdout
        );

        // We can only execute the binary when the host and target platforms match.
        if cargo_env("HOST") == target() {
            let result = execute_command(exec_path.as_os_str(), &[]);
            assert!(
                result.status,
                "Your compiler ({}) is not supported due to a memcmp related bug reported in \
                https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189.\
                We strongly recommend against using this compiler.\
                EXECUTED: {} \
                ERROR: {} \
                OUTPUT: {} \
                ",
                memcmp_compiler.path().display(),
                memcmp_compile_result.executed,
                memcmp_compile_result.stderr,
                memcmp_compile_result.stdout
            );
        }
        let _ = fs::remove_file(exec_path);
    }
    fn compiler_checks(&self, cc_build: &mut cc::Build) {
        self.compiler_check(cc_build, "stdalign_check", "AWS_LC_STDALIGN_AVAILABLE");
        self.compiler_check(
            cc_build,
            "builtin_swap_check",
            "AWS_LC_BUILTIN_SWAP_SUPPORTED",
        );
        self.memcmp_check();
    }
}

impl crate::Builder for CcBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        if OutputLibType::Dynamic == self.output_lib_type {
            // https://github.com/rust-lang/cc-rs/issues/594
            return Err("CcBuilder only supports static builds".to_string());
        }

        if PlatformConfig::default_for(&target()).is_none() {
            return Err(format!("Platform not supported: {}", target()));
        }

        if Some(true) == env_var_to_bool("CARGO_FEATURE_SSL") {
            return Err(format!("libssl not supported: {}", target()));
        }

        Ok(())
    }

    fn build(&self) -> Result<(), String> {
        println!("cargo:root={}", self.out_dir.display());
        let platform_config = PlatformConfig::default();
        let libcrypto = platform_config.libcrypto();
        self.build_library(&libcrypto);
        Ok(())
    }
}
