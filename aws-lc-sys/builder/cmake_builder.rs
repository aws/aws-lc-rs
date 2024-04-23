// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::OutputLib::{Crypto, RustWrapper, Ssl};
use crate::{
    cargo_env, execute_command, is_no_asm, target, target_arch, target_env, target_os,
    target_vendor, OutputLibType,
};
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

pub(crate) struct CmakeBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

fn test_clang_cl_command() -> bool {
    execute_command("clang-cl".as_ref(), &["--version".as_ref()]).status
}

fn test_ninja_command() -> bool {
    execute_command("ninja".as_ref(), &["--version".as_ref()]).status
        || execute_command("ninja-build".as_ref(), &["--version".as_ref()]).status
}

fn test_nasm_command() -> bool {
    execute_command("nasm".as_ref(), &["-version".as_ref()]).status
}

fn find_cmake_command() -> Option<&'static OsStr> {
    if execute_command("cmake3".as_ref(), &["--version".as_ref()]).status {
        Some("cmake3".as_ref())
    } else if execute_command("cmake".as_ref(), &["--version".as_ref()]).status {
        Some("cmake".as_ref())
    } else {
        None
    }
}

fn get_platform_output_path() -> PathBuf {
    PathBuf::new()
}

impl CmakeBuilder {
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

    fn artifact_output_dir(&self) -> PathBuf {
        self.out_dir
            .join("build")
            .join("artifacts")
            .join(get_platform_output_path())
    }

    fn get_cmake_config(&self) -> cmake::Config {
        cmake::Config::new(&self.manifest_dir)
    }

    fn prepare_cmake_build(&self) -> cmake::Config {
        let mut cmake_cfg = self.get_cmake_config();

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
        } else {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "debug");
        }

        if let Some(prefix) = &self.build_prefix {
            cmake_cfg.define("BORINGSSL_PREFIX", format!("{prefix}_"));
            let include_path = self.manifest_dir.join("generated-include");
            cmake_cfg.define(
                "BORINGSSL_PREFIX_HEADERS",
                include_path.display().to_string(),
            );
        }

        // Build flags that minimize our crate size.
        cmake_cfg.define("BUILD_TESTING", "OFF");
        if cfg!(feature = "ssl") {
            cmake_cfg.define("BUILD_LIBSSL", "ON");
        } else {
            cmake_cfg.define("BUILD_LIBSSL", "OFF");
        }
        // Build flags that minimize our dependencies.
        cmake_cfg.define("DISABLE_PERL", "ON");
        cmake_cfg.define("DISABLE_GO", "ON");

        if is_no_asm() {
            let opt_level = cargo_env("OPT_LEVEL");
            if opt_level == "0" {
                cmake_cfg.define("OPENSSL_NO_ASM", "1");
            } else {
                panic!("AWS_LC_SYS_NO_ASM only allowed for debug builds!")
            }
        }

        if target_vendor() == "apple" {
            if target_os().to_lowercase() == "ios" {
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "iOS");
                if target().ends_with("-ios-sim") || target_arch() == "x86_64" {
                    cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphonesimulator");
                } else {
                    cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphoneos");
                }
                cmake_cfg.define("CMAKE_THREAD_LIBS_INIT", "-lpthread");
            }
            if target_arch() == "aarch64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "arm64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "arm64");
            }
            if target_arch() == "x86_64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "x86_64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "x86_64");
            }
        }
        if (target_env() != "msvc") && test_ninja_command() {
            // Use Ninja if available
            cmake_cfg.generator("Ninja");
        }

        if target_os() == "windows" && target_arch() == "aarch64" && target_env() == "msvc" {
            cmake_cfg.generator("Ninja");
            cmake_cfg.define("CMAKE_C_COMPILER", "clang-cl");
            cmake_cfg.define("CMAKE_CXX_COMPILER", "clang-cl");
            cmake_cfg.define("CMAKE_ASM_COMPILER", "clang-cl");
            #[cfg(not(target_arch = "aarch64"))]
            {
                // Only needed when cross-compiling
                cmake_cfg.define("CMAKE_C_COMPILER_TARGET", "arm64-pc-windows-msvc");
                cmake_cfg.define("CMAKE_CXX_COMPILER_TARGET", "arm64-pc-windows-msvc");
                cmake_cfg.define("CMAKE_ASM_COMPILER_TARGET", "arm64-pc-windows-msvc");
            }
        }

        if cfg!(feature = "asan") {
            env::set_var("CC", "clang");
            env::set_var("CXX", "clang++");
            env::set_var("ASM", "clang");

            cmake_cfg.define("ASAN", "1");
        }

        cmake_cfg
    }

    fn build_rust_wrapper(&self) -> PathBuf {
        self.prepare_cmake_build()
            .configure_arg("--no-warn-unused-cli")
            .build()
    }
}

impl crate::Builder for CmakeBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        let mut missing_dependency = false;

        if target_os() == "windows" {
            if target_arch() == "x86_64" && !test_nasm_command() && !is_no_asm() {
                eprintln!(
                    "Consider setting `AWS_LC_SYS_NO_ASM` in the environment for development builds.\
                See User Guide about the limitations: https://aws.github.io/aws-lc-rs/index.html"
                );
                eprintln!("Missing dependency: nasm");
                missing_dependency = true;
            }
            if target_arch() == "aarch64" && target_env() == "msvc" {
                if !test_ninja_command() {
                    eprintln!("Missing dependency: ninja");
                    missing_dependency = true;
                }
                if !test_clang_cl_command() {
                    eprintln!("Missing dependency: clang-cl");
                    missing_dependency = true;
                }
            }
        }
        if let Some(cmake_cmd) = find_cmake_command() {
            env::set_var("CMAKE", cmake_cmd);
        } else {
            eprintln!("Missing dependency: cmake");
            missing_dependency = true;
        };

        if missing_dependency {
            return Err("Required build dependency is missing. Halting build.".to_owned());
        }

        Ok(())
    }
    fn build(&self) -> Result<(), String> {
        self.build_rust_wrapper();

        println!(
            "cargo:rustc-link-search=native={}",
            self.artifact_output_dir().display()
        );

        println!(
            "cargo:rustc-link-lib={}={}",
            self.output_lib_type.rust_lib_type(),
            Crypto.libname(&self.build_prefix)
        );

        if cfg!(feature = "ssl") {
            println!(
                "cargo:rustc-link-lib={}={}",
                self.output_lib_type.rust_lib_type(),
                Ssl.libname(&self.build_prefix)
            );
        }

        println!(
            "cargo:rustc-link-lib={}={}",
            self.output_lib_type.rust_lib_type(),
            RustWrapper.libname(&self.build_prefix)
        );

        Ok(())
    }
}
