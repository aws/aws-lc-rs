// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::OutputLib::{Crypto, RustWrapper, Ssl};
use crate::{
    cargo_env, emit_warning, execute_command, is_crt_static, is_no_asm, option_env, target,
    target_arch, target_env, target_os, target_underscored, target_vendor, OutputLibType,
};
use std::env;
use std::ffi::OsString;
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

fn test_nasm_command() -> bool {
    execute_command("nasm".as_ref(), &["-version".as_ref()]).status
}

fn find_cmake_command() -> Option<OsString> {
    if let Some(cmake) = option_env("CMAKE") {
        emit_warning(&format!(
            "CMAKE environment variable set: {}",
            cmake.clone()
        ));
        if execute_command(cmake.as_ref(), &["--version".as_ref()]).status {
            Some(cmake.into())
        } else {
            None
        }
    } else if execute_command("cmake3".as_ref(), &["--version".as_ref()]).status {
        Some("cmake3".into())
    } else if execute_command("cmake".as_ref(), &["--version".as_ref()]).status {
        Some("cmake".into())
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

    #[allow(clippy::too_many_lines)]
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

        if cfg!(feature = "asan") {
            env::set_var("CC", "clang");
            env::set_var("CXX", "clang++");
            env::set_var("ASM", "clang");

            cmake_cfg.define("ASAN", "1");
        }

        // Allow environment to specify CMake toolchain.
        if let Some(toolchain) = option_env("CMAKE_TOOLCHAIN_FILE").or(option_env(format!(
            "CMAKE_TOOLCHAIN_FILE_{}",
            target_underscored()
        ))) {
            emit_warning(&format!(
                "CMAKE_TOOLCHAIN_FILE environment variable set: {toolchain}"
            ));
            return cmake_cfg;
        }

        if let Some(cc) = option_env("CC") {
            emit_warning(&format!("CC environment variable set: {}", cc.clone()));
            cmake_cfg.define("CMAKE_C_COMPILER", cc);
        }
        if let Some(cxx) = option_env("CXX") {
            emit_warning(&format!("CXX environment variable set: {}", cxx.clone()));
            cmake_cfg.define("CMAKE_CXX_COMPILER", cxx);
        }

        // See issue: https://github.com/aws/aws-lc-rs/issues/453
        if target_os() == "windows" {
            Self::configure_windows(&mut cmake_cfg);
        }

        // If the build environment vendor is Apple
        #[cfg(target_vendor = "apple")]
        {
            if target_arch() == "aarch64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "arm64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "arm64");
            }
            if target_arch() == "x86_64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "x86_64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "x86_64");
            }
        }

        if target_os() == "android" {
            cmake_cfg.define("CMAKE_SYSTEM_NAME", "Android");

            let target = target();
            let proc = target.split('-').next().unwrap();
            match proc {
                "armv7" => {
                    cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "armv7-a");
                }
                "arm" => {
                    cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "armv6");
                }
                _ => {
                    cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", proc);
                }
            }
        }

        if target_vendor() == "apple" && target_os().to_lowercase() == "ios" {
            cmake_cfg.define("CMAKE_SYSTEM_NAME", "iOS");
            if target().ends_with("-ios-sim") || target_arch() == "x86_64" {
                cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphonesimulator");
            } else {
                cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphoneos");
            }
            cmake_cfg.define("CMAKE_THREAD_LIBS_INIT", "-lpthread");
        }

        if target_env() == "ohos" {
            Self::configure_open_harmony(&mut cmake_cfg);
        }

        cmake_cfg
    }

    fn configure_windows(cmake_cfg: &mut cmake::Config) {
        match (target_env().as_str(), target_arch().as_str()) {
            ("msvc", "aarch64") => {
                cmake_cfg.generator_toolset(format!(
                    "ClangCL{}",
                    if cfg!(target_arch = "x86_64") {
                        ",host=x64"
                    } else {
                        ""
                    }
                ));
                cmake_cfg.static_crt(is_crt_static());
                cmake_cfg.define("CMAKE_GENERATOR_PLATFORM", "ARM64");
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "Windows");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "ARM64");
            }
            ("msvc", "x86") => {
                cmake_cfg.static_crt(is_crt_static());
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "");
            }
            ("msvc", _) => {
                cmake_cfg.static_crt(is_crt_static());
            }
            ("gnu", "x86") => {
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "Windows");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "x86");
            }
            _ => {}
        }
    }

    fn configure_open_harmony(cmake_cfg: &mut cmake::Config) {
        const OHOS_NDK_HOME: &str = "OHOS_NDK_HOME";
        if let Ok(ndk) = env::var(OHOS_NDK_HOME) {
            cmake_cfg.define(
                "CMAKE_TOOLCHAIN_FILE",
                format!("{ndk}/native/build/cmake/ohos.toolchain.cmake"),
            );
            let mut cflags = vec!["-Wno-unused-command-line-argument"];
            let mut asmflags = vec![];
            match target().as_str() {
                "aarch64-unknown-linux-ohos" => {}
                "armv7-unknown-linux-ohos" => {
                    const ARM7_FLAGS: [&str; 6] = [
                        "-march=armv7-a",
                        "-mfloat-abi=softfp",
                        "-mtune=generic-armv7-a",
                        "-mthumb",
                        "-mfpu=neon",
                        "-DHAVE_NEON",
                    ];
                    cflags.extend(ARM7_FLAGS);
                    asmflags.extend(ARM7_FLAGS);
                }
                "x86_64-unknown-linux-ohos" => {
                    const X86_64_FLAGS: [&str; 3] = ["-msse4.1", "-DHAVE_NEON_X86", "-DHAVE_NEON"];
                    cflags.extend(X86_64_FLAGS);
                    asmflags.extend(X86_64_FLAGS);
                }
                ohos_target => {
                    emit_warning(format!("Target: {ohos_target} is not support yet!").as_str());
                }
            }
            cmake_cfg
                .cflag(cflags.join(" ").as_str())
                .cxxflag(cflags.join(" ").as_str())
                .asmflag(asmflags.join(" ").as_str());
        } else {
            emit_warning(format!("{OHOS_NDK_HOME} not set!").as_str());
        }
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
            if target_arch() == "aarch64" && target_env() == "msvc" && !test_clang_cl_command() {
                eprintln!("Missing dependency: clang-cl");
                missing_dependency = true;
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
