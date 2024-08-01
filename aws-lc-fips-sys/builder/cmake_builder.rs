// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::OutputLib::{Crypto, RustWrapper, Ssl};
use crate::{
    cargo_env, emit_warning, execute_command, is_no_asm, option_env, target, target_arch,
    target_env, target_family, target_os, target_underscored, target_vendor, OutputLibType,
};
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

pub(crate) struct CmakeBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

fn test_perl_command() -> bool {
    execute_command("perl".as_ref(), &["--version".as_ref()]).status
}

fn test_go_command() -> bool {
    let result = execute_command("go".as_ref(), &["version".as_ref()]);
    if !result.status && result.executed {
        eprintln!("Go stderr:\n--------\n{}\n--------", result.stderr);
    }
    result.status
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
        let opt_level = cargo_env("OPT_LEVEL");

        if is_no_asm() {
            if opt_level == "0" {
                cmake_cfg.define("OPENSSL_NO_ASM", "1");
            } else {
                panic!("AWS_LC_FIPS_SYS_NO_ASM only allowed for debug builds!")
            }
        }

        if opt_level != "0" {
            if opt_level == "1" || opt_level == "2" {
                cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
            } else {
                cmake_cfg.define("CMAKE_BUILD_TYPE", "release");
                if target_family() == "unix" || target_env() == "gnu" {
                    cmake_cfg.cflag(format!(
                        "-ffile-prefix-map={}=",
                        self.manifest_dir.display()
                    ));
                }
            }
        } else if target_os() == "windows" {
            // The Windows/FIPS build rejects "debug" profile
            // https://github.com/aws/aws-lc/blob/main/CMakeLists.txt#L656
            cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
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
        cmake_cfg.define("FIPS", "1");

        if cfg!(feature = "asan") {
            env::set_var("CC", "clang");
            env::set_var("CXX", "clang++");
            env::set_var("ASM", "clang");

            cmake_cfg.define("ASAN", "1");
        }

        // Allow environment to specify CMake toolchain.
        if option_env("CMAKE_TOOLCHAIN_FILE").is_some()
            || option_env(format!("CMAKE_TOOLCHAIN_FILE_{}", target_underscored())).is_some()
        {
            return cmake_cfg;
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

        if target_vendor() == "apple" && target_os().trim() == "ios" {
            cmake_cfg.define("CMAKE_SYSTEM_NAME", "iOS");
            if target().trim().ends_with("-ios-sim") {
                cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphonesimulator");
            }
        }

        if target_os() == "windows" {
            cmake_cfg.generator("Ninja");
            let env_map = self
                .collect_vcvarsall_bat()
                .map_err(|x| panic!("{}", x))
                .unwrap();
            for (key, value) in env_map {
                cmake_cfg.env(key, value);
            }
        }

        if target_env() == "ohos" {
            Self::configure_open_harmony(&mut cmake_cfg);
        }

        cmake_cfg
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

    fn collect_vcvarsall_bat(&self) -> Result<HashMap<String, String>, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        let script_path = self.manifest_dir.join("builder").join("printenv.bat");
        let result = execute_command(script_path.as_os_str(), &[]);
        if !result.status {
            eprintln!("{}", result.stdout);
            return Err("Failed to run vcvarsall.bat.".to_owned());
        }
        eprintln!("{}", result.stdout);
        let lines = result.stdout.lines();
        for line in lines {
            if let Some((var, val)) = line.split_once('=') {
                map.insert(var.to_string(), val.to_string());
            }
        }
        Ok(map)
    }
}

impl crate::Builder for CmakeBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        let mut missing_dependency = false;
        if target_os() == "windows" && !test_ninja_command() {
            eprintln!("Missing dependency: Ninja is required for FIPS on Windows.");
            missing_dependency = true;
        }
        if !test_go_command() {
            eprintln!("Missing dependency: Go is required for FIPS.");
            missing_dependency = true;
        }
        if !test_perl_command() {
            eprintln!("Missing dependency: perl is required for FIPS.");
            missing_dependency = true;
        }
        if target_os() == "windows"
            && target_arch() == "x86_64"
            && !test_nasm_command()
            && !is_no_asm()
        {
            eprintln!(
                "Consider setting `AWS_LC_FIPS_SYS_NO_ASM` in the environment for development builds.\
            See User Guide about the limitations: https://aws.github.io/aws-lc-rs/index.html"
            );
            eprintln!("Missing dependency: nasm is required for FIPS.");
            missing_dependency = true;
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
