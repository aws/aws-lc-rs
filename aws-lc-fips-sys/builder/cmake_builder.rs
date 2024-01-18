// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::OutputLib::{Crypto, RustWrapper, Ssl};
use crate::{target, target_arch, target_os, target_vendor, test_command, OutputLibType};
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
    test_command("perl".as_ref(), &["--version".as_ref()]).status
}

fn test_go_command() -> bool {
    test_command("go".as_ref(), &["version".as_ref()]).status
}

fn test_ninja_command() -> bool {
    test_command("ninja".as_ref(), &["--version".as_ref()]).status
        || test_command("ninja-build".as_ref(), &["--version".as_ref()]).status
}

fn find_cmake_command() -> Option<&'static OsStr> {
    if test_command("cmake3".as_ref(), &["--version".as_ref()]).status {
        Some("cmake3".as_ref())
    } else if test_command("cmake".as_ref(), &["--version".as_ref()]).status {
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

        if ["powerpc64", "powerpc"]
            .iter()
            .any(|arch| target_arch().eq_ignore_ascii_case(arch))
        {
            cmake_cfg.define("ENABLE_EXPERIMENTAL_BIG_ENDIAN_SUPPORT", "1");
        }

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
        } else if target_os() == "windows" {
            // The Windows/FIPS build rejects "debug" profile
            // https://github.com/aws/aws-lc/blob/main/CMakeLists.txt#L656
            cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
        } else {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "debug");
        }

        if target_os() == "windows" {
            cmake_cfg.generator("Ninja");
            let env_map = self
                .collect_vcvarsall_bat()
                .map_err(|x| panic!("{}", x))
                .unwrap();
            for (key, value) in env_map {
                println!("ENV-{}={}", key.as_str(), value.as_str());
                cmake_cfg.env(key, value);
            }
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

        if target_vendor() == "apple" {
            if target_os().trim() == "ios" {
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "iOS");
                if target().trim().ends_with("-ios-sim") {
                    cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphonesimulator");
                }
            }
            if target_arch().trim() == "aarch64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "arm64");
            }
        }
        cmake_cfg.define("FIPS", "1");

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

    fn collect_vcvarsall_bat(&self) -> Result<HashMap<String, String>, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        let script_path = self.manifest_dir.join("builder").join("printenv.bat");
        let result = test_command(script_path.as_os_str(), &[]);
        if !result.status {
            return Err("Failed to run vccarsall.bat.".to_owned());
        }
        let lines = result.output.lines();
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
        if target_os() == "windows" && test_ninja_command() {
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
