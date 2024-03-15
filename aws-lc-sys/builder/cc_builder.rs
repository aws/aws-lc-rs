// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{target, target_arch, target_os, target_vendor, OutputLibType};
use std::path::PathBuf;

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(rename = "Library")]
    libraries: Vec<Library>,
}

#[derive(Debug, Deserialize)]
struct Library {
    name: String,
    flags: Vec<String>,
    sources: Vec<String>,
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
    fn target_build_config_path(&self) -> PathBuf {
        self.manifest_dir
            .join("builder")
            .join("cc")
            .join(format!("{}.toml", target()))
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

        for source in &lib.sources {
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
}

impl crate::Builder for CcBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        if OutputLibType::Dynamic == self.output_lib_type {
            // https://github.com/rust-lang/cc-rs/issues/594
            return Err("CcBuilder only supports static builds".to_string());
        }

        let build_cfg_path = self.target_build_config_path();
        if !build_cfg_path.exists() {
            return Err(format!("Platform not supported: {}", target()));
        }
        Ok(())
    }

    fn build(&self) -> Result<(), String> {
        let build_cfg_path = self.target_build_config_path();
        println!("cargo:rerun-if-changed={}", build_cfg_path.display());
        let build_cfg_str = fs::read_to_string(build_cfg_path).map_err(|x| x.to_string())?;
        let build_cfg: Config = toml::from_str(&build_cfg_str).unwrap();

        let entries = build_cfg.libraries;
        for entry in &entries {
            let lib = entry;

            let mut cc_build = self.create_builder();

            self.add_all_files(lib, &mut cc_build);

            for flag in &lib.flags {
                cc_build.flag(flag);
            }

            if let Some(prefix) = &self.build_prefix {
                cc_build.compile(format!("{}_crypto", prefix.as_str()).as_str());
            } else {
                cc_build.compile(&lib.name);
            }
        }

        println!("cargo:root={}", self.out_dir.display());
        Ok(())
    }
}
