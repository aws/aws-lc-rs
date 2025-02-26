// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// NOTE: This module is intended to produce an equivalent "libcrypto" static library to the one
// produced by the CMake. Changes to CMake relating to compiler checks and/or special build flags
// may require modifications to the logic in this module.

mod aarch64_apple_darwin;
mod aarch64_unknown_linux_gnu;
mod aarch64_unknown_linux_musl;
mod i686_unknown_linux_gnu;
mod riscv64gc_unknown_linux_gnu;
mod x86_64_apple_darwin;
mod x86_64_unknown_linux_gnu;
mod x86_64_unknown_linux_musl;

use crate::{
    cargo_env, effective_target, emit_warning, env_var_to_bool, execute_command, get_crate_cflags,
    is_no_asm, optional_env_optional_crate_target, out_dir, requested_c_std, set_env_for_target,
    target, target_arch, target_env, target_os, CStdRequested, OutputLibType,
};
use std::path::PathBuf;

const AWS_LC_RS_UNNEEDED_SRC: [&str; 177] = [
    "crypto/asn1/a_bitstr.c",
    "crypto/asn1/a_bool.c",
    "crypto/asn1/a_d2i_fp.c",
    "crypto/asn1/a_dup.c",
    "crypto/asn1/a_gentm.c",
    "crypto/asn1/a_i2d_fp.c",
    "crypto/asn1/a_int.c",
    "crypto/asn1/a_mbstr.c",
    "crypto/asn1/a_object.c",
    "crypto/asn1/a_octet.c",
    "crypto/asn1/a_strex.c",
    "crypto/asn1/a_strnid.c",
    "crypto/asn1/a_time.c",
    "crypto/asn1/a_type.c",
    "crypto/asn1/a_utctm.c",
    "crypto/asn1/a_utf8.c",
    "crypto/asn1/asn1_lib.c",
    "crypto/asn1/asn1_par.c",
    "crypto/asn1/asn_pack.c",
    "crypto/asn1/f_int.c",
    "crypto/asn1/f_string.c",
    "crypto/asn1/posix_time.c",
    "crypto/asn1/tasn_dec.c",
    "crypto/asn1/tasn_enc.c",
    "crypto/asn1/tasn_fre.c",
    "crypto/asn1/tasn_new.c",
    "crypto/asn1/tasn_typ.c",
    "crypto/asn1/tasn_utl.c",
    "crypto/base64/base64.c",
    "crypto/bio/bio.c",
    "crypto/bio/bio_mem.c",
    "crypto/bio/connect.c",
    "crypto/bio/errno.c",
    "crypto/bio/fd.c",
    "crypto/bio/file.c",
    "crypto/bio/hexdump.c",
    "crypto/bio/pair.c",
    "crypto/bio/printf.c",
    "crypto/bio/socket.c",
    "crypto/bio/socket_helper.c",
    "crypto/blake2/blake2.c",
    "crypto/buf/buf.c",
    "crypto/bytestring/ber.c",
    "crypto/bytestring/unicode.c",
    "crypto/cipher_extra/cipher_extra.c",
    "crypto/cipher_extra/derive_key.c",
    "crypto/cipher_extra/e_aes_cbc_hmac_sha1.c",
    "crypto/cipher_extra/e_aes_cbc_hmac_sha256.c",
    "crypto/cipher_extra/e_aesctrhmac.c",
    "crypto/cipher_extra/e_des.c",
    "crypto/cipher_extra/e_null.c",
    "crypto/cipher_extra/e_rc2.c",
    "crypto/cipher_extra/e_rc4.c",
    "crypto/cipher_extra/e_tls.c",
    "crypto/cipher_extra/tls_cbc.c",
    "crypto/conf/conf.c",
    "crypto/decrepit/bio/base64_bio.c",
    "crypto/decrepit/blowfish/blowfish.c",
    "crypto/decrepit/cast/cast.c",
    "crypto/decrepit/cast/cast_tables.c",
    "crypto/decrepit/dh/dh_decrepit.c",
    "crypto/decrepit/evp/evp_do_all.c",
    "crypto/decrepit/obj/obj_decrepit.c",
    "crypto/decrepit/rsa/rsa_decrepit.c",
    "crypto/decrepit/x509/x509_decrepit.c",
    "crypto/des/des.c",
    "crypto/ec_extra/ec_derive.c",
    "crypto/ec_extra/hash_to_curve.c",
    "crypto/ecdh_extra/ecdh_extra.c",
    "crypto/evp_extra/print.c",
    "crypto/evp_extra/scrypt.c",
    "crypto/evp_extra/sign.c",
    "crypto/hpke/hpke.c",
    "crypto/hrss/hrss.c",
    "crypto/obj/obj_xref.c",
    "crypto/ocsp/ocsp_asn.c",
    "crypto/ocsp/ocsp_client.c",
    "crypto/ocsp/ocsp_extension.c",
    "crypto/ocsp/ocsp_http.c",
    "crypto/ocsp/ocsp_lib.c",
    "crypto/ocsp/ocsp_print.c",
    "crypto/ocsp/ocsp_server.c",
    "crypto/ocsp/ocsp_verify.c",
    "crypto/pem/pem_all.c",
    "crypto/pem/pem_info.c",
    "crypto/pem/pem_lib.c",
    "crypto/pem/pem_oth.c",
    "crypto/pem/pem_pk8.c",
    "crypto/pem/pem_pkey.c",
    "crypto/pem/pem_x509.c",
    "crypto/pem/pem_xaux.c",
    "crypto/pkcs7/bio/cipher.c",
    "crypto/pkcs7/bio/md.c",
    "crypto/pkcs7/pkcs7.c",
    "crypto/pkcs7/pkcs7_asn1.c",
    "crypto/pkcs7/pkcs7_x509.c",
    "crypto/pkcs8/p5_pbev2.c",
    "crypto/pkcs8/pkcs8.c",
    "crypto/pkcs8/pkcs8_x509.c",
    "crypto/pool/pool.c",
    "crypto/rc4/rc4.c",
    "crypto/rsa_extra/rsa_print.c",
    "crypto/siphash/siphash.c",
    "crypto/spake25519/spake25519.c",
    "crypto/trust_token/pmbtoken.c",
    "crypto/trust_token/trust_token.c",
    "crypto/trust_token/voprf.c",
    "crypto/x509/a_digest.c",
    "crypto/x509/a_sign.c",
    "crypto/x509/a_verify.c",
    "crypto/x509/algorithm.c",
    "crypto/x509/asn1_gen.c",
    "crypto/x509/by_dir.c",
    "crypto/x509/by_file.c",
    "crypto/x509/i2d_pr.c",
    "crypto/x509/name_print.c",
    "crypto/x509/policy.c",
    "crypto/x509/rsa_pss.c",
    "crypto/x509/t_crl.c",
    "crypto/x509/t_req.c",
    "crypto/x509/t_x509.c",
    "crypto/x509/t_x509a.c",
    "crypto/x509/v3_akey.c",
    "crypto/x509/v3_akeya.c",
    "crypto/x509/v3_alt.c",
    "crypto/x509/v3_bcons.c",
    "crypto/x509/v3_bitst.c",
    "crypto/x509/v3_conf.c",
    "crypto/x509/v3_cpols.c",
    "crypto/x509/v3_crld.c",
    "crypto/x509/v3_enum.c",
    "crypto/x509/v3_extku.c",
    "crypto/x509/v3_genn.c",
    "crypto/x509/v3_ia5.c",
    "crypto/x509/v3_info.c",
    "crypto/x509/v3_int.c",
    "crypto/x509/v3_lib.c",
    "crypto/x509/v3_ncons.c",
    "crypto/x509/v3_ocsp.c",
    "crypto/x509/v3_pcons.c",
    "crypto/x509/v3_pmaps.c",
    "crypto/x509/v3_prn.c",
    "crypto/x509/v3_purp.c",
    "crypto/x509/v3_skey.c",
    "crypto/x509/v3_utl.c",
    "crypto/x509/x509.c",
    "crypto/x509/x509_att.c",
    "crypto/x509/x509_cmp.c",
    "crypto/x509/x509_d2.c",
    "crypto/x509/x509_def.c",
    "crypto/x509/x509_ext.c",
    "crypto/x509/x509_lu.c",
    "crypto/x509/x509_obj.c",
    "crypto/x509/x509_req.c",
    "crypto/x509/x509_set.c",
    "crypto/x509/x509_trs.c",
    "crypto/x509/x509_txt.c",
    "crypto/x509/x509_v3.c",
    "crypto/x509/x509_vfy.c",
    "crypto/x509/x509_vpm.c",
    "crypto/x509/x509cset.c",
    "crypto/x509/x509name.c",
    "crypto/x509/x509rset.c",
    "crypto/x509/x509spki.c",
    "crypto/x509/x_algor.c",
    "crypto/x509/x_all.c",
    "crypto/x509/x_attrib.c",
    "crypto/x509/x_crl.c",
    "crypto/x509/x_exten.c",
    "crypto/x509/x_name.c",
    "crypto/x509/x_pubkey.c",
    "crypto/x509/x_req.c",
    "crypto/x509/x_sig.c",
    "crypto/x509/x_spki.c",
    "crypto/x509/x_val.c",
    "crypto/x509/x_x509.c",
    "crypto/x509/x_x509a.c",
];

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use std::collections::HashSet;
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
    riscv64gc_unknown_linux_gnu,
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
            PlatformConfig::riscv64gc_unknown_linux_gnu => {
                riscv64gc_unknown_linux_gnu::CRYPTO_LIBRARY
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
            "riscv64gc-unknown-linux-gnu" => Some(PlatformConfig::riscv64gc_unknown_linux_gnu),
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
        Self::default_for(&effective_target()).unwrap()
    }
}

#[allow(clippy::upper_case_acronyms)]
pub(crate) enum BuildOption {
    STD(String),
    FLAG(String),
    DEFINE(String, String),
    INCLUDE(PathBuf),
}
impl BuildOption {
    fn std<T: ToString + ?Sized>(val: &T) -> Self {
        Self::STD(val.to_string())
    }
    fn flag<T: ToString + ?Sized>(val: &T) -> Self {
        Self::FLAG(val.to_string())
    }
    fn flag_if_supported<T: ToString + ?Sized>(cc_build: &cc::Build, flag: &T) -> Option<Self> {
        if let Ok(true) = cc_build.is_flag_supported(flag.to_string()) {
            Some(Self::FLAG(flag.to_string()))
        } else {
            None
        }
    }

    fn define<K: ToString + ?Sized, V: ToString + ?Sized>(key: &K, val: &V) -> Self {
        Self::DEFINE(key.to_string(), val.to_string())
    }

    fn include<P: Into<PathBuf>>(path: P) -> Self {
        Self::INCLUDE(path.into())
    }

    fn apply_cc<'a>(&self, cc_build: &'a mut cc::Build) -> &'a mut cc::Build {
        match self {
            BuildOption::STD(val) => cc_build.std(val),
            BuildOption::FLAG(val) => cc_build.flag(val),
            BuildOption::DEFINE(key, val) => cc_build.define(key, Some(val.as_str())),
            BuildOption::INCLUDE(path) => cc_build.include(path.as_path()),
        }
    }

    pub(crate) fn apply_cmake<'a>(
        &self,
        cmake_cfg: &'a mut cmake::Config,
        is_like_msvc: bool,
    ) -> &'a mut cmake::Config {
        if is_like_msvc {
            match self {
                BuildOption::STD(val) => cmake_cfg.define(
                    "CMAKE_C_STANDARD",
                    val.to_ascii_lowercase().strip_prefix('c').unwrap_or("11"),
                ),
                BuildOption::FLAG(val) => cmake_cfg.cflag(val),
                BuildOption::DEFINE(key, val) => cmake_cfg.cflag(format!("/D{key}={val}")),
                BuildOption::INCLUDE(path) => cmake_cfg.cflag(format!("/I{}", path.display())),
            }
        } else {
            match self {
                BuildOption::STD(val) => cmake_cfg.define(
                    "CMAKE_C_STANDARD",
                    val.to_ascii_lowercase().strip_prefix('c').unwrap_or("11"),
                ),
                BuildOption::FLAG(val) => cmake_cfg.cflag(val),
                BuildOption::DEFINE(key, val) => cmake_cfg.cflag(format!("-D{key}={val}")),
                BuildOption::INCLUDE(path) => cmake_cfg.cflag(format!("-I{}", path.display())),
            }
        }
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

    pub(crate) fn collect_universal_build_options(
        &self,
        cc_build: &cc::Build,
    ) -> (bool, Vec<BuildOption>) {
        let mut build_options: Vec<BuildOption> = Vec::new();

        let compiler_is_msvc = {
            let compiler = cc_build.get_compiler();
            !compiler.is_like_gnu() && !compiler.is_like_clang()
        };

        match requested_c_std() {
            CStdRequested::C99 => {
                build_options.push(BuildOption::std("c99"));
            }
            CStdRequested::C11 => {
                build_options.push(BuildOption::std("c11"));
            }
            CStdRequested::None => {
                if self.compiler_check("c11") {
                    build_options.push(BuildOption::std("c11"));
                } else {
                    build_options.push(BuildOption::std("c99"));
                }
            }
        }

        if let Some(cc) = optional_env_optional_crate_target("CC") {
            set_env_for_target("CC", &cc);
        }
        if let Some(cxx) = optional_env_optional_crate_target("CXX") {
            set_env_for_target("CXX", &cxx);
        }

        if target_arch() == "x86" && !compiler_is_msvc {
            if let Some(option) = BuildOption::flag_if_supported(cc_build, "-msse2") {
                build_options.push(option);
            }
        }

        let opt_level = cargo_env("OPT_LEVEL");
        match opt_level.as_str() {
            "0" | "1" | "2" => {
                if is_no_asm() {
                    emit_warning("AWS_LC_SYS_NO_ASM found. Disabling assembly code usage.");
                    build_options.push(BuildOption::define("OPENSSL_NO_ASM", "1"));
                }
            }
            _ => {
                assert!(
                    !is_no_asm(),
                    "AWS_LC_SYS_NO_ASM only allowed for debug builds!"
                );
                if !compiler_is_msvc {
                    let flag = format!("-ffile-prefix-map={}=", self.manifest_dir.display());
                    if let Ok(true) = cc_build.is_flag_supported(&flag) {
                        emit_warning(&format!("Using flag: {}", &flag));
                        build_options.push(BuildOption::flag(&flag));
                    } else {
                        emit_warning("NOTICE: Build environment source paths might be visible in release binary.");
                        let flag = format!("-fdebug-prefix-map={}=", self.manifest_dir.display());
                        if let Ok(true) = cc_build.is_flag_supported(&flag) {
                            emit_warning(&format!("Using flag: {}", &flag));
                            build_options.push(BuildOption::flag(&flag));
                        }
                    }
                }
            }
        }

        if target_os() == "macos" {
            // This compiler error has only been seen on MacOS x86_64:
            // ```
            // clang: error: overriding '-mmacosx-version-min=13.7' option with '--target=x86_64-apple-macosx14.2' [-Werror,-Woverriding-t-option]
            // ```
            if let Some(option) =
                BuildOption::flag_if_supported(cc_build, "-Wno-overriding-t-option")
            {
                build_options.push(option);
            }
            if let Some(option) = BuildOption::flag_if_supported(cc_build, "-Wno-overriding-option")
            {
                build_options.push(option);
            }
        }
        (compiler_is_msvc, build_options)
    }

    pub fn collect_cc_only_build_options(&self, cc_build: &cc::Build) -> Vec<BuildOption> {
        let mut build_options: Vec<BuildOption> = Vec::new();
        let is_like_msvc = {
            let compiler = cc_build.get_compiler();
            !compiler.is_like_gnu() && !compiler.is_like_clang()
        };
        if !is_like_msvc {
            build_options.push(BuildOption::flag("-Wno-unused-parameter"));
            if target_os() == "linux"
                || target_os().ends_with("bsd")
                || target_env() == "gnu"
                || target_env() == "musl"
            {
                build_options.push(BuildOption::define("_XOPEN_SOURCE", "700"));
                build_options.push(BuildOption::flag("-pthread"));
            }
        }

        self.add_includes(&mut build_options);

        build_options
    }

    fn add_includes(&self, build_options: &mut Vec<BuildOption>) {
        // The order of includes matters
        if let Some(prefix) = &self.build_prefix {
            build_options.push(BuildOption::define("BORINGSSL_IMPLEMENTATION", "1"));
            build_options.push(BuildOption::define("BORINGSSL_PREFIX", prefix.as_str()));
            build_options.push(BuildOption::include(
                self.manifest_dir.join("generated-include"),
            ));
        }
        build_options.push(BuildOption::include(self.manifest_dir.join("include")));
        build_options.push(BuildOption::include(
            self.manifest_dir.join("aws-lc").join("include"),
        ));
        build_options.push(BuildOption::include(
            self.manifest_dir
                .join("aws-lc")
                .join("third_party")
                .join("s2n-bignum")
                .join("include"),
        ));
        build_options.push(BuildOption::include(
            self.manifest_dir
                .join("aws-lc")
                .join("third_party")
                .join("s2n-bignum")
                .join("s2n-bignum-imported")
                .join("include"),
        ));
        build_options.push(BuildOption::include(
            self.manifest_dir
                .join("aws-lc")
                .join("third_party")
                .join("jitterentropy")
                .join("jitterentropy-library"),
        ));
    }

    pub fn create_builder(&self) -> cc::Build {
        let mut cc_build = cc::Build::new();
        let build_options = self.collect_cc_only_build_options(&cc_build);
        for option in build_options {
            option.apply_cc(&mut cc_build);
        }
        cc_build
    }

    pub fn prepare_builder(&self) -> cc::Build {
        let mut cc_build = self.create_builder();
        let (_, build_options) = self.collect_universal_build_options(&cc_build);
        for option in build_options {
            option.apply_cc(&mut cc_build);
        }
        let cflags = get_crate_cflags();
        if !cflags.is_empty() {
            set_env_for_target("CFLAGS", cflags);
        }
        cc_build
    }

    fn add_all_files(&self, lib: &Library, cc_build: &mut cc::Build) {
        use core::str::FromStr;

        // s2n_bignum is compiled separately due to needing extra flags
        let mut s2n_bignum_builder = cc_build.clone();
        s2n_bignum_builder.flag(format!(
            "--include={}",
            self.manifest_dir
                .join("generated-include")
                .join("openssl")
                .join("boringssl_prefix_symbols_asm.h")
                .display()
        ));
        s2n_bignum_builder.define("S2N_BN_HIDE_SYMBOLS", "1");

        let aws_lc_rs_unneeded_files = HashSet::from(AWS_LC_RS_UNNEEDED_SRC);
        let feature_aws_lc_rs = cfg!(feature = "aws-lc-rs");
        if feature_aws_lc_rs {
            emit_warning(
                format!(
                    "Feature aws-lc-rs enabled. Ignoring source file: {:?}",
                    AWS_LC_RS_UNNEEDED_SRC
                )
                    .as_str(),
            );
        }
        for source in lib.sources {
            if feature_aws_lc_rs && aws_lc_rs_unneeded_files.contains(source) {
                continue;
            }
            let source_path = self.manifest_dir.join("aws-lc").join(source);
            let is_s2n_bignum = std::path::Path::new(source).starts_with("third_party/s2n-bignum");

            if is_s2n_bignum {
                s2n_bignum_builder.file(source_path);
            } else {
                cc_build.file(source_path);
            }
        }
        let object_files = s2n_bignum_builder.compile_intermediates();
        for object in object_files {
            cc_build.object(object);
        }
        cc_build.file(PathBuf::from_str("rust_wrapper.c").unwrap());
    }

    fn build_library(&self, lib: &Library) {
        let mut cc_build = self.prepare_builder();
        for flag in lib.flags {
            cc_build.flag(flag);
        }
        self.run_compiler_checks(&mut cc_build);

        self.add_all_files(lib, &mut cc_build);
        if let Some(prefix) = &self.build_prefix {
            cc_build.compile(format!("{}_crypto", prefix.as_str()).as_str());
        } else {
            cc_build.compile(lib.name);
        }
    }

    // This performs basic checks of compiler capabilities and sets an appropriate flag on success.
    // This should be kept in alignment with the checks performed by AWS-LC's CMake build.
    // See: https://github.com/search?q=repo%3Aaws%2Faws-lc%20check_compiler&type=code
    fn compiler_check(&self, basename: &str) -> bool {
        let mut ret_val = false;
        let output_dir = self.out_dir.join(format!("out-{basename}"));
        let source_file = self
            .manifest_dir
            .join("aws-lc")
            .join("tests")
            .join("compiler_features_tests")
            .join(format!("{basename}.c"));
        if !source_file.exists() {
            emit_warning("######");
            emit_warning("###### WARNING: MISSING GIT SUBMODULE ######");
            emit_warning(&format!(
                "  -- Did you initialize the repo's git submodules? Unable to find source file: {}.",
                source_file.display()
            ));
            emit_warning("  -- run 'git submodule update --init --recursive' to initialize.");
            emit_warning("######");
            emit_warning("######");
        }
        let mut cc_build = cc::Build::default();
        cc_build
            .file(source_file)
            .warnings_into_errors(true)
            .out_dir(&output_dir);

        let compiler = cc_build.get_compiler();
        if compiler.is_like_gnu() || compiler.is_like_clang() {
            cc_build.flag("-Wno-unused-parameter");
        }
        let result = cc_build.try_compile_intermediates();

        if result.is_ok() {
            ret_val = true;
        }
        if fs::remove_dir_all(&output_dir).is_err() {
            emit_warning(&format!("Failed to remove {}", output_dir.display()));
        }
        emit_warning(&format!(
            "Compilation of '{basename}.c' {} - {:?}.",
            if ret_val { "succeeded" } else { "failed" },
            &result
        ));
        ret_val
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
        if !memcmp_compiler.is_like_clang() && !memcmp_compiler.is_like_gnu() {
            // The logic below assumes a Clang or GCC compiler is in use
            return;
        }
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
            "COMPILER: {}\
            ARGS: {:?}\
            EXECUTED: {}\
            ERROR: {}\
            OUTPUT: {}\
            Failed to compile {basename}
            ",
            memcmp_compiler.path().display(),
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
                "### COMPILER BUG DETECTED ###\nYour compiler ({}) is not supported due to a memcmp related bug reported in \
                https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189. \
                We strongly recommend against using this compiler. \n\
                EXECUTED: {}\n\
                ERROR: {}\n\
                OUTPUT: {}\n\
                ",
                memcmp_compiler.path().display(),
                memcmp_compile_result.executed,
                memcmp_compile_result.stderr,
                memcmp_compile_result.stdout
            );
        }
        let _ = fs::remove_file(exec_path);
    }
    fn run_compiler_checks(&self, cc_build: &mut cc::Build) {
        if self.compiler_check("stdalign_check") {
            cc_build.define("AWS_LC_STDALIGN_AVAILABLE", Some("1"));
        }
        if self.compiler_check("builtin_swap_check") {
            cc_build.define("AWS_LC_BUILTIN_SWAP_SUPPORTED", Some("1"));
        }
        self.memcmp_check();
    }
}

impl crate::Builder for CcBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        if OutputLibType::Dynamic == self.output_lib_type {
            // https://github.com/rust-lang/cc-rs/issues/594
            return Err("CcBuilder only supports static builds".to_string());
        }

        if PlatformConfig::default_for(&effective_target()).is_none() {
            return Err(format!("Platform not supported: {}", effective_target()));
        }

        if Some(true) == env_var_to_bool("CARGO_FEATURE_SSL") {
            return Err("cc_builder for libssl not supported".to_string());
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

    fn name(&self) -> &'static str {
        "CC"
    }
}
