// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{
    effective_target, emit_warning, get_rust_include_path, is_all_bindings, BindingOptions,
    EnvGuard, COPYRIGHT, PRELUDE,
};
use bindgen::callbacks::{ItemInfo, ParseCallbacks};
use std::fmt::Debug;
use std::path::Path;

#[derive(Debug)]
struct StripPrefixCallback {
    remove_prefix: Option<String>,
}

impl StripPrefixCallback {
    fn new(prefix: &str) -> StripPrefixCallback {
        StripPrefixCallback {
            remove_prefix: Some(prefix.to_string()),
        }
    }
}

impl ParseCallbacks for StripPrefixCallback {
    fn generated_name_override(&self, item_info: ItemInfo<'_>) -> Option<String> {
        self.remove_prefix.as_ref().and_then(|s| {
            let prefix = format!("{s}_");
            item_info
                .name
                .strip_prefix(prefix.as_str())
                .map(String::from)
        })
    }
}

const ALLOWED_HEADERS: [&str; 30] = [
    "aead.h",
    "aes.h",
    "base.h",
    "bn.h",
    "boringssl_prefix_symbols.h",
    "boringssl_prefix_symbols_asm.h",
    "boringssl_prefix_symbols_nasm.inc",
    "bytestring.h",
    "chacha.h",
    "cipher.h",
    "cmac.h",
    "crypto.h",
    "curve25519.h",
    "digest.h",
    "ec.h",
    "ec_key.h",
    "ecdh.h",
    "ecdsa.h",
    "err.h",
    "evp.h",
    "hkdf.h",
    "hmac.h",
    "is_awslc.h",
    "kdf.h",
    "mem.h",
    "nid.h",
    "poly1305.h",
    "rand.h",
    "rsa.h",
    "sha.h",
];

// Universal bindings exclude functions with platform-dependent parameter types
// and architecture-specific functions not used by aws-lc-rs.
const BLOCKED_FUNCTIONS: [&str; 9] = [
    "BIO_vsnprintf",
    "BN_print_fp",
    "CBS_parse_generalized_time",
    "CBS_parse_utc_time",
    "ERR_print_errors_fp",
    "OPENSSL_vasprintf",
    "RSA_print_fp",
    "armv8_disable_dit",
    "armv8_enable_dit",
];

// Block implementation types as well as their public aliases: bindgen can emit
// dependencies of blocked items even when nothing in the output uses them.
const BLOCKED_TYPES: [&str; 20] = [
    "FILE",
    "fpos_t",
    "tm",
    "va_list",
    "__builtin_va_list",
    "__gnuc_va_list",
    "__darwin_va_list",
    "__va_list_tag",
    "__off_t",
    "__off64_t",
    "__int64_t",
    "__darwin_off_t",
    "_IO_FILE",
    "_IO_marker",
    "_IO_codecvt",
    "_IO_wide_data",
    "_IO_lock_t",
    "__sFILE",
    "__sbuf",
    "__sFILEX",
];

// These printf formats depend on the target's underlying BN_ULONG typedef.
const BLOCKED_CONSTANTS: [&str; 3] = ["BN_DEC_FMT1", "BN_HEX_FMT1", "BN_HEX_FMT2"];

fn configure_binding_scope(mut builder: bindgen::Builder, all_bindings: bool) -> bindgen::Builder {
    if all_bindings {
        return builder.allowlist_file(r".*(/|\\)openssl((/|\\)[^/\\]+)+\.h");
    }

    for header in ALLOWED_HEADERS {
        emit_warning(format!("Allowed header: {header}").as_str());
        builder = builder.allowlist_file(format!("{}{}", r".*(/|\\)openssl(/|\\)", header));
    }
    for function in BLOCKED_FUNCTIONS {
        emit_warning(format!("Blocked function: {function}").as_str());
        builder = builder.blocklist_function(function);
    }
    for tipe in BLOCKED_TYPES {
        emit_warning(format!("Blocked type: {tipe}").as_str());
        builder = builder.blocklist_type(tipe);
    }
    for constant in BLOCKED_CONSTANTS {
        emit_warning(format!("Blocked constant: {constant}").as_str());
        builder = builder.blocklist_var(constant);
    }
    builder
}

fn prepare_bindings_builder(manifest_dir: &Path, options: &BindingOptions) -> bindgen::Builder {
    let clang_args = crate::prepare_clang_args(manifest_dir, options);

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(r".*(/|\\)rust_wrapper\.h")
        .rustified_enum(r"point_conversion_form_t")
        .rust_target(bindgen::RustTarget::stable(70, 0).unwrap())
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .formatter(bindgen::Formatter::Rustfmt)
        .clang_args(clang_args)
        .raw_line(COPYRIGHT)
        .header(
            get_rust_include_path(manifest_dir)
                .join("rust_wrapper.h")
                .display()
                .to_string(),
        );

    builder = configure_binding_scope(builder, is_all_bindings());

    if !options.disable_prelude {
        builder = builder.raw_line(PRELUDE);
    }

    if options.include_ssl {
        builder = builder.clang_arg("-DAWS_LC_RUST_INCLUDE_SSL");
    }
    if let Some(prefix) = &options.build_prefix {
        let callbacks = StripPrefixCallback::new(prefix.as_str());
        builder = builder.parse_callbacks(Box::new(callbacks));
    }

    builder
}

pub(crate) fn generate_bindings(
    manifest_dir: &Path,
    options: &BindingOptions,
) -> bindgen::Bindings {
    let _guard_target = EnvGuard::new("TARGET", effective_target());
    prepare_bindings_builder(manifest_dir, options)
        .generate()
        .expect("Unable to generate bindings.")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = r"
typedef __builtin_va_list va_list;
typedef va_list __gnuc_va_list;
typedef va_list __darwin_va_list;
typedef long __off_t;
typedef long __off64_t;
typedef long long __int64_t;
typedef __int64_t __darwin_off_t;
struct _IO_FILE;
typedef struct _IO_FILE FILE;
struct _IO_marker;
struct _IO_codecvt;
struct _IO_wide_data;
typedef void _IO_lock_t;
struct __sFILE;
struct __sbuf;
struct __sFILEX;
typedef long fpos_t;
struct tm;
#define BN_DEC_FMT1 1
#define BN_HEX_FMT1 2
#define BN_HEX_FMT2 3
void PREFIX_BIO_vsnprintf(va_list args);
void PREFIX_BN_print_fp(FILE *file);
void PREFIX_CBS_parse_generalized_time(struct tm *time);
void PREFIX_CBS_parse_utc_time(struct tm *time);
void PREFIX_ERR_print_errors_fp(FILE *file);
void PREFIX_OPENSSL_vasprintf(va_list args);
void PREFIX_RSA_print_fp(FILE *file);
void PREFIX_armv8_disable_dit(void);
void PREFIX_armv8_enable_dit(void);
void PREFIX_SHA256(void);
";

    const TARGETS: [&str; 5] = [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "i686-pc-windows-msvc",
    ];

    fn generate_test_bindings(all_bindings: bool, target: &str, prefix: Option<&str>) -> String {
        let header = HEADER.replace(
            "PREFIX_",
            &prefix.map_or_else(String::new, |p| format!("{p}_")),
        );
        let mut builder = bindgen::Builder::default()
            .header_contents("test/openssl/mem.h", &header)
            .clang_arg(format!("--target={target}"))
            .clang_arg("-nostdinc")
            .detect_include_paths(false)
            .layout_tests(false)
            .formatter(bindgen::Formatter::None);
        if let Some(prefix) = prefix {
            builder = builder.parse_callbacks(Box::new(StripPrefixCallback::new(prefix)));
        }
        configure_binding_scope(builder, all_bindings)
            .generate()
            .expect("generate fixture bindings")
            .to_string()
    }

    #[test]
    fn test_universal_bindings_exclude_platform_specific_items() {
        for target in TARGETS {
            for prefix in [None, Some("aws_lc_0_45_0")] {
                let bindings = generate_test_bindings(false, target, prefix);
                assert!(bindings.contains("pub fn SHA256"), "{target}: {bindings}");
                for name in BLOCKED_FUNCTIONS
                    .iter()
                    .chain(&BLOCKED_TYPES)
                    .chain(&BLOCKED_CONSTANTS)
                {
                    assert!(
                        !bindings.contains(name),
                        "{target}: unexpected {name}: {bindings}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_bindings_retain_platform_specific_items() {
        for target in TARGETS {
            for prefix in [None, Some("aws_lc_0_45_0")] {
                let bindings = generate_test_bindings(true, target, prefix);
                assert!(bindings.contains("pub fn SHA256"), "{target}: {bindings}");
                for name in BLOCKED_FUNCTIONS.iter().chain(&BLOCKED_CONSTANTS) {
                    assert!(
                        bindings.contains(name),
                        "{target}: missing {name}: {bindings}"
                    );
                }
                assert!(
                    bindings.contains("pub type va_list"),
                    "{target}: {bindings}"
                );
                assert!(bindings.contains("pub type FILE"), "{target}: {bindings}");
            }
        }
    }
}
