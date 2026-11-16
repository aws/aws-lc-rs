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

const ALLOWED_HEADERS: [&str; 31] = [
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
    "sshkdf.h",
];

// Excluded from universal bindings: platform-dependent parameter types or
// architecture-specific, and unused by aws-lc-rs.
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

// The public types in the blocked functions' signatures, which differ across
// libcs. They are also made opaque: bindgen still traces blocklisted items,
// including the blocked functions, and would otherwise emit each libc's FILE
// and va_list internals, but it does not trace into opaque types.
const BLOCKED_TYPES: [&str; 3] = ["FILE", "tm", "va_list"];

// printf formats expanded from the platform's PRIu64/PRIx64, which differ even
// among 64-bit targets ("%lu" on Linux, "%llu" on Darwin and Windows). BN_ULONG
// and BN_BITS2 also follow the word width, but they agree across the 64-bit
// targets and BN_ULONG is referenced by BIGNUM, BN_MONT_CTX, and the BN_*_word
// functions, so they stay.
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
        builder = builder.blocklist_type(tipe).opaque_type(tipe);
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
    use crate::strip_binding_link_prefixes;
    use std::collections::BTreeSet;

    const OPENSSL_HEADER: &str = r"
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

    // Condensed from each libc's headers, keeping the typedef and field chains
    // that the blocked functions reach through FILE, va_list, and struct tm.
    const GLIBC: &str = r"
typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;
typedef long __off_t;
typedef long __off64_t;
struct _IO_marker;
struct _IO_codecvt;
struct _IO_wide_data;
typedef void _IO_lock_t;
struct _IO_FILE {
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  __off_t _old_offset;
  _IO_lock_t *_lock;
  __off64_t _offset;
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
};
typedef struct _IO_FILE FILE;
struct tm { int tm_sec; long tm_gmtoff; const char *tm_zone; };
";
    const DARWIN: &str = r"
typedef __builtin_va_list __darwin_va_list;
typedef __darwin_va_list va_list;
typedef long long __int64_t;
typedef __int64_t __darwin_off_t;
typedef __darwin_off_t fpos_t;
struct __sbuf { unsigned char *_base; int _size; };
struct __sFILEX;
typedef struct __sFILE {
  struct __sbuf _bf;
  fpos_t (*_seek)(void *, fpos_t, int);
  struct __sFILEX *_extra;
  fpos_t _offset;
} FILE;
struct tm { int tm_sec; long tm_gmtoff; char *tm_zone; };
";
    const FREEBSD: &str = r"
typedef long long __int64_t;
typedef __int64_t __intptr_t;
typedef __int64_t __off_t;
typedef __off_t fpos_t;
typedef __builtin_va_list __va_list;
typedef union {
  char __mbstate8[128];
  __int64_t _mbstateL;
  __intptr_t _mbstateP;
} __mbstate_t;
struct __sbuf { unsigned char *_base; int _size; };
struct __sFILEX;
struct __sFILE {
  struct __sbuf _bf;
  fpos_t (*_seek)(void *, fpos_t, int);
  struct __sFILEX *_extra;
  __mbstate_t _mbstate;
};
typedef struct __sFILE FILE;
struct tm { int tm_sec; long tm_gmtoff; const char *tm_zone; };
";
    const MSVC: &str = r"
typedef char *va_list;
typedef struct _iobuf { void *_Placeholder; } FILE;
struct tm { int tm_sec; int tm_isdst; };
";

    // FreeBSD 14's stdio.h declares va_list as __va_list; 15.0 switched to
    // __builtin_va_list.
    const LIBC_HEADERS: [(&str, &[&str]); 5] = [
        ("glibc", &[GLIBC]),
        ("darwin", &[DARWIN]),
        ("freebsd14", &[FREEBSD, "typedef __va_list va_list;\n"]),
        (
            "freebsd15",
            &[FREEBSD, "typedef __builtin_va_list va_list;\n"],
        ),
        ("msvc", &[MSVC]),
    ];

    const TARGETS: [&str; 5] = [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "i686-pc-windows-msvc",
    ];

    fn generate_test_bindings(
        all_bindings: bool,
        target: &str,
        prefix: Option<&str>,
        libc_header: &[&str],
    ) -> String {
        let header = OPENSSL_HEADER.replace(
            "PREFIX_",
            &prefix.map_or_else(String::new, |p| format!("{p}_")),
        );
        let mut builder = bindgen::Builder::default()
            .header_contents("test/openssl/mem.h", &header)
            // bindgen passes every header after the first to clang via
            // -include, so the libc types are declared ahead of mem.h, and, as
            // with real system headers, they are reached only through the
            // declarations that use them.
            .header_contents("test/libc.h", &libc_header.concat())
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

    // Names declared as `pub <kind> <name>` or `pub static mut <name>`,
    // matched on whole identifier tokens so `FILE` is not `_IO_FILE` and a
    // `*mut tm` parameter is not `tm`. Skips `pub const fn` helper methods.
    fn declared_items(bindings: &str) -> BTreeSet<&str> {
        let tokens: Vec<&str> = bindings
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|token| !token.is_empty())
            .collect();
        let mut items = BTreeSet::new();
        for (i, token) in tokens.iter().enumerate() {
            if *token != "pub" {
                continue;
            }
            match &tokens[i + 1..] {
                ["static", "mut", name, ..]
                | ["fn" | "type" | "struct" | "union" | "enum" | "const", name, ..]
                    if *name != "fn" =>
                {
                    items.insert(*name);
                }
                _ => {}
            }
        }
        items
    }

    #[test]
    fn test_declared_items() {
        let bindings = r#"pub type FILE = _IO_FILE; pub struct _IO_FILE { pub _flags : c_int }
# [link_name = "tm_alias"] pub fn CBS_parse_utc_time (time : * mut tm) ; pub const BN_DEC_FMT1 : u32 = 1 ;
pub static mut OPENSSL_ia32cap_P: [u32; 4]; pub union __mbstate_t { pub _mbstateL : i64 }
impl < T > __BindgenUnionField < T > { pub const fn new () -> Self { } }
"#;
        assert_eq!(
            declared_items(bindings),
            BTreeSet::from([
                "BN_DEC_FMT1",
                "CBS_parse_utc_time",
                "FILE",
                "OPENSSL_ia32cap_P",
                "_IO_FILE",
                "__mbstate_t",
            ])
        );
    }

    #[test]
    fn test_universal_bindings_exclude_platform_specific_items() {
        for (libc, libc_header) in LIBC_HEADERS {
            for prefix in [None, Some("aws_lc_0_45_0")] {
                // Mirror generate_src_bindings: link-name decoration is the one
                // remaining target-dependent output, and main.rs normalizes it.
                let bindings: Vec<String> = TARGETS
                    .iter()
                    .map(|target| {
                        strip_binding_link_prefixes(&generate_test_bindings(
                            false,
                            target,
                            prefix,
                            libc_header,
                        ))
                    })
                    .collect();
                // An exact set, so a leaked libc type fails here whether or not
                // anything names it.
                for (target, bindings) in TARGETS.iter().zip(&bindings) {
                    assert_eq!(
                        declared_items(bindings),
                        BTreeSet::from(["SHA256"]),
                        "{libc} {target}: {bindings}"
                    );
                }
                // One universal_crypto.rs serves every target, so the output
                // must not depend on the generation target.
                for (target, other) in TARGETS.iter().zip(&bindings).skip(1) {
                    assert_eq!(
                        other, &bindings[0],
                        "{libc}: {target} differs from {}",
                        TARGETS[0]
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_bindings_retain_platform_specific_items() {
        for (libc, libc_header) in LIBC_HEADERS {
            for target in TARGETS {
                for prefix in [None, Some("aws_lc_0_45_0")] {
                    let bindings = generate_test_bindings(true, target, prefix, libc_header);
                    let declared = declared_items(&bindings);
                    for name in BLOCKED_FUNCTIONS
                        .iter()
                        .chain(&BLOCKED_TYPES)
                        .chain(&BLOCKED_CONSTANTS)
                        .chain(&["SHA256"])
                    {
                        assert!(
                            declared.contains(name),
                            "{libc} {target}: missing {name}: {bindings}"
                        );
                    }
                }
            }
        }
    }
}
