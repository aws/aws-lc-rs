// SPDX-License-Identifier: Apache-2.0 OR ISC
// Modifications Copyright Amazon.com, Inc. or its affiliates. See GitHub history for details.

use crate::{
    get_aws_lc_include_path, get_aws_lc_sys_includes_path, get_generated_include_path,
    get_rust_include_path,
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

#[cfg(feature = "bindgen")]
impl ParseCallbacks for StripPrefixCallback {
    fn generated_name_override(&self, item_info: ItemInfo<'_>) -> Option<String> {
        self.remove_prefix.as_ref().and_then(|s| {
            let prefix = format!("{}_", s);
            item_info
                .name
                .strip_prefix(prefix.as_str())
                .map(String::from)
        })
    }
}

fn prepare_clang_args(manifest_dir: &Path, build_prefix: &Option<&str>) -> Vec<String> {
    let mut clang_args: Vec<String> = vec![
        "-I".to_string(),
        get_rust_include_path(manifest_dir).display().to_string(),
        "-I".to_string(),
        get_aws_lc_include_path(manifest_dir).display().to_string(),
    ];

    if let Some(include_path) = get_aws_lc_sys_includes_path() {
        clang_args.push("-I".to_string());
        clang_args.push(include_path.display().to_string());
    }

    if let Some(prefix) = build_prefix {
        clang_args.push(format!("-DBORINGSSL_PREFIX={}", prefix));
        clang_args.push("-I".to_string());
        clang_args.push(
            get_generated_include_path(manifest_dir)
                .display()
                .to_string(),
        );
    }

    clang_args
}

const COPYRIGHT: &str = r#"
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
"#;

const PRELUDE: &str = r#"
#![allow(
    unused_imports,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    improper_ctypes,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::default_trait_access,
    clippy::must_use_candidate,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::ptr_as_ptr,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::used_underscore_binding,
    clippy::useless_transmute
)]
"#;

#[derive(Default)]
pub(crate) struct BindingOptions<'a> {
    pub build_prefix: Option<&'a str>,
    pub include_ssl: bool,
    pub disable_prelude: bool,
}

fn prepare_bindings_builder(manifest_dir: &Path, options: BindingOptions<'_>) -> bindgen::Builder {
    let clang_args = prepare_clang_args(manifest_dir, &options.build_prefix);

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(".*/openssl/[^/]+\\.h")
        .allowlist_file(".*/rust_wrapper\\.h")
        .rustified_enum("point_conversion_form_t")
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .rustfmt_bindings(true)
        .clang_args(clang_args)
        .raw_line(COPYRIGHT)
        .header(
            get_rust_include_path(manifest_dir)
                .join("rust_wrapper.h")
                .display()
                .to_string(),
        );

    if !options.disable_prelude {
        builder = builder.raw_line(PRELUDE);
    }

    if options.include_ssl {
        builder = builder.clang_arg("-DAWS_LC_RUST_INCLUDE_SSL");
    }

    if let Some(ps) = &options.build_prefix {
        builder = builder.parse_callbacks(Box::new(StripPrefixCallback::new(ps)));
    }

    builder
}

pub(crate) fn generate_bindings(
    manifest_dir: &Path,
    options: BindingOptions<'_>,
) -> Result<bindgen::Bindings, &'static str> {
    let bindings = prepare_bindings_builder(&manifest_dir, options)
        .generate()
        .expect("Unable to generate bindings.");
    Ok(bindings)
}
