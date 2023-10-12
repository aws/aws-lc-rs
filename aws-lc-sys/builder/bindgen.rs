// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{
    get_aws_lc_include_path, get_aws_lc_rand_extra_path, get_aws_lc_sys_includes_path,
    get_generated_include_path, get_rust_include_path, is_private_api_enabled,
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

fn add_header_include_path(args: &mut Vec<String>, path: String) {
    args.push("-I".to_string());
    args.push(path);
}

fn prepare_clang_args(manifest_dir: &Path) -> Vec<String> {
    let mut clang_args: Vec<String> = Vec::new();

    add_header_include_path(
        &mut clang_args,
        get_rust_include_path(manifest_dir).display().to_string(),
    );

    add_header_include_path(
        &mut clang_args,
        get_generated_include_path(manifest_dir)
            .display()
            .to_string(),
    );

    add_header_include_path(
        &mut clang_args,
        get_aws_lc_include_path(manifest_dir).display().to_string(),
    );

    if is_private_api_enabled() {
        clang_args.push("-I".to_string());
        clang_args.push(
            get_aws_lc_rand_extra_path(manifest_dir)
                .display()
                .to_string(),
        );
    }

    if let Some(include_paths) = get_aws_lc_sys_includes_path() {
        for path in include_paths {
            add_header_include_path(&mut clang_args, path.display().to_string());
        }
    }

    clang_args
}

const COPYRIGHT: &str = r"
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
";

const PRELUDE: &str = r"
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
";

#[derive(Default)]
pub(crate) struct BindingOptions<'a> {
    pub build_prefix: &'a str,
    pub include_ssl: bool,
    pub disable_prelude: bool,
}

fn prepare_bindings_builder(manifest_dir: &Path, options: &BindingOptions<'_>) -> bindgen::Builder {
    let clang_args = prepare_clang_args(manifest_dir);

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(r".*(/|\\)openssl(/|\\)[^/\\]+\.h")
        .allowlist_file(r".*(/|\\)rust_wrapper\.h")
        .rustified_enum(r"point_conversion_form_t")
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

    if !options.disable_prelude {
        builder = builder.raw_line(PRELUDE);
    }

    if options.include_ssl {
        builder = builder.clang_arg("-DAWS_LC_RUST_INCLUDE_SSL");
    }

    if is_private_api_enabled() {
        builder = builder
            .clang_arg("-DAWS_LC_RUST_PRIVATE_INTERNALS")
            .allowlist_file(r".*(/|\\)pq_custom_randombytes\.h");
    }

    builder = builder.parse_callbacks(Box::new(StripPrefixCallback::new(options.build_prefix)));

    builder
}

pub(crate) fn generate_bindings(
    manifest_dir: &Path,
    options: &BindingOptions<'_>,
) -> bindgen::Bindings {
    prepare_bindings_builder(manifest_dir, options)
        .generate()
        .expect("Unable to generate bindings.")
}
