// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{get_rust_include_path, BindingOptions, COPYRIGHT};
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

const PRELUDE: &str = r"
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::default_trait_access,
    clippy::must_use_candidate,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::ptr_as_ptr,
    clippy::pub_underscore_fields,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::used_underscore_binding,
    clippy::useless_transmute,
    dead_code,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports,
)]
";

fn prepare_bindings_builder(manifest_dir: &Path, options: &BindingOptions) -> bindgen::Builder {
    let clang_args = crate::prepare_clang_args(manifest_dir, options);

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(r".*(/|\\)openssl((/|\\)[^/\\]+)+\.h")
        .allowlist_file(r".*(/|\\)rust_wrapper\.h")
        .rustified_enum(r"point_conversion_form_t")
        .rust_target(bindgen::RustTarget::Stable_1_59)
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
    prepare_bindings_builder(manifest_dir, options)
        .generate()
        .expect("Unable to generate bindings.")
}
