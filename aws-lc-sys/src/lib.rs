// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg_attr(not(clippy), allow(unexpected_cfgs))]
#![cfg_attr(not(clippy), allow(unknown_lints))]

use std::os::raw::{c_char, c_long, c_void};

#[allow(unused_macros)]
macro_rules! use_bindings {
    ($bindings:ident) => {
        mod $bindings;
        pub use $bindings::*;
    };
}

macro_rules! platform_binding {
    ($platform:ident, $platform_crypto:ident, $platform_ssl:ident) => {
        #[cfg(all($platform, not(feature = "ssl"), not(use_bindgen_generated)))]
        use_bindings!($platform_crypto);
        #[cfg(all($platform, feature = "ssl", not(use_bindgen_generated)))]
        use_bindings!($platform_ssl);
    };
}

platform_binding!(
    aarch64_linux_android,
    aarch64_linux_android_crypto,
    aarch64_linux_android_crypto_ssl
);
platform_binding!(
    aarch64_apple_darwin,
    aarch64_apple_darwin_crypto,
    aarch64_apple_darwin_crypto_ssl
);
platform_binding!(
    aarch64_pc_windows_msvc,
    aarch64_pc_windows_msvc_crypto,
    aarch64_pc_windows_msvc_crypto_ssl
);
platform_binding!(
    aarch64_unknown_linux_gnu,
    aarch64_unknown_linux_gnu_crypto,
    aarch64_unknown_linux_gnu_crypto_ssl
);
platform_binding!(
    aarch64_unknown_linux_musl,
    aarch64_unknown_linux_musl_crypto,
    aarch64_unknown_linux_musl_crypto_ssl
);
platform_binding!(
    i686_pc_windows_msvc,
    i686_pc_windows_msvc_crypto,
    i686_pc_windows_msvc_crypto_ssl
);
platform_binding!(
    i686_unknown_linux_gnu,
    i686_unknown_linux_gnu_crypto,
    i686_unknown_linux_gnu_crypto_ssl
);
platform_binding!(
    riscv64gc_unknown_linux_gnu,
    riscv64gc_unknown_linux_gnu_crypto,
    riscv64gc_unknown_linux_gnu_crypto_ssl
);
platform_binding!(
    x86_64_apple_darwin,
    x86_64_apple_darwin_crypto,
    x86_64_apple_darwin_crypto_ssl
);
platform_binding!(
    x86_64_pc_windows_gnu,
    x86_64_pc_windows_gnu_crypto,
    x86_64_pc_windows_gnu_crypto_ssl
);
platform_binding!(
    x86_64_pc_windows_msvc,
    x86_64_pc_windows_msvc_crypto,
    x86_64_pc_windows_msvc_crypto_ssl
);
platform_binding!(
    x86_64_unknown_linux_gnu,
    x86_64_unknown_linux_gnu_crypto,
    x86_64_unknown_linux_gnu_crypto_ssl
);
platform_binding!(
    x86_64_unknown_linux_musl,
    x86_64_unknown_linux_musl_crypto,
    x86_64_unknown_linux_musl_crypto_ssl
);

#[cfg(use_bindgen_generated)]
#[allow(
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
    unused_imports
)]
mod generated {

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
#[cfg(use_bindgen_generated)]
pub use generated::*;

#[allow(non_snake_case)]
#[must_use]
pub fn ERR_GET_LIB(packed_error: u32) -> i32 {
    unsafe { ERR_GET_LIB_RUST(packed_error) }
}

#[allow(non_snake_case)]
#[must_use]
pub fn ERR_GET_REASON(packed_error: u32) -> i32 {
    unsafe { ERR_GET_REASON_RUST(packed_error) }
}

#[allow(non_snake_case)]
#[must_use]
pub fn ERR_GET_FUNC(packed_error: u32) -> i32 {
    unsafe { ERR_GET_FUNC_RUST(packed_error) }
}

#[allow(non_snake_case, clippy::not_unsafe_ptr_arg_deref)]
pub fn BIO_get_mem_data(b: *mut BIO, pp: *mut *mut c_char) -> c_long {
    unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, pp.cast::<c_void>()) }
}

pub fn init() {
    unsafe { CRYPTO_library_init() }
}
