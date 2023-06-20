// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! A [*ring*](https://github.com/briansmith/ring)-compatible crypto library using the cryptographic
//! operations provided by [*AWS-LC*](https://github.com/awslabs/aws-lc). It uses either the
//! auto-generated [*aws-lc-sys*](https://crates.io/crates/aws-lc-sys) or [*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys)
//! Foreign Function Interface (FFI) crates found in this repository for invoking *AWS-LC*.
//!
//! # Build
//!
//! `aws-lc-rs` is available through [crates.io](https://crates.io/crates/aws-lc-rs). It can
//! be added to your project in the [standard way](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
//! using `Cargo.toml`:
//! ```toml
//! [dependencies]
//! aws-lc-rs = "1.0.0"
//! ```
//! Consuming projects will need a C Compiler (Clang or GCC) and Cmake to build.
//!
//! **Requirements**:
//! * C compiler (Clang or GCC or Visual Studio Build Tools 2017)
//! * Cmake (>= v3.12)
//! * Linux or [macOS](https://www.apple.com/macos) or Windows
//!
//! **Platform- and Feature-specific Requirements**
//!   * Linux - required for `fips`
//!   * [Go](https://go.dev/) - required for `fips`
//!   * [libclang](https://llvm.org/) - required for `bindgen` and for any platform lacking pre-generated bindings (like Windows or M1 Macs)
//!
//! See our [User Guide](https://awslabs.github.io/aws-lc-rs/) for guidance on installing these requirements.
//!
//! ## Contributor Quickstart for Amazon Linux 2023
//!
//! For those who would like to contribute to our project or build it directly from our repository,
//! a few more packages may be needed. The listing below shows the steps needed for you to begin
//! building and testing our project locally.
//! ```shell
//! # Install dependencies needed for build and testing
//! sudo yum install -y cmake3 clang git clang-libs golang openssl-devel
//!
//! # Install Rust
//! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//! source "$HOME/.cargo/env"
//!
//! # Clone and initialize a local repository
//! git clone https://github.com/awslabs/aws-lc-rs.git
//! cd aws-lc-rs
//! git submodule update --init --recursive
//!
//! # Build and test the project
//! cargo test
//!
//! ```
//!
//! # Feature Flags
//!
//! #### - alloc (default) ####
//! Allows implementation to allocate values of arbitrary size. (The meaning of this feature differs
//! from the "alloc" feature of *ring*.) Currently, this is required by the `io::writer` module.
//!
//! #### - ring-io (default) ####
//! Enable feature to access the  `io`  module.
//!
//! #### - ring-sig-verify (default) ####
//! Enable feature to preserve compatibility with ring's `signature::VerificationAlgorithm::verify`
//! function. This adds a requirement on `untrusted = "0.7.1"`.
//!
//! #### - fips ####
//! **EXPERIMENTAL** Enable this feature to have aws-lc-rs use the
//! [*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys) crate for the cryptographic
//! implementations. The *aws-lc-fips-sys* crate provides bindings to the FIPS variant of
//! [*AWS-LC*](https://github.com/aws/aws-lc). AWS-LC has been submitted to an accredited lab
//! for FIPS validation testing, and upon completion will be submitted to NIST for certification.
//! Once NIST grants a validation certificate to AWS-LC, we will make an announcement to Rust
//! developers on how to leverage the FIPS mode. This feature is currently only available on Linux.
//!
//! #### - asan ####
//! Performs an "address sanitizer" build. This can be used to help detect memory leaks. See the
//! ["Address Sanitizer" section](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#addresssanitizer)
//! of the [Rust Unstable Book](https://doc.rust-lang.org/beta/unstable-book/).
//!
//! #### - bindgen ####
//! Causes `aws-lc-sys` or `aws-lc-fips-sys` to generates fresh bindings for AWS-LC instead of using
//! the pre-generated bindings. This feature requires `libclang` to be installed. See the
//! [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)
//! for [rust-bindgen](https://github.com/rust-lang/rust-bindgen)
//!
//! # *ring*-compatibility
//!
//! Although this library attempts to be fully compatible with *ring*, there are a few places where our
//! behavior is observably different.
//!
//! * Our implementation requires the `std` library. We currently do not support a
//! [`#![no_std]`](https://docs.rust-embedded.org/book/intro/no-std.html) build.
//! * We can only support a subset of the platforms supported by `aws-lc-sys`. See the list of
//! supported platforms above.
//! * `Ed25519KeyPair::from_pkcs8` and `Ed25519KeyPair::from_pkcs8_maybe_unchecked` both support
//! parsing of v1 or v2 PKCS#8 documents. If a v2 encoded key is provided to either function,
//! public key component, if present, will be verified to match the one derived from the encoded
//! private key.
//!
//! # Motivation
//!
//! Rust developers increasingly need to deploy applications that meet US and Canadian government
//! cryptographic requirements. We evaluated how to deliver FIPS validated cryptography in idiomatic
//! and performant Rust, built around our AWS-LC offering. We found that the popular ring (v0.16)
//! library fulfilled much of the cryptographic needs in the Rust community, but it did not meet the
//! needs of developers with FIPS requirements. Our intention is to contribute a drop-in replacement
//! for ring that provides FIPS support and is compatible with the ring API. Rust developers with
//! prescribed cryptographic requirements can seamlessly integrate aws-lc-rs into their applications
//! and deploy them into AWS Regions.
//!

#![warn(missing_docs)]

#[cfg(feature = "fips")]
extern crate aws_lc_fips_sys as aws_lc;

#[cfg(not(feature = "fips"))]
extern crate aws_lc_sys as aws_lc;
extern crate core;

pub mod aead;
pub mod agreement;
pub mod constant_time;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
#[cfg(feature = "ring-io")]
pub mod io;
pub mod pbkdf2;
pub mod pkcs8;
pub mod rand;
pub mod signature;
pub mod test;

mod bn;
mod cbb;
mod cbs;
pub mod cipher;
mod debug;
mod ec;
mod ed25519;
mod endian;
mod evp_pkey;
pub mod iv;
mod ptr;
mod rsa;

use aws_lc::{
    CRYPTO_library_init, ERR_error_string, ERR_get_error, FIPS_mode, ERR_GET_FUNC, ERR_GET_LIB,
    ERR_GET_REASON,
};
use std::ffi::CStr;
use std::sync::Once;

static START: Once = Once::new();

#[inline]
/// Initialize the *AWS-LC* library. (This should generally not be needed.)
pub fn init() {
    START.call_once(|| unsafe {
        CRYPTO_library_init();
    });
}

#[cfg(test)]
/// # Panics
/// TODO
pub fn init_set_mem_functions() {
    use aws_lc::CRYPTO_set_mem_functions;
    START.call_once(|| unsafe {
        CRYPTO_library_init();

        if 1 != CRYPTO_set_mem_functions(
            Some(mem::malloc_bridge),
            Some(mem::realloc_bridge),
            Some(mem::free_bridge),
        ) {
            panic!("Failure setting mem functions")
        }
    });
}

#[cfg(test)]
mod mem {
    use std::alloc::{
        alloc as rust_alloc, dealloc as rust_dealloc, realloc as rust_realloc, Layout,
    };
    use std::mem::size_of;

    use std::os::raw::{c_char, c_int, c_void};

    pub unsafe extern "C" fn malloc_bridge(
        size: usize,
        _file: *const c_char,
        _line: c_int,
    ) -> *mut c_void {
        malloc(size)
    }

    pub unsafe extern "C" fn realloc_bridge(
        ptr: *mut c_void,
        new_size: usize,
        _file: *const c_char,
        _line: c_int,
    ) -> *mut c_void {
        realloc(ptr, new_size)
    }

    pub unsafe extern "C" fn free_bridge(ptr: *mut c_void, _file: *const c_char, _line: c_int) {
        free(ptr);
    }

    #[derive(Copy, Clone)]
    struct AllocData(*mut c_void, Layout);

    const MEM_ALIGNMENT: usize = size_of::<usize>();

    fn get_layout_offset(size: usize) -> (Layout, usize) {
        let required_layout = Layout::from_size_align(size, MEM_ALIGNMENT)
            .unwrap_or_else(|_| panic!("Unable to obtain layout: {size}"));
        let header_layout = Layout::from_size_align(size_of::<AllocData>(), MEM_ALIGNMENT)
            .expect("Unable to obtain header layout.");
        header_layout
            .extend(required_layout)
            .expect("Unable to obtain layout.")
    }

    fn write_alloc_data(alloc_ptr: *mut u8, layout: Layout, offset: usize) -> *mut c_void {
        //return alloc_ptr;
        assert!(!alloc_ptr.is_null(), "unable to allocate!");
        unsafe {
            let result_ptr = alloc_ptr.add(offset).cast::<c_void>();

            let data_ptr = result_ptr.sub(size_of::<AllocData>()).cast::<AllocData>();

            data_ptr.write_unaligned(AllocData(alloc_ptr.cast::<c_void>(), layout));

            result_ptr
        }
    }

    fn read_alloc_data(ptr: *mut c_void) -> AllocData {
        unsafe {
            let data_ptr = ptr.sub(size_of::<AllocData>()).cast::<AllocData>();
            data_ptr.read_unaligned()
        }
    }

    fn malloc(size: usize) -> *mut c_void {
        let (layout, offset) = get_layout_offset(size);
        unsafe {
            let alloc_ptr = rust_alloc(layout);
            write_alloc_data(alloc_ptr, layout, offset)
        }
    }

    fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
        if ptr.is_null() {
            return ptr;
        }
        unsafe {
            let alloc_data = read_alloc_data(ptr);
            let (new_layout, offset) = get_layout_offset(new_size);

            let realloc_ptr =
                rust_realloc(alloc_data.0.cast::<u8>(), alloc_data.1, new_layout.size());

            write_alloc_data(realloc_ptr, new_layout, offset)
        }
    }

    fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }
        unsafe {
            let data_ptr = ptr.sub(size_of::<AllocData>()).cast::<AllocData>();
            let alloc_data = data_ptr.read_unaligned();
            rust_dealloc(alloc_data.0.cast::<u8>(), alloc_data.1);
        }
    }
}

#[cfg(feature = "fips")]
/// Panics if the underlying implementation is not FIPS, otherwise it returns.
///
/// # Panics
/// Panics if the underlying implementation is not FIPS.
pub fn fips_mode() {
    try_fips_mode().unwrap();
}

/// Indicates whether the underlying implementation is FIPS.
///
/// # Errors
/// Return an error if the underlying implementation is not FIPS, otherwise ok
pub fn try_fips_mode() -> Result<(), &'static str> {
    init();
    unsafe {
        match FIPS_mode() {
            1 => Ok(()),
            _ => Err("FIPS mode not enabled!"),
        }
    }
}

#[allow(dead_code)]
unsafe fn dump_error() {
    let err = ERR_get_error();
    let lib = ERR_GET_LIB(err);
    let reason = ERR_GET_REASON(err);
    let func = ERR_GET_FUNC(err);
    let mut buffer = [0u8; 256];
    ERR_error_string(err, buffer.as_mut_ptr().cast());
    let error_msg = CStr::from_bytes_with_nul_unchecked(&buffer);
    eprintln!("Raw Error -- {error_msg:?}\nErr: {err}, Lib: {lib}, Reason: {reason}, Func: {func}");
}

mod sealed {
    /// Traits that are designed to only be implemented internally in *aws-lc-rs*.
    //
    // Usage:
    // ```
    // use crate::sealed;
    //
    // pub trait MyType: sealed::Sealed {
    //     // [...]
    // }
    //
    // impl sealed::Sealed for MyType {}
    // ```
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use crate::{dump_error, init, init_set_mem_functions};

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_dump() {
        unsafe {
            dump_error();
        }
    }

    #[test]
    fn test_init_set_mem() {
        use crate::signature::RsaKeyPair;
        use crate::test::from_dirty_hex;

        init_set_mem_functions();
        let rsa_pkcs8_input: Vec<u8> = from_dirty_hex(
            r#"308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b9d7a
        f84fa4184a5f22037ec8aff2db5f78bd8c21e714e579ae57c6398c4950f3a694b17bfccf488766159aec5bb7c2c4
        3d59c798cbd45a09c9c86933f126879ee7eadcd404f61ecfc425197cab03946ba381a49ef3b4d0f60b17f8a747cd
        e56a834a7f6008f35ffb2f60a54ceda1974ff2a9963aba7f80d4e2916a93d8c74bb1ba5f3b189a4e8f0377bd3e94
        b5cc3f9c53cb8c8c7c0af394818755e968b7a76d9cada8da7af5fbe25da2a09737d5e4e4d7092aa16a0718d7322c
        e8aca767015128d6d35775ea9cb8bb1ac6512e1b787d34015221be780a37b1d69bc3708bfd8832591be6095a768f
        0fd3b3457927e6ae3641d55799a29a0a269cb4a693bc14b0203010001028201001c5fb7e69fa6dd2fd0f5e653f12
        ce0b7c5a1ce6864e97bc2985dad4e2f86e4133d21d25b3fe774f658cca83aace9e11d8905d62c20b6cd28a680a77
        357cfe1afac201f3d1532898afb40cce0560bedd2c49fc833bd98da3d1cd03cded0c637d4173e62de865b572d410
        f9ba83324cd7a3573359428232f1628f6d104e9e6c5f380898b5570201cf11eb5f7e0c4933139c7e7fba67582287
        ffb81b84fa81e9a2d9739815a25790c06ead7abcf286bd43c6e3d009d01f15fca3d720bbea48b0c8ccf8764f3c82
        2e61159d8efcbff38c794f8afe040b45df14c976a91b1b6d886a55b8e68969bcb30c7197920d97d7721d78d954d8
        9ffecbcc93c6ee82a86fe754102818100eba1cbe453f5cb2fb7eabc12d697267d25785a8f7b43cc2cb14555d3618
        c63929b19839dcd4212397ecda8ad872f97ede6ac95ebda7322bbc9409bac2b24ae56ad62202800c670365ae2867
        1195fe934978a5987bee2fcea06561b782630b066b0a35c3f559a281f0f729fc282ef8ebdbb065d60000223da6ed
        b732fa32d82bb02818100c9e81e353315fd88eff53763ed7b3859f419a0a158f5155851ce0fe6e43188e44fb43dd
        25bcdb7f3839fe84a5db88c6525e5bcbae513bae5ff54398106bd8ae4d241c082f8a64a9089531f7b57b09af5204
        2efa097140702dda55a2141c174dd7a324761267728a6cc4ce386c034393d855ebe985c4e5f2aec2bd3f2e2123ab
        1028180566889dd9c50798771397a68aa1ad9b970e136cc811676ac3901c51c741c48737dbf187de8c47eec68acc
        05b8a4490c164230c0366a36c2c52fc075a56a3e7eecf3c39b091c0336c2b5e00913f0de5f62c5046ceb9d88188c
        c740d34bd44839bd4d0c346527cea93a15596727d139e53c35eed25043bc4ac18950f237c02777b0281800f9dd98
        049e44088efee6a8b5b19f5c0d765880c12c25a154bb6817a5d5a0b798544aea76f9c58c707fe3d4c4b3573fe7ad
        0eb291580d22ae9f5ccc0d311a40590d1af1f3236427c2d72f57367d3ec185b9771cb5d041a8ab93409e59a9d68f
        99c72f91c658a3fe5aed59f9f938c368530a4a45f4a7c7155f3906c4354030ef102818100c89e0ba805c970abd84
        a70770d8fc57bfaa34748a58b77fcddaf0ca285db91953ef5728c1be7470da5540df6af56bb04c0f5ec500f83b08
        057664cb1551e1e29c58d8b1e9d70e23ed57fdf9936c591a83c1dc954f6654d4a245b6d8676d045c2089ffce537d
        234fc88e98d92afa92926c75b286e8fee70e273d762bbe63cd63b"#,
        );

        let _key = RsaKeyPair::from_pkcs8(&rsa_pkcs8_input).unwrap();
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_fips() {
        assert!(crate::try_fips_mode().is_err());
    }

    #[test]
    // FIPS mode is disabled for an ASAN build
    #[cfg(all(feature = "fips", not(feature = "asan")))]
    fn test_fips() {
        crate::fips_mode();
    }
}
