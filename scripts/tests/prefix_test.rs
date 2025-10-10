#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[dependencies]
# TODO: Also test pulling multiple versions from crates.io
aws-lc-sys = { path = "../../aws-lc-sys", package = "aws-lc-sys" }
aws-lc-sys-v0_31_0 = { package = "aws-lc-sys", version = "0.31.0" }
aws-lc-fips-sys = { path = "../../aws-lc-fips-sys" }
openssl-sys = "0"
boring-sys = "4"
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

macro_rules! generate_test {
    ($crate_name:ident, $mod_name:ident) => {
        mod $mod_name {
            use $crate_name::*;

            pub(crate) fn test() {
                let evp_pkey = key_gen().unwrap();
                let signature = sign(unsafe { &mut *evp_pkey }).unwrap();
                println!("Signature: {:?}", signature);
            }

            pub(crate) fn key_gen() -> Result<*mut EVP_PKEY, &'static str> {
                use std::ptr::null_mut;

                let pkey_ctx = unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null_mut()) };
                if pkey_ctx.is_null() {
                    return Err("EVP_PKEY_CTX_new_id");
                }

                if 1 != unsafe { EVP_PKEY_keygen_init(pkey_ctx) } {
                    unsafe { EVP_PKEY_CTX_free(pkey_ctx) };
                    return Err("EVP_PKEY_keygen_init");
                }

                let mut pkey = null_mut::<EVP_PKEY>();

                if unsafe { 1 != EVP_PKEY_keygen(pkey_ctx, &mut pkey) } {
                    unsafe { EVP_PKEY_CTX_free(pkey_ctx) };
                    return Err("EVP_PKEY_keygen");
                }

                unsafe { EVP_PKEY_CTX_free(pkey_ctx) };
                Ok(pkey)
            }
            pub(crate) fn sign(evp_pkey: &mut EVP_PKEY) -> Result<Box<[u8]>, &'static str> {
                use std::ptr::null_mut;

                let message = b"message to sign";

                let md_ctx = unsafe { EVP_MD_CTX_new() };
                if md_ctx.is_null() {
                    return Err("EVP_MD_CTX_new");
                }

                let evp_md = unsafe { EVP_sha1() };
                let mut pctx = null_mut::<EVP_PKEY_CTX>();
                if 1 != unsafe {
                    // EVP_DigestSignInit does not mutate |pkey| for thread-safety purposes and may be
                    // used concurrently with other non-mutating functions on |pkey|.
                    // https://github.com/aws/aws-lc/blob/9b4b5a15a97618b5b826d742419ccd54c819fa42/include/openssl/evp.h#L297-L313
                    EVP_DigestSignInit(md_ctx, &mut pctx, evp_md, null_mut(), evp_pkey)
                } {
                    unsafe { EVP_MD_CTX_free(md_ctx) };
                    return Err("EVP_DigestSignInit");
                }

                // Determine the maximum length of the signature.
                let mut sig_len = 0;
                if 1 != unsafe {
                    EVP_DigestSign(
                        md_ctx,
                        null_mut(),
                        &mut sig_len,
                        message.as_ptr(),
                        message.len(),
                    )
                } {
                    unsafe { EVP_MD_CTX_free(md_ctx) };
                    return Err("EVP_DigestSign - determine length");
                }
                if sig_len == 0 {
                    unsafe { EVP_MD_CTX_free(md_ctx) };
                    return Err("EVP_DigestSign - bad assumption");
                }

                let mut signature = vec![0u8; sig_len];
                if 1 != unsafe {
                    EVP_DigestSign(
                        md_ctx,
                        signature.as_mut_ptr(),
                        &mut sig_len,
                        message.as_ptr(),
                        message.len(),
                    )
                } {
                    unsafe { EVP_MD_CTX_free(md_ctx) };
                    return Err("EVP_DigestSign");
                }

                unsafe { EVP_MD_CTX_free(md_ctx) };
                signature.truncate(sig_len);
                Ok(signature.into_boxed_slice())
            }
        }
    };
}

generate_test!(aws_lc_fips_sys, test_fips);
generate_test!(aws_lc_sys, test_sys);
generate_test!(aws_lc_sys_v0_31_0, test_sys_v0_31_0);
generate_test!(openssl_sys, test_openssl);
generate_test!(boring_sys, test_boring);

fn main() {
    println!("Testing fips");
    test_fips::test();
    println!("Testing sys-local");
    test_sys::test();
    println!("Testing sys-v0.31.0");
    test_sys_v0_31_0::test();
    println!("Testing openssl");
    test_openssl::test();
    println!("Testing boring");
    test_boring::test();

    assert_eq!(1, unsafe { aws_lc_fips_sys::FIPS_mode() });
    assert_ne!(1, unsafe { aws_lc_sys::FIPS_mode() });
    assert_ne!(1, unsafe { aws_lc_sys_v0_31_0::FIPS_mode() });
}
