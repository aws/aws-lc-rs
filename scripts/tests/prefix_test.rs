#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[dependencies]
# TODO: Also test pulling multiple versions from crates.io
aws-lc-sys = { path = "../../aws-lc-sys", package = "aws-lc-sys" }
aws-lc-fips-sys = { path = "../../aws-lc-fips-sys" }
---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

macro_rules! generate_test {
    ($crate_name:ident, $mod_name:ident) => {
        mod $mod_name {
            use $crate_name::*;
            use std::ptr::null_mut;

            pub(crate) fn test() {
                let evp_pkey = key_gen().unwrap();
                let signature = sign(unsafe { &mut *evp_pkey }).unwrap();
                println!("Signature: {:?}", signature);
            }

            pub(crate) fn key_gen() -> Result<*mut EVP_PKEY, &'static str> {


                let pkey_type = EVP_PKEY_EC;
                let pkey_ctx = unsafe { EVP_PKEY_CTX_new_id(pkey_type, null_mut()) };
                if pkey_ctx.is_null() {
                    return Err("EVP_PKEY_CTX_new_id");
                }

                if 1 != unsafe { EVP_PKEY_keygen_init(pkey_ctx) } {
                    return Err("EVP_PKEY_keygen_init");
                }

                if 1 != unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1) } {
                    return Err("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
                }

                let mut pkey = null_mut::<EVP_PKEY>();

                if unsafe { 1 !=  EVP_PKEY_keygen(pkey_ctx, &mut pkey) } {
                    return Err("EVP_PKEY_keygen");
                }

                Ok(pkey)
            }
            pub(crate) fn sign(
                evp_pkey: &mut EVP_PKEY,
            ) -> Result<Box<[u8]>, &'static str>
            where
            {
                use std::mem::MaybeUninit;
                use std::ptr::null_mut;

                let message = b"message to sign";

                let mut md_ctx = MaybeUninit::<EVP_MD_CTX>::uninit();
                unsafe { EVP_MD_CTX_init(md_ctx.as_mut_ptr()) };
                let mut md_ctx = unsafe { md_ctx.assume_init() };
                let evp_md = unsafe { EVP_sha1() };
                let mut pctx = null_mut::<EVP_PKEY_CTX>();
                if 1 != unsafe {
                    // EVP_DigestSignInit does not mutate |pkey| for thread-safety purposes and may be
                    // used concurrently with other non-mutating functions on |pkey|.
                    // https://github.com/aws/aws-lc/blob/9b4b5a15a97618b5b826d742419ccd54c819fa42/include/openssl/evp.h#L297-L313
                    EVP_DigestSignInit(
                        &mut md_ctx,
                        &mut pctx,
                        evp_md,
                        null_mut(),
                        evp_pkey,
                    )
                } {
                    return Err("EVP_DigestSignInit");
                }

                // Determine the maximum length of the signature.
                let mut sig_len = 0;
                if 1 != unsafe {
                    EVP_DigestSign(
                        &mut md_ctx,
                        null_mut(),
                        &mut sig_len,
                        message.as_ptr(),
                        message.len(),
                    )
                } {
                    return Err("EVP_DigestSign - determine length");
                }
                if sig_len == 0 {
                    return Err("EVP_DigestSign - bad assumption");
                }

                let mut signature = vec![0u8; sig_len];
                if 1 != unsafe {
                        EVP_DigestSign(
                            &mut md_ctx,
                            signature.as_mut_ptr(),
                            &mut sig_len,
                            message.as_ptr(),
                            message.len(),
                        )
                    } {
                    return Err("EVP_DigestSign");
                }
                signature.truncate(sig_len);
                Ok(signature.into_boxed_slice())
            }
        }
    }
}

generate_test!(aws_lc_fips_sys, test_fips);
generate_test!(aws_lc_sys, test_sys);

fn main() {
    println!("Testing fips");
    test_fips::test();
    println!("Testing sys-local");
    test_sys::test();
}
