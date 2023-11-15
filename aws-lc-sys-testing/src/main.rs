// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::ffi::c_int;

extern "C" {
    fn testing_evp_key_type(nid: c_int) -> c_int;
}

fn main() {
    let v = unsafe { testing_evp_key_type(123) };
    println!("Hello EVP {v}!");
}

#[test]
fn link_test() {
    let _ = unsafe { testing_evp_key_type(123) };
}
