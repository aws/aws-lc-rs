// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#[no_mangle]
pub extern "C" fn system_fips_link_crypto_len() -> usize {
    wrapper::crypto().as_ref().len()
}
