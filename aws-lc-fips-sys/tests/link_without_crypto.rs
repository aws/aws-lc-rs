// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// Link the FIPS runtime check without making any libcrypto calls.
extern crate aws_lc_fips_sys;

#[test]
fn links_without_crypto_calls() {}
