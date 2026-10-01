// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// A test binary that never calls into libcrypto. On a static FIPS build the
// runtime check still references `FIPS_mode`, so this only links if libcrypto
// is placed after the runtime check on the link line.
extern crate aws_lc_fips_sys;

#[test]
fn links_without_crypto_calls() {}
