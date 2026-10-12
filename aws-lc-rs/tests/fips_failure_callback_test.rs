// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(feature = "fips-failure-callback")]

use core::ffi::c_char;

extern "C" {
    /// Defined by aws-lc-fips-sys; AWS-LC calls it on a FIPS failure.
    fn AWS_LC_fips_failure_callback(message: *const c_char);
}

// The failure latch is process-global and never resets, so this must stay the
// only test in this binary.
#[test]
fn fips_status_reports_first_failure() {
    assert_eq!(aws_lc_rs::try_fips_status(), Ok(()));
    assert_eq!(aws_lc_rs::fips_failure_message(), None);

    unsafe {
        AWS_LC_fips_failure_callback(b"first failure\0".as_ptr().cast());
        AWS_LC_fips_failure_callback(core::ptr::null());
    }

    assert_eq!(
        aws_lc_rs::try_fips_status(),
        Err(aws_lc_rs::error::Unspecified)
    );
    assert_eq!(aws_lc_rs::fips_failure_message(), Some("first failure"));
}
