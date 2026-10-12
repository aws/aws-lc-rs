// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(feature = "fips-failure-callback")]

use core::ffi::{c_char, CStr};

extern "C" {
    /// AWS-LC's internal handler, called on every FIPS self-test and pairwise
    /// consistency test failure. It aborts unless `AWS_LC_fips_failure_callback`
    /// is linked in.
    #[link_name = concat!(env!("AWS_LC_FIPS_SYS_SYMBOL_PREFIX"), "AWS_LC_FIPS_failure")]
    fn aws_lc_fips_failure(message: *const c_char);
}

// The failure latch is process-global and never resets, so this must stay the
// only test in this binary.
#[test]
fn fips_failure_latches_instead_of_aborting() {
    aws_lc_fips_sys::init();
    unsafe {
        assert_eq!(aws_lc_fips_sys::aws_lc_fips_sys_failure_detected(), 0);
        assert!(aws_lc_fips_sys::aws_lc_fips_sys_failure_message().is_null());

        aws_lc_fips_failure(b"first failure\0".as_ptr().cast());
        aws_lc_fips_failure(b"second failure\0".as_ptr().cast());

        assert_ne!(aws_lc_fips_sys::aws_lc_fips_sys_failure_detected(), 0);
        let message = CStr::from_ptr(aws_lc_fips_sys::aws_lc_fips_sys_failure_message());
        assert_eq!(message.to_str(), Ok("first failure"));
    }
}
