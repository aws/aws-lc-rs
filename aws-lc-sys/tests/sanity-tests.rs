// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#[test]
fn test_fips_mode() {
    unsafe {
        assert_eq!(aws_lc_sys::FIPS_mode(), 0);
    }
}

#[test]
fn error_checking() {
    unsafe {
        let error = aws_lc_sys::ERR_get_error();
        let err_lib = aws_lc_sys::ERR_GET_LIB(error);
        let err_reason = aws_lc_sys::ERR_GET_REASON(error);
        let err_func = aws_lc_sys::ERR_GET_FUNC(error);
        assert_eq!(err_lib, 0);
        assert_eq!(err_reason, 0);
        assert_eq!(err_func, 0);
    }
}

#[cfg(feature = "all-bindings")]
#[test]
fn bio_get_mem_data() {
    unsafe {
        let bio = aws_lc_sys::BIO_new(aws_lc_sys::BIO_s_mem());
        assert!(!bio.is_null());

        let input = b"hello\0world";
        let input_len = i32::try_from(input.len()).unwrap();
        assert_eq!(
            aws_lc_sys::BIO_write(bio, input.as_ptr().cast(), input_len),
            input_len
        );

        let mut data = core::ptr::null_mut();
        let len = aws_lc_sys::BIO_get_mem_data(bio, &mut data);
        assert_eq!(len, input_len.into());
        assert!(!data.is_null());
        assert_eq!(
            core::slice::from_raw_parts(data.cast::<u8>(), input.len()),
            input
        );
        aws_lc_sys::BIO_free(bio);
    }
}
