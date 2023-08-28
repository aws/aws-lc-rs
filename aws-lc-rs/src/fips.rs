// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

/// Retrieve the FIPS module service status.
#[allow(dead_code)] // appease clippy
#[cfg(all(feature = "fips", debug_assertions))]
pub(crate) fn get_fips_service_status() -> FipsServiceStatus<()> {
    if indicator::is_approved() {
        FipsServiceStatus::ApprovedMode(())
    } else {
        FipsServiceStatus::NonApprovedMode(())
    }
}

#[inline]
pub(crate) fn set_fips_service_status_unapproved() {
    #[cfg(all(feature = "fips", debug_assertions))]
    indicator::set_unapproved();
}

/// Clears the FIPS module service status. Useful if a thread has executed an unapproved
/// algorithm, but you desire to reset the module status without destroying the thread.
#[allow(dead_code)] // appease clippy
#[cfg(all(feature = "fips", debug_assertions))]
pub(crate) fn reset_fips_service_status() {
    indicator::reset();
}

#[cfg(all(feature = "fips", debug_assertions))]
pub(crate) mod indicator {
    use std::cell::Cell;

    thread_local! {
        static APPROVED_OPERATING_MODE: Cell<bool> = const { Cell::new(true) };
    }

    pub fn is_approved() -> bool {
        APPROVED_OPERATING_MODE.with(std::cell::Cell::get)
    }

    #[allow(dead_code)]
    pub fn is_nonapproved() -> bool {
        !is_approved()
    }

    pub fn set_unapproved() {
        APPROVED_OPERATING_MODE.with(|v| v.set(false));
    }

    pub fn reset() {
        APPROVED_OPERATING_MODE.with(|v| v.set(true));
    }
}

#[cfg(all(feature = "fips", debug_assertions))]
#[inline]
pub(crate) fn service_indicator_before_call() -> u64 {
    unsafe { aws_lc::FIPS_service_indicator_before_call() }
}

#[cfg(all(feature = "fips", debug_assertions))]
#[inline]
pub(crate) fn service_indicator_after_call() -> u64 {
    unsafe { aws_lc::FIPS_service_indicator_after_call() }
}

/// The FIPS Module Service Status
#[allow(dead_code)] // appease clippy
#[cfg(all(feature = "fips", debug_assertions))]
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FipsServiceStatus<R> {
    /// Indicates that the current thread is using approved FIPS cryptographic services.
    ApprovedMode(R),

    /// Indicates that the current thread has used non-approved FIPS cryptographic services.
    /// The service indicator status can be reset using `reset_fips_service_status`.
    /// `reset_fips_service_status` will return `NonApprovedMode` if the service used a non-approved
    /// service, and automatically resets the service status for you.
    NonApprovedMode(R),

    /// Indicates that FIPS mode is not enabled for the crate. To enable FIPS you must specify the
    /// `fips` the cargo feature.
    #[allow(dead_code)]
    NotEnabled(R),
}

#[cfg(all(feature = "fips", debug_assertions))]
impl<R> FipsServiceStatus<R> {
    /// Maps a `ServiceStatus<R>` to a `ServiceStatus<S>` by applying a function to a contained value.
    #[allow(dead_code)]
    pub fn map<S, F>(self, op: F) -> FipsServiceStatus<S>
    where
        F: FnOnce(R) -> S,
    {
        match self {
            FipsServiceStatus::ApprovedMode(v) => FipsServiceStatus::ApprovedMode(op(v)),
            FipsServiceStatus::NonApprovedMode(v) => FipsServiceStatus::NonApprovedMode(op(v)),
            FipsServiceStatus::NotEnabled(v) => FipsServiceStatus::NotEnabled(op(v)),
        }
    }
}

macro_rules! indicator_check {
    ($function:expr) => {{
        #[cfg(all(feature = "fips", debug_assertions))]
        {
            use crate::fips::{service_indicator_after_call, service_indicator_before_call};
            let before = service_indicator_before_call();
            let result = $function;
            let after = service_indicator_after_call();
            if before == after {
                crate::fips::indicator::set_unapproved();
                result
            } else {
                result
            }
        }
        #[cfg(any(not(feature = "fips"), not(debug_assertions)))]
        {
            $function
        }
    }};
}

pub(crate) use indicator_check;

#[allow(unused_macros)]
#[cfg(all(feature = "fips", debug_assertions))]
macro_rules! check_fips_service_status {
    ($function:expr) => {{
        use $crate::fips::{get_fips_service_status, reset_fips_service_status, FipsServiceStatus};
        let result = $function;
        let result = get_fips_service_status().map(|()| result);
        #[allow(clippy::ignored_unit_patterns)]
        match &result {
            FipsServiceStatus::ApprovedMode(_) => {}
            FipsServiceStatus::NonApprovedMode(_) => {
                reset_fips_service_status();
            }
            _ => {
                panic!("unexpected `fips_service_status` status")
            }
        }
        result
    }};
}

#[allow(unused_imports)]
#[cfg(all(feature = "fips", debug_assertions))]
pub(crate) use check_fips_service_status;

#[allow(unused_macros)]
#[cfg(all(feature = "fips", debug_assertions))]
macro_rules! assert_fips_status_indicator {
    ($function:expr, $expect:path) => {
        assert_fips_status_indicator!($function, $expect, "unexpected service indicator")
    };
    ($function:expr, $expect:path, $message:literal) => {{
        match crate::fips::check_fips_service_status!($function) {
            $expect(v) => v,
            _ => panic!($message),
        }
    }};
}

#[allow(unused_imports)]
#[cfg(all(feature = "fips", debug_assertions))]
pub(crate) use assert_fips_status_indicator;

#[cfg(test)]
mod tests {

    #[cfg(all(feature = "fips", debug_assertions))]
    #[test]
    fn test_service_status() {
        use crate::fips::FipsServiceStatus;

        assert_eq!(
            FipsServiceStatus::ApprovedMode(true),
            FipsServiceStatus::ApprovedMode(()).map(|()| true)
        );
        assert_eq!(
            FipsServiceStatus::NonApprovedMode(true),
            FipsServiceStatus::NonApprovedMode(()).map(|()| true)
        );
        assert_eq!(
            FipsServiceStatus::NotEnabled(true),
            FipsServiceStatus::NotEnabled(()).map(|()| true)
        );
    }
}
