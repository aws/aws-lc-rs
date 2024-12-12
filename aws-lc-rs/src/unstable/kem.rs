// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::fmt::Debug;

use crate::kem::Algorithm;

#[deprecated(note = "use aws_lc_rs::kem::{ML_KEM_512, ML_KEM_768, ML_KEM_1024}")]
pub use crate::kem::{ML_KEM_1024, ML_KEM_512, ML_KEM_768};

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AlgorithmId {}

impl crate::kem::AlgorithmIdentifier for AlgorithmId {
    #[inline]
    fn nid(self) -> i32 {
        unreachable!("There are no AlgorithmIds")
    }
}

impl crate::sealed::Sealed for AlgorithmId {}

/// Retrieve an unstable KEM [`Algorithm`] using the [`AlgorithmId`] specified by `id`.
/// May return [`None`] if support for the algorithm has been removed from the unstable module.
/// # ⚠️ Warning
/// This function currently only returns [`None`].
#[must_use]
pub const fn get_algorithm(_id: AlgorithmId) -> Option<&'static Algorithm<AlgorithmId>> {
    None
}
