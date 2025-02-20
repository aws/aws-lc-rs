// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(feature = "unstable")]

//! This module contains unstable/experimental APIs.
//!
//! # ⚠️ Warning
//! The APIs under this module are not stable and may change in the future.
//! They are not covered by semver guarantees.
//!
#[deprecated(note = "use  `aws_lc_rs::kdf` instead")]
/// TODO: Remove this module
pub mod kdf;

#[deprecated(note = "use `aws_lc_rs::kem` instead")]
/// TODO: Remove this module
pub mod kem;

#[cfg(not(feature = "fips"))]
pub mod signature;
