// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#[inline(never)]
pub fn harmless() -> usize {
    42
}

// Keep a real transitive aws-lc-rs dependency, but let LTO remove its calls when
// the application only uses harmless(). The native startup check must remain.
pub fn crypto() -> aws_lc_rs::digest::Digest {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"test")
}
