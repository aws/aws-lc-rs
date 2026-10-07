// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

fn main() {
    assert_eq!(wrapper::harmless(), 42);
    #[cfg(feature = "live-crypto")]
    assert_eq!(wrapper::crypto().as_ref().len(), 32);
}
