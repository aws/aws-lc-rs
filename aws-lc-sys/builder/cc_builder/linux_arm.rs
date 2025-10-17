// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// Fri Oct 17 14:12:18 UTC 2025

pub(super) const CRYPTO_LIBRARY: &[&str] = &[
    "crypto/poly1305/poly1305_arm_asm.S",
    "generated-src/linux-arm/crypto/chacha/chacha-armv4.S",
    "generated-src/linux-arm/crypto/fipsmodule/aesv8-armx.S",
    "generated-src/linux-arm/crypto/fipsmodule/armv4-mont.S",
    "generated-src/linux-arm/crypto/fipsmodule/bsaes-armv7.S",
    "generated-src/linux-arm/crypto/fipsmodule/ghash-armv4.S",
    "generated-src/linux-arm/crypto/fipsmodule/ghashv8-armx.S",
    "generated-src/linux-arm/crypto/fipsmodule/sha1-armv4-large.S",
    "generated-src/linux-arm/crypto/fipsmodule/sha256-armv4.S",
    "generated-src/linux-arm/crypto/fipsmodule/sha512-armv4.S",
    "generated-src/linux-arm/crypto/fipsmodule/vpaes-armv7.S",
    "generated-src/linux-arm/crypto/test/trampoline-armv4.S",
];
