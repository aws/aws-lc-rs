// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

pub(super) const CRYPTO_LIBRARY: &[&str] = &[
    "generated-src/linux-x86/crypto/chacha/chacha-x86.S",
    "generated-src/linux-x86/crypto/fipsmodule/aesni-x86.S",
    "generated-src/linux-x86/crypto/fipsmodule/bn-586.S",
    "generated-src/linux-x86/crypto/fipsmodule/co-586.S",
    "generated-src/linux-x86/crypto/fipsmodule/ghash-ssse3-x86.S",
    "generated-src/linux-x86/crypto/fipsmodule/ghash-x86.S",
    "generated-src/linux-x86/crypto/fipsmodule/md5-586.S",
    "generated-src/linux-x86/crypto/fipsmodule/sha1-586.S",
    "generated-src/linux-x86/crypto/fipsmodule/sha256-586.S",
    "generated-src/linux-x86/crypto/fipsmodule/sha512-586.S",
    "generated-src/linux-x86/crypto/fipsmodule/vpaes-x86.S",
    "generated-src/linux-x86/crypto/fipsmodule/x86-mont.S",
    "generated-src/linux-x86/crypto/test/trampoline-x86.S",
];
