// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <stddef.h>

extern size_t system_fips_link_crypto_len(void);

int main(void) {
    return system_fips_link_crypto_len() != 32;
}
