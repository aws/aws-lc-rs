#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -ex
set -o pipefail

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
SCRIPT_NAME="$(basename -s .sh -- "${BASH_SOURCE[0]}")"

source "${SCRIPT_DIR}/_common.sh"

pushd "${AWS_LC_DIR}"
declare -a SOURCE_FILES
SOURCE_FILES=()
mapfile -O 1 -t SOURCE_FILES < <(find crypto -name "*.c" -type f | rg --pcre2 -v 'crypto/fipsmodule/(?!(bcm.c|cpucap/cpucap.c))' | rg --pcre2 -v 'crypto/kyber/pqcrystals_kyber_ref_common/(?!fips202.c)' | rg --pcre2 -v '_test\.c$' | sort -f)
echo "${SOURCE_FILES[@]}"
mapfile -O ${#SOURCE_FILES[@]} -t SOURCE_FILES < <(find third_party/jitterentropy/jitterentropy-library/src -type f -name "*.c" | sort -f)
echo "${SOURCE_FILES[@]}"
popd

# Sort SOURCE_FILES array
mapfile -t SOURCE_FILES < <(printf '%s\n' "${SOURCE_FILES[@]}" | sort -f)

generate_output "${SOURCE_FILES[@]}" > "${BUILD_CFG_FILE}"
