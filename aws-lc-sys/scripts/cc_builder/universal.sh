#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

SCRIPT_NAME="$(basename -s .sh -- "${BASH_SOURCE[0]}")"
REPO_ROOT=$(git rev-parse --show-toplevel)
SYS_CRATE_DIR="${REPO_ROOT}/aws-lc-sys"
AWS_LC_DIR="${SYS_CRATE_DIR}/aws-lc"
BUILD_CFG_DIR="${SYS_CRATE_DIR}/builder/cc_builder"
BUILD_CFG_FILE="${BUILD_CFG_DIR}/${SCRIPT_NAME}".rs
mkdir -p "${BUILD_CFG_DIR}"

function generate_output() {
    TIMESTAMP="$(date -u)"
    cat << EOF
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// $TIMESTAMP

pub(super) const CRYPTO_LIBRARY: &[&str] = &[
EOF
    for FILE in "${@}"; do
        echo "    \"${FILE}\","
    done
    cat << EOF
];
EOF
}

pushd "${AWS_LC_DIR}"
declare -a SOURCE_FILES
SOURCE_FILES=("generated-src/err_data.c")
mapfile -O 1 -t SOURCE_FILES < <(find crypto -name "*.c" -type f | rg --pcre2 -v 'crypto/fipsmodule/(?!(bcm.c|cpucap/cpucap.c))' | rg --pcre2 -v 'crypto/kyber/pqcrystals_kyber_ref_common/(?!fips202.c)' | rg --pcre2 -v '_test\.c$' | sort -f)
echo "${SOURCE_FILES[@]}"
mapfile -O ${#SOURCE_FILES[@]} -t SOURCE_FILES < <(find third_party/jitterentropy/jitterentropy-library/src -type f -name "*.c" | sort -f)
echo "${SOURCE_FILES[@]}"
popd

# Sort SOURCE_FILES array
mapfile -t SOURCE_FILES < <(printf '%s\n' "${SOURCE_FILES[@]}" | sort -f)

generate_output "${SOURCE_FILES[@]}" > "${BUILD_CFG_FILE}"
