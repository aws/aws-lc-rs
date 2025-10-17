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
SOURCE_FILES=( "crypto/poly1305/poly1305_arm_asm.S" )
mapfile -O ${#SOURCE_FILES[@]} -t SOURCE_FILES < <(find generated-src/linux-arm/crypto -name "*.S" -type f  | sort -f)
echo "${SOURCE_FILES[@]}"

popd

# Sort SOURCE_FILES array
mapfile -t SOURCE_FILES < <(printf '%s\n' "${SOURCE_FILES[@]}" | sort -f)

generate_output "${SOURCE_FILES[@]}" > "${BUILD_CFG_FILE}"
