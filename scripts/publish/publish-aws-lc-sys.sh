#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PUBLISH=0
REPO_ROOT=$(git rev-parse --show-toplevel)
CRATE_NAME=aws-lc-sys
CRATE_DIR="${REPO_ROOT}/${CRATE_NAME}"

source "${SCRIPT_DIR}"/_publish_tools.sh
publish_options "$@"

pushd "${CRATE_DIR}" &>/dev/null

CRATE_VERSION_PREFIX=$(crate_version_prefix "${CRATE_DIR}")
CRATE_PREFIX="aws_lc_${CRATE_VERSION_PREFIX}"
EXPECTED_MACRO_LINE="#define BORINGSSL_PREFIX ${CRATE_PREFIX}"
PREFIX_INCLUDE_PATH="${CRATE_DIR}"/generated-include/openssl/boringssl_prefix_symbols_asm.h

if ! grep "${EXPECTED_MACRO_LINE}" "${PREFIX_INCLUDE_PATH}"; then
  echo
  echo ERROR: Expected prefix macro not found in: "${PREFIX_INCLUDE_PATH}"
  echo "${EXPECTED_MACRO_LINE}"
  exit 1
fi

run_prepublish_checks -c "${CRATE_NAME}"
publish_crate "${CRATE_NAME}" ${PUBLISH}
popd &>/dev/null
