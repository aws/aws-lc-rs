#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
RELATIVE_CRATE_PATH=""

while getopts c:fm option; do
  case $option in
  c)
    RELATIVE_CRATE_PATH="${OPTARG}"
    ;;
  ?)
    usage
    exit 1
    ;;
  esac
done

if [[ -z "${RELATIVE_CRATE_PATH}" ]]; then
  echo "Relative crate path must be provided"
  exit 1
fi

CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"
AWS_LC_DIR="${CRATE_DIR}/aws-lc"
SYMBOLS_DIR="${CRATE_DIR}/symbols"
GEN_INCLUDE_DIR="${CRATE_DIR}/generated-include"

pushd "${AWS_LC_DIR}" &>/dev/null
TEMP_FILE=$(mktemp)

find "${SYMBOLS_DIR}" -type f -print0 | xargs -0 sort | uniq >"${TEMP_FILE}"
go env -w GOPROXY=direct
go run -mod readonly "${AWS_LC_DIR}"/util/make_prefix_headers.go -out "${GEN_INCLUDE_DIR}" "${TEMP_FILE}"
rm "${TEMP_FILE}" &>/dev/null || true

popd &>/dev/null # ${AWS_LC_DIR}
