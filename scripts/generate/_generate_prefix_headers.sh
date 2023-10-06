#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
  echo "-f fips build"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
GENERATE_FIPS=0
RELATIVE_CRATE_PATH=""

while getopts c:fm option; do
  case $option in
  c)
    RELATIVE_CRATE_PATH="${OPTARG}"
    ;;
  f)
    GENERATE_FIPS=1
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
GEN_INCLUDE_DIR="${CRATE_DIR}/generated-include/openssl"

pushd "${CRATE_DIR}" &>/dev/null
CRATE_VERSION=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -v)
PREFIX=$(echo -n "${CRATE_VERSION}" | tr '.' '_')
if [[ "${GENERATE_FIPS}" -eq 1 ]]; then
  PREFIX="aws_lc_fips_${PREFIX}"
else
  PREFIX="aws_lc_${PREFIX}"
fi
popd &>/dev/null

pushd "${AWS_LC_DIR}" &>/dev/null
TEMP_FILE=$(mktemp)

if [[ -z "${GOPROXY:+x}" ]]; then
  export GOPROXY=direct
fi

find "${SYMBOLS_DIR}" -type f -print0 | env LC_ALL=C xargs -0 sort | uniq >"${TEMP_FILE}"
go run -mod readonly "${AWS_LC_DIR}"/util/make_prefix_headers.go -prefix "${PREFIX}" -out "${GEN_INCLUDE_DIR}" "${TEMP_FILE}"
rm "${TEMP_FILE}" &>/dev/null || true

popd &>/dev/null # ${AWS_LC_DIR}
