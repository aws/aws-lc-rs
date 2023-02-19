#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo "Validates that the target crate can be packaged and built from the package"
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

pushd "${CRATE_DIR}" &>/dev/null

go env -w GOPROXY=direct

TEMP_TARGET_DIR=$(mktemp -d)
cargo package --target-dir "${TEMP_TARGET_DIR}" --allow-dirty
rm -rf "${TEMP_TARGET_DIR}"

popd &>/dev/null # ${CRATE_DIR}
