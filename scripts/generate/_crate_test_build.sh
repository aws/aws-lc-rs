#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
RELATIVE_CRATE_PATH=""

while getopts c:f option; do
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
  echo "Relative crate path must not be empty"
  exit 1
fi

CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

TEMP_TARGET_DIR=$(mktemp -d)

if [[ ! -d ${TEMP_TARGET_DIR} || ! -d ${CRATE_DIR} ]]; then
  echo "$(basename "${0}")" Sanity Check Failed
  exit 1
fi

pushd "${CRATE_DIR}" &>/dev/null

export GOPROXY=direct

cargo clean --target-dir "${TEMP_TARGET_DIR}"
cargo test --target-dir "${TEMP_TARGET_DIR}" --release
cargo test --target-dir "${TEMP_TARGET_DIR}" --release --features ssl

rm -rf "${TEMP_TARGET_DIR}" &>/dev/null || true

popd &>/dev/null
