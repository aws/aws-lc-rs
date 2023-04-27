#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
}

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
  echo "Relative crate path must be provided"
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

TEMP_TARGET_DIR=$(mktemp -d)

pushd "${CRATE_DIR}" &>/dev/null

export GOPROXY=direct

cargo clean --target-dir "${TEMP_TARGET_DIR}"
cargo clippy --fix --allow-no-vcs
cargo fmt
cargo test --target-dir "${TEMP_TARGET_DIR}" # sanity check
cargo package --target-dir "${TEMP_TARGET_DIR}" --allow-dirty # checks if published package will build.
cargo clean --target-dir "${TEMP_TARGET_DIR}"

popd &>/dev/null # "${CRATE_DIR}"

rm -rf "${TEMP_TARGET_DIR}" &>/dev/null || true
