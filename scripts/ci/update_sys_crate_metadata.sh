#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -ex
set -o pipefail

function usage() {
  echo Must specify sys-crate name:
  echo Usage:
  echo     "${0} <CRATE_NAME>"
  echo
}

CRATE_NAME="${1}"
if [[ -z "${CRATE_NAME}" ]]; then
  usage
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
CRATE_DIR="${REPO_ROOT}"/"${CRATE_NAME}"
if [[ ! -d "${CRATE_DIR}" ]]; then
  usage
  exit 1
fi

# Finds the version of the crate based on current working directory
function crate_version_prefix {
  "${REPO_ROOT}"/scripts/tools/cargo-dig.rs -v | sed -e 's/\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)/\1_\2_\3/'
}

function links_sys_crate_metadata {
  local PREFIX CRATE_VERSION_PREFIX CRATE_PREFIX
  PREFIX=$(echo "${CRATE_NAME}" | sed -e 's/-/_/g' | sed -e 's/^\(.*\)_sys/\1/')
  pushd "${CRATE_DIR}" || exit 1
  CRATE_VERSION_PREFIX=$(crate_version_prefix)
  popd || exit 1
  CRATE_PREFIX="${PREFIX}_${CRATE_VERSION_PREFIX}"
  perl -pi -e "s/links = .*/links = \"${CRATE_PREFIX}\"/" "${CRATE_DIR}"/Cargo.toml
}

function submodule_commit_metadata {
  COMMIT_HASH=$(git submodule status -- "${CRATE_DIR}"/aws-lc | sed -e 's/.\([0-9a-f]*\).*/\1/')
  perl -pi -e "s/commit-hash .*/commit-hash = \"${COMMIT_HASH}\"/" "${CRATE_DIR}"/Cargo.toml
}

links_sys_crate_metadata

submodule_commit_metadata
