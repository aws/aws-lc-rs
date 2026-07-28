#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PUBLISH=0
RELATIVE_CRATE_PATH=aws-lc-rs
REPO_ROOT=$(git rev-parse --show-toplevel)
CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

source "${SCRIPT_DIR}"/_publish_tools.sh

publish_options "$@"

pushd "${CRATE_DIR}" &>/dev/null
run_prepublish_checks -c "${RELATIVE_CRATE_PATH}"
# Verify the packaged crate builds/tests against the sys crate versions
# currently available on crates.io, resolved to the minimum versions allowed
# by our Cargo.toml. Checks both the default (non-FIPS) and FIPS builds.
verify_crate_with_published_deps "${RELATIVE_CRATE_PATH}" \
  "" \
  "--no-default-features --features fips"
publish_crate "${RELATIVE_CRATE_PATH}" ${PUBLISH}
popd &>/dev/null
