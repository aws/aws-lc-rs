#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PUBLISH=0
REPO_ROOT=$(git rev-parse --show-toplevel)
CRATE_NAME=aws-lc-fips-sys
CRATE_DIR="${REPO_ROOT}/${CRATE_NAME}"

source "${SCRIPT_DIR}"/_publish_tools.sh

publish_options "$@"

pushd "${CRATE_DIR}" &>/dev/null

sanity_check_sys_crate "${CRATE_DIR}"

cat << HERE > ./aws-lc/go.mod
module boringssl.googlesource.com/boringssl

go 1.13
HERE

run_prepublish_checks -c "${CRATE_NAME}"
publish_crate "${CRATE_NAME}" ${PUBLISH}
git --git-dir="${CRATE_DIR}/aws-lc/.git" restore go.mod
popd &>/dev/null
