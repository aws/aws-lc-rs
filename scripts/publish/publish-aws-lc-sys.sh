#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PUBLISH=0
REPO_ROOT=$(git rev-parse --show-toplevel)
RELATIVE_CRATE_PATH=aws-lc-sys
CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

source "${SCRIPT_DIR}"/_publish_tools.sh

publish_options "$@"

pushd "${CRATE_DIR}" &>/dev/null
run_prepublish_checks -c "${RELATIVE_CRATE_PATH}"
publish_crate "${RELATIVE_CRATE_PATH}" ${PUBLISH}
popd &>/dev/null
