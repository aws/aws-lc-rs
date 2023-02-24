#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

IGNORE_DIRTY=0
IGNORE_BRANCH=0
IGNORE_UPSTREAM=0
IGNORE_MACOS=0
SKIP_TEST=0

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
REPO_ROOT=$(git rev-parse --show-toplevel)

source "${SCRIPT_DIR}"/_generation_tools.sh

generation_options "$@"
shift $((OPTIND - 1))

assert_docker_status

pushd "${REPO_ROOT}" &>/dev/null

check_workspace $IGNORE_DIRTY
check_branch $IGNORE_BRANCH $IGNORE_UPSTREAM

IS_MACOS_HOST=$(check_running_on_macos [[ $IGNORE_MACOS -eq 0 ]])
if [[ $IS_MACOS_HOST -ne 0 ]]; then
  echo Script is not running on macOS!
fi

validate_crate_version "${REPO_ROOT}/aws-lc-sys"

SCRIPT_ARGS=(-c aws-lc-sys)
if [[ ${IGNORE_MACOS} -eq 1 ]]; then
  SCRIPT_ARGS=("${SCRIPT_ARGS[@]}" -m)
fi

"${SCRIPT_DIR}"/_run_supported_symbol_builds.sh "${SCRIPT_ARGS[@]}"
"${SCRIPT_DIR}"/_generate_prefix_headers.sh "${SCRIPT_ARGS[@]}"
"${SCRIPT_DIR}"/_verify_crate_api_diff.sh "${SCRIPT_ARGS[@]}"
"${SCRIPT_DIR}"/_generate_all_bindings_flavors.sh "${SCRIPT_ARGS[@]}"
"${SCRIPT_DIR}"/_verify_crate_packaging.sh "${SCRIPT_ARGS[@]}"

# Crate testing.
if [[ ${SKIP_TEST} -eq 1 ]]; then
  echo Aborting. Crate generated but not tested.
  exit 1
fi
"${SCRIPT_DIR}"/_test_supported_builds.sh "${SCRIPT_ARGS[@]}"

popd &>/dev/null # ${REPO_ROOT}
