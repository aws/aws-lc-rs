#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

IGNORE_DIRTY=0
IGNORE_BRANCH=0
IGNORE_UPSTREAM=0
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

validate_crate_version "${REPO_ROOT}/aws-lc-fips-sys"

SCRIPT_ARGS=(-c aws-lc-fips-sys)

"${SCRIPT_DIR}"/_run_supported_symbol_builds.sh -f "${SCRIPT_ARGS[@]}"
"${SCRIPT_DIR}"/_generate_prefix_headers.sh -f "${SCRIPT_ARGS[@]}"
# TODO: Can we trigger this in docker and still get the confirmation prompt? -a STDIN does not work correctly here
#docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/amd64 rust:linux-x86_64 /bin/bash -c "${SCRIPT_DIR}/_verify_crate_api_diff.sh ${SCRIPT_ARGS[*]}"
"${SCRIPT_DIR}"/_verify_crate_api_diff.sh "${SCRIPT_ARGS[@]}"
"${SCRIPT_DIR}"/_generate_all_bindings_flavors.sh -f "${SCRIPT_ARGS[@]}"
docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/amd64 rust:linux-x86_64 /bin/bash -c "${SCRIPT_DIR}/_verify_crate_packaging.sh ${SCRIPT_ARGS[*]}"

# Crate testing.
if [[ ${SKIP_TEST} -eq 1 ]]; then
  echo Aborting. Crate generated but not tested.
  exit 1
fi
"${SCRIPT_DIR}"/_test_supported_builds.sh "${SCRIPT_ARGS[@]}" -f

submodule_commit_metadata aws-lc-fips-sys

popd &>/dev/null # ${REPO_ROOT}

echo 'Generation Succeeded!'

