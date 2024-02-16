#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "${SCRIPT_DIR}/_generation_tools.sh"

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
  echo "-f FIPS build"
  echo "-m Ignore macOS"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
GENERATE_FIPS=0
IGNORE_MACOS=0
RELATIVE_CRATE_PATH=""
CRATE_TEST_SCRIPT="${SCRIPT_DIR}/_crate_test_build.sh"

while getopts c:f option; do
  case $option in
  c)
    RELATIVE_CRATE_PATH="${OPTARG}"
    ;;
  f)
    GENERATE_FIPS=1
    ;;
  m)
    IGNORE_MACOS=1
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

assert_docker_status

pushd "${REPO_ROOT}" &>/dev/null

pids=''
if [[ "${GENERATE_FIPS}" -eq 0 ]]; then
  ### Test crate on Mac
  IS_MACOS_HOST=$(check_running_on_macos ${IGNORE_MACOS})
  if [[ $IS_MACOS_HOST -eq 1 ]]; then
    ${CRATE_TEST_SCRIPT} -c "${RELATIVE_CRATE_PATH}" &
  else
    echo Script is not running on macOS.
    echo Crate will not be tested on macOS!
    echo
  fi

  ## 386 test
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/386 rust:linux-386 /bin/bash -c "${CRATE_TEST_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  pids="$! ${pids}"
  ## x86_64 test
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/amd64 rust:linux-x86_64 /bin/bash -c "${CRATE_TEST_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  pids="$! ${pids}"
  ## arm64 test
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/arm64 rust:linux-arm64 /bin/bash -c "${CRATE_TEST_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  pids="$! ${pids}"
else
  ## x86_64 test
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/amd64 rust:linux-x86_64 /bin/bash -c "${CRATE_TEST_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  pids="$! ${pids}"
  ## arm64 test
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/arm64 rust:linux-arm64 /bin/bash -c "${CRATE_TEST_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  pids="$! ${pids}"
fi

echo "Waiting for tests to complete"
for pid in ${pids}; do
  wait ${pid}
done

popd &>/dev/null # ${REPO_ROOT}
