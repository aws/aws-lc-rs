#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

source "${SCRIPT_DIR}/_generation_tools.sh"

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f] [-m]"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
  echo "-f fips build"
  echo "-m ignore mac"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
COLLECT_SYMBOLS_SCRIPT="${SCRIPT_DIR}/_collect_symbols_build.sh"
GENERATE_FIPS=0
IGNORE_MACOS=0
RELATIVE_CRATE_PATH=""

while getopts c:fm option; do
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

pushd "${REPO_ROOT}" &>/dev/null

##
## These docker image can be built from Dockerfiles under: <AWS-LC-DIR>/tests/ci/docker_images/rust
##
if [[ "${GENERATE_FIPS}" -eq 0 ]]; then
  ## macOS symbols
  IS_MACOS_HOST=$(check_running_on_macos [[ $IGNORE_MACOS -eq 0 ]])
  if [[ $IS_MACOS_HOST -eq 0 ]]; then
    ${COLLECT_SYMBOLS_SCRIPT} -c "${RELATIVE_CRATE_PATH}" &
  else
    echo Script is not running on macOS.
    echo Symbols will not be collected for macOS!
    echo
  fi

  ## 386 build
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/386 -- rust:linux-386 /bin/bash -c "${COLLECT_SYMBOLS_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  ## x86_64 build
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/amd64 -- rust:linux-x86_64 /bin/bash -c "${COLLECT_SYMBOLS_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &
  ## arm64 build
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/arm64 -- rust:linux-arm64 /bin/bash -c "${COLLECT_SYMBOLS_SCRIPT} -c ${RELATIVE_CRATE_PATH}" &

else

  ## x86_64 build
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/amd64 -- rust:linux-x86_64 /bin/bash -c "${COLLECT_SYMBOLS_SCRIPT} -c ${RELATIVE_CRATE_PATH} -f" &
  ## arm64 build
  docker run -v "$(pwd)":"$(pwd)" -w "$(pwd)" --rm --platform linux/arm64 -- rust:linux-arm64 /bin/bash -c "${COLLECT_SYMBOLS_SCRIPT} -c ${RELATIVE_CRATE_PATH} -f" &
fi

wait

popd &>/dev/null # ${REPO_ROOT}
