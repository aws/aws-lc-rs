# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

function usage {
  echo
  echo "Usage: $(basename "${0}") [-p]"
  echo
  echo "-p Actually publish the crate (defaults to dry-run)"
  echo
}

function publish_options {
  while getopts "p" option; do
    case ${option} in
    p)
      PUBLISH=1
      ;;
    *)
      echo Invalid argument: -"${?}"
      usage
      exit 1
      ;;
    esac
  done
}

function run_prepublish_checks {
  local SCRIPT_DIR
  SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
  "${SCRIPT_DIR}"/_prepublish_checks.sh "$@"
}

# FIPS static build is only supported on linux.
function run_prepublish_checks_linux {
  local SCRIPT_DIR
  SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
  local REPO_ROOT
  REPO_ROOT=$(git rev-parse --show-toplevel)
  docker run -v "${REPO_ROOT}":"${REPO_ROOT}" -w "${REPO_ROOT}" --rm --platform linux/amd64 rust:linux-x86_64 /bin/bash -c "${SCRIPT_DIR}/_prepublish_checks.sh $*"
}

function publish_crate {
  local RELATIVE_CRATE_PATH=$1
  local PUBLISH=$2
  local REPO_ROOT
  REPO_ROOT=$(git rev-parse --show-toplevel)
  local CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

  pushd "${CRATE_DIR}" &>/dev/null

  cargo publish --dry-run

  if [[ ${PUBLISH} -eq 1 ]]; then
    cargo publish
  else
    echo Not published. Use -p to publish.
  fi

  popd &>/dev/null # "${CRATE_DIR}"

  return
}
