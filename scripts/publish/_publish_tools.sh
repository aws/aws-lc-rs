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

# Finds the version of the crate based on current working directory
function crate_version_prefix {
  local REPO_ROOT
  REPO_ROOT=$(git rev-parse --show-toplevel)
  "${REPO_ROOT}"/scripts/tools/cargo-dig.rs -v | sed -e 's/\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)/\1_\2_\3/'
}

function sanity_check_sys_crate {
  local CRATE_DIR CRATE_NAME PREFIX
  CRATE_DIR="${1}"
  CRATE_NAME=$(basename "${CRATE_DIR}")
  PREFIX=$(echo "${CRATE_NAME}" | sed -e 's/-/_/g' | sed -e 's/^\(.*\)_sys/\1/')

  local CRATE_VERSION_PREFIX CRATE_PREFIX EXPECTED_LINKS_LINE
  CRATE_VERSION_PREFIX=$(crate_version_prefix "${CRATE_DIR}")
  CRATE_PREFIX="${PREFIX}_${CRATE_VERSION_PREFIX}"
  EXPECTED_LINKS_LINE="links = \"${CRATE_PREFIX}\""
  if ! grep "${EXPECTED_LINKS_LINE}" "${CRATE_DIR}/Cargo.toml"; then
    echo
    echo ERROR: Expected 'links' line not found in: "${CRATE_DIR}/Cargo.toml"
    echo "${EXPECTED_LINKS_LINE}"
    exit 1
  fi

  local EXPECTED_MACRO_LINE PREFIX_INCLUDE_PATH
  EXPECTED_MACRO_LINE="#define BORINGSSL_PREFIX ${CRATE_PREFIX}"
  PREFIX_INCLUDE_PATH="${CRATE_DIR}"/generated-include/openssl/boringssl_prefix_symbols_asm.h
  if ! grep "${EXPECTED_MACRO_LINE}" "${PREFIX_INCLUDE_PATH}"; then
    echo
    echo ERROR: Expected prefix macro not found in: "${PREFIX_INCLUDE_PATH}"
    echo "${EXPECTED_MACRO_LINE}"
    exit 1
  fi

  local COMMIT_HASH
  COMMIT_HASH=$(git submodule status -- "${CRATE_DIR}"/aws-lc | sed -e 's/.\([0-9a-f]*\).*/\1/')
  if ! grep "${COMMIT_HASH}" "${CRATE_DIR}/Cargo.toml"; then
    echo
    echo ERROR: Expected 'commit-hash' line not found in: "${CRATE_DIR}/Cargo.toml"
    echo "${COMMIT_HASH}"
    exit 1
  fi

  echo Sanity check: SUCCESS
}

# Verifies that the packaged crate builds and tests against the dependency
# versions currently published on crates.io. The manifest in the packaged
# .crate has all `path` entries stripped, so dependency resolution comes from
# the registry rather than the local workspace. Direct dependencies are pinned
# to the *minimum* versions allowed by Cargo.toml to verify that the declared
# version requirements are actually sufficient.
#
# This catches the failure that occurred with aws-lc-rs v1.17.2, which
# depended on symbols only available in a not-yet-published aws-lc-fips-sys.
# Local checks passed (path deps), but the published crate failed to build
# with the `fips` feature.
#
# Usage: verify_crate_with_published_deps RELATIVE_CRATE_PATH CARGO_ARGS...
#   Each CARGO_ARGS element is a (space-separated) set of arguments appended
#   to `cargo test` for one build configuration.
function verify_crate_with_published_deps {
  local RELATIVE_CRATE_PATH=$1
  shift
  local FEATURE_CONFIGS=("$@")

  local REPO_ROOT CRATE_DIR
  REPO_ROOT=$(git rev-parse --show-toplevel)
  CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

  local TEMP_TARGET_DIR TEMP_UNPACK_DIR
  TEMP_TARGET_DIR=$(mktemp -d)
  TEMP_UNPACK_DIR=$(mktemp -d)

  pushd "${CRATE_DIR}" &>/dev/null
  cargo package --no-verify --allow-dirty --target-dir "${TEMP_TARGET_DIR}"
  popd &>/dev/null # "${CRATE_DIR}"

  local CRATE_FILES UNPACKED_CRATE_DIRS
  CRATE_FILES=("${TEMP_TARGET_DIR}"/package/*.crate)
  tar xzf "${CRATE_FILES[0]}" -C "${TEMP_UNPACK_DIR}"
  UNPACKED_CRATE_DIRS=("${TEMP_UNPACK_DIR}"/*)

  pushd "${UNPACKED_CRATE_DIRS[0]}" &>/dev/null

  export GOPROXY=direct

  # Pin direct dependencies to the minimum versions allowed by Cargo.toml.
  # This fails if a dependency version requirement has not been published yet.
  cargo +nightly update -Zdirect-minimal-versions

  local CONFIG
  for CONFIG in "${FEATURE_CONFIGS[@]}"; do
    # shellcheck disable=SC2086
    cargo test --target-dir "${TEMP_TARGET_DIR}" ${CONFIG}
  done

  popd &>/dev/null # "${UNPACKED_CRATE_DIRS[0]}"

  rm -rf "${TEMP_TARGET_DIR}" "${TEMP_UNPACK_DIR}" &>/dev/null || true

  echo Published dependency check: SUCCESS
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

  cargo publish --dry-run --allow-dirty

  if [[ ${PUBLISH} -eq 1 ]]; then
    cargo publish --allow-dirty
  else
    echo Not published. Use -p to publish.
  fi

  popd &>/dev/null # "${CRATE_DIR}"

  return
}
