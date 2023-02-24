# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

function usage {
  echo
  echo "Usage: $(basename "${0}") [-d] [-b] [-u] [-m] [-s]"
  echo
}

function generation_options {
  while getopts "dbums" option; do
    case ${option} in
    d)
      IGNORE_DIRTY=1
      ;;
    b)
      IGNORE_BRANCH=1
      ;;
    u)
      IGNORE_UPSTREAM=1
      ;;
    m)
      IGNORE_MACOS=1
      ;;
    s)
      SKIP_TEST=1
      ;;
    *)
      echo Invalid argument: -"${?}"
      usage
      exit 1
      ;;
    esac
  done
}

function check_workspace {
  local IGNORE_DIRTY=$1

  if [[ $(git status --porcelain | wc -l) -gt 0 ]]; then
    echo Workspace is dirty.
    if [[ ${IGNORE_DIRTY} -eq 0 ]]; then
      echo Aborting. Use '-d' to ignore.
      echo
      exit 1
    else
      echo Ignoring dirty workspace.
      echo
    fi
  fi
}

function check_branch {
  local IGNORE_BRANCH=$1
  local IGNORE_UPSTREAM=$2
  local CURRENT_BRANCH

  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
  if [ "${CURRENT_BRANCH}" != "main" ]; then
    echo Branch is not main.
    if [[ ${IGNORE_BRANCH} -eq 0 ]]; then
      echo Aborting. Use '-b' to ignore.
      echo
      exit 1
    else
      echo Ignoring wrong branch.
      echo
    fi
  fi

  local UPSTREAM
  UPSTREAM=$(git status -sb | head -n 1 | sed -e 's/^## [^\.]*\(\.\.\.\)*\([^\.]*\)$/\2/')
  if [ -z "${UPSTREAM}" ]; then
    echo No upstream branch found.
    if [[ ${IGNORE_UPSTREAM} -eq 0 ]]; then
      echo Aborting. Use '-u' to ignore.
      echo
      exit 1
    else
      echo Ignoring missing upstream branch.
      echo
      return 0
    fi
  fi

  local LOCAL_HASH
  local UPSTREAM_HASH
  git fetch
  LOCAL_HASH=$(git rev-parse HEAD)
  UPSTREAM_HASH=$(git rev-parse "${UPSTREAM}")

  if [[ ! "${LOCAL_HASH}" == "${UPSTREAM_HASH}" ]]; then
    echo "${CURRENT_BRANCH}" not up to date with upstream.
    if [[ ${IGNORE_UPSTREAM} -eq 0 ]]; then
      echo Aborting. Use '-u' to ignore.
      echo
      exit 1
    else
      echo Ignoring branch not up to date.
      echo
    fi
  fi
}

# If host is macOS returns successfully (zero value return)
function check_running_on_macos {
  local FAIL_NON_MACOS=$1
  if [[ "$(uname)" =~ [Dd]arwin ]]; then
    return 0
  fi
  if [[ $FAIL_NON_MACOS -eq 1 ]]; then
    echo Script is not running on macOS.
    echo Aborting. Use '-m' to ignore.
    echo
    exit 1
  fi
  return 1
}

function assert_docker_status {
  if ! docker stats --no-stream; then
    echo Please start the Docker daemon to continue.
    exit 1
  fi
}

function parse_version {
  local VERSION="${1}"
  echo Version: "${VERSION}"
  echo "${VERSION}" | egrep -q '^[0-9]+\.[0-9]+\.[0-9]+$'
}

function prompt_yes_no {
  while true; do
    read -p "$1 (y/n): " yn
    case $yn in
    [Yy]*) break ;;
    [Nn]*) return 1 ;;
    *) echo "Please answer (y)es or (n)o." ;;
    esac
  done
  return 0
}

function validate_crate_version {
  local CRATE_DIR=$1
  local REPO_ROOT
  REPO_ROOT=$(git rev-parse --show-toplevel)

  pushd "${CRATE_DIR}" &>/dev/null

  local CRATE_NAME
  CRATE_NAME=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -n "Cargo.toml")

  local CRATE_VERSION
  CRATE_VERSION=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -v "Cargo.toml")

  PUBLISHED_CRATE_VERSION=$(cargo search "${CRATE_NAME}" | egrep "^${CRATE_NAME} " | sed -e 's/.*"\(.*\)".*/\1/')

  if ! parse_version "${PUBLISHED_CRATE_VERSION}"; then
    echo Could not find current version of published crate.
    exit 1
  fi

  echo
  echo "Current published version of ${CRATE_NAME}: ${PUBLISHED_CRATE_VERSION}"
  if parse_version "${CRATE_VERSION}"; then
    if ! perl -e "exit !(version->parse('${CRATE_VERSION}')>version->parse('${PUBLISHED_CRATE_VERSION}'))"; then
      echo "New version must come after: ${PUBLISHED_CRATE_VERSION}"
      exit 1
    fi
  else
    echo Could not parse version: "${CRATE_VERSION}"
    exit 1
  fi

  popd &>/dev/null # "${CRATE_DIR}"

  echo
  echo "Generating crate with version: ${CRATE_VERSION}"
}
