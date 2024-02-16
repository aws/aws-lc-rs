# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

function usage {
  echo
  echo "Usage: $(basename "${0}") [-d] [-b] [-u] [-m] [-s]"
  echo
}

IGNORE_DIRTY=0
IGNORE_BRANCH=0
IGNORE_UPSTREAM=0
IGNORE_MACOS=0
SKIP_TEST=0

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
      # shellcheck disable=SC2034
      IGNORE_MACOS=1
      ;;
    s)
      # shellcheck disable=SC2034
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
  # TODO: determine expectations for branch name
  # Always ignore branch
  local IGNORE_BRANCH=1
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
  UPSTREAM=$(git status -sb | head -n 1 | sed -e 's/^## \(.*\.\.\.\)*\(.*\)$/\2/')
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

# If host is macOS, echos 1 and returns successfully (zero value return)
function check_running_on_macos {
  local ALLOW_NON_MACOS=$1
  if [[ "$(uname)" =~ [Dd]arwin ]]; then
    echo "1"
    return 0
  fi
  echo "0"
  >&2 echo Script is not running on macOS.
  if [[ $ALLOW_NON_MACOS -ne 1 ]]; then
    return 1
  fi
  >&2 echo Ignoring script not running on macOS
  return 0
}

function assert_docker_status {
  if ! docker ps &>/dev/null; then
    echo Please start the Docker daemon to continue.
    exit 1
  fi
}

function parse_version {
  local VERSION="${1}"
  echo Version: "${VERSION}"
  echo "${VERSION}" | grep -E -q '^[0-9]+\.[0-9]+\.[0-9]+$'
}

function prompt_yes_no {
  while true; do
    read -rp "$1 (y/n): " yn
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

  pushd "${CRATE_DIR}" &>/dev/null || exit 1

  local CRATE_NAME
  CRATE_NAME=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -n)

  local CRATE_VERSION
  CRATE_VERSION=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -v)

  PUBLISHED_CRATE_VERSION=$(cargo search "${CRATE_NAME}" | grep -E "^${CRATE_NAME} " | sed -e 's/.*"\(.*\)".*/\1/')

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

  popd &>/dev/null || exit 1 # "${CRATE_DIR}"

  echo
  echo "Generating crate with version: ${CRATE_VERSION}"
}

function submodule_commit_metadata {
  local CRATE_DIR=$1
  local REPO_ROOT
  REPO_ROOT=$(git rev-parse --show-toplevel)

  pushd "${REPO_ROOT}" &>/dev/null || exit 1
  COMMIT_HASH=$(git submodule status -- "${CRATE_DIR}"/aws-lc | sed -e 's/.\([0-9a-f]*\).*/\1/')
  perl -pi -e "s/commit-hash .*/commit-hash = \"${COMMIT_HASH}\"/" "${CRATE_DIR}"/Cargo.toml
  popd &>/dev/null || exit 1
}
