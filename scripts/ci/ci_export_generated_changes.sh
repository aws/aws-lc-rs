#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Used by the bindings-generator jobs that build and generate files. Those jobs
# run third-party code and have no write access, so instead of committing they
# export their changes as a patch for a commit job to apply (see
# ci_commit_generated_changes.sh).
#
# Fails if anything outside of the given pathspecs changed, then writes the
# allowed changes to "${RUNNER_TEMP}/generated-changes/<NAME>.patch".

set -euxo pipefail

usage() {
  echo "Usage: ${0} <NAME> <PATHSPEC>..." >&2
  exit 1
}

[[ $# -ge 2 ]] || usage
NAME="${1}"
shift
[[ "${NAME}" =~ ^[A-Za-z0-9._-]+$ ]] || usage

OUT_DIR="${RUNNER_TEMP:?RUNNER_TEMP must be set}/generated-changes"
if command -v cygpath &>/dev/null; then
  OUT_DIR="$(cygpath -u "${OUT_DIR}")"
fi
mkdir -p "${OUT_DIR}"

EXCLUDES=()
for pathspec in "$@"; do
  EXCLUDES+=(":(exclude)${pathspec}")
done

cargo fmt
git add --all .

UNEXPECTED="$(git diff --cached --name-only -- . "${EXCLUDES[@]}")"
if [[ -n "${UNEXPECTED}" ]]; then
  echo "Unexpected changes outside of: $*" >&2
  echo "${UNEXPECTED}" >&2
  exit 1
fi

git diff --cached --binary -- "$@" >"${OUT_DIR}/${NAME}.patch"
git diff --cached --stat -- "$@"
