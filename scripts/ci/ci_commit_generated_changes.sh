#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Used by the bindings-generator commit jobs, which can push but run none of the
# generation tooling. Applies the patches written by
# ci_export_generated_changes.sh, rejects any change outside of the given
# pathspecs, then commits and pushes to the branch being generated.
# These checks contain writes; they do not establish that generated source or
# object code is benign. See README.md for the security boundary.

set -euxo pipefail

usage() {
  echo "Usage: ${0} <COMMIT_MESSAGE> <PATCH_DIR> <PATHSPEC>..." >&2
  exit 1
}

[[ $# -ge 3 ]] || usage
MESSAGE="${1}"
PATCH_DIR="${2}"
shift 2
BRANCH="${GITHUB_REF_NAME:?GITHUB_REF_NAME must be set}"
BASE_SHA="$(git rev-parse HEAD)"

EXCLUDES=()
for pathspec in "$@"; do
  EXCLUDES+=(":(exclude)${pathspec}")
done

shopt -s nullglob
PATCHES=("${PATCH_DIR}"/*.patch)
if [[ ${#PATCHES[@]} -eq 0 ]]; then
  echo "No patches found in ${PATCH_DIR}" >&2
  exit 1
fi

# Apply to the index only, so nothing in the worktree (including this script)
# changes until the result has been validated.
for patch in "${PATCHES[@]}"; do
  if [[ -s "${patch}" ]]; then
    git apply --cached --whitespace=nowarn "${patch}"
  fi
done

UNEXPECTED="$(git diff --cached --name-only -- . "${EXCLUDES[@]}")"
if [[ -n "${UNEXPECTED}" ]]; then
  echo "Patches change files outside of: $*" >&2
  echo "${UNEXPECTED}" >&2
  exit 1
fi

# Generated output must use regular files with non-executable file modes.
# This does not prevent those files from containing code.
UNEXPECTED="$(git diff --cached --raw --no-renames | awk '$2 != "100644" && $2 != "000000" { print $NF }')"
UNEXPECTED+="$(git diff --cached --name-only | grep -E '(^|/)\.git' || true)"
if [[ -n "${UNEXPECTED}" ]]; then
  echo "Patches add unexpected file types or modes:" >&2
  echo "${UNEXPECTED}" >&2
  exit 1
fi

git diff --cached --stat
git commit --allow-empty -m "${MESSAGE}"
COMMIT_SHA="$(git rev-parse HEAD)"
# Leave generated content in the index, not the worktree. No generation tooling
# or generated code should run in this job while it holds a write token.

for ((attempt = 1; attempt <= 5; attempt++)); do
  # The sole parent is BASE_SHA. The explicit lease makes the update conditional
  # on that exact input commit, even if the branch was rewound or deleted. Never
  # rebase: input changes can invalidate output without causing a merge conflict.
  if git push --force-with-lease="refs/heads/${BRANCH}:${BASE_SHA}" origin "HEAD:refs/heads/${BRANCH}"; then
    exit 0
  fi
  if REMOTE_SHA="$(git ls-remote --refs origin "refs/heads/${BRANCH}" | cut -f1)"; then
    # A push may have succeeded even if the client did not receive confirmation.
    if [[ "${REMOTE_SHA}" == "${COMMIT_SHA}" ]]; then
      exit 0
    fi
    if [[ "${REMOTE_SHA}" != "${BASE_SHA}" ]]; then
      echo "Branch ${BRANCH} changed since generation at ${BASE_SHA}; start a new generation run from the current tip." >&2
      exit 1
    fi
  fi
  if ((attempt < 5)); then
    sleep $((attempt * 5))
  fi
done

echo "Failed to push to ${BRANCH}" >&2
exit 1
