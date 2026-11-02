#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Used by the bindings-generator commit jobs, which can push but run none of the
# generation tooling. Applies the patches written by
# ci_export_generated_changes.sh, rejects any change outside of the given
# pathspecs, then commits and pushes to the branch being generated.

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

# Generated output only consists of regular, non-executable files.
UNEXPECTED="$(git diff --cached --raw --no-renames | awk '$2 != "100644" && $2 != "000000" { print $NF }')"
UNEXPECTED+="$(git diff --cached --name-only | grep -E '(^|/)\.git' || true)"
if [[ -n "${UNEXPECTED}" ]]; then
  echo "Patches add unexpected file types or modes:" >&2
  echo "${UNEXPECTED}" >&2
  exit 1
fi

git diff --cached --stat
git commit --allow-empty -m "${MESSAGE}"
# Sync the worktree with the validated commit so that a rebase can run.
git reset --hard HEAD

for ((attempt = 1; attempt <= 5; attempt++)); do
  if git push origin "HEAD:refs/heads/${BRANCH}"; then
    exit 0
  fi
  sleep $((attempt * 5))
  git pull --rebase origin "${BRANCH}"
done

echo "Failed to push to ${BRANCH}" >&2
exit 1
