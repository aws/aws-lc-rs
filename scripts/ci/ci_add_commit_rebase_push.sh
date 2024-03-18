#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -ex
set -o pipefail

cargo fmt
git add .
git commit --allow-empty -m "${1}"

set +e

MAX_ITERS=10
COUNTER=0
PUSH_SUCCESS=0
MAX_WAIT=7
while [[ ${PUSH_SUCCESS} -eq 0 && ${COUNTER} -lt ${MAX_ITERS} ]]; do
  sleep $((RANDOM % MAX_WAIT))
  git pull --rebase
  git push
  if [ ${?} -eq 0 ]; then
    PUSH_SUCCESS=1
  fi
  COUNTER=$(( COUNTER + 1 ))
done

if [[ ${PUSH_SUCCESS} -ne 1 ]]; then
  echo Failed to push commit.
  exit 1
fi

echo SUCCESS
