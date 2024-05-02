#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)

SIM_IMAGE_LIST_PATH='/Library/Developer/CoreSimulator/Images/images.plist'
SIM_IMAGE_MOUNT_BASE='/Volumes'
SIM_IMAGE_PATTERN='iOS-17'

if [[ ! -r "${SIM_IMAGE_LIST_PATH}" ]]; then
  echo ERROR: Image list not found: "${SIM_IMAGE_LIST_PATH}"
  exit 1
fi

function plist_count_images() {
  plutil -extract 'images' raw  "${SIM_IMAGE_LIST_PATH}" -o -
}

function plist_image_id_for() {
  plutil -extract "images.${1}.runtimeInfo.bundleIdentifier" raw  "${SIM_IMAGE_LIST_PATH}" -o -
}

function plist_image_path_for() {
  plutil -extract "images.${1}.path.relative" raw  "${SIM_IMAGE_LIST_PATH}" -o - | sed -e 's/^file:\/\///'
}

function plist_image_build_for() {
  plutil -extract "images.${1}.runtimeInfo.build" raw  "${SIM_IMAGE_LIST_PATH}" -o -
}

function find_mount() {
  hdiutil info | grep -s "${1}"
}

function find_runtime_root() {
  find "${1}" -type d -name "RuntimeRoot" |head -n 1
}


IMAGE_LIST_SIZE=$(plist_count_images)
IMAGE_LIST_LAST_IDX=$(( "${IMAGE_LIST_SIZE}" - 1 ))
IMAGE_PATH=''
IMAGE_BUILD=''


for i in $(seq 0 "${IMAGE_LIST_LAST_IDX}"); do
  if [[ $(plist_image_id_for "${i}") == *"${SIM_IMAGE_PATTERN}"* ]]; then
    IMAGE_PATH=$(plist_image_path_for "${i}")
    IMAGE_BUILD=$(plist_image_build_for "${i}")
  fi
done

if [[ -z ${IMAGE_PATH} ]]; then
  echo ERROR: ${SIM_IMAGE_PATTERN} image not found.
  exit 1
fi

IMAGE_MOUNT_POINT="${SIM_IMAGE_MOUNT_BASE}/iOS_${IMAGE_BUILD}"

if ! find_mount "${IMAGE_MOUNT_POINT}"; then
  sudo hdiutil attach "${IMAGE_PATH}" -mountpoint "${IMAGE_MOUNT_POINT}"
fi

if ! find_mount "${IMAGE_MOUNT_POINT}"; then
  echo ERROR: Unable to mount runtime
  exit 1
fi

DYLD_ROOT_PATH=''
DYLD_ROOT_PATH=$(find_runtime_root "${IMAGE_MOUNT_POINT}")

if [[ -z "${DYLD_ROOT_PATH}" ]]; then
  echo ERROR: RuntimeRoot not found: "${IMAGE_MOUNT_POINT}"
  exit 1
fi

export DYLD_ROOT_PATH
cd "${REPO_ROOT}"/aws-lc-rs

cargo test --features bindgen,unstable --target aarch64-apple-ios-sim

cargo test --release --features bindgen,unstable --target aarch64-apple-ios-sim
