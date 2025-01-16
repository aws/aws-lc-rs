#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

. "${HOME}/.cargo/env"
SRC_DIR="${SRC_DIR:-/aws_lc_rs}"

pushd "${SRC_DIR}"

declare -A target_map
target_map[aarch64-unknown-linux-ohos]="aarch64-linux-ohos"
target_map[armv7-unknown-linux-ohos]="arm-linux-ohos"
target_map[x86_64-unknown-linux-ohos]="x86_64-linux-ohos"

function build_ohos_targets() {
  for target in aarch64-unknown-linux-ohos armv7-unknown-linux-ohos x86_64-unknown-linux-ohos
  do
    export CPATH=/ohos/linux/native/sysroot/usr/include/:/ohos/linux/native/sysroot/usr/include/${target_map[${target}]}
    cargo build -p aws-lc-rs --target ${target}
    cargo clean
  done
}

cargo clean
build_ohos_targets
unset CMAKE_TOOLCHAIN_FILE
build_ohos_targets
unset OHOS_NDK_HOME
build_ohos_targets

popd # ${SRC_DIR}
