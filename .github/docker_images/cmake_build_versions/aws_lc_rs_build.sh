#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

echo "Building with CMake Version: $(cmake --version)"
FIPS_BUILD=1

. "${HOME}/.cargo/env"
SRC_DIR="${SRC_DIR:-/aws_lc_rs}"


pushd "${SRC_DIR}"
cargo clean
cargo test -p aws-lc-rs --features=unstable
cargo clean
if  [ ${FIPS_BUILD} -eq 1 ]; then
  cargo test -p aws-lc-rs --features=unstable,fips
  cargo clean
fi
cargo test -p aws-lc-rs --release --features=unstable
cargo clean
if  [ ${FIPS_BUILD} -eq 1 ]; then
  cargo test -p aws-lc-rs --release --features=unstable,fips
  cargo clean
fi


popd # ${BUILD_DIR}
