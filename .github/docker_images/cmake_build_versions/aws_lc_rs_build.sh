#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

echo "Building with CMake Version: $(cmake --version)"

. "${HOME}/.cargo/env"
SRC_DIR="${SRC_DIR:-/aws_lc_rs}"


pushd "${SRC_DIR}"
cargo clean
cargo test -p aws-lc-rs --features=unstable
cargo clean
cargo test -p aws-lc-rs --features=unstable,fips
cargo clean
cargo test -p aws-lc-rs --release --features=unstable
cargo clean
cargo test -p aws-lc-rs --release --features=unstable,fips


popd # ${BUILD_DIR}
