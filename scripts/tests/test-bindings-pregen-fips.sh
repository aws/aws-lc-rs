#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -ex
set -o pipefail

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
REPO_ROOT=$(git -C "${SCRIPT_DIR}"  rev-parse --show-toplevel)

pushd "${REPO_ROOT}" || exit
cargo clean
AWS_LC_FIPS_SYS_NO_PREFIX=1 cargo test -p aws-lc-fips-sys --features bindgen
rm -rf ./aws-lc-fips-sys/symbols/* ./aws-lc-fips-sys/generated-include/*
mkdir -p ./aws-lc-fips-sys/symbols ./aws-lc-fips-sys/generated-include/openssl
./scripts/build/collect_symbols.sh -c aws-lc-fips-sys
./scripts/generate/_generate_prefix_headers.sh -f -c aws-lc-fips-sys
./scripts/ci/update_sys_crate_metadata.sh aws-lc-fips-sys
cargo clean
AWS_LC_FIPS_SYS_PREGENERATING_BINDINGS=1 cargo test -p aws-lc-fips-sys --features bindgen
popd
