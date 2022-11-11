#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

RUSTLS_RING_STRING="^ring = \".*\""
RUSTLS_OUR_STRING="ring = { path = \"../../../aws-lc-ring\", package = \"aws-lc-ring\"}"

git clone https://github.com/rustls/rustls.git
cd rustls

# replace instances of ring with our crate
if [[ "$(uname)" == "Darwin" ]]; then
	find ./ -type f  -name "Cargo.toml" | xargs sed -i '' "s|${RUSTLS_RING_STRING}|${RUSTLS_OUR_STRING}|g"
else
	find ./ -type f  -name "Cargo.toml" | xargs sed -i "s|${RUSTLS_RING_STRING}|${RUSTLS_OUR_STRING}|g"
fi
cargo test
