#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

ROOT=$PWD
QUIC_RING_STRING="^ring = { .* optional .* }"
QUIC_OUR_STRING="ring = { path = \"${PWD}\", optional = true, package = \"aws-lc-rust\"}"
QUIC_CRYPTO_RING_STRING="^ring = { .* }"
QUIC_CRYPTO_OUR_STRING="ring = { path = \"${PWD}\", package = \"aws-lc-rust\"}"

git clone https://github.com/aws/s2n-quic.git
cd s2n-quic

# replace instances of ring with our crate
if [[ "$(uname)" == "Darwin" ]]; then
	find ./ -type f  -name "Cargo.toml" | xargs sed -i '' -e "s|${QUIC_RING_STRING}|${QUIC_OUR_STRING}|g" -e "s|${QUIC_CRYPTO_RING_STRING}|${QUIC_CRYPTO_OUR_STRING}|g"
else
	find ./ -type f  -name "Cargo.toml" | xargs sed -i -e "s|${QUIC_RING_STRING}|${QUIC_OUR_STRING}|g" -e "s|${QUIC_CRYPTO_RING_STRING}|${QUIC_CRYPTO_OUR_STRING}|g"
fi
cargo test
