#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

QUIC_AWS_LC_RS_STRING="^aws-lc-rs = { .* }"
QUIC_PATH_STRING="aws-lc-rs = { path = \"${PWD}\" }"

git clone https://github.com/aws/s2n-quic.git
cd s2n-quic

# replace instances of ring with our crate
if [[ "$(uname)" == "Darwin" ]]; then
	find ./ -type f  -name "Cargo.toml" | xargs sed -i '' -e "s|${QUIC_AWS_LC_RS_STRING}|${QUIC_PATH_STRING}|"
else
	find ./ -type f  -name "Cargo.toml" | xargs sed -i -e "s|${QUIC_AWS_LC_RS_STRING}|${QUIC_PATH_STRING}|"
fi
cargo test
