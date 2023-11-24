#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"

CLEANUP_ON_EXIT=()

function cleanup() {
    for x in ${CLEANUP_ON_EXIT[@]}; do
        rm -rf "${x}"
    done
}

trap cleanup EXIT

# Get aws-lc-rs version
pushd "${ROOT}/aws-lc-rs"
AWS_LC_RS_VERSION=$(cargo read-manifest | jq .version -r)
popd &>/dev/null # "${ROOT}/aws-lc-rs"

RUSTLS_WEBPKI_DIR="$(mktemp -d)"
CLEANUP_ON_EXIT+=("${RUSTLS_WEBPKI_DIR}")
cargo download rustls-webpki | tar xvzf - -C "${RUSTLS_WEBPKI_DIR}" --strip-components=1
RUSTLS_WEBPKI_COMMIT="$(jq -r '.git.sha1' ${RUSTLS_WEBPKI_DIR}/.cargo_vcs_info.json)"
rm -rf "${RUSTLS_WEBPKI_DIR}" # Cleanup before we clone

RUSTLS_DIR="$(mktemp -d)"
CLEANUP_ON_EXIT+=("${RUSTLS_DIR}")
cargo download rustls | tar xvzf - -C "${RUSTLS_DIR}" --strip-components=1
RUSTLS_COMMIT="$(jq -r '.git.sha1' ${RUSTLS_DIR}/.cargo_vcs_info.json)"
rm -rf "${RUSTLS_DIR}" # Cleanup before we clone

git clone https://github.com/rustls/webpki.git "${RUSTLS_WEBPKI_DIR}"
git clone https://github.com/rustls/rustls.git "${RUSTLS_DIR}"

# Update rustls-webpki to use the GitHub repository reference under test.
pushd "${RUSTLS_WEBPKI_DIR}"
git checkout "${RUSTLS_WEBPKI_COMMIT}"
cargo add --path "${ROOT}/aws-lc-rs"
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
cargo tree -i aws-lc-rs --features aws_lc_rs
cargo test --features aws_lc_rs
popd &>/dev/null # "${RUSTLS_WEBPKI_DIR}"

pushd "${RUSTLS_DIR}"
git checkout "${RUSTLS_COMMIT}"
pushd ./rustls
# Update the Cargo.toml to use the GitHub repository reference under test.
cargo add --path "${RUSTLS_WEBPKI_DIR}" --rename webpki
cargo add --path "${ROOT}/aws-lc-rs"
# Trigger Cargo to generate the lock file
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
# Print the dependency tree for debug purposes, if we did everything right there
# should only be one aws-lc-rs version. Otherwise this will fail sine there are multiple versions
cargo tree -i aws-lc-rs --features aws_lc_rs
# Run the rustls tests with the aws_lc_rs feature enabled
cargo test --features aws_lc_rs
popd &>/dev/null # ./rustls
popd &>/dev/null # ${RUSTLS_DIR}
