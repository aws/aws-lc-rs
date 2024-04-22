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

RUSTLS_RCGEN_DIR="$(mktemp -d)"
CLEANUP_ON_EXIT+=("${RUSTLS_RCGEN_DIR}")
cargo download rcgen | tar xvzf - -C "${RUSTLS_RCGEN_DIR}" --strip-components=1
RUSTLS_RCGEN_COMMIT="$(jq -r '.git.sha1' ${RUSTLS_RCGEN_DIR}/.cargo_vcs_info.json)"
rm -rf "${RUSTLS_RCGEN_DIR}" # Cleanup before we clone

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

git clone https://github.com/rustls/rcgen "${RUSTLS_RCGEN_DIR}"
git clone https://github.com/rustls/webpki.git "${RUSTLS_WEBPKI_DIR}"
git clone https://github.com/rustls/rustls.git "${RUSTLS_DIR}"

# Update rcgen to use the GitHub repository reference under test.
pushd "${RUSTLS_RCGEN_DIR}"
git checkout "${RUSTLS_RCGEN_COMMIT}"
cargo add --path "${ROOT}/aws-lc-rs" --package rcgen
cargo add --path "${ROOT}/aws-lc-rs" --package rustls-cert-gen
cargo update
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
cargo test --features aws_lc_rs
popd &>/dev/null # "${RUSTLS_RCGEN_DIR}"

# Update rustls-webpki to use the GitHub repository reference under test.
pushd "${RUSTLS_WEBPKI_DIR}"
git checkout "${RUSTLS_WEBPKI_COMMIT}"
WEBPKI_RCGEN_STRING="^rcgen = { .* }"
WEBPKI_RCGEN_PATH_STRING="rcgen = { path = \"${RUSTLS_RCGEN_DIR}/rcgen\" , default-features = false, features = [\"aws_lc_rs\"] }"
WEBPKI_AWS_LC_RS_STRING="^aws-lc-rs = { version.* }"
WEBPKI_AWS_LC_RS_PATH_STRING="aws-lc-rs = { path = \"${ROOT}/aws-lc-rs\", optional = true, default-features = false, features = [\"aws-lc-sys\"] }"
if [[ "$(uname)" == "Darwin" ]]; then
	find ./ -type f  -name "Cargo.toml" | xargs sed -i '' -e "s|${WEBPKI_RCGEN_STRING}|${WEBPKI_RCGEN_PATH_STRING}|g" -e "s|${WEBPKI_AWS_LC_RS_STRING}|${WEBPKI_AWS_LC_RS_PATH_STRING}|g"
else
	find ./ -type f  -name "Cargo.toml" | xargs sed -i -e "s|${WEBPKI_RCGEN_STRING}|${WEBPKI_RCGEN_PATH_STRING}|g" -e "s|${WEBPKI_AWS_LC_RS_STRING}|${WEBPKI_AWS_LC_RS_PATH_STRING}|g"
fi
# Trigger Cargo to generate the lock file
cargo update
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
cargo tree -i aws-lc-rs --features aws_lc_rs
cargo test --features aws_lc_rs
popd &>/dev/null # "${RUSTLS_WEBPKI_DIR}"

pushd "${RUSTLS_DIR}"
git checkout "${RUSTLS_COMMIT}"
pushd ./rustls
# Update the Cargo.toml to use the GitHub repository reference under test.
RUSTLS_RCGEN_STRING="^rcgen = { .* }"
RUSTLS_RCGEN_PATH_STRING="rcgen = { path = \"${RUSTLS_RCGEN_DIR}/rcgen\" , default-features = false, features = [\"aws_lc_rs\", \"pem\"] }"
RUSTLS_AWS_LC_RS_STRING="^aws-lc-rs = { version.* }"
RUSTLS_AWS_LC_RS_PATH_STRING="aws-lc-rs = { path = \"${ROOT}/aws-lc-rs\", optional = true, default-features = false, features = [\"aws-lc-sys\"] }"
RUSTLS_WEBPKI_STRING="^webpki = { package.* }"
RUSTLS_WEBPKI_PATH_STRING="webpki = { package = \"rustls-webpki\", path = \"${RUSTLS_WEBPKI_DIR}\", features = [\"alloc\"], default-features = false }"
if [[ "$(uname)" == "Darwin" ]]; then
	find ./ -type f  -name "Cargo.toml" | xargs sed -i '' -e "s|${RUSTLS_RCGEN_STRING}|${RUSTLS_RCGEN_PATH_STRING}|g" -e "s|${RUSTLS_AWS_LC_RS_STRING}|${RUSTLS_AWS_LC_RS_PATH_STRING}|g" -e "s|${RUSTLS_WEBPKI_STRING}|${RUSTLS_WEBPKI_PATH_STRING}|g"
else
	find ./ -type f  -name "Cargo.toml" | xargs sed -i -e "s|${RUSTLS_RCGEN_STRING}|${RUSTLS_RCGEN_PATH_STRING}|g" -e "s|${RUSTLS_AWS_LC_RS_STRING}|${RUSTLS_AWS_LC_RS_PATH_STRING}|g" -e "s|${RUSTLS_WEBPKI_STRING}|${RUSTLS_WEBPKI_PATH_STRING}|g"
fi
# Trigger Cargo to generate the lock file
cargo update
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
# Print the dependency tree for debug purposes, if we did everything right there
# should only be one aws-lc-rs version. Otherwise this will fail sine there are multiple versions
cargo tree -i aws-lc-rs --features aws_lc_rs
# Run the rustls tests with the aws_lc_rs feature enabled
cargo test --features aws_lc_rs
popd &>/dev/null # ./rustls
popd &>/dev/null # ${RUSTLS_DIR}
