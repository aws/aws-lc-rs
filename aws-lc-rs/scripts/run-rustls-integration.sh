#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"

latest_release=0
for arg in "$@"; do
  if [ "$arg" = "--latest-release" ]; then
    latest_release=1
  fi
done

CLEANUP_ON_EXIT=()

function cleanup() {
    for x in "${CLEANUP_ON_EXIT[@]}"; do
        rm -rf "${x}"
    done
}

trap cleanup EXIT

#TODO: Call this function for all uses of sed
function sed_replace {
  local filepath="${1}";
  shift
  while [[ $# -gt 0 ]]; do
      local pattern="${1}";
      if [[ "$(uname)" == "Darwin" ]]; then
      	sed -i '' -e "${pattern}" "${filepath}"
      else
      	sed -i -e "${pattern}" "${filepath}"
      fi
      shift
  done
}


# Get aws-lc-rs version
pushd "${ROOT}/aws-lc-rs"
AWS_LC_RS_VERSION=$(cargo read-manifest | jq .version -r)
popd &>/dev/null # "${ROOT}/aws-lc-rs"

RUSTLS_RCGEN_DIR="$(mktemp -d)"
CLEANUP_ON_EXIT+=("${RUSTLS_RCGEN_DIR}")
cargo download -o "${RUSTLS_RCGEN_DIR}"/rcgen.tar.gz rcgen
tar xvzf "${RUSTLS_RCGEN_DIR}"/rcgen.tar.gz -C "${RUSTLS_RCGEN_DIR}" --strip-components=1
rm "${RUSTLS_RCGEN_DIR}"/rcgen.tar.gz
RUSTLS_RCGEN_COMMIT="$(jq -r '.git.sha1' ${RUSTLS_RCGEN_DIR}/.cargo_vcs_info.json)"
rm -rf "${RUSTLS_RCGEN_DIR}" # Cleanup before we clone

RUSTLS_WEBPKI_DIR="$(mktemp -d)"
CLEANUP_ON_EXIT+=("${RUSTLS_WEBPKI_DIR}")
cargo download -o "${RUSTLS_WEBPKI_DIR}"/rustls-webpki.tar.gz rustls-webpki
tar xvzf "${RUSTLS_WEBPKI_DIR}"/rustls-webpki.tar.gz -C "${RUSTLS_WEBPKI_DIR}" --strip-components=1
rm "${RUSTLS_WEBPKI_DIR}"/rustls-webpki.tar.gz
RUSTLS_WEBPKI_COMMIT="$(jq -r '.git.sha1' ${RUSTLS_WEBPKI_DIR}/.cargo_vcs_info.json)"
rm -rf "${RUSTLS_WEBPKI_DIR}" # Cleanup before we clone

RUSTLS_DIR="$(mktemp -d)"
CLEANUP_ON_EXIT+=("${RUSTLS_DIR}")
if [[ $latest_release == "1" ]]; then
  cargo download -o "${RUSTLS_DIR}"/rustls.tar.gz rustls
  tar xvzf "${RUSTLS_DIR}"/rustls.tar.gz -C "${RUSTLS_DIR}" --strip-components=1
  rm "${RUSTLS_DIR}"/rustls.tar.gz
  RUSTLS_COMMIT="$(jq -r '.git.sha1' ${RUSTLS_DIR}/.cargo_vcs_info.json)"
  rm -rf "${RUSTLS_DIR}" # Cleanup before we clone
fi

git clone https://github.com/rustls/rcgen "${RUSTLS_RCGEN_DIR}"
git clone https://github.com/rustls/webpki.git "${RUSTLS_WEBPKI_DIR}"
git clone https://github.com/rustls/rustls.git "${RUSTLS_DIR}"

# Update rcgen to use the GitHub repository reference under test.
pushd "${RUSTLS_RCGEN_DIR}"
git checkout "${RUSTLS_RCGEN_COMMIT}"
rm Cargo.lock
RCGEN_AWS_LC_RS_STRING="^aws-lc-rs = .*"
RCGEN_AWS_LC_RS_PATH_STRING="aws-lc-rs = { path = \"${ROOT}/aws-lc-rs\", default-features = false, features = [\"aws-lc-sys\"] }"
sed_replace ./Cargo.toml "s|${RCGEN_AWS_LC_RS_STRING}|${RCGEN_AWS_LC_RS_PATH_STRING}|g"
cargo add --path "${ROOT}/aws-lc-rs" --package rustls-cert-gen
cargo update
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
cargo test --features aws_lc_rs
popd &>/dev/null # "${RUSTLS_RCGEN_DIR}"

# Update rustls-webpki to use the GitHub repository reference under test.
pushd "${RUSTLS_WEBPKI_DIR}"
git checkout "${RUSTLS_WEBPKI_COMMIT}"
rm Cargo.lock
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
cargo tree -i aws-lc-rs --features aws-lc-rs
cargo test --features aws-lc-rs
popd &>/dev/null # "${RUSTLS_WEBPKI_DIR}"

pushd "${RUSTLS_DIR}"
if [[ $latest_release == "1" ]]; then
  git checkout "${RUSTLS_COMMIT}"
fi
rm Cargo.lock
# Update the Cargo.toml to use the GitHub repository reference under test.
RUSTLS_RCGEN_STRING="^rcgen = { .* }"
RUSTLS_RCGEN_PATH_STRING="rcgen = { path = \"${RUSTLS_RCGEN_DIR}/rcgen\" , default-features = false, features = [\"aws_lc_rs\", \"pem\"] }"
RUSTLS_AWS_LC_RS_STRING="^aws-lc-rs = { version.* }"
RUSTLS_AWS_LC_RS_PATH_STRING="aws-lc-rs = { path = \"${ROOT}/aws-lc-rs\", default-features = false, features = [\"aws-lc-sys\"] }"
RUSTLS_AWS_LC_RS_NON_OPTIONAL_PATH_STRING="aws-lc-rs = { path = \"${ROOT}/aws-lc-rs\", default-features = false, features = [\"unstable\", \"aws-lc-sys\"] }"
RUSTLS_WEBPKI_STRING="^webpki = { package.* }"
RUSTLS_WEBPKI_PATH_STRING="webpki = { package = \"rustls-webpki\", path = \"${RUSTLS_WEBPKI_DIR}\", features = [\"alloc\"], default-features = false }"
sed_replace ./rustls-post-quantum/Cargo.toml "s|${RUSTLS_AWS_LC_RS_STRING}|${RUSTLS_AWS_LC_RS_NON_OPTIONAL_PATH_STRING}|g"
if [[ "$(uname)" == "Darwin" ]]; then
	find ./ -type f  -name "Cargo.toml" | xargs sed -i '' -e "s|${RUSTLS_RCGEN_STRING}|${RUSTLS_RCGEN_PATH_STRING}|g" -e "s|${RUSTLS_AWS_LC_RS_STRING}|${RUSTLS_AWS_LC_RS_PATH_STRING}|g" -e "s|${RUSTLS_WEBPKI_STRING}|${RUSTLS_WEBPKI_PATH_STRING}|g"
else
	find ./ -type f  -name "Cargo.toml" | xargs sed -i -e "s|${RUSTLS_RCGEN_STRING}|${RUSTLS_RCGEN_PATH_STRING}|g" -e "s|${RUSTLS_AWS_LC_RS_STRING}|${RUSTLS_AWS_LC_RS_PATH_STRING}|g" -e "s|${RUSTLS_WEBPKI_STRING}|${RUSTLS_WEBPKI_PATH_STRING}|g"
fi
# Trigger Cargo to generate the lock file
cargo update
cargo update "aws-lc-rs@${AWS_LC_RS_VERSION}"
pushd ./rustls

# Print the dependency tree for debug purposes, if we did everything right there
# should only be one aws-lc-rs version. Otherwise this will fail sine there are multiple versions
cargo tree -i aws-lc-rs --features aws-lc-rs
# Run the rustls tests with the aws-lc-rs feature enabled
cargo test --features aws-lc-rs
popd &>/dev/null # ./rustls
popd &>/dev/null # ${RUSTLS_DIR}
