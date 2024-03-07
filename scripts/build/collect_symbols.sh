#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

function find_rust_platform() {
  rustc -Vv | grep -E "^host" | perl -p -e 's/^host:\s*(\S*)/\1/'
}

PLATFORM="$(find_rust_platform)"

while getopts "t:" option; do
  case ${option} in
  t)
    PLATFORM="${OPTARG}"
    ;;
  *)
    echo Invalid argument: -"${?}"
    usage
    exit 1
    ;;
  esac
done

if [[ -z "${PLATFORM}" ]]; then
  echo "MUST SPECIFY PLATFORM"
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
AWS_LC_DIR="${REPO_ROOT}/aws-lc-sys/aws-lc"
SYMBOLS_FILE="${REPO_ROOT}/aws-lc-sys/symbols/${PLATFORM}.txt"


function filter_symbols() {
    grep -v "^_\?bignum_" | grep -v "_\?curve25519_x25519" | grep -v "_\?edwards25519_" | grep -v "pqcrystals"
}

function find_libcryptos() {
  find "${REPO_ROOT}/target" -type f -name "libcrypto.a" | grep "aws-lc-sys"
}

function find_libssls() {
  find "${REPO_ROOT}/target" -type f -name "libssl.a" | grep "aws-lc-sys"
}

LIBCRYPTO_PATH=("$(find_libcryptos)")
if [[ "${?}" -ne 0 ]]; then
  echo "Unable to find libcrypto.a"
  exit 1
fi

LIBSSL_PATH=("$(find_libssls)")
if [[ "${?}" -ne 0 ]]; then
  echo "Unable to find libssl.a"
  exit 1
fi

mkdir -p "$(dirname "${SYMBOLS_FILE}")"
echo Writing symbols to: ${SYMBOLS_FILE}

pushd "${AWS_LC_DIR}"
go run -mod readonly "${AWS_LC_DIR}"/util/read_symbols.go ${LIBCRYPTO_PATH[@]} ${LIBSSL_PATH[@]} | filter_symbols >"${SYMBOLS_FILE}"
popd

echo SUCCESS
