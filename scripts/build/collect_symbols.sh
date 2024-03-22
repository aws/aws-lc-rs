#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

function find_rust_platform() {
  rustc -Vv | grep -E "^host" | perl -p -e 's/^host:\s*(\S*)/\1/'
}

function usage() {
  echo Usage:
  echo     "${0} -c <CRATE_NAME> [-t <PLATFORM>]"
  echo
}

CRATE_NAME=""
PLATFORM="$(find_rust_platform)"

while getopts "t:c:" option; do
  case ${option} in
  t)
    PLATFORM="${OPTARG}"
    ;;
  c)
    CRATE_NAME="${OPTARG}"
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
  usage
  exit 1
fi

if [[ -z "${CRATE_NAME}" ]]; then
  echo "MUST SPECIFY CRATE_NAME"
  usage
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
AWS_LC_DIR="${REPO_ROOT}/${CRATE_NAME}/aws-lc"
SYMBOLS_FILE="${REPO_ROOT}/${CRATE_NAME}/symbols/${PLATFORM}.txt"

if [[ ! -d "${AWS_LC_DIR}" ]]; then
  echo "INVALID DIRECTORY: ${AWS_LC_DIR}"
  usage
  exit 1
fi

function filter_symbols() {
  grep -v -E "^bignum_" | grep -v "curve25519_x25519" | grep -v "edwards25519_"
}

function filter_nm_symbols() {
  grep -v -E '^_Z' | grep -v 'BORINGSSL_bcm_' | grep -v 'BORINGSSL_integrity_test'
}

function filter_macho_symbols() {
  grep -E '^_' | sed -e 's/^_\(.*\)/\1/'
}

function find_libcrypto() {
  find "${REPO_ROOT}/target" -type f \( -name "lib*crypto.a" -o -name "lib*crypto.so" -o -name "lib*crypto.dylib" \) | grep "${CRATE_NAME}"
}

function find_libssl() {
  find "${REPO_ROOT}/target" -type f \( -name "lib*ssl.a" -o -name "lib*ssl.so" -o -name "lib*ssl.dylib" \) | grep "${CRATE_NAME}"
}

LIBCRYPTO_PATH="$(find_libcrypto)"
if [[ "${?}" -ne 0 ]]; then
  echo "Unable to find libcrypto"
  exit 1
fi

LIBSSL_PATH="$(find_libssl)"
if [[ "${?}" -ne 0 ]]; then
  echo "Unable to find libssl"
  exit 1
fi

mkdir -p "$(dirname "${SYMBOLS_FILE}")"
echo Writing symbols to: ${SYMBOLS_FILE}

if [[ "${LIBCRYPTO_PATH}" = *.dylib ]]; then
  nm --extern-only --defined-only -j  "${LIBCRYPTO_PATH}" "${LIBSSL_PATH}" | grep -v "${REPO_ROOT}" | sort | uniq | filter_macho_symbols | filter_nm_symbols |  filter_symbols >"${SYMBOLS_FILE}"
elif [[ "${LIBCRYPTO_PATH}" = *.so ]]; then
  nm --extern-only --defined-only --format=just-symbols  "${LIBCRYPTO_PATH}" "${LIBSSL_PATH}" | grep -v "${REPO_ROOT}" | sort | uniq | filter_nm_symbols | filter_symbols >"${SYMBOLS_FILE}"
else
  pushd "${AWS_LC_DIR}"
  go run -mod readonly "${AWS_LC_DIR}"/util/read_symbols.go "${LIBCRYPTO_PATH}" "${LIBSSL_PATH}" | filter_symbols >"${SYMBOLS_FILE}"
  popd
fi

echo SUCCESS
