#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# This shell script performs a target-specific CMake static build of libcrypto. It extracts from that build artifact
# debug information on the complete set of source files utilized for the build and then generates a target-specific
# Rust source file (e.g., `x86_64_unknown_linux_gnu.rs`) that lists the files for subsequent use by the `cc_builder`
# module for consumer builds where CMake might not be available.

set -ex
set -o pipefail

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

CROSS_TARGET_ARCH=''

while getopts "t:" option; do
  case ${option} in
  t)
    CROSS_TARGET_ARCH="${OPTARG}";
    ;;
  *)
    echo Invalid argument: -"${?}"
    usage
    exit 1
    ;;
  esac
done

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
REPO_ROOT=$(git rev-parse --show-toplevel)
SYS_CRATE_DIR="${REPO_ROOT}/aws-lc-sys"
BUILD_CFG_DIR="${SYS_CRATE_DIR}/builder/cc_builder"
mkdir -p "${BUILD_CFG_DIR}"

function find_target() {
  if [[ -z "${CROSS_TARGET_ARCH}" ]]; then
    rustc -vV | grep host | sed -e 's/host: *\(\w*\)/\1/'
  else
    echo "${CROSS_TARGET_ARCH}"
  fi
}

function target_filename() {
  local target
  target=$(find_target)
  echo "${target//-/_}"
}

function collect_source_files() {
    TARGET_PLATFORM_ARCH=$(find_target)
    if [ $? -eq 1 ]; then
      echo "Error: find_target failed"
      exit 1
    fi
    if [[ "${TARGET_PLATFORM_ARCH}" =~ apple ]]; then
        dwarfdump --debug-info "${1}" | grep DW_AT_name | grep "$(pwd)" | cut -d\" -f 2 | sort | uniq
    elif [[ "${TARGET_PLATFORM_ARCH}" =~ linux ]]; then
        readelf -w "${1}" | grep DW_AT_name | grep 'aws-lc-sys' | cut -d: -f 4 | grep -E '\.[csS]$' | sort | uniq
    else
        echo Unknown OS: "${TARGET_PLATFORM_ARCH}"
        exit 1
    fi
}

function find_s2n_bignum_src_dir() {
    TARGET_PLATFORM_ARCH=$(find_target)
    if [ $? -eq 1 ]; then
      echo "Error: find_target failed"
      exit 1
    fi
    if [[ "${TARGET_PLATFORM_ARCH}" =~ aarch64 ]]; then
        echo arm
    else
        echo x86_att
    fi
}


function find_generated_src_dir() {
    TARGET_PLATFORM_ARCH=$(find_target)
    if [ $? -eq 1 ]; then
      echo "Error: find_target failed"
      exit 1
    fi

    if [[ "${TARGET_PLATFORM_ARCH}" =~ "linux" ]]; then
      OS_NAME="linux"
    elif [[ "${TARGET_PLATFORM_ARCH}" =~ "apple" ]]; then
      OS_NAME="mac"
      if [[ "${TARGET_PLATFORM_ARCH}" =~ "aarch64" ]]; then
        OS_NAME="ios"
      fi
    else
      echo Unknown OS: "${TARGET_PLATFORM_ARCH}"
      exit 1
    fi

    if [[ "${TARGET_PLATFORM_ARCH}" =~ "aarch64" ]]; then
      ARCH_NAME="aarch64"
    elif [[ "${TARGET_PLATFORM_ARCH}" =~ "x86_64" ]]; then
      ARCH_NAME="x86_64"
    elif [[ "${TARGET_PLATFORM_ARCH}" =~ "i686" ]]; then
      ARCH_NAME="x86"
    else
      echo Unknown ARCH: "${TARGET_PLATFORM_ARCH}"
      exit 1
    fi

    echo "${OS_NAME}-${ARCH_NAME}"
}

function cleanup_source_files() {
    GS_DIR=$(find_generated_src_dir)
    if [ $? -eq 1 ]; then
      echo "Error: find_generated_src_dir failed"
      exit 1
    fi
    S2N_BN_DIR=$(find_s2n_bignum_src_dir)
    if [ $? -eq 1 ]; then
      echo "Error: find_s2n_bignum_src_dir failed"
      exit 1
    fi
    for FILE in "${@}"; do
        if [[ -n "${FILE}" || -n "${SCRIPT_DIR}${FILE}" ]]; then
            #FILE=$(realpath "${FILE}")
            echo "${FILE}" | \
                sed -e "s/.*\/aws-lc-sys\/aws-lc\///" | \
                sed -e "s/.*\/out\/build\/aws-lc\/crypto\/fipsmodule\/\(.*\.S\)\.S$/third_party\/s2n-bignum\/${S2N_BN_DIR}\/\1/" | \
                sed -e "s/.*\/out\/build\/aws-lc\//generated-src\/${GS_DIR}\//" | \
                sed -e 's/\(.*\)\/[^\/]*\/crypto\/err_data\.c/\1\/err_data.c/'
        fi
    done
}

function process_source_files() {
    cleanup_source_files "${@}" | sort | uniq
    if [ $? -eq 1 ]; then
      echo "Error: process_source_files failed"
      exit 1
    fi
}

function verify_source_files() {
    for FILE in "${@}"; do
        FILE_PATH="${SYS_CRATE_DIR}/aws-lc/${FILE}"
        if [[ ! -f "${FILE_PATH}" ]]; then
            echo File does not exist: "${FILE_PATH}"
            exit 1
        fi
    done
}

function generate_output() {
    TIMESTAMP="$(date -u)"
    cat << EOF
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// $TIMESTAMP

use crate::cc_builder::Library;

pub(super) const CRYPTO_LIBRARY: Library = Library {
    name: "crypto",
    // This attribute is intentionally let blank
    flags: &[],
    sources: &[
EOF
    for FILE in "${@}"; do
        echo "        \"${FILE}\","
    done
    cat << EOF
    ],
};
EOF
}

pushd "${REPO_ROOT}"

cargo clean

if [[ -z "${CROSS_TARGET_ARCH}" ]]; then
AWS_LC_SYS_CMAKE_BUILDER=1 AWS_LC_SYS_CC_SRC_COLLECTOR=1 cargo build --package aws-lc-sys --profile dev --features bindgen
else
# Install cross
cargo install cross --locked --git https://github.com/cross-rs/cross
AWS_LC_SYS_CMAKE_BUILDER=1 AWS_LC_SYS_CC_SRC_COLLECTOR=1 cross build --package aws-lc-sys --profile dev --target ${CROSS_TARGET_ARCH} --features bindgen
fi

if [[ -z "${CROSS_TARGET_ARCH}" ]]; then
LIB_CRYPTO_PATH=$(find target/debug -name "libaws_lc_0_*crypto.a"| head -n 1)
else
LIB_CRYPTO_PATH=$(find target/"${CROSS_TARGET_ARCH}" -name "libaws_lc_0_*crypto.a"| head -n 1)
fi
LIB_CRYPTO_PATH="${REPO_ROOT}/${LIB_CRYPTO_PATH}"

SOURCE_FILES=($(collect_source_files "${LIB_CRYPTO_PATH}"))
if [ $? -eq 1 ]; then
  echo "Error: collect_source_files failed"
  exit 1
fi

# Both "refcount_lock.c" and "refcount_c11.c" should always be listed, even though only one may provide implementations
SOURCE_FILES+=("crypto/refcount_lock.c")
SOURCE_FILES+=("crypto/refcount_c11.c")

PROCESSED_SRC_FILES=($(process_source_files "${SOURCE_FILES[@]}"))
if [ $? -eq 1 ]; then
  echo "Error: process_source_files failed"
  exit 1
fi

verify_source_files "${PROCESSED_SRC_FILES[@]}"

RUST_TRIPLE=$(target_filename)
BUILD_CFG_PATH="${BUILD_CFG_DIR}/${RUST_TRIPLE}.rs"

generate_output ${PROCESSED_SRC_FILES[@]} > ${BUILD_CFG_PATH}

echo
echo Build configuration written to: ${BUILD_CFG_PATH}
echo

cargo clean
if [[ -z "${CROSS_TARGET_ARCH}" ]]; then
  AWS_LC_SYS_CMAKE_BUILDER=0 cargo test --package aws-lc-sys --profile dev
  AWS_LC_SYS_CMAKE_BUILDER=0 cargo test --package aws-lc-rs --profile dev
else
  AWS_LC_SYS_CMAKE_BUILDER=0 cross test --package aws-lc-sys --profile dev --target ${CROSS_TARGET_ARCH}
  AWS_LC_SYS_CMAKE_BUILDER=0 cross test --package aws-lc-rs --profile dev --target ${CROSS_TARGET_ARCH}
fi
popd

echo
echo COMPLETE
