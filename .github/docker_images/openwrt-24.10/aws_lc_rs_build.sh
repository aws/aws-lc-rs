#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# This script simulates the OpenWrt build environment to verify that
# aws-lc-sys correctly handles cross-compilation where:
# - CC points to the host compiler
# - TARGET_CC points to the cross compiler
# - TARGET_CFLAGS contains cross-compiler-specific flags
#
# See: https://github.com/aws/aws-lc-rs/issues/1009

set -ex -o pipefail

SRC_DIR="${SRC_DIR:-/aws_lc_rs}"
OPENWRT_SDK_DIR="${OPENWRT_SDK_DIR:-/openwrt-sdk}"

# Source Rust environment
source "${HOME}/.cargo/env"

# Find the cross-compiler in the OpenWrt SDK
TOOLCHAIN_DIR=$(find "${OPENWRT_SDK_DIR}/staging_dir" -maxdepth 1 -type d -name 'toolchain-*' | head -1)
if [ -z "${TOOLCHAIN_DIR}" ]; then
    echo "ERROR: Could not find OpenWrt toolchain directory"
    exit 1
fi

CROSS_COMPILER="${TOOLCHAIN_DIR}/bin/aarch64-openwrt-linux-musl-gcc"
CROSS_CXX="${TOOLCHAIN_DIR}/bin/aarch64-openwrt-linux-musl-g++"

if [ ! -x "${CROSS_COMPILER}" ]; then
    echo "ERROR: Cross compiler not found at ${CROSS_COMPILER}"
    exit 1
fi

echo "Using cross compiler: ${CROSS_COMPILER}"

# Set up environment to simulate OpenWrt build system
# This is the key test: CC points to host compiler, TARGET_CC points to cross compiler
# The build system should prefer TARGET_CC over CC for cross-compilation

# CC is set to HOST compiler (this simulates what OpenWrt does)
export CC="/usr/bin/gcc"

# TARGET_CC is set to the CROSS compiler
export TARGET_CC="${CROSS_COMPILER}"
export TARGET_CXX="${CROSS_CXX}"

# TARGET_CFLAGS contains cross-compiler-specific flags
# These flags would fail if passed to the host compiler
export TARGET_CFLAGS="-Os -pipe -mcpu=cortex-a53 -fno-caller-saves -fno-plt"

# The linker for the target
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CROSS_COMPILER}"

# Add sysroot include paths
TARGET_DIR=$(find "${OPENWRT_SDK_DIR}/staging_dir" -maxdepth 1 -type d -name 'target-*' | head -1)
if [ -n "${TARGET_DIR}" ]; then
    export TARGET_CFLAGS="${TARGET_CFLAGS} --sysroot=${TARGET_DIR}"
fi

echo "Environment setup:"
echo "  CC=${CC}"
echo "  TARGET_CC=${TARGET_CC}"
echo "  TARGET_CXX=${TARGET_CXX}"
echo "  TARGET_CFLAGS=${TARGET_CFLAGS}"
echo "  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER}"

pushd "${SRC_DIR}"

# Test 1: Build aws-lc-sys with cross-compilation
# This should use TARGET_CC (cross compiler) instead of CC (host compiler)
echo "=== Test 1: Building aws-lc-sys for aarch64-unknown-linux-musl ==="
cargo build -p aws-lc-sys --target aarch64-unknown-linux-musl

# Test 2: Build in release mode
echo "=== Test 2: Building aws-lc-sys release for aarch64-unknown-linux-musl ==="
cargo build -p aws-lc-sys --release --target aarch64-unknown-linux-musl

# Test 3: Build aws-lc-rs
echo "=== Test 3: Building aws-lc-rs for aarch64-unknown-linux-musl ==="
cargo build -p aws-lc-rs --target aarch64-unknown-linux-musl

echo "=== All OpenWrt cross-compilation tests passed ==="

cargo clean

popd # ${SRC_DIR}