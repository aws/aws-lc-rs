#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Integration test script for prebuilt AWS-LC linking support.
#
# Usage:
#   ./scripts/test_prebuilt.sh <AWS_LC_INSTALL_DIR>
#
# Optional environment variables:
#   PREFIXED_INSTALL_DIR       Path to prefixed AWS-LC installation
#   INSTALL_WITH_BINDINGS_DIR  Path to installation with share/rust/aws_lc_bindings.rs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <AWS_LC_INSTALL_DIR>"
    echo ""
    echo "This script tests linking aws-lc-rs against a prebuilt AWS-LC installation."
    echo ""
    echo "Required:"
    echo "  AWS_LC_INSTALL_DIR       Path to AWS-LC installation directory"
    echo ""
    echo "Optional environment variables:"
    echo "  PREFIXED_INSTALL_DIR       Path to prefixed AWS-LC installation"
    echo "  INSTALL_WITH_BINDINGS_DIR  Path to installation with share/rust/aws_lc_bindings.rs"
    echo ""
    echo "Example:"
    echo "  $0 /usr/local/aws-lc"
    exit 1
fi

INSTALL_DIR="$1"

cd "${REPO_ROOT}"

echo "=== Testing prebuilt AWS-LC linking ==="
echo "Repository root: ${REPO_ROOT}"
echo "Install directory: ${INSTALL_DIR}"
echo ""

# Validate install directory
if [ ! -d "$INSTALL_DIR" ]; then
    echo "ERROR: Install directory not found: $INSTALL_DIR"
    exit 1
fi

if [ ! -d "$INSTALL_DIR/include/openssl" ]; then
    echo "ERROR: Headers not found at $INSTALL_DIR/include/openssl"
    exit 1
fi

if [ ! -d "$INSTALL_DIR/lib" ] && [ ! -d "$INSTALL_DIR/lib64" ]; then
    echo "ERROR: Library directory not found at $INSTALL_DIR/lib or $INSTALL_DIR/lib64"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
cargo clean

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo ""
    echo "=== Test: $test_name ==="
    if eval "$test_cmd"; then
        echo "SUCCESS: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "FAILED: $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

skip_test() {
    local test_name="$1"
    local reason="$2"
    echo ""
    echo "=== Test: $test_name ==="
    echo "SKIPPED: $reason"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

# Test 1: Build with conventional bindings location (if present)
if [ -f "$INSTALL_DIR/share/rust/aws_lc_bindings.rs" ]; then
    run_test "aws-lc-sys with conventional bindings location" \
        "AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys"
else
    skip_test "aws-lc-sys with conventional bindings location" \
        "No share/rust/aws_lc_bindings.rs present"
fi

# Clean between tests
cargo clean -p aws-lc-sys 2>/dev/null || true

# Test 2: Build with bindgen feature (static linking)
run_test "aws-lc-sys with bindgen feature (static)" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys --features bindgen"

# Clean between tests
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 3: Build aws-lc-rs with prebuilt aws-lc-sys
run_test "aws-lc-rs with prebuilt aws-lc-sys (static)" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_DIR' cargo build -p aws-lc-rs --features aws-lc-sys/bindgen"

# Test 4: Run aws-lc-rs tests with static linking
run_test "aws-lc-rs tests with prebuilt (static)" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_DIR' cargo test -p aws-lc-rs --features aws-lc-sys/bindgen --lib"

# Clean between tests  
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 5: Build with dynamic linking (requires DYLD_LIBRARY_PATH/LD_LIBRARY_PATH at runtime)
run_test "aws-lc-sys with bindgen feature (dynamic)" \
    "AWS_LC_SYS_STATIC=0 AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys --features bindgen"

# Test 6: Run tests with dynamic linking
case "$(uname)" in
    Darwin)
        LIB_PATH_VAR="DYLD_LIBRARY_PATH"
        ;;
    *)
        LIB_PATH_VAR="LD_LIBRARY_PATH"
        ;;
esac

LIB_DIR="$INSTALL_DIR/lib"
if [ -d "$INSTALL_DIR/lib64" ]; then
    LIB_DIR="$INSTALL_DIR/lib64"
fi

run_test "aws-lc-rs tests with prebuilt (dynamic)" \
    "${LIB_PATH_VAR}='${LIB_DIR}' AWS_LC_SYS_STATIC=0 AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_DIR' cargo test -p aws-lc-rs --features aws-lc-sys/bindgen --lib"

# Test 7: Prefixed build (if available)
if [ -n "$PREFIXED_INSTALL_DIR" ] && [ -d "$PREFIXED_INSTALL_DIR" ]; then
    cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true
    run_test "aws-lc-sys with prefixed prebuilt" \
        "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_PREBUILT_INSTALL_DIR='$PREFIXED_INSTALL_DIR' cargo build -p aws-lc-sys --features bindgen"
else
    skip_test "aws-lc-sys with prefixed prebuilt" \
        "PREFIXED_INSTALL_DIR not set or directory doesn't exist"
fi

# Test 8: Custom bindings location (if available)
if [ -n "$INSTALL_WITH_BINDINGS_DIR" ] && [ -f "$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" ]; then
    cargo clean -p aws-lc-sys 2>/dev/null || true
    run_test "aws-lc-sys with custom bindings override" \
        "AWS_LC_SYS_PREBUILT_INSTALL_DIR='$INSTALL_WITH_BINDINGS_DIR' AWS_LC_SYS_PREBUILT_BINDINGS='$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs' cargo build -p aws-lc-sys"
else
    skip_test "aws-lc-sys with custom bindings override" \
        "INSTALL_WITH_BINDINGS_DIR not set or bindings file doesn't exist"
fi

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed:  $TESTS_PASSED"
echo "Failed:  $TESTS_FAILED"
echo "Skipped: $TESTS_SKIPPED"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    echo "RESULT: Some tests failed!"
    exit 1
else
    echo "RESULT: All tests passed!"
    exit 0
fi