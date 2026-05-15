#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Integration test script for system-library AWS-LC linking support.
#
# Usage:
#   ./scripts/tests/test_system_lib.sh <AWS_LC_INSTALL_DIR>
#
# Required:
#   AWS_LC_INSTALL_DIR  AWS-LC installation that provides the crypto and ssl
#                       libraries used by the default (non-override) test
#                       cases. The script probes this directory to decide
#                       whether Test 1 (conventional bindings location) can
#                       actually exercise that code path.
#
# Optional environment variables:
#   PREFIXED_INSTALL_DIR        Path to an AWS-LC install built with
#                               BORINGSSL_PREFIX. Required for Test 7.
#   INSTALL_WITH_BINDINGS_DIR   Path to an install that populated
#                               share/rust/aws_lc_bindings.rs via
#                               GENERATE_RUST_BINDINGS. Required for Test 8.
#   ALLOW_SKIPS                 Set to "0" to fail the script if any test
#                               gets skipped. Intended for CI, where every
#                               fixture should be present. Default is "1"
#                               (skip-tolerant), which is convenient for
#                               local runs that only care about the
#                               vanilla install path.
#   SKIP_CLEAN                  Set to "1" to skip the initial `cargo clean`
#                               during local iteration.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <AWS_LC_INSTALL_DIR>"
    echo ""
    echo "This script tests linking aws-lc-rs against a system-installed AWS-LC."
    echo ""
    echo "Required:"
    echo "  AWS_LC_INSTALL_DIR       Path to AWS-LC installation directory"
    echo ""
    echo "Optional environment variables:"
    echo "  PREFIXED_INSTALL_DIR       Path to prefixed AWS-LC installation"
    echo "  INSTALL_WITH_BINDINGS_DIR  Path to installation with share/rust/aws_lc_bindings.rs"
    echo "  ALLOW_SKIPS                Set to 0 to fail on any skipped test (default 1)"
    echo "  SKIP_CLEAN                 Set to 1 to skip the initial cargo clean"
    echo ""
    echo "Example:"
    echo "  $0 /usr/local/aws-lc"
    exit 1
fi

INSTALL_DIR="$1"
ALLOW_SKIPS="${ALLOW_SKIPS:-1}"

cd "${REPO_ROOT}"

echo "=== Testing prebuilt AWS-LC linking ==="
echo "Repository root: ${REPO_ROOT}"
echo "Install directory: ${INSTALL_DIR}"
echo "ALLOW_SKIPS: ${ALLOW_SKIPS}"
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

# Clean previous builds (set SKIP_CLEAN=1 to speed up repeated local runs)
if [ "${SKIP_CLEAN:-0}" != "1" ]; then
    echo "Cleaning previous builds..."
    cargo clean
fi

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

# Records a skipped test. When ALLOW_SKIPS=0 this increments the skip counter
# and the summary at the end turns a non-zero count into a failure exit code.
skip_test() {
    local test_name="$1"
    local reason="$2"
    echo ""
    echo "=== Test: $test_name ==="
    echo "SKIPPED: $reason"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

# Asserts that a fixture path referenced by an environment variable actually
# resolves to something usable. When ALLOW_SKIPS=0, a missing/invalid fixture
# is a hard error before we even try to run tests against it. When ALLOW_SKIPS=1,
# the caller is expected to branch on the return code and invoke skip_test.
#
# Args: <env_var_name> <path> <type: dir|file>
# Returns 0 if fixture is valid, 1 otherwise.
require_fixture() {
    local var_name="$1"
    local path="$2"
    local kind="$3"

    if [ -z "$path" ]; then
        if [ "$ALLOW_SKIPS" = "0" ]; then
            echo "ERROR: ${var_name} must be set (ALLOW_SKIPS=0)"
            exit 1
        fi
        return 1
    fi

    case "$kind" in
        dir)  [ -d "$path" ] && return 0 ;;
        file) [ -f "$path" ] && return 0 ;;
        *)    echo "internal error: unknown fixture kind '$kind'"; exit 2 ;;
    esac

    if [ "$ALLOW_SKIPS" = "0" ]; then
        echo "ERROR: ${var_name} points to a missing ${kind}: ${path} (ALLOW_SKIPS=0)"
        exit 1
    fi
    return 1
}

# Test 1: Build with conventional bindings location.
#
# This exercises the priority-2 branch in find_system_bindings: the builder
# should pick up <install>/share/rust/aws_lc_bindings.rs without any env var
# override. The file is only produced when AWS-LC is configured with
# -DGENERATE_RUST_BINDINGS=ON. Under ALLOW_SKIPS=0 we require it.
CONVENTIONAL_BINDINGS="$INSTALL_DIR/share/rust/aws_lc_bindings.rs"
if require_fixture "INSTALL_DIR/share/rust/aws_lc_bindings.rs" "$CONVENTIONAL_BINDINGS" file; then
    run_test "aws-lc-sys with conventional bindings location" \
        "AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys"
else
    skip_test "aws-lc-sys with conventional bindings location" \
        "No share/rust/aws_lc_bindings.rs under \$INSTALL_DIR (GENERATE_RUST_BINDINGS was OFF)"
fi

# Clean between tests
cargo clean -p aws-lc-sys 2>/dev/null || true

# Test 2: Build with bindgen feature (static linking)
run_test "aws-lc-sys with bindgen feature (static)" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys --features bindgen"

# Clean between tests
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 3: Build aws-lc-rs with prebuilt aws-lc-sys
run_test "aws-lc-rs with prebuilt aws-lc-sys (static)" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo build -p aws-lc-rs --features aws-lc-sys/bindgen"

# Test 4: Run aws-lc-rs tests with static linking
run_test "aws-lc-rs tests with prebuilt (static)" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo test -p aws-lc-rs --features aws-lc-sys/bindgen --lib"

# Clean between tests
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 5: Build with dynamic linking (requires DYLD_LIBRARY_PATH/LD_LIBRARY_PATH at runtime)
run_test "aws-lc-sys with bindgen feature (dynamic)" \
    "AWS_LC_SYS_STATIC=0 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys --features bindgen"

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
    "${LIB_PATH_VAR}='${LIB_DIR}' AWS_LC_SYS_STATIC=0 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo test -p aws-lc-rs --features aws-lc-sys/bindgen --lib"

# Test 7: Prefixed build.
#
# This exercises detect_prefix() + the bindgen prefix plumbing. The install
# MUST come from upstream AWS-LC's own CMake (not the aws-lc-sys wrapper),
# so that the library is named libcrypto.{a,so} while the installed
# boringssl_prefix_symbols.h declares #define BORINGSSL_PREFIX <name>.
if require_fixture "PREFIXED_INSTALL_DIR" "$PREFIXED_INSTALL_DIR" dir; then
    cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true
    run_test "aws-lc-sys with prefixed prebuilt" \
        "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$PREFIXED_INSTALL_DIR' cargo build -p aws-lc-sys --features bindgen"
else
    skip_test "aws-lc-sys with prefixed prebuilt" \
        "PREFIXED_INSTALL_DIR not set or directory doesn't exist"
fi

# Test 8: Custom bindings override.
#
# Exercises the priority-1 branch in find_system_bindings: an explicit
# AWS_LC_SYS_SYSTEM_BINDINGS path beats the conventional location.
if require_fixture "INSTALL_WITH_BINDINGS_DIR" "$INSTALL_WITH_BINDINGS_DIR" dir \
    && require_fixture "INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" \
        "$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" file; then
    cargo clean -p aws-lc-sys 2>/dev/null || true
    run_test "aws-lc-sys with custom bindings override" \
        "AWS_LC_SYS_SYSTEM_DIR='$INSTALL_WITH_BINDINGS_DIR' AWS_LC_SYS_SYSTEM_BINDINGS='$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs' cargo build -p aws-lc-sys"
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
fi

if [ "$ALLOW_SKIPS" = "0" ] && [ $TESTS_SKIPPED -gt 0 ]; then
    echo "RESULT: ${TESTS_SKIPPED} test(s) skipped with ALLOW_SKIPS=0; treating as failure."
    exit 1
fi

echo "RESULT: All tests passed!"
exit 0
