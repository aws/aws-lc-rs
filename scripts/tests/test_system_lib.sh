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
#                               BORINGSSL_PREFIX. Required for Test 4.
#   INSTALL_WITH_BINDINGS_DIR   Path to an install that populated
#                               share/rust/aws_lc_bindings.rs via
#                               GENERATE_RUST_BINDINGS. Required for Test 5.
#   ALLOW_SKIPS                 Set to "0" to fail the script if any test
#                               gets skipped. Intended for CI, where every
#                               fixture should be present. Default is "1"
#                               (skip-tolerant), which is convenient for
#                               local runs that only care about the
#                               vanilla install path.
#   SKIP_CLEAN                  Set to "1" to skip the initial `cargo clean`
#                               during local iteration.

set -eo pipefail

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

# Temp files created during tests; cleaned up on exit.
CLEANUP_FILES=()
cleanup() { rm -f "${CLEANUP_FILES[@]}"; }
trap cleanup EXIT

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
# This exercises the conventional-location branch in resolve_bindings: the
# builder should pick up <install>/share/rust/aws_lc_bindings.rs without any
# env var override. The file is only produced when AWS-LC is configured with
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
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 2: Build and test aws-lc-rs with static linking.
run_test "aws-lc-rs tests, static" \
    "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo test -p aws-lc-rs --lib"

# Clean between tests
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 3: Build and test aws-lc-rs with dynamic linking.
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

run_test "aws-lc-rs tests, dynamic" \
    "${LIB_PATH_VAR}='${LIB_DIR}' AWS_LC_SYS_STATIC=0 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo test -p aws-lc-rs --lib"

# Clean between tests
cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true

# Test 4: Build with ssl feature enabled.
#
# Exercises the SSL library resolution path (SSL_LIB_CANDIDATES) which
# requires both libcrypto and libssl to be present in the install.
SSL_LIB_PRESENT=0
if [ -f "$INSTALL_DIR/lib/libssl.a" ] || [ -f "$INSTALL_DIR/lib/libssl.so" ] \
    || [ -f "$INSTALL_DIR/lib/libssl.dylib" ] || [ -f "$INSTALL_DIR/lib64/libssl.a" ] \
    || [ -f "$INSTALL_DIR/lib64/libssl.so" ]; then
    SSL_LIB_PRESENT=1
fi

if [ "$SSL_LIB_PRESENT" = "1" ]; then
    run_test "aws-lc-sys with ssl feature, static" \
        "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$INSTALL_DIR' cargo build -p aws-lc-sys --features ssl"
else
    skip_test "aws-lc-sys with ssl feature, static" \
        "No libssl found under \$INSTALL_DIR"
fi

# Test 5: Prefixed build.
#
# Exercises BORINGSSL_PREFIX detection. The install must come from upstream
# AWS-LC's own CMake so that the library is named libcrypto.{a,so} while the
# installed boringssl_prefix_symbols.h declares #define BORINGSSL_PREFIX <name>.
if require_fixture "PREFIXED_INSTALL_DIR" "$PREFIXED_INSTALL_DIR" dir; then
    cargo clean -p aws-lc-sys -p aws-lc-rs 2>/dev/null || true
    run_test "aws-lc-sys with prefixed prebuilt" \
        "AWS_LC_SYS_STATIC=1 AWS_LC_SYS_SYSTEM_DIR='$PREFIXED_INSTALL_DIR' cargo build -p aws-lc-sys"
else
    skip_test "aws-lc-sys with prefixed prebuilt" \
        "PREFIXED_INSTALL_DIR not set or directory doesn't exist"
fi

# Test 6: Custom bindings override.
#
# Exercises the override branch in resolve_bindings: an explicit
# AWS_LC_SYS_SYSTEM_BINDINGS path beats the conventional location. We copy
# the bindings to a non-standard temp path to prove the override actually
# takes priority rather than the conventional location being used.
if require_fixture "INSTALL_WITH_BINDINGS_DIR" "$INSTALL_WITH_BINDINGS_DIR" dir \
    && require_fixture "INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" \
        "$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" file; then
    cargo clean -p aws-lc-sys 2>/dev/null || true
    OVERRIDE_BINDINGS="$(mktemp "${TMPDIR:-/tmp}/aws_lc_bindings_override.XXXXXX.rs")"
    CLEANUP_FILES+=("$OVERRIDE_BINDINGS")
    cp "$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" "$OVERRIDE_BINDINGS"
    run_test "aws-lc-sys with custom bindings override" \
        "AWS_LC_SYS_SYSTEM_DIR='$INSTALL_WITH_BINDINGS_DIR' AWS_LC_SYS_SYSTEM_BINDINGS='$OVERRIDE_BINDINGS' cargo build -p aws-lc-sys"
else
    skip_test "aws-lc-sys with custom bindings override" \
        "INSTALL_WITH_BINDINGS_DIR not set or bindings file doesn't exist"
fi

# Test 7: Invalid SYSTEM_DIR must fail.
#
# Sanity check that a bogus directory is rejected rather than silently
# falling through to the from-source build path.
cargo clean -p aws-lc-sys 2>/dev/null || true
run_test "aws-lc-sys rejects invalid SYSTEM_DIR" \
    "! AWS_LC_SYS_SYSTEM_DIR='/nonexistent/path' cargo build -p aws-lc-sys 2>/dev/null"

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
