#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Integration test script for system-library AWS-LC FIPS linking support.
#
# Usage:
#   ./scripts/tests/test_system_lib_fips.sh <AWS_LC_FIPS_INSTALL_DIR>
#
# Required:
#   AWS_LC_FIPS_INSTALL_DIR     AWS-LC FIPS installation (built with -DFIPS=1)
#                               that provides the crypto library and headers.
#
# Optional environment variables:
#   NONFIPS_INSTALL_DIR         Path to a non-FIPS AWS-LC install. Used to
#                               verify that the FIPS probe correctly rejects
#                               a non-FIPS library. Required for Test 5.
#   PREFIXED_FIPS_INSTALL_DIR   Path to a FIPS AWS-LC install built with
#                               BORINGSSL_PREFIX. Required for Test 6.
#   INSTALL_WITH_BINDINGS_DIR   Path to a FIPS install that populated
#                               share/rust/aws_lc_bindings.rs via
#                               GENERATE_RUST_BINDINGS. Required for Test 7.
#   ALLOW_SKIPS                 Set to "0" to fail the script if any test
#                               gets skipped. Intended for CI, where every
#                               fixture should be present. Default is "1"
#                               (skip-tolerant), which is convenient for
#                               local runs.
#   SKIP_CLEAN                  Set to "1" to skip the initial `cargo clean`
#                               during local iteration.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <AWS_LC_FIPS_INSTALL_DIR>"
    echo ""
    echo "This script tests linking aws-lc-fips-sys against a system-installed AWS-LC FIPS module."
    echo ""
    echo "Required:"
    echo "  AWS_LC_FIPS_INSTALL_DIR    Path to AWS-LC FIPS installation directory"
    echo ""
    echo "Optional environment variables:"
    echo "  NONFIPS_INSTALL_DIR          Path to a non-FIPS AWS-LC installation (negative fixture)"
    echo "  PREFIXED_FIPS_INSTALL_DIR    Path to a prefixed FIPS AWS-LC installation"
    echo "  INSTALL_WITH_BINDINGS_DIR    Path to FIPS installation with share/rust/aws_lc_bindings.rs"
    echo "  ALLOW_SKIPS                  Set to 0 to fail on any skipped test (default 1)"
    echo "  SKIP_CLEAN                   Set to 1 to skip the initial cargo clean"
    echo ""
    echo "Example:"
    echo "  $0 /usr/local/aws-lc-fips"
    exit 1
fi

INSTALL_DIR="$1"
ALLOW_SKIPS="${ALLOW_SKIPS:-1}"

cd "${REPO_ROOT}"

echo "=== Testing system-library AWS-LC FIPS linking ==="
echo "Repository root: ${REPO_ROOT}"
echo "FIPS install directory: ${INSTALL_DIR}"
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

skip_test() {
    local test_name="$1"
    local reason="$2"
    echo ""
    echo "=== Test: $test_name ==="
    echo "SKIPPED: $reason"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

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

# Asserts that a cargo log file contains evidence the system-library path was
# entered and the FIPS verification ran. Returns non-zero on failure.
assert_system_fips_path() {
    local log_file="$1"
    if ! grep -q 'Using system-installed AWS-LC from' "$log_file"; then
        echo "  ERROR: System-library code path was not entered (possible silent fallback to source build)."
        return 1
    fi
    if ! grep -q 'FIPS verification' "$log_file"; then
        echo "  ERROR: FIPS verification did not run on the system-library path."
        return 1
    fi
    return 0
}

# Determine library linkage form: static on Linux, dynamic on macOS.
# AWS-LC FIPS only supports static builds on Linux; macOS/Windows require shared.
select_static_preference() {
    case "$(uname -s)" in
        Linux)  echo "1" ;;
        *)      echo "0" ;;
    esac
}

FIPS_STATIC="$(select_static_preference)"
echo "FIPS link preference: $([ "$FIPS_STATIC" = "1" ] && echo "static" || echo "dynamic")"
echo ""

# Common env vars for FIPS system-library tests.
# AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1 is set because the installed
# library may not match the bundled submodule version exactly.
FIPS_ENV_BASE="AWS_LC_FIPS_SYS_SYSTEM_DIR='$INSTALL_DIR' AWS_LC_FIPS_SYS_STATIC='$FIPS_STATIC' AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1"

# For dynamic linking (macOS), the shared library must be discoverable at runtime.
LIB_DIR="$INSTALL_DIR/lib"
if [ -d "$INSTALL_DIR/lib64" ]; then
    LIB_DIR="$INSTALL_DIR/lib64"
fi

case "$(uname)" in
    Darwin) LIB_PATH_VAR="DYLD_LIBRARY_PATH" ;;
    *)      LIB_PATH_VAR="LD_LIBRARY_PATH" ;;
esac

RUNTIME_LIB_PATH="${LIB_PATH_VAR}='${LIB_DIR}'"

# Test 1: Build aws-lc-fips-sys with conventional bindings location.
CONVENTIONAL_BINDINGS="$INSTALL_DIR/share/rust/aws_lc_bindings.rs"
if require_fixture "INSTALL_DIR/share/rust/aws_lc_bindings.rs" "$CONVENTIONAL_BINDINGS" file; then
    run_test "aws-lc-fips-sys build with conventional bindings" \
        "${RUNTIME_LIB_PATH} ${FIPS_ENV_BASE} cargo build -vv -p aws-lc-fips-sys 2>&1 | tee /tmp/fips_test1.log && assert_system_fips_path /tmp/fips_test1.log"
else
    skip_test "aws-lc-fips-sys build with conventional bindings" \
        "No share/rust/aws_lc_bindings.rs under \$INSTALL_DIR (GENERATE_RUST_BINDINGS was OFF)"
fi

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 2: Build and test aws-lc-rs with FIPS feature.
run_test "aws-lc-rs fips tests" \
    "${RUNTIME_LIB_PATH} ${FIPS_ENV_BASE} cargo test -vv -p aws-lc-rs --no-default-features --features fips --lib 2>&1 | tee /tmp/fips_test2.log && assert_system_fips_path /tmp/fips_test2.log"

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 3: Explicit static linking (Linux only — macOS/Windows FIPS requires shared).
if [ "$FIPS_STATIC" = "1" ]; then
    run_test "aws-lc-rs fips tests, explicit static" \
        "${RUNTIME_LIB_PATH} AWS_LC_FIPS_SYS_SYSTEM_DIR='$INSTALL_DIR' AWS_LC_FIPS_SYS_STATIC=1 AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1 cargo test -vv -p aws-lc-rs --no-default-features --features fips --lib 2>&1 | tee /tmp/fips_test3.log && assert_system_fips_path /tmp/fips_test3.log"
else
    # On macOS, test explicit dynamic linking.
    run_test "aws-lc-rs fips tests, explicit dynamic" \
        "${RUNTIME_LIB_PATH} AWS_LC_FIPS_SYS_SYSTEM_DIR='$INSTALL_DIR' AWS_LC_FIPS_SYS_STATIC=0 AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1 cargo test -vv -p aws-lc-rs --no-default-features --features fips --lib 2>&1 | tee /tmp/fips_test3.log && assert_system_fips_path /tmp/fips_test3.log"
fi

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 4: Build aws-lc-fips-sys only (no tests — useful for verifying the
# build script path in isolation).
run_test "aws-lc-fips-sys build only" \
    "${RUNTIME_LIB_PATH} ${FIPS_ENV_BASE} cargo build -vv -p aws-lc-fips-sys 2>&1 | tee /tmp/fips_test4.log && assert_system_fips_path /tmp/fips_test4.log"

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 5: Non-FIPS install must be rejected.
#
# The FIPS link probe checks for BORINGSSL_integrity_test, which is only
# exported by FIPS builds. A non-FIPS library must cause a build failure.
if require_fixture "NONFIPS_INSTALL_DIR" "$NONFIPS_INSTALL_DIR" dir; then
    run_test "aws-lc-fips-sys rejects non-FIPS install" \
        "if AWS_LC_FIPS_SYS_SYSTEM_DIR='$NONFIPS_INSTALL_DIR' AWS_LC_FIPS_SYS_STATIC=1 AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1 cargo build -p aws-lc-fips-sys -vv 2>&1 | tee /tmp/fips_test5.log; then
            echo '  ERROR: Build unexpectedly succeeded against a non-FIPS install.'
            false
        else
            if grep -q 'FIPS verification failed' /tmp/fips_test5.log; then
                true
            else
                echo '  ERROR: Build failed, but not at the FIPS probe rejection.'
                cat /tmp/fips_test5.log | tail -20
                false
            fi
        fi"
else
    skip_test "aws-lc-fips-sys rejects non-FIPS install" \
        "NONFIPS_INSTALL_DIR not set or directory doesn't exist"
fi

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 6: Prefixed FIPS build.
#
# Exercises BORINGSSL_PREFIX detection with a FIPS install.
if require_fixture "PREFIXED_FIPS_INSTALL_DIR" "$PREFIXED_FIPS_INSTALL_DIR" dir; then
    run_test "aws-lc-fips-sys with prefixed FIPS install" \
        "${RUNTIME_LIB_PATH} AWS_LC_FIPS_SYS_SYSTEM_DIR='$PREFIXED_FIPS_INSTALL_DIR' AWS_LC_FIPS_SYS_STATIC=1 AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1 cargo build -vv -p aws-lc-fips-sys 2>&1 | tee /tmp/fips_test6.log && assert_system_fips_path /tmp/fips_test6.log"
else
    skip_test "aws-lc-fips-sys with prefixed FIPS install" \
        "PREFIXED_FIPS_INSTALL_DIR not set or directory doesn't exist"
fi

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 7: Custom bindings override.
#
# Exercises the override branch in resolve_bindings: an explicit
# AWS_LC_FIPS_SYS_SYSTEM_BINDINGS path beats the conventional location.
if require_fixture "INSTALL_WITH_BINDINGS_DIR" "$INSTALL_WITH_BINDINGS_DIR" dir \
    && require_fixture "INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" \
        "$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" file; then
    OVERRIDE_BINDINGS="$(mktemp "${TMPDIR:-/tmp}/aws_lc_fips_bindings_override.XXXXXX.rs")"
    CLEANUP_FILES+=("$OVERRIDE_BINDINGS")
    cp "$INSTALL_WITH_BINDINGS_DIR/share/rust/aws_lc_bindings.rs" "$OVERRIDE_BINDINGS"
    run_test "aws-lc-fips-sys with custom bindings override" \
        "${RUNTIME_LIB_PATH} AWS_LC_FIPS_SYS_SYSTEM_DIR='$INSTALL_WITH_BINDINGS_DIR' AWS_LC_FIPS_SYS_STATIC='$FIPS_STATIC' AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK=1 AWS_LC_FIPS_SYS_SYSTEM_BINDINGS='$OVERRIDE_BINDINGS' cargo build -vv -p aws-lc-fips-sys 2>&1 | tee /tmp/fips_test7.log && assert_system_fips_path /tmp/fips_test7.log"
else
    skip_test "aws-lc-fips-sys with custom bindings override" \
        "INSTALL_WITH_BINDINGS_DIR not set or bindings file doesn't exist"
fi

# Clean between tests
cargo clean -p aws-lc-fips-sys -p aws-lc-rs 2>/dev/null || true

# Test 8: Invalid SYSTEM_DIR must fail.
run_test "aws-lc-fips-sys rejects invalid SYSTEM_DIR" \
    "! AWS_LC_FIPS_SYS_SYSTEM_DIR='/nonexistent/path' cargo build -p aws-lc-fips-sys 2>/dev/null"

# Summary
echo ""
echo "=========================================="
echo "FIPS System Library Test Summary"
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
