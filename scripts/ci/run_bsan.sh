#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -euo pipefail

# Run from the workspace root inside the pinned container in analysis.yml.
# Rebuild bundled C with bsan; assembly and system libraries are not instrumented.
export RUSTUP_TOOLCHAIN=bsan
export AWS_LC_SYS_USE_SYSTEM=0
export AWS_LC_SYS_NO_ASM=1
export AWS_LC_RS_DISABLE_SLOW_TESTS=1
export CARGO_BUILD_JOBS=4
export BSAN_OPTIONS=stacktrace_max_len=16

log_dir=target/bsan-logs
mkdir -p "${log_dir}"

run_logged() {
    local name="$1"
    shift
    # pipefail preserves sanitizer/compiler errors and timeout exit codes through tee.
    timeout --verbose --kill-after=15s 5m "$@" 2>&1 | tee "${log_dir}/${name}.log"
}

run_tests() {
    local name="$1"
    run_logged "$@"
    # A renamed test/filter must not silently turn this check into a zero-test pass.
    if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed;' "${log_dir}/${name}.log"; then
        echo "No passing tests were recorded for ${name}." >&2
        return 1
    fi
}

rustc --version | tee "${log_dir}/rustc-version.log"
cargo bsan --version | tee "${log_dir}/bsan-version.log"

# Cargo.lock is not tracked. Resolve once and retain it with the failure logs.
if [[ ! -f Cargo.lock ]]; then
    run_logged resolve cargo generate-lockfile
fi
cp Cargo.lock "${log_dir}/Cargo.lock"
run_logged setup cargo bsan setup

# Capture native compiler invocations as well as Rust diagnostics on a clean build.
BSAN_VERBOSE=1 run_tests cbb cargo bsan test --locked -vv -p aws-lc-rs --lib cbb::tests -- --test-threads=1
run_tests cfb1 cargo bsan test --locked -p aws-lc-rs --lib \
    cipher::aes::tests::cfb1_chunking_does_not_change_the_result -- --exact --test-threads=1

# Explicit bounded coverage, not the full suite: Poly1305/AEAD vector tests exhausted
# 6 GiB in the pilot, and digest/streaming stress tests took minutes per case.
# See https://github.com/BorrowSanitizer/bsan/issues/355 for upstream resource issues.
# Keep each integration binary separate so the timeout and log identify the culprit.
# Do not add --lib here: that would also run the entire unit test suite.
for test_target in \
    aead_out_of_place \
    aead_out_of_place_tls \
    basic_aead_test \
    basic_openssh_test \
    basic_quic_test \
    basic_rsa_test \
    cipher_test \
    cmac_tests; do
    run_tests "${test_target}" cargo bsan test --locked -p aws-lc-rs \
        --test "${test_target}" -- --test-threads=1
done
