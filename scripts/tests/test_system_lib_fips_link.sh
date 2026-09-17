#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Linux consumer-link regression; reuse an install from system-lib-tests-fips.yml.
# Usage: bash scripts/tests/test_system_lib_fips_link.sh <FIPS_INSTALL_DIR>
# No native libraries are built here. CARGO_TARGET_DIR may retain the test logs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="$(cd "${1:?Usage: $0 <FIPS_INSTALL_DIR>}" && pwd)"
if [ "$(uname -s)" != Linux ]; then
    echo 'This regression requires Linux and GNU ld.bfd.' >&2
    exit 1
fi

export AWS_LC_FIPS_SYS_SYSTEM_DIR="$INSTALL_DIR"
export AWS_LC_FIPS_SYS_STATIC=1
# The x86_64 Rust toolchain may default to lld, which masks this archive-order bug.
export RUSTFLAGS="${RUSTFLAGS:-} -C linker=gcc -C link-arg=-fuse-ld=bfd"
unset CARGO_ENCODED_RUSTFLAGS

if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    CARGO_TARGET_DIR="$(mktemp -d)"
    trap 'rm -rf "$CARGO_TARGET_DIR"' EXIT
fi
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"
MANIFEST="$REPO_ROOT/tests/system-fips-link/Cargo.toml"

rustc -vV
gcc -fuse-ld=bfd -Wl,--version

check_binary() {
    local binary="$1" log="$2"
    # A successful empty program is not a regression test: require both startup
    # functions in .init_array, not just an unused symbol somewhere in the ELF.
    nm "$binary" > "$log.symbols"
    readelf -x .init_array "$binary" > "$log.init-array"
    python3 - "$log" <<'PY'
import re
import struct
import sys
from pathlib import Path

log = sys.argv[1]
symbols = Path(log + '.symbols').read_text()
array = b''.join(bytes.fromhex(word) for line in Path(log + '.init-array').read_text().splitlines()
                 if line.strip().startswith('0x') for word in line.split()[1:5]
                 if re.fullmatch('[0-9a-fA-F]{8}', word))
for name in ['aws_lc_fips_sys_runtime_check_assert_fips_mode_v1', 'BORINGSSL_bcm_power_on_self_test']:
    match = re.search(r'^([0-9a-fA-F]+) [Tt] (?:\w+_)?' + name + r'$', symbols, re.M)
    assert match, 'Missing constructor: ' + name
    assert struct.pack('P', int(match[1], 16)) in array, 'Not in .init_array: ' + name
assert re.search(r' T (?:\w+_)?FIPS_mode$', symbols, re.M), 'Missing FIPS_mode'
PY
    readelf -d "$binary" > "$log.dynamic"
    if grep -Eq 'NEEDED.*lib(crypto|.*_crypto).*\.so' "$log.dynamic"; then
        echo 'Unexpected shared libcrypto dependency' >&2
        exit 1
    fi
    "$binary"
}

for lto in true false; do
    for live in unused live; do
        args=()
        if [ "$live" = live ]; then
            args+=(--features live-crypto)
        fi
        log="$CARGO_TARGET_DIR/fips-link-$lto-$live.log"
        echo "=== FIPS static system link: lto=$lto crypto=$live ==="
        CARGO_PROFILE_RELEASE_LTO="$lto" cargo build -vv --release --bin system-fips-link \
            --manifest-path "$MANIFEST" "${args[@]}" 2>&1 | tee "$log"
        grep -q 'Using system-installed AWS-LC from' "$log"
        grep -q 'FIPS verification: build-time link probe and runtime FIPS_mode() check passed' "$log"

        check_binary "$CARGO_TARGET_DIR/release/system-fips-link" "$log"
    done

    log="$CARGO_TARGET_DIR/fips-staticlib-$lto.log"
    CARGO_PROFILE_RELEASE_LTO="$lto" cargo build -vv --release --lib \
        --manifest-path "$MANIFEST" 2>&1 | tee "$log"
    # Raw .a files cannot convey Rust's whole-archive modifier. Force-including
    # the Rust staticlib retains constructor-only objects; do not add libcrypto
    # separately here, since that would hide a regression in native bundling.
    binary="$CARGO_TARGET_DIR/staticlib-consumer"
    gcc -fuse-ld=bfd "$REPO_ROOT/tests/system-fips-link/staticlib-main.c" \
        -Wl,--gc-sections -Wl,--whole-archive \
        "$CARGO_TARGET_DIR/release/libsystem_fips_link.a" \
        -Wl,--no-whole-archive -ldl -lpthread -lm -o "$binary"
    check_binary "$binary" "$log"
done
