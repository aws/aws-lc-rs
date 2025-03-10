#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

SRC_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}/aws-lc-rs"

case `uname -s` in
    CYGWIN*)    echo Cygwin;;
    MINGW*)     echo MinGw;;
    MSYS_NT*)   echo MSys;;
    *)          echo Unknown OS: `uname -s`; exit 1;;
esac

TMP_DIR=`mktemp -d`

pushd "${TMP_DIR}"
cargo new --bin aws-lc-rs-test
pushd aws-lc-rs-test

cargo add aws-lc-rs rustls rustls-platform-verifier
cat << EOF >> Cargo.toml
[profile.release]
debug = "limited"

[patch.crates-io]
"aws-lc-rs" = { path = "${SRC_ROOT//\\/\/}" }
EOF

mkdir -p .cargo
cat << EOF > .cargo/config.toml
[target.'cfg(target_os = "windows")']
rustflags = ["-C", "target-feature=+crt-static"]
EOF

cargo update
cargo build --release

popd
popd
