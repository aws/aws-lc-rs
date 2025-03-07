#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

SRC_DIR="${SRC_DIR:-/aws_lc_rs}"

su mockbuilder -c "mock -r fedora-rawhide-s390x --install git cargo cmake perl rustfmt clang"
su mockbuilder -c "mock -r fedora-rawhide-s390x --shell 'mkdir /builddir/aws-lc-rs/'"
# Use globbing to avoid copying the .git directory
su mockbuilder -c "mock -r fedora-rawhide-s390x --copyin /aws_lc_rs/* /builddir/aws-lc-rs/"
su mockbuilder -c "mock -r fedora-rawhide-s390x --enable-network --cwd /builddir/aws-lc-rs/ --shell 'cargo test -p aws-lc-rs'"
