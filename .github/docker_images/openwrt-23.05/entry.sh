#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

# Fix permissions on mounted volume
# The volume is mounted from GitHub Actions runner and may be owned by a different user
sudo chown -R builder:builder /aws_lc_rs

/aws_lc_rs_build.sh