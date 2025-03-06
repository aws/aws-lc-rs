#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

export PATH="/opt/cmake/bin:${PATH}"

/aws_lc_rs_build.sh "${argv[@]}"
