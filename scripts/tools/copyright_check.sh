#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

AWS_LC_RS_FILES=$(find "$PWD" -type f \( -name "*.rs" -o -name "*.sh" \) -not \( -path "*/aws-lc-fips-sys/aws-lc/*" -o -path "*/aws-lc-sys/aws-lc/*" -o -path "*/target/*" \))

FAILED=0

for file in $AWS_LC_RS_FILES; do
    # The word "Copyright" should appear at least once in the first 25 lines of every file
    COUNT=`head -n 25 "${file}" | grep "Copyright" | wc -l`;
    if [ "${COUNT}" -eq "0" ]; then
        FAILED=1;
        echo "Copyright Check Failed: $file";
    fi
done

if [ $FAILED == 1 ]; then
    printf "\\033[31;1mFAILED Copyright Check\\033[0m\\n"
    exit -1
else
    printf "\\033[32;1mPASSED Copyright Check\\033[0m\\n"
fi
