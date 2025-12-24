#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
SYS_CRATE_DIR="${REPO_ROOT}/aws-lc-sys"
AWS_LC_DIR="${SYS_CRATE_DIR}/aws-lc"
BUILD_CFG_DIR="${SYS_CRATE_DIR}/builder/cc_builder"
BUILD_CFG_FILE="${BUILD_CFG_DIR}/${SCRIPT_NAME}".rs
mkdir -p "${BUILD_CFG_DIR}"

function generate_output() {
    TIMESTAMP="$(date -u)"
    cat << EOF
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// $TIMESTAMP

pub(super) const CRYPTO_LIBRARY: &[&str] = &[
EOF
    for FILE in "${@}"; do
        echo "    \"${FILE}\","
    done
    cat << EOF
];
EOF
}

function s2n_bignum_aarch64() {
  find third_party/s2n-bignum/s2n-bignum-imported/arm -name "*.S" -type f \
      | rg --pcre2 -v '/arm/(mlkem|sm2|tutorial|secp256k1)' \
      | rg --pcre2 -v '/arm/curve25519/bignum_(?!(madd_n|mod_n25519.S|neg_p))' \
      | rg --pcre2 -v '/arm/curve25519/curve25519_(?!(x25519_byte|x25519base_byte))' \
      | rg --pcre2 -v '/arm/curve25519/edwards25519_(?!(decode|encode.S|scalarmul))' \
      | rg --pcre2 -v '/arm/fastmul/(?!(bignum_k..._16_32|bignum_k..._32_64|bignum_emontredc_8n.S))' \
      | rg --pcre2 -v '/arm/generic/(word|bignum_(?!(copy_row_from_table|ge.S|mul.S|optsub.S|sqr.S)))' \
      | rg --pcre2 -v '/arm/p256/(?!(bignum_montinv_|p256_montjscalarmul))' \
      | rg --pcre2 -v '/arm/.*/unopt/' \
      | rg --pcre2 -v '/arm/p384/(p384_montj(mix)?add|bignum_(?!add|deamont|littleendian|mont|neg|nonzero|sub|tomont))' \
      | rg --pcre2 -v '/arm/p521/(bignum_(.*mont.*|cmul|double|half|optneg|triple)_p521(_alt)?\.S|bignum_mod_[np]521_9\.S|p521_j(mix)?add(_alt)?\.S)' \
      | rg --pcre2 -v '/arm/sha3/sha3_keccak(4_f1600|2_f1600_alt)\.S' \
      | sort -f
}

function s2n_bignum_x86_64() {
  find third_party/s2n-bignum/s2n-bignum-imported/x86_att -name "*.S" -type f \
      | rg --pcre2 -v '/x86_att/(fastmul|generic|mlkem|sm2|tutorial|secp256k1)' \
      | rg --pcre2 -v '/x86_att/curve25519/bignum_(?!(madd_n|mod_n25519.S|neg_p))' \
      | rg --pcre2 -v '/x86_att/curve25519/curve25519_(?!x25519(base)?(_alt)?)' \
      | rg --pcre2 -v '/x86_att/curve25519/edwards25519_(?!(decode|encode.S|scalarmul))' \
      | rg --pcre2 -v '/x86_att/fastmul/(?!(bignum_k..._16_32|bignum_k..._32_64|bignum_emontredc_8n.S))' \
      | rg --pcre2 -v '/x86_att/generic/(word|bignum_(?!(copy_row_from_table|ge.S|mul.S|optsub.S|sqr.S)))' \
      | rg --pcre2 -v '/x86_att/p256/(?!(bignum_montinv_|p256_montjscalarmul))' \
      | rg --pcre2 -v '/x86_att/.*/unopt/' \
      | rg --pcre2 -v '/x86_att/p384/(p384_montj(mix)?add|bignum_(?!add|deamont|littleendian|mont|neg|nonzero|sub|tomont))' \
      | rg --pcre2 -v '/x86_att/p521/(bignum_(.*mont.*|cmul|double|half|optneg|triple)_p521(_alt)?\.S|bignum_mod_[np]521_9(_alt)?\.S|p521_j(mix)?add(_alt)?\.S)' \
      | sort -f
}
