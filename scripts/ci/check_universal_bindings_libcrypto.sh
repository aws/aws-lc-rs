#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -euo pipefail

# Checks the libcrypto that a universal-bindings build of aws-lc-sys produces,
# which leaves out `builder/cc_builder/universal_bindings_excluded.rs`, against
# the full archive that `AWS_LC_SYS_FULL_LIBCRYPTO=1` produces:
#
#   1. every symbol the universal bindings declare is defined in the reduced
#      archive, and
#   2. the reduced archive leaves no reference unresolved that the full archive
#      resolves, so it links wherever the full one does.
#
# Both are set comparisons over `nm` output, so this runs on a cross-compiled
# archive without linking anything. It also checks that the reduction happened
# at all (the full archive defines X.509 symbols the reduced one must not).
#
# Usage: check_universal_bindings_libcrypto.sh [--target <triple>]
#   CARGO  cargo-compatible command for the builds (default: cargo; e.g. cross)
#   NM     nm-compatible tool for the archives (default: nm; e.g. llvm-nm)
#
# Compiles aws-lc-sys twice into temporary target directories.

TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

CARGO="${CARGO:-cargo}"
NM="${NM:-nm}"
# `comm` needs both sides sorted the same way; underscores collate differently
# outside the C locale.
export LC_ALL=C

REPO_ROOT=$(git rev-parse --show-toplevel)
UNIVERSAL="${REPO_ROOT}/aws-lc-sys/src/universal_crypto.rs"
BUILD_DIR=$(mktemp -d)
# Git Bash hands out MSYS paths, which cargo (a native program) resolves
# differently than bash does; use the Windows spelling for both.
if command -v cygpath > /dev/null 2>&1; then
  BUILD_DIR=$(cygpath -m "${BUILD_DIR}")
fi
trap 'rm -rf "${BUILD_DIR}"' EXIT

CARGO_ARGS=(build -p aws-lc-sys --no-default-features --manifest-path "${REPO_ROOT}/Cargo.toml")
if [[ -n "${TARGET}" ]]; then
  CARGO_ARGS+=(--target "${TARGET}")
fi

# The reduction only applies to the cc builder's archive.
export AWS_LC_SYS_CMAKE_BUILDER=0

echo "Building the universal-bindings libcrypto..."
CARGO_TARGET_DIR="${BUILD_DIR}/reduced" "${CARGO}" "${CARGO_ARGS[@]}"
echo "Building the full libcrypto..."
AWS_LC_SYS_FULL_LIBCRYPTO=1 CARGO_TARGET_DIR="${BUILD_DIR}/full" "${CARGO}" "${CARGO_ARGS[@]}"

find_archive() {
  local archive
  archive=$(find "$1" -type f \( -name 'libaws_lc_*_crypto.a' -o -name 'aws_lc_*_crypto.lib' \) -print -quit)
  test -f "${archive}" || { echo "FAIL: libcrypto archive not found under $1" >&2; exit 1; }
  echo "${archive}"
}
REDUCED=$(find_archive "${BUILD_DIR}/reduced")
FULL=$(find_archive "${BUILD_DIR}/full")

# Writes `<out>.defined` and `<out>.unresolved`: the global symbols the archive
# defines, and the undefined references no member of it defines. Weak undefined
# references (`w`/`v`) never pull in a member and are ignored. A leading
# underscore (Mach-O, i686 Windows) is stripped so names match the bindings.
symbol_sets() {
  local archive="$1" out="$2"
  "${NM}" -A -g "${archive}" |
    awk 'NF >= 3 {
      type = $(NF - 1); sym = $NF
      if (type == "U") print "U", sym
      else if (type != "w" && type != "v") print "D", sym
    }' > "${out}.raw"
  if grep -q '^D _aws_lc_' "${out}.raw"; then
    sed -i.bak -E 's/^([UD]) _/\1 /' "${out}.raw"
  fi
  awk '$1 == "D" { print $2 }' "${out}.raw" | sort -u > "${out}.defined"
  awk '$1 == "U" { print $2 }' "${out}.raw" | sort -u | comm -23 - "${out}.defined" > "${out}.unresolved"
  test -s "${out}.defined" || { echo "FAIL: no defined symbols read from ${archive}" >&2; exit 1; }
}
symbol_sets "${REDUCED}" "${BUILD_DIR}/reduced"
symbol_sets "${FULL}" "${BUILD_DIR}/full"

# rust_wrapper.h declares these, but no AWS-LC source defines them; aws-lc-sys
# implements ERR_GET_LIB, ERR_GET_REASON and ERR_GET_FUNC in Rust instead.
NEVER_DEFINED='_ERR_GET_(LIB|REASON|FUNC)_RUST$'
grep -o 'link_name = "[^"]*"' "${UNIVERSAL}" |
  cut -d '"' -f 2 |
  grep -Ev "${NEVER_DEFINED}" |
  sort -u > "${BUILD_DIR}/declared.txt"
test -s "${BUILD_DIR}/declared.txt" || { echo "FAIL: no link_name attributes in ${UNIVERSAL}" >&2; exit 1; }

STATUS=0

MISSING=$(comm -23 "${BUILD_DIR}/declared.txt" "${BUILD_DIR}/reduced.defined")
if [[ -n "${MISSING}" ]]; then
  echo "FAIL: declared by the universal bindings but not defined in ${REDUCED}:"
  echo "${MISSING}"
  STATUS=1
fi

NEW_UNRESOLVED=$(comm -23 "${BUILD_DIR}/reduced.unresolved" "${BUILD_DIR}/full.unresolved")
if [[ -n "${NEW_UNRESOLVED}" ]]; then
  echo "FAIL: referenced in ${REDUCED} but defined only by the sources it leaves out:"
  echo "${NEW_UNRESOLVED}"
  STATUS=1
fi

# The reduction must have happened, and in the right direction.
if ! grep -q '_X509_verify_cert$' "${BUILD_DIR}/full.defined"; then
  echo "FAIL: ${FULL} does not define X509_verify_cert; AWS_LC_SYS_FULL_LIBCRYPTO=1 did not build all of libcrypto"
  STATUS=1
fi
if grep -q '_X509_verify_cert$' "${BUILD_DIR}/reduced.defined"; then
  echo "FAIL: ${REDUCED} defines X509_verify_cert; the universal-bindings build kept the excluded sources"
  STATUS=1
fi
EXTRA=$(comm -23 "${BUILD_DIR}/reduced.defined" "${BUILD_DIR}/full.defined")
if [[ -n "${EXTRA}" ]]; then
  echo "FAIL: defined in ${REDUCED} but not in ${FULL}:"
  echo "${EXTRA}"
  STATUS=1
fi

if [[ "${STATUS}" -eq 0 ]]; then
  echo "OK: all $(wc -l < "${BUILD_DIR}/declared.txt" | tr -d ' ') universal-bindings symbols are defined;" \
    "the reduced archive defines $(wc -l < "${BUILD_DIR}/reduced.defined" | tr -d ' ') of the full archive's" \
    "$(wc -l < "${BUILD_DIR}/full.defined" | tr -d ' ') symbols and leaves no new reference unresolved."
fi
exit "${STATUS}"
