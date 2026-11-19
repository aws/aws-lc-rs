#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -ex
set -o pipefail

# Generates `builder/cc_builder/universal_bindings_excluded.rs`: the portable C
# sources (`portable.rs`) that no symbol declared by the universal bindings
# (`src/universal_crypto.rs`) reaches, directly or through other objects, so a
# build that ships those bindings can skip compiling them.
#
# It builds the full libcrypto with the cc builder, reads every archive member's
# defined and undefined global symbols with `nm`, seeds the needed set with the
# universal bindings' `link_name`s, and walks it to a fixpoint. Members never
# reached are excluded. Members that define no global symbol on this host are
# never excluded: they are conditionally compiled sources (e.g. `refcount_lock.c`,
# `rand_extra/windows.c`) that another target may need. CI checks the result on
# every target with pregenerated bindings (`scripts/ci/check_universal_bindings_libcrypto.sh`).
#
# Requires the universal bindings to be current: run after
# `generate-universal-bindings-and-commit` (see sys-bindings-generator.yml).

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
SCRIPT_NAME="$(basename -s .sh -- "${BASH_SOURCE[0]}")"

source "${SCRIPT_DIR}/.common.sh"

NM="${NM:-nm}"
UNIVERSAL_BINDINGS="${SYS_CRATE_DIR}/src/universal_crypto.rs"
PORTABLE_SOURCES="${BUILD_CFG_DIR}/portable.rs"

export LC_ALL=C

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_DIR}"' EXIT

pushd "${REPO_ROOT}"
# `--no-default-features` is the configuration that ships the universal bindings;
# the override makes the archive complete so every source has a member to analyze.
AWS_LC_SYS_FULL_LIBCRYPTO=1 AWS_LC_SYS_CMAKE_BUILDER=0 CARGO_TARGET_DIR="${BUILD_DIR}" \
    cargo build -p aws-lc-sys --no-default-features
popd

LIBCRYPTO=$(find "${BUILD_DIR}" -type f -name 'libaws_lc_*_crypto.a' -print -quit)
test -f "${LIBCRYPTO}"

# `member defined|undefined symbol` per line. `U` is an undefined reference;
# weak undefined references (`w`/`v`) do not pull in archive members and are
# ignored. Every other global symbol type is a definition.
"${NM}" -A -g "${LIBCRYPTO}" |
    awk '
        NF >= 3 {
            split($1, loc, ":")
            member = loc[2]
            type = $(NF - 1)
            sym = $NF
            if (type == "U") print member, "undefined", sym
            else if (type != "w" && type != "v") print member, "defined", sym
        }' > "${BUILD_DIR}/symbols.txt"
test -s "${BUILD_DIR}/symbols.txt"

# Mach-O (and i686 Windows) prefix every C symbol with an underscore; strip it
# so the names match the bindings' `link_name`s.
if grep -q ' defined _aws_lc_' "${BUILD_DIR}/symbols.txt"; then
    sed -i.bak -E 's/^([^ ]+ (defined|undefined)) _/\1 /' "${BUILD_DIR}/symbols.txt"
fi

grep -o 'link_name = "[^"]*"' "${UNIVERSAL_BINDINGS}" | cut -d '"' -f 2 | sort -u > "${BUILD_DIR}/seeds.txt"
test -s "${BUILD_DIR}/seeds.txt"

grep -oE '"[^"]+\.c"' "${PORTABLE_SOURCES}" | tr -d '"' | sort > "${BUILD_DIR}/portable.txt"
test -s "${BUILD_DIR}/portable.txt"

# Archive members are named `<hash>-<basename>.o`, one hash per source
# directory, so a basename identifies a portable source only if it is unique.
if [[ -n "$(sed 's|.*/||' "${BUILD_DIR}/portable.txt" | sort | uniq -d)" ]]; then
    echo "FAIL: portable sources with the same basename; this script maps archive members by basename" >&2
    sed 's|.*/||' "${BUILD_DIR}/portable.txt" | sort | uniq -d >&2
    exit 1
fi

# Fixpoint over the archive: a member is reached when it defines a needed
# symbol, and then everything it references is needed too.
awk '
    FILENAME == ARGV[1] { needed[$1] = 1; next }
    FILENAME == ARGV[2] {
        if ($2 == "defined") {
            if (!($3 in definer)) definer[$3] = $1
            defines[$1]++
        } else {
            refs[$1] = refs[$1] " " $3
        }
        next
    }
    FILENAME == ARGV[3] {
        base = $0; sub(/.*\//, "", base); sub(/\.c$/, "", base)
        source_of[base] = $0
        next
    }
    END {
        work_len = 0
        for (sym in needed) work[++work_len] = sym
        while (work_len > 0) {
            sym = work[work_len--]
            if (!(sym in definer)) continue
            member = definer[sym]
            if (member in reached) continue
            reached[member] = 1
            n = split(refs[member], list, " ")
            for (i = 1; i <= n; i++) {
                if (list[i] != "" && !(list[i] in needed)) {
                    needed[list[i]] = 1
                    work[++work_len] = list[i]
                }
            }
        }
        for (member in defines) {
            if (member in reached) continue
            base = member
            sub(/^[0-9a-f]+-/, "", base); sub(/\.(o|obj)$/, "", base)
            if (base in source_of) print source_of[base]
        }
    }' "${BUILD_DIR}/seeds.txt" "${BUILD_DIR}/symbols.txt" "${BUILD_DIR}/portable.txt" |
    sort -f > "${BUILD_DIR}/excluded.txt"

# Sanity checks on this host's result before it is written.
EXCLUDED_COUNT=$(wc -l < "${BUILD_DIR}/excluded.txt" | tr -d ' ')
PORTABLE_COUNT=$(wc -l < "${BUILD_DIR}/portable.txt" | tr -d ' ')
if [[ "${EXCLUDED_COUNT}" -eq 0 || "${EXCLUDED_COUNT}" -ge "${PORTABLE_COUNT}" ]]; then
    echo "FAIL: implausible result, ${EXCLUDED_COUNT} of ${PORTABLE_COUNT} portable sources excluded" >&2
    exit 1
fi
for REQUIRED in crypto/fipsmodule/bcm.c crypto/fipsmodule/cpucap/cpucap.c crypto/err/err.c generated-src/err_data.c; do
    if grep -qx "${REQUIRED}" "${BUILD_DIR}/excluded.txt"; then
        echo "FAIL: ${REQUIRED} is reached by the universal bindings but was excluded" >&2
        exit 1
    fi
done

mapfile -t SOURCE_FILES < "${BUILD_DIR}/excluded.txt"

OUTPUT_CONST_NAME="SOURCES"
OUTPUT_DOC_COMMENT="/// Portable C sources (\`portable::CRYPTO_LIBRARY\`) that no symbol declared by the
/// universal bindings (\`src/universal_crypto.rs\`) reaches, directly or through
/// other objects. A build whose Rust code can only call those bindings never links
/// these objects, so it does not compile them; see \`builds_full_libcrypto\`.
///
/// Generated by \`scripts/cc_builder/${SCRIPT_NAME}.sh\`. Do not edit by hand."
generate_output "${SOURCE_FILES[@]}" > "${BUILD_CFG_FILE}"

echo
echo "Excluded ${EXCLUDED_COUNT} of ${PORTABLE_COUNT} portable sources; written to: ${BUILD_CFG_FILE}"
echo
