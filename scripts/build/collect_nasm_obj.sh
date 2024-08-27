#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
REPO_ROOT=$(git rev-parse --show-toplevel)
SYS_CRATE_DIR="${REPO_ROOT}/aws-lc-sys"
PREBUILT_NASM_DIR="${SYS_CRATE_DIR}/builder/prebuilt-nasm"
mkdir -p "${PREBUILT_NASM_DIR}"
rm -f "${PREBUILT_NASM_DIR}"/*

DUMPBIN="$(find /c/Program\ Files/Microsoft\ Visual\ Studio/ -path "*/Hostx64/x64/*" -name "dumpbin.exe" -print -quit)"

for nasm_file in `find aws-lc-sys/aws-lc/generated-src/win-x86_64/ -name "*.asm"`; do
  OBJNAME=$(basename "${nasm_file}");
  NASM_OBJ=$(find target/ -name "${OBJNAME/.asm/.obj}");
  cp "${NASM_OBJ}" "${PREBUILT_NASM_DIR}"
  # We remove the '.debug$S' value, which indicates the size of the debug section. This value can change across builds
  # because it typically contains full source file paths that vary by build environment
  "${DUMPBIN}" //DISASM "${PREBUILT_NASM_DIR}"/"${OBJNAME/.asm/.obj}" | grep -v '.debug$S' | sed -e "s/^Dump of file.*/Dump of file ${OBJNAME/.asm/.obj}/" > "${PREBUILT_NASM_DIR}"/"${OBJNAME/.asm/}"-disasm.txt
done
