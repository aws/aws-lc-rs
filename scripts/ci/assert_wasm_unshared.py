#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

"""Assert that emitted WebAssembly modules do not use shared memory.

A shared-memory module requires ``SharedArrayBuffer`` at runtime, which browsers
gate behind cross-origin isolation (COOP/COEP). Defaulting to it would force that
constraint onto every downstream consumer for no benefit -- AWS-LC builds fine
single-threaded on this target. On ``wasm32-unknown-emscripten`` a stray
``-pthread`` silently flips the module to shared memory, and functional CI can't
catch it: the Node test runner always provides ``SharedArrayBuffer``, so a shared
module passes tests just like an unshared one. The only reliable signal is the
emitted artifact's memory declaration, which this script inspects.

Usage:
    assert_wasm_unshared.py PATH [PATH ...]

Each PATH may be a ``.wasm`` file or a directory (searched recursively). Exits
non-zero if any module declares shared memory, or if no modules are found.
"""

import sys
from pathlib import Path

WASM_MAGIC = b"\x00asm"
SECTION_IMPORT = 2
SECTION_MEMORY = 5
IMPORT_KIND_MEMORY = 2

# A wasm memory's limits flag byte encodes ``shared`` as bit 0x02 (so a shared,
# max-bounded memory has flag 0x03). Memory may be declared internally (memory
# section) or imported (import section); emscripten imports it under -pthread.
SHARED_BIT = 0x02


def _read_uleb(data, offset):
    """Decode an unsigned LEB128 integer; return (value, next_offset)."""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def _skip_limits(data, offset):
    """Skip a limits record (flag + min + optional max); return next offset."""
    flag = data[offset]
    offset += 1
    _, offset = _read_uleb(data, offset)  # min
    if flag & 0x01:  # has max
        _, offset = _read_uleb(data, offset)
    return offset


def shared_memories(path):
    """Return a list of human-readable descriptions of shared memories found."""
    data = path.read_bytes()
    if data[:4] != WASM_MAGIC:
        raise ValueError(f"{path}: not a wasm module")
    offset = 8  # magic (4) + version (4)
    found = []
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = _read_uleb(data, offset)
        end = offset + size
        if section_id == SECTION_MEMORY:
            count, pos = _read_uleb(data, offset)
            for _ in range(count):
                flag = data[pos]
                if flag & SHARED_BIT:
                    found.append(f"internal memory (flag=0x{flag:02x})")
                pos = _skip_limits(data, pos)
        elif section_id == SECTION_IMPORT:
            count, pos = _read_uleb(data, offset)
            for _ in range(count):
                mlen, pos = _read_uleb(data, pos)
                pos += mlen
                flen, pos = _read_uleb(data, pos)
                pos += flen
                kind = data[pos]
                pos += 1
                if kind == IMPORT_KIND_MEMORY:
                    flag = data[pos]
                    if flag & SHARED_BIT:
                        found.append(f"imported memory (flag=0x{flag:02x})")
                    pos = _skip_limits(data, pos)
                elif kind == 0:  # func
                    _, pos = _read_uleb(data, pos)
                elif kind == 1:  # table: reftype + limits
                    pos += 1
                    pos = _skip_limits(data, pos)
                elif kind == 3:  # global: valtype + mutability
                    pos += 2
        offset = end
    return found


def main(argv):
    roots = [Path(a) for a in argv[1:]]
    if not roots:
        print("usage: assert_wasm_unshared.py PATH [PATH ...]", file=sys.stderr)
        return 2

    wasm_files = []
    for root in roots:
        if root.is_dir():
            wasm_files.extend(sorted(root.rglob("*.wasm")))
        elif root.suffix == ".wasm":
            wasm_files.append(root)

    if not wasm_files:
        print(f"ERROR: no .wasm files found under {', '.join(map(str, roots))}",
              file=sys.stderr)
        return 1

    violations = 0
    for wasm in wasm_files:
        shared = shared_memories(wasm)
        if shared:
            violations += 1
            print(f"FAIL {wasm.name}: {'; '.join(shared)}")
        else:
            print(f"ok   {wasm.name}: memory is non-shared")

    if violations:
        print(f"\n{violations} module(s) use shared memory. On emscripten this "
              "usually means '-pthread' leaked into the build.", file=sys.stderr)
        return 1
    print(f"\nAll {len(wasm_files)} module(s) use non-shared memory.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
