"""Minimal hand-rolled ELF writer for test fixtures.

No cross-compiler toolchains are available in this environment for
ARM/MIPS/RISC-V/PowerPC, so test binaries for those architectures are
built by assembling real machine code with keystone and wrapping it in
the smallest ELF LIEF will parse correctly -- a real file on disk, read
back through the same loader.load() path everything else uses, not a
mocked-up Image.
"""
from __future__ import annotations

import struct

EM = {
    "x86": 3, "arm": 40, "x86_64": 62, "arm64": 183,
    "mips": 8, "mips64": 8, "ppc": 20, "ppc64": 21, "riscv32": 243, "riscv64": 243,
}


def write_minimal_elf(path: str, arch: str, code: bytes, base: int = 0x400000,
                       bits: int = 64, little_endian: bool = True, e_flags: int = 0):
    is64 = bits == 64
    ei_class = 2 if is64 else 1
    ei_data = 1 if little_endian else 2
    e_machine = EM[arch]
    endian = "<" if little_endian else ">"

    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    phoff = ehsize
    entry = base + ehsize + phentsize

    e_ident = bytes([0x7F, 0x45, 0x4C, 0x46, ei_class, ei_data, 1, 0]) + bytes(8)
    if is64:
        ehdr = e_ident + struct.pack(
            endian + "HHIQQQIHHHHHH", 2, e_machine, 1, entry, phoff, 0, e_flags,
            ehsize, phentsize, 1, 0, 0, 0)
        phdr = struct.pack(endian + "IIQQQQQQ", 1, 5, 0, base, base, 0, 0, 0x1000)
        # filesz/memsz get patched below once we know the total size
    else:
        ehdr = e_ident + struct.pack(
            endian + "HHIIIIIHHHHHH", 2, e_machine, 1, entry, phoff, 0, e_flags,
            ehsize, phentsize, 1, 0, 0, 0)
        phdr = struct.pack(endian + "IIIIIIII", 1, 0, base, base, 0, 0, 5, 0x1000)

    body = ehdr + phdr + code
    total = len(body)
    if is64:
        # p_offset=0, p_filesz/p_memsz = total (patch the two Q fields at
        # offsets 32 and 40 within phdr, i.e. absolute offsets ehsize+32/40)
        body = bytearray(body)
        struct.pack_into(endian + "Q", body, ehsize + 32, total)
        struct.pack_into(endian + "Q", body, ehsize + 40, total)
        body = bytes(body)
    else:
        body = bytearray(body)
        struct.pack_into(endian + "I", body, ehsize + 16, total)  # p_filesz
        struct.pack_into(endian + "I", body, ehsize + 20, total)  # p_memsz
        body = bytes(body)

    with open(path, "wb") as f:
        f.write(body)
    return entry
