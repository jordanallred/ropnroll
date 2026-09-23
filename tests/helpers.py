"""Minimal hand-rolled PE writer for test fixtures.

No MSVC/MinGW toolchain invocation is wanted here for tiny synthetic
gadget sets (that would mean shipping a compiler dependency just to embed
a handful of hand-assembled instructions) -- so test binaries built purely
from raw machine code (via keystone) are wrapped in the smallest PE LIEF
will parse correctly: a real file on disk, read back through the same
loader.load() path everything else uses, not a mocked-up Image.
"""

from __future__ import annotations

import struct

_PE_MACHINE = {"x86": 0x14C, "x86_64": 0x8664, "arm64": 0xAA64}


def _align_up(x: int, a: int) -> int:
    return (x + a - 1) & ~(a - 1)


def write_minimal_pe(path: str, arch: str, code: bytes, base: int = 0x400000) -> int:
    """Write a single-section, executable-only PE containing exactly
    `code`, and return its entrypoint's virtual address (base + the
    section's RVA -- code always starts at the very first byte of the
    section)."""
    bits = 32 if arch == "x86" else 64
    machine = _PE_MACHINE[arch]
    align = 0x1000  # same value for both SectionAlignment and FileAlignment
    n_sections = 1
    opt_size = 240 if bits == 64 else 224
    unaligned_headers = 64 + 4 + 20 + opt_size + n_sections * 40
    size_of_headers = _align_up(unaligned_headers, align)

    code_rva = align
    code_raw_size = _align_up(max(len(code), 1), align)
    size_of_image = _align_up(code_rva + len(code), align)

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
    assert len(dos_header) == 64

    characteristics = 0x0002 | (
        0x0100 if bits == 32 else 0x0020
    )  # EXECUTABLE_IMAGE, +32BIT_MACHINE/LARGE_ADDRESS_AWARE
    file_header = struct.pack(
        "<HHIIIHH", machine, n_sections, 0, 0, 0, opt_size, characteristics
    )

    subsystem = 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    if bits == 64:
        opt_header = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B,
            0,
            0,
            code_raw_size,
            0,
            0,
            code_rva,
            code_rva,
            base,
            align,
            align,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size_of_image,
            size_of_headers,
            0,
            subsystem,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
    else:
        opt_header = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B,
            0,
            0,
            code_raw_size,
            0,
            0,
            code_rva,
            code_rva,
            code_rva,
            base,
            align,
            align,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size_of_image,
            size_of_headers,
            0,
            subsystem,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
    opt_header += b"\x00" * (8 * 16)  # 16 empty IMAGE_DATA_DIRECTORY entries

    name = b".text\x00\x00\x00"
    section_chars = 0x20 | 0x20000000 | 0x40000000  # CNT_CODE | MEM_EXECUTE | MEM_READ
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        name,
        len(code),
        code_rva,
        code_raw_size,
        size_of_headers,
        0,
        0,
        0,
        0,
        section_chars,
    )

    headers = dos_header + b"PE\x00\x00" + file_header + opt_header + section_header
    headers = headers.ljust(size_of_headers, b"\x00")
    body = headers + code.ljust(code_raw_size, b"\x00")

    with open(path, "wb") as f:
        f.write(body)
    return base + code_rva
