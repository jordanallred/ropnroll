"""
Binary loading & abstraction layer.

Wraps LIEF so the rest of ropnroll never has to care whether the target is
x86, x86-64 or ARM64 -- PE is the only format this tool parses. Everything
downstream (scanner, semantics, solvers, verifier) talks to this uniform
`Image` object.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import lief

ARCH_X86 = "x86"
ARCH_X86_64 = "x86_64"
ARCH_ARM64 = "arm64"

_SUPPORTED = {ARCH_X86, ARCH_X86_64, ARCH_ARM64}


@dataclass
class Segment:
    vaddr: int
    data: bytes
    executable: bool
    writable: bool
    readable: bool
    name: str = ""

    @property
    def size(self) -> int:
        return len(self.data)

    def contains(self, addr: int) -> bool:
        return self.vaddr <= addr < self.vaddr + self.size


@dataclass
class Image:
    path: str
    sha256: str
    format: str  # "PE"
    arch: str  # one of the ARCH_* constants
    bits: int  # 32 | 64
    little_endian: bool
    pie: bool  # position independent / ASLR-relocatable base
    entrypoint: int
    image_base: (
        int  # base LIEF assumed while parsing (the PE's own preferred ImageBase)
    )
    base_known: bool = (
        True  # is `image_base` (and every address derived from it) a real,
    )
    # trustworthy runtime address? False for an ASLR-relocatable
    # module (pie=True) that hasn't been .rebase()'d to a leaked
    # base yet -- addresses are still computed (as the file's own
    # linker-preferred base + RVA, same as ROPgadget/ropper print),
    # but they're a stable per-build identifier, not where the
    # module actually lives at runtime. Chain-building uses this to
    # decide whether a gadget's address can be baked into a payload
    # as-is or must stay a symbolic (module, offset) pair for the
    # caller to resolve once they have a leak (see solve/chain.py).
    os: str = "windows"  # always "windows" -- kept as a field for the ABI-choice call sites that key off it
    segments: list[Segment] = field(default_factory=list)
    symbols: dict[str, int] = field(default_factory=dict)  # defined symbols
    plt: dict[str, int] = field(
        default_factory=dict
    )  # imported func -> PLT stub / IAT thunk
    got: dict[str, int] = field(
        default_factory=dict
    )  # imported func -> GOT/IAT slot address
    mitigations: dict[str, bool] = field(default_factory=dict)
    cfg_valid_targets: set[int] = field(
        default_factory=set
    )  # PE Control Flow Guard bitmap, if present
    _raw: lief.Binary = field(repr=False, default=None)

    # ---- convenience -----------------------------------------------
    def executable_segments(self) -> list[Segment]:
        return [s for s in self.segments if s.executable]

    def segment_at(self, addr: int) -> Segment | None:
        for s in self.segments:
            if s.contains(addr):
                return s
        return None

    def read(self, addr: int, size: int) -> bytes | None:
        seg = self.segment_at(addr)
        if seg is None:
            return None
        off = addr - seg.vaddr
        if off + size > seg.size:
            return None
        return seg.data[off : off + size]

    def rebase(self, new_base: int) -> Image:
        """Return a shallow copy with all vaddrs shifted to `new_base`.

        Used once you have a leaked base address (e.g. from your read
        primitive) and want gadget addresses that are actually valid at
        runtime for a PIE binary / shared library.
        """
        delta = new_base - self.image_base
        segs = [
            Segment(
                s.vaddr + delta, s.data, s.executable, s.writable, s.readable, s.name
            )
            for s in self.segments
        ]
        return Image(
            path=self.path,
            sha256=self.sha256,
            format=self.format,
            arch=self.arch,
            bits=self.bits,
            little_endian=self.little_endian,
            pie=self.pie,
            entrypoint=self.entrypoint + delta,
            image_base=new_base,
            base_known=True,
            os=self.os,
            segments=segs,
            symbols={k: v + delta for k, v in self.symbols.items()},
            plt={k: v + delta for k, v in self.plt.items()},
            got={k: v + delta for k, v in self.got.items()},
            mitigations=dict(self.mitigations),
            cfg_valid_targets={a + delta for a in self.cfg_valid_targets},
            _raw=self._raw,
        )


def _lief_arch_to_ropnroll(binary: lief.Binary) -> tuple[str, int, bool]:
    """Return (arch, bits, little_endian). PE is always little-endian."""
    if binary.format != lief.Binary.FORMATS.PE:
        raise ValueError(
            f"unsupported binary format: {binary.format} (ropnroll only reads PE)"
        )
    machine = binary.header.machine
    name = machine.name if hasattr(machine, "name") else str(machine)
    bits = 64 if "64" in name or "AMD64" in name else 32
    if "AMD64" in name or "X64" in name:
        return ARCH_X86_64, 64, True
    if "I386" in name:
        return ARCH_X86, 32, True
    if "ARM64" in name:
        return ARCH_ARM64, 64, True
    raise ValueError(f"unsupported PE machine type: {name}")


def load(path: str) -> Image:
    data = Path(path).read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"LIEF could not parse {path}")

    arch, bits, le = _lief_arch_to_ropnroll(binary)
    fmt = binary.format.name

    segments: list[Segment] = []
    symbols: dict[str, int] = {}
    plt: dict[str, int] = {}
    got: dict[str, int] = {}
    mitigations: dict[str, bool] = {}
    cfg_targets: set[int] = set()
    image_base = 0
    entry = int(binary.entrypoint)
    pie = False

    if fmt == "PE":
        pe: lief.PE.Binary = binary
        image_base = int(pe.optional_header.imagebase)
        pie = bool(
            pe.optional_header.has(
                lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE
            )
        )
        for sec in pe.sections:
            content = bytes(sec.content)
            if not content:
                continue
            chars = int(sec.characteristics)
            segments.append(
                Segment(
                    vaddr=image_base + int(sec.virtual_address),
                    data=content,
                    executable=bool(chars & 0x20000000),
                    writable=bool(chars & 0x80000000),
                    readable=bool(chars & 0x40000000),
                    name=sec.name,
                )
            )
        for sym in getattr(pe, "exported_functions", []):
            symbols[sym.name] = image_base + int(sym.address)
        for entry_imp in pe.imports:
            for f in entry_imp.entries:
                if f.name:
                    got[f.name] = image_base + int(f.iat_address)
        entry = image_base + int(pe.optional_header.addressof_entrypoint)
        try:
            has_canary_sym = any(
                s.name in ("__security_check_cookie", "__stack_chk_fail")
                for s in pe.symbols
            )
        except Exception:
            has_canary_sym = False
        # MSVC-linked PEs are almost always stripped of the COFF symbol table,
        # so the symbol check above misses /GS. The authoritative signal is a
        # non-zero SecurityCookie in the load configuration.
        if not has_canary_sym:
            try:
                if pe.has_configuration:
                    has_canary_sym = pe.load_configuration.security_cookie != 0
            except Exception:
                pass
        dll_chars = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
        cfg_enabled = False
        xfg_enabled = False
        try:
            if pe.has_configuration and pe.optional_header.has(dll_chars.GUARD_CF):
                lc = pe.load_configuration
                cfg_enabled = True
                # XFG (eXtended Flow Guard) is the type-checked successor to
                # CFG; it also sets GUARD_CF, so it is only distinguishable via
                # the XFG_ENABLED guard flag. When on, indirect-call targets are
                # constrained more tightly than plain CFG.
                xfg_bit = lief.PE.LoadConfiguration.IMAGE_GUARD.XFG_ENABLED
                xfg_enabled = bool(int(lc.guard_flags) & int(xfg_bit))
                for f in lc.guard_cf_functions:
                    rva = f.rva if hasattr(f, "rva") else int(f)
                    cfg_targets.add(image_base + rva)
        except Exception:
            pass
        # CET / hardware shadow stack (/CETCOMPAT) validates return addresses in
        # hardware and defeats classic ROP outright -- the single most decisive
        # fact for chain building. It is signalled by an extended-DLL-
        # characteristics debug directory entry, separate from the optional
        # header's DllCharacteristics.
        cet_enabled = False
        try:
            cet_bit = lief.PE.ExDllCharacteristics.CHARACTERISTICS.CET_COMPAT
            for dbg in pe.debug:
                if isinstance(dbg, lief.PE.ExDllCharacteristics):
                    cet_enabled = dbg.has(cet_bit)
        except Exception:
            pass
        mitigations = {
            "nx": bool(pe.optional_header.has(dll_chars.NX_COMPAT)),
            "pie": pie,
            "canary": has_canary_sym,
            # Control Flow Guard restricts indirect call/jmp targets to a
            # known-good bitmap -- decisive for our JOP dispatcher builder.
            "cfg": cfg_enabled,
            "xfg": xfg_enabled,
            "cet": cet_enabled,
            "safeseh": bool(pe.optional_header.has(dll_chars.NO_SEH))
            if bits == 32
            else True,
            "high_entropy_va": bool(pe.optional_header.has(dll_chars.HIGH_ENTROPY_VA)),
        }

    else:
        raise ValueError(f"unsupported format {fmt} (ropnroll only reads PE)")

    return Image(
        path=path,
        sha256=sha256,
        format=fmt,
        arch=arch,
        bits=bits,
        little_endian=le,
        pie=pie,
        entrypoint=entry,
        image_base=image_base,
        base_known=not pie,
        os="windows",
        segments=segments,
        symbols=symbols,
        plt=plt,
        got=got,
        mitigations=mitigations,
        cfg_valid_targets=cfg_targets,
        _raw=binary,
    )
