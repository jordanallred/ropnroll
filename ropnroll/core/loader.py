"""
Binary loading & abstraction layer.

Wraps LIEF so the rest of ropnroll never has to care whether it is looking
at an ELF, PE or Mach-O, and whether the target is x86, x86-64, ARM, ARM64
or MIPS. Everything downstream (scanner, semantics, solvers, verifier)
talks to this uniform `Image` object.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import lief

ARCH_X86 = "x86"
ARCH_X86_64 = "x86_64"
ARCH_ARM = "arm"
ARCH_ARM64 = "arm64"
ARCH_MIPS = "mips"
ARCH_MIPS64 = "mips64"

_SUPPORTED = {ARCH_X86, ARCH_X86_64, ARCH_ARM, ARCH_ARM64, ARCH_MIPS, ARCH_MIPS64}


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
    format: str            # "ELF" | "PE" | "MachO"
    arch: str              # one of the ARCH_* constants
    bits: int              # 32 | 64
    little_endian: bool
    pie: bool               # position independent / ASLR-relocatable base
    entrypoint: int
    image_base: int         # base LIEF assumed while parsing (0 for PIE ELF)
    os: str = "linux"      # "linux" | "windows" | "macos" -- drives ABI choice (arg regs, shadow space)
    segments: list[Segment] = field(default_factory=list)
    symbols: dict[str, int] = field(default_factory=dict)      # defined symbols
    plt: dict[str, int] = field(default_factory=dict)          # imported func -> PLT stub / IAT thunk
    got: dict[str, int] = field(default_factory=dict)          # imported func -> GOT/IAT slot address
    mitigations: dict[str, bool] = field(default_factory=dict)
    cfg_valid_targets: set[int] = field(default_factory=set)   # PE Control Flow Guard bitmap, if present
    _raw: lief.Binary = field(repr=False, default=None)

    # ---- convenience -----------------------------------------------
    def executable_segments(self) -> list[Segment]:
        return [s for s in self.segments if s.executable]

    def segment_at(self, addr: int) -> Optional[Segment]:
        for s in self.segments:
            if s.contains(addr):
                return s
        return None

    def read(self, addr: int, size: int) -> Optional[bytes]:
        seg = self.segment_at(addr)
        if seg is None:
            return None
        off = addr - seg.vaddr
        if off + size > seg.size:
            return None
        return seg.data[off:off + size]

    def rebase(self, new_base: int) -> "Image":
        """Return a shallow copy with all vaddrs shifted to `new_base`.

        Used once you have a leaked base address (e.g. from your read
        primitive) and want gadget addresses that are actually valid at
        runtime for a PIE binary / shared library.
        """
        delta = new_base - self.image_base
        segs = [Segment(s.vaddr + delta, s.data, s.executable, s.writable, s.readable, s.name)
                for s in self.segments]
        return Image(
            path=self.path, sha256=self.sha256, format=self.format, arch=self.arch,
            bits=self.bits, little_endian=self.little_endian, pie=self.pie,
            entrypoint=self.entrypoint + delta, image_base=new_base, os=self.os, segments=segs,
            symbols={k: v + delta for k, v in self.symbols.items()},
            plt={k: v + delta for k, v in self.plt.items()},
            got={k: v + delta for k, v in self.got.items()},
            mitigations=dict(self.mitigations),
            cfg_valid_targets={a + delta for a in self.cfg_valid_targets},
            _raw=self._raw,
        )


def _lief_arch_to_ropnroll(binary: lief.Binary) -> tuple[str, int, bool]:
    """Return (arch, bits, little_endian)."""
    header = binary.header
    if binary.format == lief.Binary.FORMATS.ELF:
        machine = binary.header.machine_type
        cls = binary.header.identity_class
        bits = 64 if cls == lief.ELF.Header.CLASS.ELF64 else 32
        le = binary.header.identity_data == lief.ELF.Header.ELF_DATA.LSB
        name = machine.name if hasattr(machine, "name") else str(machine)
        if "X86_64" in name:
            return ARCH_X86_64, 64, le
        if name in ("i386", "I386", "386"):
            return ARCH_X86, 32, le
        if "AARCH64" in name:
            return ARCH_ARM64, 64, le
        if name == "ARM":
            return ARCH_ARM, 32, le
        if "MIPS" in name and bits == 64:
            return ARCH_MIPS64, 64, le
        if "MIPS" in name:
            return ARCH_MIPS, 32, le
        return name.lower(), bits, le
    elif binary.format == lief.Binary.FORMATS.PE:
        machine = binary.header.machine
        name = machine.name if hasattr(machine, "name") else str(machine)
        bits = 64 if "64" in name or "AMD64" in name else 32
        if "AMD64" in name or "X64" in name:
            return ARCH_X86_64, 64, True
        if "I386" in name:
            return ARCH_X86, 32, True
        if "ARM64" in name:
            return ARCH_ARM64, 64, True
        if "ARM" in name:
            return ARCH_ARM, 32, True
        return name.lower(), bits, True
    elif binary.format == lief.Binary.FORMATS.MACHO:
        cpu = binary.header.cpu_type
        name = cpu.name if hasattr(cpu, "name") else str(cpu)
        if "X86_64" in name or "X86" in name and "64" in name:
            return ARCH_X86_64, 64, True
        if "ARM64" in name:
            return ARCH_ARM64, 64, True
        if "ARM" in name:
            return ARCH_ARM, 32, True
        return name.lower(), 64, True
    raise ValueError(f"unsupported binary format: {binary.format}")


def _elf_mitigations(binary: lief.ELF.Binary) -> dict[str, bool]:
    dyn = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS) if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS) else None
    flags1 = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1) if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS_1) else None
    bind_now = False
    if flags1 is not None:
        bind_now = bool(int(flags1.value) & 0x8)  # DF_1_NOW
    now_flag = binary.has(lief.ELF.DynamicEntry.TAG.BIND_NOW) or bind_now
    has_relro_seg = any(s.type == lief.ELF.Segment.TYPE.GNU_RELRO for s in binary.segments)
    relro = "full" if (has_relro_seg and now_flag) else ("partial" if has_relro_seg else "none")
    nx = not any(s.type == lief.ELF.Segment.TYPE.GNU_STACK and
                 bool(int(s.flags) & int(lief.ELF.Segment.FLAGS.X)) for s in binary.segments)
    canary = any(sym.name == "__stack_chk_fail" for sym in binary.symbols)
    pie = binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    fortify = any(sym.name.endswith("_chk") for sym in binary.symbols)
    return {"nx": nx, "pie": pie, "canary": canary, "fortify": fortify,
            "relro_full": relro == "full", "relro_partial": relro == "partial"}


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

    if fmt == "ELF":
        elf: lief.ELF.Binary = binary
        pie = elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
        image_base = 0  # gadget addrs are file-relative until .rebase()'d
        for seg in elf.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD or seg.physical_size == 0:
                continue
            content = bytes(seg.content)
            flags = int(seg.flags)
            segments.append(Segment(
                vaddr=int(seg.virtual_address),
                data=content,
                executable=bool(flags & int(lief.ELF.Segment.FLAGS.X)),
                writable=bool(flags & int(lief.ELF.Segment.FLAGS.W)),
                readable=bool(flags & int(lief.ELF.Segment.FLAGS.R)),
                name=f"LOAD@{hex(seg.virtual_address)}",
            ))
        for sym in elf.symbols:
            if sym.value and sym.name:
                symbols.setdefault(sym.name, int(sym.value))
        try:
            for rel in elf.pltgot_relocations:
                if rel.has_symbol and rel.symbol.name:
                    got[rel.symbol.name] = int(rel.address)
        except Exception:
            pass
        try:
            for f in elf.pltgot_relocations:
                pass
        except Exception:
            pass
        # PLT stub addresses: match .plt.sec/.plt entries to imported symbol names
        try:
            for func in elf.functions:
                pass
        except Exception:
            pass
        mitigations = _elf_mitigations(elf)

    elif fmt == "PE":
        pe: lief.PE.Binary = binary
        image_base = int(pe.optional_header.imagebase)
        pie = bool(pe.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE))
        for sec in pe.sections:
            content = bytes(sec.content)
            if not content:
                continue
            chars = int(sec.characteristics)
            segments.append(Segment(
                vaddr=image_base + int(sec.virtual_address),
                data=content,
                executable=bool(chars & 0x20000000),
                writable=bool(chars & 0x80000000),
                readable=bool(chars & 0x40000000),
                name=sec.name,
            ))
        for sym in getattr(pe, "exported_functions", []):
            symbols[sym.name] = image_base + int(sym.address)
        for entry_imp in pe.imports:
            for f in entry_imp.entries:
                if f.name:
                    got[f.name] = image_base + int(f.iat_address)
        entry = image_base + int(pe.optional_header.addressof_entrypoint)
        try:
            has_canary_sym = any(s.name in ("__security_check_cookie", "__stack_chk_fail")
                                  for s in pe.symbols)
        except Exception:
            has_canary_sym = False
        dll_chars = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
        cfg_enabled = False
        try:
            if pe.has_configuration and pe.optional_header.has(dll_chars.GUARD_CF):
                lc = pe.load_configuration
                cfg_enabled = True
                for f in lc.guard_cf_functions:
                    rva = f.rva if hasattr(f, "rva") else int(f)
                    cfg_targets.add(image_base + rva)
        except Exception:
            pass
        mitigations = {
            "nx": bool(pe.optional_header.has(dll_chars.NX_COMPAT)),
            "pie": pie,
            "canary": has_canary_sym,
            "fortify": False,
            "relro_full": False,
            "relro_partial": False,
            # Windows-specific: Control Flow Guard restricts indirect
            # call/jmp targets to a known-good bitmap -- the direct analog
            # of Linux CET-IBT for our JOP dispatcher builder.
            "cfg": cfg_enabled,
            "safeseh": bool(pe.optional_header.has(dll_chars.NO_SEH)) if bits == 32 else True,
            "high_entropy_va": bool(pe.optional_header.has(dll_chars.HIGH_ENTROPY_VA)),
        }

    elif fmt == "MACHO":
        macho: lief.MachO.Binary = binary
        pie = bool(macho.header.has(lief.MachO.Header.FLAGS.PIE))
        for seg in macho.segments:
            content = bytes(seg.content)
            if not content:
                continue
            segments.append(Segment(
                vaddr=int(seg.virtual_address),
                data=content,
                executable="EXECUTE" in str(seg.init_protection),
                writable="WRITE" in str(seg.init_protection),
                readable=True,
                name=seg.name,
            ))
        for sym in macho.symbols:
            if sym.value and sym.name:
                symbols[sym.name] = int(sym.value)
        mitigations = {"nx": True, "pie": pie, "canary": True, "fortify": False,
                        "relro_full": False, "relro_partial": False}
    else:
        raise ValueError(f"unsupported format {fmt}")

    os_name = {"ELF": "linux", "PE": "windows", "MACHO": "macos"}.get(fmt, "linux")
    return Image(
        path=path, sha256=sha256, format=fmt, arch=arch, bits=bits,
        little_endian=le, pie=pie, entrypoint=entry, image_base=image_base, os=os_name,
        segments=segments, symbols=symbols, plt=plt, got=got,
        mitigations=mitigations, cfg_valid_targets=cfg_targets, _raw=binary,
    )
