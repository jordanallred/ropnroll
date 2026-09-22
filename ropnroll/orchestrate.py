"""
Primitive-to-exploit orchestration: the "I already have read/write (or a
plain overflow), now what" layer the rest of this tool is built to serve.

`read_proc_maps`/`rebase_from_pid` turn "attach to a live process" into
real ASLR-defeated `Image` objects with correct runtime addresses, using
nothing but /proc/<pid>/maps (no ptrace, no special privileges beyond
running as the same user) -- the same information a real leak primitive
would ultimately need to give you. Everything downstream (the solver,
verifier, chain builders) is exactly what you already used against a
static binary; this module's only job is supplying the right addresses.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .core.loader import Image


@dataclass
class MapEntry:
    start: int
    end: int
    perms: str
    path: str


def read_proc_maps(pid: int) -> list[MapEntry]:
    entries = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5:
                continue
            addr_range, perms = parts[0], parts[1]
            path = parts[5] if len(parts) > 5 else ""
            start_s, end_s = addr_range.split("-")
            entries.append(MapEntry(int(start_s, 16), int(end_s, 16), perms, path))
    return entries


def find_module_base(maps: list[MapEntry], name_substr: str) -> int | None:
    """Lowest mapped address for the first module whose path contains
    `name_substr` (e.g. "libc.so.6", or a binary's own basename)."""
    candidates = [m for m in maps if name_substr in m.path]
    if not candidates:
        return None
    return min(m.start for m in candidates)


def rebase_from_pid(img: Image, pid: int, name_substr: str | None = None) -> Image:
    """Rebase `img` to wherever it's *actually* mapped in the live process
    `pid`. `name_substr` defaults to the image's own basename -- pass it
    explicitly if the on-disk filename won't match what shows up in maps
    (e.g. a renamed copy)."""
    maps = read_proc_maps(pid)
    substr = name_substr or Path(img.path).name
    base = find_module_base(maps, substr)
    if base is None:
        raise LookupError(f"no mapped module matching {substr!r} in pid {pid}'s maps")
    return img.rebase(base)
