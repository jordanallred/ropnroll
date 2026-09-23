"""
Persistent on-disk cache for semantic gadget effects.

Computing a GadgetEffect costs several real Unicorn emulation runs (see
semantics/engine.py), and the realistic workflow -- building an exploit -- means
running `search`/`call` repeatedly against the *same* binary or DLL.
Without persistence, every single invocation pays that cost again from zero.

Cache files are keyed by the target binary's content hash (Image.sha256), so a
different build of "the same path" never collides, and by each gadget's own raw
bytes within that file, mirroring the existing in-memory cache key in
SemanticEngine. A version stamp guards against a future engine change silently
serving stale results from an old cache file.
"""

from __future__ import annotations

import atexit
import json
import os
import sys
from pathlib import Path

from ..semantics.effect import GadgetEffect


def cache_dir() -> Path:
    override = os.environ.get("ROPNROLL_CACHE_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "ropnroll" / "Cache"
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "ropnroll"


class EffectDiskCache:
    """One JSON file per binary (keyed by content hash), holding gadget-raw-bytes
    -> serialized GadgetEffect. Reads are lazy; writes are buffered in memory and
    flushed once via atexit, since the CLI is a one-shot process per invocation."""

    def __init__(self, sha256: str, version: int, root: Path | None = None):
        self.path = (root or cache_dir()) / "effects" / f"{sha256}.json"
        self.version = version
        self._entries: dict[bytes, GadgetEffect] = {}
        self._dirty = False
        self._loaded = False
        atexit.register(self.flush)

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if data.get("version") != self.version:
            return  # stale schema/engine version -- treat as a cold cache
        for raw_hex, eff_dict in data.get("effects", {}).items():
            try:
                self._entries[bytes.fromhex(raw_hex)] = GadgetEffect.from_dict(eff_dict)
            except (KeyError, ValueError, TypeError):
                continue  # corrupt entry -- skip rather than fail the whole cache

    def get(self, raw: bytes) -> GadgetEffect | None:
        self._load()
        return self._entries.get(raw)

    def put(self, raw: bytes, effect: GadgetEffect):
        self._load()
        self._entries[raw] = effect
        self._dirty = True

    def flush(self):
        if not self._dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": self.version,
                "effects": {
                    raw.hex(): eff.to_dict() for raw, eff in self._entries.items()
                },
            }
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError:
            pass  # a failed cache write should never break the actual command


class GadgetScanCache:
    """One JSON file per binary (keyed by content hash), holding the full
    gadget list produced by a scan with a specific ScanOptions configuration.

    Scanning (scanner.scan_image) is the syntactic disassembly pass that
    finds every gadget in a module -- for a large module (a Windows system
    DLL routinely runs 500KB-1MB+) this is the dominant cost of a command,
    often an order of magnitude more than everything else combined, and
    unlike per-gadget semantic effects (EffectDiskCache above) it was
    previously redone from scratch on every single invocation.

    Addresses are stored as RVAs (offset from img.image_base) rather than
    absolute addresses: Image.rebase() shifts image_base and every segment
    vaddr by the same delta, so `address - image_base` is invariant across
    rebasing and a cached scan stays valid regardless of what --base
    override (if any) was in effect when it was produced or when it is
    read back.

    A version stamp plus a scan_key (the ScanOptions fields that actually
    affect which gadgets are found) guard against silently serving stale or
    mismatched results -- either one changing treats the cache as cold.
    """

    def __init__(
        self, sha256: str, scan_key: str, version: int, root: Path | None = None
    ):
        self.path = (root or cache_dir()) / "scans" / f"{sha256}.json"
        self.scan_key = scan_key
        self.version = version

    def get(self) -> list[tuple[int, bytes, str]] | None:
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        if data.get("version") != self.version or data.get("scan_key") != self.scan_key:
            return None  # stale schema/scanner version or different scan options -- cold cache
        try:
            return [
                (rva, bytes.fromhex(raw_hex), term)
                for rva, raw_hex, term in data["gadgets"]
            ]
        except (KeyError, ValueError, TypeError):
            return None  # corrupt cache -- treat as cold rather than fail the scan

    def put(self, gadgets: list[tuple[int, bytes, str]]):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": self.version,
                "scan_key": self.scan_key,
                "gadgets": [[rva, raw.hex(), term] for rva, raw, term in gadgets],
            }
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError:
            pass  # a failed cache write should never break the actual command
