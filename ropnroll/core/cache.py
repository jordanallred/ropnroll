"""
Persistent on-disk cache for semantic gadget effects.

Computing a GadgetEffect costs several real Unicorn emulation runs (see
semantics/engine.py), and the realistic workflow -- building an exploit -- means
running `search`/`call`/`syscall` repeatedly against the *same* binary or libc.
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
from typing import Optional

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

    def __init__(self, sha256: str, version: int, root: Optional[Path] = None):
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

    def get(self, raw: bytes) -> Optional[GadgetEffect]:
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
            data = {"version": self.version,
                    "effects": {raw.hex(): eff.to_dict() for raw, eff in self._entries.items()}}
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError:
            pass  # a failed cache write should never break the actual command
