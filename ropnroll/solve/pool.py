"""A GadgetPool merges gadgets from one or more same-architecture modules
(e.g. the target binary + libc) behind one lazily-evaluated semantic view.

Effects are expensive-ish to compute (a handful of Unicorn runs per
gadget), so nothing here computes them eagerly for the whole pool -- only
for gadgets a cheap syntactic pre-filter has already shortlisted. This is
the same "structural search narrows it, semantics confirms it" split
Ropper/Ropinator use, just with a concrete-emulation confirmer instead of
a modeled one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.archinfo import ArchInfo, get_archinfo
from ..core.cache import EffectDiskCache
from ..core.gadget import Gadget, Terminator
from ..core.loader import Image
from ..semantics.effect import GadgetEffect
from ..semantics.engine import SEMANTIC_ENGINE_VERSION, SemanticEngine


@dataclass
class GadgetPool:
    ai: ArchInfo = None
    os: str = "linux"
    use_cache: bool = True
    _engines: dict[str, SemanticEngine] = field(default_factory=dict)
    _images: dict[str, Image] = field(default_factory=dict)
    _gadgets: dict[str, list[Gadget]] = field(default_factory=dict)

    def add(self, img: Image, gadgets: list[Gadget]):
        ai = get_archinfo(img.arch, img.little_endian)
        if self.ai is None:
            self.ai = ai
            self.os = img.os
        elif self.ai.arch != ai.arch:
            raise ValueError(f"GadgetPool is arch={self.ai.arch}, can't add arch={ai.arch} module")
        self._images[img.path] = img
        self._gadgets[img.path] = gadgets
        disk_cache = EffectDiskCache(img.sha256, SEMANTIC_ENGINE_VERSION) if self.use_cache else None
        self._engines[img.path] = SemanticEngine(img, ai, disk_cache=disk_cache)

    def all(self) -> list[Gadget]:
        out = []
        for gs in self._gadgets.values():
            out.extend(gs)
        return out

    def effect_of(self, g: Gadget) -> GadgetEffect:
        eng = self._engines[g.module]
        return eng.compute(g)

    def find_text(self, pattern: str) -> list[Gadget]:
        rx = re.compile(pattern)
        return [g for g in self.all() if rx.match(g.text)]

    def shortlist_pop_style(self, reg: str, max_insns: int = 3) -> list[Gadget]:
        """Cheap syntactic pre-filter: gadgets that plausibly load `reg`
        directly off the stack, ranked shortest-first."""
        rx = re.compile(rf"(^|; )pop {re.escape(reg)}\b")
        out = [g for g in self.all() if g.terminator in (Terminator.RET, Terminator.RET_IMM)
               and g.n_insns <= max_insns and rx.search(g.text)]
        out.sort(key=lambda g: g.n_insns)
        return out

    def shortlist_touching(self, reg: str, max_insns: int = 4) -> list[Gadget]:
        rx = re.compile(rf"\b{re.escape(reg)}\b")
        out = [g for g in self.all() if g.terminator in (Terminator.RET, Terminator.RET_IMM)
               and g.n_insns <= max_insns and rx.search(g.text)]
        out.sort(key=lambda g: g.n_insns)
        return out

    def shortlist_mem_write(self, max_insns: int = 4) -> list[Gadget]:
        rx = re.compile(r"mov [a-z0-9]+ ptr \[")
        out = [g for g in self.all() if g.terminator in (Terminator.RET, Terminator.RET_IMM)
               and g.n_insns <= max_insns and rx.search(g.text)]
        out.sort(key=lambda g: g.n_insns)
        return out

    def shortlist_terminator(self, term: Terminator, max_insns: int = 6) -> list[Gadget]:
        out = [g for g in self.all() if g.terminator == term and g.n_insns <= max_insns]
        out.sort(key=lambda g: g.n_insns)
        return out
