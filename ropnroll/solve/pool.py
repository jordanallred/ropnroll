"""A GadgetPool merges gadgets from one or more same-architecture modules
(e.g. the target EXE + a DLL it imports from) behind one lazily-evaluated
semantic view.

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
from ..core.badchars import has_bad_bytes
from ..core.cache import EffectDiskCache
from ..core.gadget import Gadget, Terminator
from ..core.loader import Image
from ..semantics.effect import GadgetEffect
from ..semantics.engine import SEMANTIC_ENGINE_VERSION, SemanticEngine


@dataclass
class GadgetPool:
    ai: ArchInfo = None
    os: str = "windows"
    use_cache: bool = True
    # byte values no gadget *address* may contain -- e.g. the exploit's
    # delivery path is a strcpy and can't carry a NUL. Checked once here so
    # every solver (chain, pivot, jop) automatically only ever sees usable
    # candidates, instead of each having to filter separately.
    bad_chars: frozenset[int] = field(default_factory=frozenset)
    _engines: dict[str, SemanticEngine] = field(default_factory=dict)
    _images: dict[str, Image] = field(default_factory=dict)
    _gadgets: dict[str, list[Gadget]] = field(default_factory=dict)

    def add(self, img: Image, gadgets: list[Gadget]):
        ai = get_archinfo(img.arch, img.little_endian)
        if self.ai is None:
            self.ai = ai
            self.os = img.os
        elif self.ai.arch != ai.arch:
            raise ValueError(
                f"GadgetPool is arch={self.ai.arch}, can't add arch={ai.arch} module"
            )
        self._images[img.path] = img
        self._gadgets[img.path] = gadgets
        disk_cache = (
            EffectDiskCache(img.sha256, SEMANTIC_ENGINE_VERSION)
            if self.use_cache
            else None
        )
        self._engines[img.path] = SemanticEngine(img, ai, disk_cache=disk_cache)

    def all(self) -> list[Gadget]:
        out = []
        for gs in self._gadgets.values():
            out.extend(gs)
        if self.bad_chars and self.ai is not None:
            out = [
                g
                for g in out
                if not has_bad_bytes(g.address, self.ai.reg_width, self.bad_chars)
            ]
        return out

    def effect_of(self, g: Gadget) -> GadgetEffect:
        eng = self._engines[g.module]
        return eng.compute(g)

    def dst_read_deps(self, g: Gadget) -> dict[str, set[str]]:
        eng = self._engines[g.module]
        return eng.dst_read_deps(g)

    def image_of(self, module: str) -> Image | None:
        """The Image a gadget/symbol address came from, keyed the same way
        Gadget.module is set (img.path) -- used to decide whether an
        address can be baked into a chain as-is or needs to stay symbolic
        (see solve/chain.py's _tag)."""
        return self._images.get(module)

    def find_text(self, pattern: str) -> list[Gadget]:
        rx = re.compile(pattern)
        return [g for g in self.all() if rx.match(g.text)]

    def shortlist_pop_style(self, reg: str, max_insns: int = 3) -> list[Gadget]:
        """Cheap syntactic pre-filter: gadgets that plausibly load `reg`
        directly off the stack, ranked shortest-first."""
        rx = re.compile(rf"(^|; )pop {re.escape(reg)}\b")
        out = [
            g
            for g in self.all()
            if g.terminator in (Terminator.RET, Terminator.RET_IMM)
            and g.n_insns <= max_insns
            and rx.search(g.text)
        ]
        out.sort(key=lambda g: g.n_insns)
        return out

    def shortlist_touching(self, reg: str, max_insns: int = 4) -> list[Gadget]:
        rx = re.compile(rf"\b{re.escape(reg)}\b")
        out = [
            g
            for g in self.all()
            if g.terminator in (Terminator.RET, Terminator.RET_IMM)
            and g.n_insns <= max_insns
            and rx.search(g.text)
        ]
        out.sort(key=lambda g: g.n_insns)
        return out

    def shortlist_mem_write(self, max_insns: int = 4) -> list[Gadget]:
        rx = re.compile(r"mov [a-z0-9]+ ptr \[")
        out = [
            g
            for g in self.all()
            if g.terminator in (Terminator.RET, Terminator.RET_IMM)
            and g.n_insns <= max_insns
            and rx.search(g.text)
        ]
        out.sort(key=lambda g: g.n_insns)
        return out

    def shortlist_terminator(
        self, term: Terminator, max_insns: int = 6
    ) -> list[Gadget]:
        out = [g for g in self.all() if g.terminator == term and g.n_insns <= max_insns]
        out.sort(key=lambda g: g.n_insns)
        return out
