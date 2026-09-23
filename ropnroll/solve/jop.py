"""
Automatic JOP dispatcher/trampoline synthesis (Bletsch et al., "Jump-
Oriented Programming: A New Class of Code-Reuse Attack", 2011).

Most tools that claim "JOP support" just tag gadgets ending in an indirect
jmp/call -- useful for browsing, but you still have to hand-build the
dispatch mechanism yourself. A real JOP chain needs a *dispatcher*: a
gadget of the form `<advance dispatch-reg> ; jmp [dispatch-reg]` that,
after running each "functional" gadget in your table, lands right back on
itself to fetch the next entry. We find these by asking the semantic
engine a precise question: does this JMP/CALL-through-memory gadget also
advance the exact register its own jump dereferences by a constant? If
yes, that's a self-feeding dispatcher and a table of function-pointer-like
entries turns it into an arbitrary-length JOP chain.

On CET/CFG-hardened targets, an indirect branch may only land on an
approved entry point (`endbr64`/`endbr32` under CET-IBT, or the PE Guard
CF table under CFG) -- we filter dispatcher *and* functional-gadget
candidates against that automatically instead of silently producing a
chain that CET/CFG will kill on the first hop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.gadget import Gadget, Terminator
from ..semantics.effect import EKind
from .pool import GadgetPool

_MEM_TARGET_RE = re.compile(r"\[\s*(\w+)\s*\]\s*$")


@dataclass
class Dispatcher:
    gadget: Gadget
    reg: str  # the dispatch register (both the jump base and what advances)
    advance: int  # bytes it advances per cycle -- your table's stride


def _cet_ok(img, g: Gadget) -> bool:
    return not img.mitigations.get("endbr_required", False) or g.text.startswith(
        "endbr"
    )


def _cfg_ok(img, addr: int) -> bool:
    return (
        not img.mitigations.get("cfg")
        or not img.cfg_valid_targets
        or addr in img.cfg_valid_targets
    )


def find_dispatchers(
    pool: GadgetPool, img=None, max_insns: int = 4
) -> list[Dispatcher]:
    out = []
    candidates = pool.shortlist_terminator(
        Terminator.JMP_MEM, max_insns=max_insns
    ) + pool.shortlist_terminator(Terminator.CALL_MEM, max_insns=max_insns)
    for g in candidates:
        m = _MEM_TARGET_RE.search(g.text)
        if not m:
            continue
        reg = m.group(1)
        eff = pool.effect_of(g)
        if not eff.ok:
            continue
        re_ = eff.reg_effects.get(reg)
        if re_ is None or re_.kind != EKind.ADD or re_.src != reg or re_.c == 0:
            continue
        if img is not None and (not _cfg_ok(img, g.address) or not _cet_ok(img, g)):
            continue
        out.append(Dispatcher(gadget=g, reg=reg, advance=re_.c & re_.mask()))
    out.sort(key=lambda d: d.gadget.n_insns)
    return out


@dataclass
class Trampoline:
    dispatcher: Dispatcher
    table_addr: int
    table_bytes: bytes
    initial_reg_value: int
    entry_address: int  # what to jump to (the dispatcher itself) to kick things off
    warnings: list[str] = field(default_factory=list)


def _validate_functional_targets(
    pool: GadgetPool, img, functional_targets: list[int]
) -> list[str]:
    """CFG/CET-validate each table entry, mirroring the checks `find_dispatchers`
    already applies to the dispatcher itself -- without this, a functional
    target that CFG/CET would reject gets silently written into the table
    and only fails at runtime, on whichever hop reaches it."""
    if img is None:
        return []
    warnings: list[str] = []
    by_addr: dict[int, Gadget] | None = None
    for addr in functional_targets:
        if not _cfg_ok(img, addr):
            warnings.append(f"0x{addr:x} is not a CFG-valid indirect-call target")
            continue
        if img.mitigations.get("endbr_required", False):
            if by_addr is None:
                by_addr = {g.address: g for g in pool.all()}
            g = by_addr.get(addr)
            if g is not None and not _cet_ok(img, g):
                warnings.append(
                    f"0x{addr:x} ({g.text}) does not start with endbr -- CET-IBT will reject it"
                )
    return warnings


def build_trampoline(
    pool: GadgetPool,
    dispatcher: Dispatcher,
    functional_targets: list[int],
    table_addr: int,
    img=None,
) -> Trampoline:
    """`functional_targets` are addresses of "functional" JOP gadgets you
    want executed in order -- typically other JMP_MEM/CALL_MEM gadgets
    through the *same* dispatch register, so each one falls back into the
    dispatcher automatically. The table itself is what you write into
    memory at `table_addr` via your write primitive; `initial_reg_value`
    is what the dispatch register must hold before the first jump.

    Pass `img` (the same Image given to `find_dispatchers`) to CFG/CET-validate
    the table entries; any that would be rejected at runtime are reported in
    the returned `Trampoline.warnings` instead of silently included."""
    warnings = _validate_functional_targets(pool, img, functional_targets)
    w = pool.ai.reg_width
    table = b"".join(
        (addr & ((1 << (w * 8)) - 1)).to_bytes(w, "little")
        for addr in functional_targets
    )
    return Trampoline(
        dispatcher=dispatcher,
        table_addr=table_addr,
        table_bytes=table,
        initial_reg_value=table_addr,
        entry_address=dispatcher.gadget.address,
        warnings=warnings,
    )
