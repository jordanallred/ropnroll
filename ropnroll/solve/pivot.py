"""Stack-pivot gadget discovery.

Pivots (`pop rsp`, `xchg rsp, reg`, `mov rsp, reg`, `leave ; ret`, `add rsp,
N`) redirect rsp to attacker-controlled memory -- exactly what you need
once your read/write primitive can plant a fake stack but you can't
control the real one yet (a classic use: format-string or heap-write
primitives that land you a ROP chain in a *predictable* location).

These are found structurally rather than through the semantic engine:
once rsp becomes attacker/pointer-controlled, feeding the emulator a real
pointer would require knowing where the fake stack lives, which is
target-specific. A syntactic classifier is exactly as precise here and
works even when full effect emulation of the gadget can't succeed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.gadget import Gadget
from .pool import GadgetPool

_PATTERNS = [
    (re.compile(r"^pop (e?sp|rsp)\b"), "pop-sp", 1),
    (re.compile(r"^xchg (\w+), (e?sp|rsp)\b|^xchg (e?sp|rsp), (\w+)\b"), "xchg-sp", 1),
    (re.compile(r"^mov (e?sp|rsp), (\w+)\b"), "mov-sp", 0),
    (re.compile(r"^leave\b"), "leave (rsp = rbp, then pop rbp)", 2),
    (re.compile(r"^add (e?sp|rsp), (0x[0-9a-f]+)"), "stack-shift (add rsp, N)", 3),
    (re.compile(r"^xchg (\w+), (e?sp|rsp)\b"), "xchg-sp", 1),
]


@dataclass
class Pivot:
    gadget: Gadget
    kind: str
    rank: int  # lower = more directly useful (pure pivots first)


def find_pivots(pool: GadgetPool, max_insns: int = 4) -> list[Pivot]:
    out = []
    seen = set()
    for g in pool.all():
        if g.n_insns > max_insns:
            continue
        for rx, kind, rank in _PATTERNS:
            if rx.match(g.text) and g.address not in seen:
                out.append(Pivot(gadget=g, kind=kind, rank=rank))
                seen.add(g.address)
                break
    out.sort(key=lambda p: (p.rank, p.gadget.n_insns))
    return out
