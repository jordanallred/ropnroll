"""
Tiny semantic query DSL, ROPium-style: `rax=rbx+8`, `rdi=0x1000`,
`[rdi]=rsi`, `[rbp-0x10]=0`, `rax=rbx^0xff`.

Grammar (regex-based, deliberately small):
    target := reg | '[' reg (('+'|'-') int)? ']'
    query  := target '=' (int | reg (('+'|'-'|'^'|'&'|'|') int)?)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .effect import EKind, GadgetEffect

_INT = r"0x[0-9a-fA-F]+|-?\d+"
_REG = r"[a-zA-Z][a-zA-Z0-9]*"
_OP = {"+": EKind.ADD, "-": EKind.ADD, "^": EKind.XOR, "&": EKind.AND, "|": EKind.OR}

_RE_MEM_TARGET = re.compile(rf"^\[\s*({_REG})\s*(?:([+-])\s*({_INT}))?\s*\]$")
_RE_QUERY = re.compile(
    rf"^\s*(?P<dst>{_REG}|\[[^\]]+\])\s*=\s*(?P<rhs>.+?)\s*$"
)
_RE_RHS_INT = re.compile(rf"^({_INT})$")
_RE_RHS_REG = re.compile(rf"^({_REG})$")
_RE_RHS_REGOP = re.compile(rf"^({_REG})\s*([+\-^&|])\s*({_INT})$")


def _parse_int(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") or s.lower().startswith("-0x") else int(s)


@dataclass
class Query:
    dst_mem: bool
    dst: str                 # register name (the target reg, or the base reg if dst_mem)
    dst_mem_offset: int = 0
    kind: EKind = EKind.CONST
    src: Optional[str] = None
    k: int = 1
    c: int = 0

    def matches_reg_effect(self, eff) -> bool:
        if eff is None or eff.kind != self.kind:
            return False
        if self.kind == EKind.CONST:
            return (eff.c & eff.mask()) == (self.c & eff.mask())
        return eff.src == self.src and (eff.c & eff.mask()) == (self.c & eff.mask()) and eff.k == self.k


def parse_query(text: str) -> Query:
    m = _RE_QUERY.match(text)
    if not m:
        raise ValueError(f"can't parse query: {text!r}")
    dst_raw, rhs = m.group("dst"), m.group("rhs")

    dst_mem = dst_raw.startswith("[")
    dst_mem_offset = 0
    if dst_mem:
        mm = _RE_MEM_TARGET.match(dst_raw)
        if not mm:
            raise ValueError(f"bad memory target: {dst_raw!r}")
        dst = mm.group(1).lower()
        if mm.group(2):
            dst_mem_offset = _parse_int(mm.group(3))
            if mm.group(2) == "-":
                dst_mem_offset = -dst_mem_offset
    else:
        dst = dst_raw.lower()

    if _RE_RHS_INT.match(rhs):
        return Query(dst_mem, dst, dst_mem_offset, EKind.CONST, None, 1, _parse_int(rhs))
    if _RE_RHS_REG.match(rhs):
        return Query(dst_mem, dst, dst_mem_offset, EKind.COPY, rhs.lower(), 1, 0)
    mm = _RE_RHS_REGOP.match(rhs)
    if mm:
        src, op, imm = mm.group(1).lower(), mm.group(2), _parse_int(mm.group(3))
        kind = _OP[op]
        c = -imm if op == "-" else imm
        return Query(dst_mem, dst, dst_mem_offset, kind, src, 1, c)
    raise ValueError(f"can't parse right-hand side: {rhs!r}")


def search(pool, query_text: str, limit: int = 20) -> list[tuple]:
    """Returns [(Gadget, GadgetEffect, matched_field), ...]."""
    q = parse_query(query_text)
    results = []
    if q.dst_mem:
        candidates = pool.shortlist_mem_write()
    else:
        candidates = pool.shortlist_touching(q.dst)
    for g in candidates:
        eff = pool.effect_of(g)
        if not eff.ok:
            continue
        if q.dst_mem:
            for mw in eff.mem_writes:
                if mw.addr.src == q.dst and mw.addr.c == q.dst_mem_offset and q.matches_reg_effect(mw.value):
                    results.append((g, eff, f"*({q.dst}+{q.dst_mem_offset:#x})"))
                    break
        else:
            reff = eff.reg_effects.get(q.dst)
            if q.matches_reg_effect(reff):
                results.append((g, eff, q.dst))
        if len(results) >= limit:
            break
    return results
