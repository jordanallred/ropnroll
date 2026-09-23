"""Bounded multi-gadget chain search.

`semantics/query.search` only ever answers "does *one* gadget produce this
effect?". Plenty of real effects need two or more gadgets relayed through a
register -- e.g. no single gadget in a given binary might set `rcx=rax`,
but a gadget that copies `rax` into `rbx` followed by one that copies `rbx`
into `rcx` does. This module extends the same query DSL (see
semantics/query.py) to bounded chains of such relays.

Soundness gate
---------------
A gadget like `or rcx, rax` cannot be composed into a chain safely in
general. The semantic engine characterizes each gadget by varying *one*
candidate source register at a time while holding every other GPR it reads
at a fixed baseline (see semantics/engine.py's module docstring). For an
instruction that truly reads two *different* GPRs to produce its result
(rcx and rax here), the fitted relation just reflects that fixed baseline,
not a universal law -- reusing it in a chain would be wrong unless the real
runtime register happens to equal that exact baseline. So this module only
ever composes a hop whose destination depends on exactly one GPR --
`engine.dst_read_deps` confirms that per gadget before it's added to the
search. Two-register combining ops are left out of automatic chaining
entirely; they still show up in `scan`/`search` for a human to combine by
hand (e.g. zeroing a register first, then OR-ing it with the value you
want -- sound by the arithmetic identity `0 | x == x`, not by trusting the
engine's measured constant).

Memory relays (write a value to an address, read it back into another
register) are also out of scope for this first version -- only register-to-
register relays are searched.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.gadget import Gadget, Terminator
from ..semantics.effect import EKind, RegEffect
from ..semantics.query import Query, parse_query
from .pool import GadgetPool


@dataclass(frozen=True)
class SymConcrete:
    value: int
    size: int = 8


@dataclass(frozen=True)
class SymLinear:  # value == orig_reg * k + c  (mod 2**(size*8))
    orig_reg: str
    k: int
    c: int
    size: int = 8


@dataclass(frozen=True)
class SymBitwise:  # value == orig_reg <kind> c, kind in {AND, OR, XOR}
    orig_reg: str
    kind: EKind
    c: int
    size: int = 8


SymValue = SymConcrete | SymLinear | SymBitwise


@dataclass
class ChainSearchResult:
    hops: list[Gadget]
    dst: str


def _sound_dst_effects(pool: GadgetPool, g: Gadget) -> list[tuple[str, RegEffect]]:
    """(dst, effect) pairs for this gadget that pass the soundness gate --
    i.e. depend on exactly the one `src` GPR the engine measured, *and*
    write the full register width. A gadget like `mov edx, ecx` only
    writes the low 32 bits (zero-extending on x86-64) -- relaying that
    forward as if it copied all 64 bits would silently drop the source's
    upper bits whenever they're nonzero, so a sub-width effect is excluded
    rather than composed (see query.py's matches_reg_effect for the same
    concern in single-gadget search)."""
    eff = pool.effect_of(g)
    if not eff.ok:
        return []
    width = pool.ai.reg_width
    deps_by_dst = pool.dst_read_deps(g)
    out = []
    for dst, re_ in eff.reg_effects.items():
        if dst == pool.ai.sp_reg or re_.kind in (EKind.UNKNOWN, EKind.LOAD, EKind.CONST):
            continue
        if re_.size != width:
            continue
        if deps_by_dst.get(dst, set()) != {re_.src}:
            continue
        out.append((dst, re_))
    return out


def _compose(state: SymValue, re_: RegEffect) -> SymValue | None:
    mask = re_.mask()
    if isinstance(state, SymConcrete):
        v = re_.value_given(state.value)
        return None if v is None else SymConcrete(v & mask, re_.size)
    if re_.kind in (EKind.COPY, EKind.ADD, EKind.SCALE):
        if isinstance(state, SymLinear):
            return SymLinear(
                state.orig_reg,
                (state.k * re_.k) & mask,
                (state.c * re_.k + re_.c) & mask,
                re_.size,
            )
        if isinstance(state, SymBitwise) and re_.kind == EKind.COPY and re_.k == 1 and re_.c == 0:
            return SymBitwise(state.orig_reg, state.kind, state.c, re_.size)
        return None  # can't re-express arithmetic layered on a bitwise result
    if re_.kind in (EKind.AND, EKind.OR, EKind.XOR):
        if isinstance(state, SymLinear) and (state.k & mask) == 1 and (state.c & mask) == 0:
            return SymBitwise(state.orig_reg, re_.kind, re_.c, re_.size)
        return None  # a query is a single op; a second bitwise hop can never match it
    return None


def _matches(q: Query, state: SymValue) -> bool:
    mask = (1 << (state.size * 8)) - 1
    if q.kind == EKind.COPY:
        return (
            isinstance(state, SymLinear)
            and state.orig_reg == q.src
            and (state.k & mask) == 1
            and (state.c & mask) == 0
        )
    if q.kind in (EKind.ADD, EKind.SCALE):
        return (
            isinstance(state, SymLinear)
            and state.orig_reg == q.src
            and (state.k & mask) == (q.k & mask)
            and (state.c & mask) == (q.c & mask)
        )
    if q.kind in (EKind.AND, EKind.OR, EKind.XOR):
        return (
            isinstance(state, SymBitwise)
            and state.orig_reg == q.src
            and state.kind == q.kind
            and (state.c & mask) == (q.c & mask)
        )
    return False


def search_chain(
    pool: GadgetPool,
    query_text: str,
    max_depth: int = 3,
    limit: int = 5,
    max_insns: int = 4,
) -> list[ChainSearchResult]:
    """Bounded BFS for a sequence of up to `max_depth` ret-terminated
    gadgets whose composed effect satisfies `query_text`. Only register
    targets with a register source are searched -- a memory target
    (`[reg]=...`) or a bare-constant target (`reg=0x1000`) needs no relay
    and is already exactly what single-gadget `search` answers."""
    q = parse_query(query_text)
    if q.dst_mem:
        raise ValueError("chain search doesn't support memory targets yet")
    if q.src is None:
        return []

    width = pool.ai.reg_width
    candidates = [
        g
        for g in pool.all()
        if g.terminator in (Terminator.RET, Terminator.RET_IMM)
        and g.n_insns <= max_insns
        # A gadget with an embedded `call` runs a whole other function --
        # its measured effect can be an exact fit (the engine really did
        # execute it) yet still a bad building block to synthesize into a
        # chain automatically: unlike a plain instruction sequence, its
        # behavior depends on a callee this search never inspects (it may
        # branch on registers the trials didn't vary, touch global state,
        # or not be a leaf function at all). Single-gadget `search`/`scan`
        # still surface these for a human to judge; chain search doesn't
        # build on top of them.
        and " call " not in f" {g.text} "
    ]
    by_src: dict[str, list[tuple[Gadget, str, RegEffect]]] = {}
    for g in candidates:
        for dst, re_ in _sound_dst_effects(pool, g):
            by_src.setdefault(re_.src, []).append((g, dst, re_))

    start_state: dict[str, SymValue] = {q.src: SymLinear(q.src, 1, 0, width)}
    frontier: list[tuple[dict[str, SymValue], list[Gadget]]] = [(start_state, [])]
    visited = {frozenset(start_state.items())}
    results: list[ChainSearchResult] = []

    for _ in range(max_depth):
        next_frontier = []
        for state, path in frontier:
            for src_reg, value in list(state.items()):
                for g, dst, re_ in by_src.get(src_reg, ()):
                    if g in path:
                        continue
                    new_val = _compose(value, re_)
                    if new_val is None or state.get(dst) == new_val:
                        continue
                    new_state = dict(state)
                    new_state[dst] = new_val
                    key = frozenset(new_state.items())
                    if key in visited:
                        continue
                    visited.add(key)
                    new_path = path + [g]
                    if dst == q.dst and _matches(q, new_val):
                        results.append(ChainSearchResult(hops=new_path, dst=q.dst))
                        if len(results) >= limit:
                            return results
                    next_frontier.append((new_state, new_path))
        frontier = next_frontier
        if not frontier:
            break
    return results
