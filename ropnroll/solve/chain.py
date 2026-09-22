"""Chain representation + the register-value solver.

A Chain is exactly the sequence of 8-byte (or arch-width) stack words an
attacker needs to write, in order. Each gadget "owns" a block of
`effect.sp_delta` bytes: its own address word, then one word per stack
slot it pops, then (for ret-terminated gadgets) a trailing word that is
always "whatever comes next" -- the next gadget's address, or the final
call target. That trailing word is left as an open placeholder so chains
compose by simply filling it in / concatenating.
"""
from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import Optional

from ..core.archinfo import ArchInfo
from ..core.gadget import Gadget
from ..semantics.effect import EKind, GadgetEffect
from .pool import GadgetPool

DEFAULT_JUNK = 0x4141414141414141


@dataclass
class ChainWord:
    value: Optional[int]
    label: str


@dataclass
class Chain:
    ai: ArchInfo
    words: list[ChainWord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def append_gadget_block(self, gadget: Gadget, effect: GadgetEffect,
                             fills: dict[int, tuple[int, str]]):
        w = self.ai.reg_width
        self.words.append(ChainWord(gadget.address, f"0x{gadget.address:x}: {gadget.text}"))
        n_slots = max(0, effect.sp_delta // w - 1)
        for i in range(n_slots):
            off = i * w
            if off in fills:
                val, label = fills[off]
                self.words.append(ChainWord(val, label))
            else:
                self.words.append(ChainWord(None, "junk (unused stack slot)"))
        self.words.append(ChainWord(None, "-> next"))

    def set_last(self, value: int, label: str):
        if not self.words:
            self.words.append(ChainWord(value, label))
        else:
            self.words[-1] = ChainWord(value, label)

    def extend(self, other: "Chain"):
        if not other.words:
            return
        self.set_last(other.words[0].value, other.words[0].label)
        self.words.extend(other.words[1:])
        self.warnings.extend(other.warnings)

    def append_raw(self, value: int, label: str):
        self.words.append(ChainWord(value, label))

    def to_bytes(self, little_endian: bool = True, junk: int = DEFAULT_JUNK) -> bytes:
        w = self.ai.reg_width
        mask = (1 << (w * 8)) - 1
        out = bytearray()
        for word in self.words:
            v = (word.value if word.value is not None else junk) & mask
            out += v.to_bytes(w, "little" if little_endian else "big")
        return bytes(out)


@dataclass
class SolveResult:
    chain: Optional[Chain]
    resolved: dict[str, int]
    unresolved: list[str]
    log: list[str]

    @property
    def ok(self) -> bool:
        return not self.unresolved


def _conflicts(effect: GadgetEffect, protect: set[str], covers: set[str]) -> bool:
    for reg, eff in effect.reg_effects.items():
        if reg in protect and reg not in covers:
            return True
    return False


def _is_stack_safe(effect: GadgetEffect, ai: ArchInfo) -> bool:
    """Reject gadgets where sp ends up derived from some *other* register
    (`leave` -> rsp=rbp, `xchg rsp,reg`, `mov rsp,reg`, ...). Those are
    stack *pivots* -- a real, separate primitive (see solve/pivot.py) --
    and silently letting the general solver pick one up would make every
    stack offset after it depend on a register we never arranged to
    control, producing a chain that looks fine here and is garbage for
    real use.
    """
    sp_eff = effect.reg_effects.get(ai.sp_reg)
    if sp_eff is None:
        return True
    return sp_eff.kind in (EKind.COPY, EKind.ADD) and sp_eff.src == ai.sp_reg


def _no_unsafe_memory_access(effect: GadgetEffect, ai: ArchInfo) -> bool:
    """Reject gadgets whose body touches memory through a register we
    never set (e.g. `pop rdx ; or byte ptr [rcx-0xa], al ; ret` -- the
    `or` is incidental to what we picked the gadget for, but `rcx` is
    whatever garbage it happens to hold, and this dereferences it
    unconditionally). Only a stack-relative access (which we always
    control -- it's our own chain layout) or a fixed constant address is
    safe to accept automatically; anything keyed off another register is
    a live landmine the caller has no way to see from the chain listing.
    Found by the verifier catching exactly this on a real libc build.
    """
    for mem in effect.mem_writes + effect.mem_reads:
        if mem.addr.kind == EKind.CONST:
            continue
        if mem.addr.src != ai.sp_reg:
            return False
    return True


def _gadget_ok(effect: GadgetEffect, ai: ArchInfo) -> bool:
    return effect.ok and _is_stack_safe(effect, ai) and _no_unsafe_memory_access(effect, ai)


# candidates are already shortlisted shortest-first; only the cheapest few
# are worth trying as a *direct* (one-gadget) solution to a subproblem --
# beyond this it's diminishing returns for combinatorially more work.
_INDIRECT_BREADTH = 8
# per-node fanout cap when *expanding* a subproblem into transform
# candidates. This is deliberately much larger than _INDIRECT_BREADTH: the
# old fixed per-node cutoff of 8 here was exactly why the solver could miss
# a chain that existed, if the one useful transform gadget happened to be
# ranked 9th+ by instruction count at some level. Cross-branch
# prioritization now comes from the global best-first queue below, not
# from truncating any single node's options, so raising this only bounds
# per-node work, not the search's actual reach.
_MAX_EXPAND = 24
# hard ceiling on total node expansions for one top-level register, so a
# gadget-poor pool degrades to "gave up" instead of hanging.
_INDIRECT_BUDGET = 4000


def _goal_test(pool: GadgetPool, ai: ArchInfo, reg: str, target_val: int,
               protect: set[str], avoid: set[str], max_insns: int):
    """Can (reg, target_val) be solved in exactly one more gadget? Tries a
    direct "pop reg ; ret"-style load first, then an unconditional
    const-setter. Returns a one-step (gadget, effect, fills) list, or None.

    This doubles as the A* heuristic's zero-cost check (see
    _solve_register_indirect) and as the actual step generator once a
    subproblem is popped off the frontier as the best candidate.
    """
    for pg in pool.shortlist_pop_style(reg, max_insns=max_insns)[:_INDIRECT_BREADTH]:
        pe = pool.effect_of(pg)
        if not _gadget_ok(pe, ai):
            continue
        pe_reg = pe.reg_effects.get(reg)
        if pe_reg is None or pe_reg.kind != EKind.LOAD or pe_reg.src != ai.sp_reg:
            continue
        if _conflicts(pe, protect, {reg}) or (set(pe.reg_effects) & avoid):
            continue
        fills = {pe_reg.c: (target_val, f"{reg} = 0x{target_val:x}")}
        return [(pg, pe, fills)]

    for g in pool.shortlist_touching(reg, max_insns=max_insns)[:_INDIRECT_BREADTH]:
        eff = pool.effect_of(g)
        if not _gadget_ok(eff, ai):
            continue
        e = eff.reg_effects.get(reg)
        if e is not None and e.kind == EKind.CONST and (e.c & e.mask()) == (target_val & e.mask()):
            if _conflicts(eff, protect, {reg}) or (set(eff.reg_effects) & avoid):
                continue
            return [(g, eff, {})]
    return None


def _solve_register_indirect(pool: GadgetPool, ai: ArchInfo, reg: str, target_val: int,
                              protect: set[str], avoid: set[str], max_insns: int, max_depth: int,
                              visited: frozenset[str], memo: dict, budget: list[int]):
    """Best-first (A*) backward-chaining search: "what value would gadget
    g's *source* register need to hold for g to leave `reg` == target_val,
    and can we reach *that*?" Search states are subproblems `(reg,
    target_val, visited)`; expanding one means "pick a gadget that computes
    reg from some other register, and recurse on solving that register's
    required value instead."

    This replaces a plain depth-first walk that only ever tried the first
    `_INDIRECT_BREADTH` candidates at each level: a real fix, not a
    depth-first walk in different clothes -- with a global priority queue,
    the subproblem most likely to be cheap to finish is expanded next
    *regardless of which branch it's in*, so a chain that exists but needs
    a candidate ranked outside the old fixed cutoff is no longer silently
    unreachable. Concretely, this is textbook A* (Russell & Norvig ch. 3):

      priority(state) = depth(state) + heuristic(state)
      heuristic(state) = 0 if _goal_test already solves it in one more
                          gadget, else 1

    That heuristic never overestimates the gadgets still needed (an unsolved
    state always needs at least one more), so it's admissible: subject to
    `max_depth` and `budget`, this returns a minimum-gadget solution, not
    just the first one a fixed traversal order happened to trip over.

    `memo` doubles as A*'s closed set here: it records the cheapest depth at
    which each `(reg, target_val, visited)` state has already been queued,
    so a worse-or-equal rediscovery of the same subproblem (common --
    unrelated registers frequently bottom out needing the same value in the
    same source register) is skipped rather than re-expanded. `budget` caps
    total node expansions, same role as before.

    A monotonic tie-breaking counter (`seq`) keeps heap ordering fully
    deterministic regardless of hash randomization or dict/set iteration
    order -- no bare set is ever iterated for ordering here, which matters:
    see commit 2f47a48, which fixed exactly this class of bug in the solver.

    Returns an ordered list of (gadget, effect, fills) steps (poppers
    first, transforms last) or None if nothing within max_depth/budget works.
    """
    seq = itertools.count()
    frontier: list[tuple[int, int, str, int, frozenset, int, list]] = []

    def push(r: str, tv: int, vis: frozenset, depth: int, chain: list):
        key = (r, tv, vis)
        prior = memo.get(key)
        if prior is not None and prior <= depth:
            return  # a cheaper-or-equal path to this state is already queued
        memo[key] = depth
        h = 0 if _goal_test(pool, ai, r, tv, protect, avoid, max_insns) is not None else 1
        heapq.heappush(frontier, (depth + h, next(seq), r, tv, vis, depth, chain))

    push(reg, target_val, visited, 0, [])

    while frontier and budget[0] > 0:
        _, _, r, tv, vis, depth, chain = heapq.heappop(frontier)
        budget[0] -= 1

        step = _goal_test(pool, ai, r, tv, protect, avoid, max_insns)
        if step is not None:
            return step + chain

        if depth >= max_depth:
            continue

        for g in pool.shortlist_touching(r, max_insns=max_insns)[:_MAX_EXPAND]:
            eff = pool.effect_of(g)
            if not _gadget_ok(eff, ai):
                continue
            e = eff.reg_effects.get(r)
            if e is None or e.kind not in (EKind.COPY, EKind.ADD, EKind.SCALE, EKind.XOR, EKind.AND, EKind.OR):
                continue
            if e.src is None or e.src == ai.sp_reg or e.src in vis:
                continue
            needed = e.solve_for_target(tv)
            if needed is None:
                continue
            if _conflicts(eff, protect, {r}) or (set(eff.reg_effects) & avoid):
                continue
            # prepend: this gadget consumes e.src's value, so it must run
            # *after* whatever the recursive chain produces for e.src.
            push(e.src, needed, vis | {r}, depth + 1, [(g, eff, {})] + chain)

    return None


def set_registers(pool: GadgetPool, targets: dict[str, int],
                   avoid: set[str] = frozenset(), max_insns: int = 6) -> SolveResult:
    ai = pool.ai
    remaining = dict(targets)
    fixed: set[str] = set()
    chosen: list[tuple[Gadget, GadgetEffect, dict[int, tuple[int, str]]]] = []
    log: list[str] = []

    # ---- phase 1: greedy multi-cover "pop"-style (LOAD-from-stack) gadgets
    while remaining:
        # a *set* of candidates would iterate in an order that depends on
        # Gadget.__hash__, which folds in a module-path string -- and
        # Python randomizes str hashing per-process (PYTHONHASHSEED)
        # unless told not to. That made tie-breaking between equally-good
        # candidates (same coverage, same instruction count) silently
        # nondeterministic run to run: confirmed in CI, where four
        # identical jobs against the identical system libc picked
        # different gadgets and only some verified cleanly. Dedup via a
        # dict keyed by (module, address) instead, and iterate in a fixed
        # sort order, so the same input always makes the same choice.
        cand_gadgets: dict[tuple[str, int], Gadget] = {}
        for reg in remaining:
            for g in pool.shortlist_pop_style(reg, max_insns=max_insns):
                cand_gadgets[(g.module, g.address)] = g
        best = None  # (score, gadget, effect, covers)
        for g in sorted(cand_gadgets.values(), key=lambda g: (g.module, g.address)):
            eff = pool.effect_of(g)
            if not _gadget_ok(eff, ai):
                continue
            covers = {r for r in remaining
                      if (e := eff.reg_effects.get(r)) is not None
                      and e.kind == EKind.LOAD and e.src == ai.sp_reg}
            if not covers:
                continue
            if _conflicts(eff, fixed | (set(remaining) - covers), covers):
                continue
            if set(eff.reg_effects) & avoid:
                continue
            score = (len(covers), -g.n_insns)
            if best is None or score > best[0]:
                best = (score, g, eff, covers)
        if best is None:
            break
        _, g, eff, covers = best
        fills = {eff.reg_effects[r].c: (remaining[r], f"{r} = 0x{remaining[r]:x}") for r in covers}
        chosen.append((g, eff, fills))
        log.append(f"pop-style: {g.text} @ 0x{g.address:x} sets {sorted(covers)}")
        for r in covers:
            fixed.add(r)
            del remaining[r]

    # ---- phase 2: N-level register-to-register indirection (backward
    # chaining -- see _solve_register_indirect below). Depth is bounded so
    # this stays a search, not an explosion, but it's no longer limited to
    # a single hop like the original pop-then-copy special case.
    still = dict(remaining)
    for reg, target_val in still.items():
        protect = fixed | (set(remaining) - {reg})
        steps = _solve_register_indirect(pool, ai, reg, target_val, protect, avoid,
                                          max_insns=max_insns, max_depth=4, visited=frozenset(),
                                          memo={}, budget=[_INDIRECT_BUDGET])
        if steps is None:
            continue
        chosen.extend(steps)
        log.append(f"indirect ({len(steps)} gadget(s)): -> {reg} = 0x{target_val:x}")
        fixed.add(reg)
        del remaining[reg]

    chain = Chain(ai=ai)
    for g, eff, fills in chosen:
        step = Chain(ai=ai)
        step.append_gadget_block(g, eff, fills)
        if chain.words:
            # link the previous block's open "-> next" placeholder to this
            # gadget's own address instead of leaving both dangling
            chain.extend(step)
        else:
            chain.words = step.words
    for reg in remaining:
        log.append(f"UNRESOLVED: could not find a gadget to set {reg} = 0x{targets[reg]:x}")

    # an empty chain (e.g. calling a zero-argument function) is a valid,
    # fully-resolved result -- only a genuinely unresolved target should
    # make the caller treat this as a failure.
    ok_chain = chain if not remaining else None
    return SolveResult(chain=ok_chain, resolved={r: targets[r] for r in fixed},
                        unresolved=sorted(remaining), log=log)
