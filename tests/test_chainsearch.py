"""Bounded multi-gadget chain search (solve/chainsearch.py).

`semantics.query.search` only ever answers "does one gadget produce this
effect?" -- these tests build tiny synthetic gadget sets (same
write_minimal_pe + keystone pattern as test_solver.py) that need more than
one gadget relayed through a register, and check search_chain finds them
while single-gadget search doesn't. They also pin down the soundness gate:
a gadget whose destination depends on two different GPRs (e.g. `or rcx,
rax`) must never be composed into a chain, even when a human could combine
it correctly with a zeroing trick.
"""

import struct

import keystone

from ropnroll.core import loader, scanner
from ropnroll.semantics import query as querymod
from ropnroll.solve import chainsearch
from ropnroll.solve.pool import GadgetPool
from tests.helpers import write_minimal_pe

_ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def _asm(s: str) -> bytes:
    enc, _ = _ks.asm(s)
    return bytes(enc)


def _pool(img_path, max_insns=6):
    img = loader.load(img_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=max_insns))
    pool = GadgetPool()
    pool.add(img, gadgets)
    return pool, img


def test_no_direct_gadget_but_two_hop_relay_exists(tmp_path):
    """No gadget sets rcx from rax directly -- only via rbx. Single-gadget
    search must find nothing; chain search must find the 2-hop relay."""
    code = _asm("mov rbx, rax ; ret") + _asm("mov rcx, rbx ; ret")
    path = str(tmp_path / "relay.exe")
    write_minimal_pe(path, "x86_64", code, base=0x400000)
    pool, img = _pool(path)

    assert querymod.search(pool, "rcx=rax") == []

    results = chainsearch.search_chain(pool, "rcx=rax", max_depth=2)
    assert results, "expected a 2-hop chain relaying rax -> rbx -> rcx"
    texts = [g.text for g in results[0].hops]
    assert texts == ["mov rbx, rax ; ret", "mov rcx, rbx ; ret"]


def test_chain_respects_max_depth(tmp_path):
    """The same 2-hop relay must not be found when max_depth caps the
    search at a single gadget."""
    code = _asm("mov rbx, rax ; ret") + _asm("mov rcx, rbx ; ret")
    path = str(tmp_path / "relay.exe")
    write_minimal_pe(path, "x86_64", code, base=0x400000)
    pool, img = _pool(path)

    assert chainsearch.search_chain(pool, "rcx=rax", max_depth=1) == []


def test_two_register_combine_is_never_chained(tmp_path):
    """`or rcx, rax` genuinely depends on two GPRs (rcx *and* rax). Even
    though `0 | rax == rax` makes "pop rcx (0) ; or rcx, rax" a correct
    hand-built chain for rcx=rax, the engine's per-gadget effect for a
    two-register op only reflects the fixed baseline it held the other
    register at during measurement (see engine.py's module docstring) --
    not a universal law. Chain search must never compose it automatically."""
    code = _asm("pop rcx ; ret") + _asm("or rcx, rax ; ret")
    path = str(tmp_path / "combine.exe")
    write_minimal_pe(path, "x86_64", code, base=0x400000)
    pool, img = _pool(path)

    assert querymod.search(pool, "rcx=rax") == []
    assert chainsearch.search_chain(pool, "rcx=rax", max_depth=3) == []


def test_sub_width_copy_is_not_treated_as_full_width(tmp_path):
    """`mov edx, ecx` zero-extends to 64 bits on x86-64 -- it only equals a
    genuine 64-bit `rdx=rcx` copy when rcx's upper 32 bits happen to be
    zero. Neither single-gadget search nor chain search should report it
    as satisfying a full-width `rdx=rcx` query."""
    code = _asm("mov edx, ecx ; ret")
    path = str(tmp_path / "subwidth.exe")
    write_minimal_pe(path, "x86_64", code, base=0x400000)
    pool, img = _pool(path)

    assert querymod.search(pool, "rdx=rcx") == []
    assert chainsearch.search_chain(pool, "rdx=rcx", max_depth=2) == []


def test_gadget_with_embedded_call_is_excluded_from_chaining(tmp_path):
    """`mov rcx, r10 ; call helper ; ret` has a perfectly sound, engine-
    measured COPY effect for rcx (set by its own "mov rcx, r10" before the
    call even runs) -- single-gadget search rightly reports it. But an
    embedded call is a worse building block for *automated* composition
    than a plain instruction: the callee is a whole function this search
    never inspects, so whatever it does to rcx between that write and the
    gadget's own trailing ret (nothing, here, but a tool can't assume that
    in general) isn't accounted for. Chain search excludes any gadget
    containing a call outright, even when the gadget's own effect is fine
    in isolation."""
    # write_minimal_pe always places code at RVA 0x1000 (its own `align`
    # constant), so the load address of `helper` (the very first byte of
    # `code`) is deterministically base + 0x1000 -- computed up front so
    # the call's rel32 can be baked in before the single write to disk.
    base = 0x400000
    helper_addr = base + 0x1000

    helper = _asm("mov rax, rcx ; ret")
    prefix = _asm("mov rcx, r10")
    call_site_addr = helper_addr + len(helper) + len(prefix)
    rel32 = helper_addr - (call_site_addr + 5)
    call_instr = b"\xe8" + struct.pack("<i", rel32)
    caller = prefix + call_instr + _asm("ret")

    code = helper + caller
    path = str(tmp_path / "withcall.exe")
    entry = write_minimal_pe(path, "x86_64", code, base=base)
    assert entry == helper_addr  # sanity: our address math matches the writer's layout

    pool, img = _pool(path)

    single = querymod.search(pool, "rcx=r10")
    assert single, "expected the call-embedding gadget to be a valid single-gadget match"
    assert " call " in f" {single[0][0].text} "

    assert chainsearch.search_chain(pool, "rcx=r10", max_depth=1) == []
