import os
import subprocess
import sys

import keystone

from ropnroll.core import loader, scanner
from ropnroll.solve.callchain import build_call
from ropnroll.solve.chain import set_registers
from ropnroll.solve.pool import GadgetPool
from ropnroll.verify.emulate import verify_chain
from tests.helpers import write_minimal_pe


def _pool(img_path, max_insns=6):
    img = loader.load(img_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=max_insns))
    pool = GadgetPool()
    pool.add(img, gadgets)
    return pool, img


def test_direct_register_solve_and_verify(ntdll_path):
    pool, img = _pool(ntdll_path)
    res = set_registers(pool, {"rcx": 0x1337, "rdx": 0, "r8": 0x41414141})
    assert res.ok, res.log
    goal = {"rcx": 0x1337, "rdx": 0, "r8": 0x41414141}
    rep = verify_chain(img, res.chain, goal_regs=goal)
    # no final_target is given, so the chain legitimately runs off its own
    # end into an unfilled placeholder -- that's expected, not a failure.
    # What must hold is that every goal register actually got set.
    assert all(ok for ok, *_ in rep.goal_results.values()), rep.goal_results
    assert all(ok for ok, *_ in rep.goal_results.values())


def test_call_windows_export_with_ms64_args(ntdll_path):
    """Windows analog of a classic ret2libc call: reach a real exported
    function's entry with the MS x64 ABI's argument registers (rcx/rdx,
    not SysV's rdi/rsi) set correctly. final_target stops emulation the
    instant rip reaches the export, so this doesn't need the function
    itself to run to completion."""
    pool, img = _pool(ntdll_path)
    target_addr = img.symbols["RtlComputeCrc32"]
    res = build_call(pool, target=target_addr, args=[0, 0x1337])
    assert res.ok
    rep = verify_chain(
        img, res.chain, final_target=target_addr, goal_regs={"rcx": 0, "rdx": 0x1337}
    )
    assert rep.ok, rep.fault


def test_stack_pivot_gadgets_rejected_by_general_solver(ntdll_path):
    """Regression: a `leave ; ret`-style gadget must never be silently
    picked to set a plain register -- it pivots rsp to an uncontrolled
    value (rbp), corrupting every subsequent stack offset in the chain."""
    pool, img = _pool(ntdll_path)
    res = set_registers(pool, {"rax": 0x1234, "rdx": 0x5678})
    if not res.ok:
        return  # fine -- just means no such gadget existed to mis-pick
    used_addrs = {w.value for w in res.chain.words}
    for g in pool.all():
        if g.text.startswith("leave") and g.address in used_addrs:
            raise AssertionError(
                "a leave-based pivot gadget was used as a plain register setter"
            )


def test_call_chain_alignment_pad(ntdll_path):
    """Regression: entering a function via a direct `ret` (no `call`
    instruction) must leave it with the same rsp%16==8 residue it would
    see from a real call, or its own callees crash on the first SSE
    instruction requiring 16-byte alignment. This checks the parity math
    itself against several arbitrary amounts of preceding padding.
    """
    pool, img = _pool(ntdll_path)
    target_addr = img.symbols["RtlComputeCrc32"]
    # only multiples of 8 are realistic here: x86-64 stack frames are
    # always 8-byte aligned, so padding before a return-address overwrite
    # is inherently a multiple of the pointer width. A single 8-byte pad
    # gadget can only shift the 16-byte residue by 8, so it can fix "off
    # by one word" misalignment, not an arbitrary byte-level skew -- that
    # never occurs on a real stack.
    #
    # Expected residue is 8, not 0: the overwritten return-address slot
    # itself sits at bytes_before_chain==0, and that slot is always at an
    # address ==8 (mod 16) (it's exactly where a real `call` would have
    # pushed its return address). Landing on the target word `k` words
    # later puts rsp at (that slot's address) + (k+1)*8 once the target's
    # own `ret`-driven pop happens, so it's aligned correctly (==8 mod 16,
    # matching a real `call`) exactly when (offset + 8) % 16 == 8, i.e.
    # offset % 16 == 8.
    for padding in (0, 8, 40, 72, 104):
        res = build_call(
            pool, target=target_addr, args=[0x1000], bytes_before_chain=padding
        )
        assert res.ok
        target_word_index = next(
            i for i, w in enumerate(res.chain.words) if w.value == target_addr
        )
        target_offset = padding + target_word_index * 8
        assert target_offset % 16 == 8, (padding, target_offset)


def test_call_chain_alignment_pad_regression_4_args(ntdll_path):
    """Regression for the exact bug: with bytes_before_chain=0 and any
    number of single-slot `pop reg ; ret` gadgets, each argument adds
    exactly 16 bytes (a gadget word + its popped value) -- a multiple of
    16 -- so the misalignment present at 0 args never self-corrects as
    more arguments are added. A padding check that only ever fires for the
    *other* residue (as the original code did) silently never pads any of
    these chains."""
    pool, img = _pool(ntdll_path)
    target_addr = img.symbols["RtlComputeCrc32"]
    for n_args in (0, 1, 2, 3, 4):
        res = build_call(
            pool,
            target=target_addr,
            args=[0x1000] * n_args,
            bytes_before_chain=0,
        )
        assert res.ok
        pad_words = [w for w in res.chain.words if "alignment pad" in w.label]
        assert len(pad_words) == 1, (n_args, [w.label for w in res.chain.words])
        target_word_index = next(
            i for i, w in enumerate(res.chain.words) if w.value == target_addr
        )
        assert (target_word_index * 8) % 16 == 8, n_args


def test_call_chain_alignment_pad_synthetic(tmp_path):
    """Same regression as test_call_chain_alignment_pad_regression_4_args,
    but against a synthetic PE instead of ntdll.dll, so it isn't skipped
    off Windows. Uses a pool with *only* single-slot pop-style gadgets and
    a trailing `ret` (deliberately not scanned as its own bare-ret gadget
    -- see the comment in build_call -- to prove the pad lookup finds a
    usable ret address by reusing an existing gadget's terminator
    instruction instead of depending on a standalone one-instruction ret
    gadget existing in the pool)."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    def asm(s):
        enc, _ = ks.asm(s)
        return bytes(enc)

    code = (
        asm("pop rcx ; ret")
        + asm("pop rdx ; ret")
        + asm("pop r8 ; ret")
        + asm("pop r9 ; ret")
        + asm("ret")
    )
    path = str(tmp_path / "align.exe")
    write_minimal_pe(path, "x86_64", code, base=0x140000000)
    pool, img = _pool(path)
    target_addr = 0x141000000

    for n_args in (0, 1, 2, 3, 4):
        res = build_call(
            pool,
            target=target_addr,
            args=[0x100] * n_args,
            bytes_before_chain=0,
        )
        assert res.ok, (n_args, res.solve.log)
        pad_words = [w for w in res.chain.words if "alignment pad" in w.label]
        assert len(pad_words) == 1, (n_args, [w.label for w in res.chain.words])
        target_word_index = next(
            i for i, w in enumerate(res.chain.words) if w.value == target_addr
        )
        assert (target_word_index * 8) % 16 == 8, n_args


def test_build_call_warns_when_bytes_before_chain_omitted(tmp_path):
    """The alignment residue at the call target is only corrected when the
    caller says what precedes the chain; omitting --bytes-before-chain
    must not silently ship an uncorrected chain -- it should say so."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm("pop rcx ; ret")
    path = str(tmp_path / "warn.exe")
    write_minimal_pe(path, "x86_64", bytes(enc), base=0x400000)
    pool, img = _pool(path)

    res = build_call(pool, target=0x402000, args=[0x1337])
    assert res.ok
    assert any("--bytes-before-chain" in w for w in res.chain.warnings)

    res = build_call(pool, target=0x402000, args=[0x1337], bytes_before_chain=0)
    assert res.ok
    assert not any("--bytes-before-chain" in w for w in res.chain.warnings)


def test_multihop_indirection_forced(tmp_path):
    """Synthetic gadget set with *no* direct popper for rdi -- only reachable
    via pop rax -> mov rbx,rax -> mov rdi,rbx. Proves the solver chains
    more than one level of indirection, not just the original single hop."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    def asm(s):
        enc, _ = ks.asm(s)
        return bytes(enc)

    code = asm("pop rax; ret") + asm("mov rbx, rax; ret") + asm("mov rdi, rbx; ret")
    path = str(tmp_path / "indirect.exe")
    write_minimal_pe(path, "x86_64", code, base=0x400000)

    pool, img = _pool(path)
    res = set_registers(pool, {"rdi": 0x1337})
    assert res.ok
    assert len(res.chain.words) >= 4  # at least 2 gadgets' worth of words

    rep = verify_chain(img, res.chain, goal_regs={"rdi": 0x1337})
    assert rep.final_regs.get("rdi") == 0x1337


def test_build_call_warns_on_cet_shadow_stack(tmp_path):
    """CET shadow stack breaks return-based ROP outright; build_call should
    say so instead of silently handing back a chain that will fault on its
    first `ret` -- mirroring find_dispatchers' existing CFG/CET steering for
    JOP (solve/jop.py)."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm("pop rcx ; ret")
    path = str(tmp_path / "cet.exe")
    write_minimal_pe(path, "x86_64", bytes(enc), base=0x400000)
    pool, img = _pool(path)

    # bytes_before_chain=0 throughout -- these assertions are about the CET
    # warning specifically; leaving it unset would also add the (unrelated)
    # missing-alignment-correction warning tested separately below.
    res = build_call(pool, target=0x402000, args=[0x1337], bytes_before_chain=0)
    assert res.ok
    assert res.chain.warnings == []  # no img given -- nothing to warn about

    res = build_call(
        pool, target=0x402000, args=[0x1337], bytes_before_chain=0, img=img
    )
    assert res.ok
    assert res.chain.warnings == []  # img given but CET not enabled

    img.mitigations["cet"] = True
    res = build_call(
        pool, target=0x402000, args=[0x1337], bytes_before_chain=0, img=img
    )
    assert res.ok
    assert any("CET" in w for w in res.chain.warnings)


def test_build_call_cdecl_warns_on_cet_shadow_stack(tmp_path):
    """Same warning must reach the x86 cdecl/stdcall branch of build_call
    too -- no register-passed args, so it's a separate code path from the
    MS x64 one above."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    enc, _ = ks.asm("ret")
    path = str(tmp_path / "cet32.exe")
    write_minimal_pe(path, "x86", bytes(enc), base=0x400000)
    pool, img = _pool(path)

    img.mitigations["cet"] = True
    res = build_call(pool, target=0x402000, args=[1, 2], img=img)
    assert res.ok
    assert any("CET" in w for w in res.chain.warnings)


def _write_beyond_old_breadth_binary(path):
    """Synthetic gadget set where the *only* useful transform for rdi is
    ranked 16th among gadgets that textually touch rdi -- 13 `cmp rdi, X`
    decoys, 2 `cmp X, rdi` decoys, then the real `mov rdi, r12 ; ret`, then
    a direct `pop r12 ; ret`. Verified empirically (see git history/PR
    discussion) that the x86 byte-level scanner's "unintended gadget" pass
    only turns up *longer* (3+ instruction) noise from this byte sequence,
    which sorts after the real gadget by instruction count -- so the real
    gadget's rank stays comfortably beyond the old `_INDIRECT_BREADTH=8`
    cutoff and comfortably within the new `_MAX_EXPAND=24` one.
    """
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    def asm(s):
        enc, _ = ks.asm(s)
        return bytes(enc)

    decoy_regs = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rbp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r13",
        "r14",
        "r15",
    ]
    code = b"".join(asm(f"cmp rdi, {r} ; ret") for r in decoy_regs)
    code += asm("cmp rax, rdi ; ret") + asm("cmp rbx, rdi ; ret")
    code += asm("mov rdi, r12 ; ret")
    code += asm("pop r12 ; ret")
    write_minimal_pe(path, "x86_64", code, base=0x400000)


def test_indirect_solver_finds_chain_beyond_old_fixed_breadth_cutoff(tmp_path):
    """Regression for the A*-style rewrite of _solve_register_indirect: the
    old implementation truncated every node's candidates to the first 8
    (by instruction count), so a real, working transform ranked outside
    that window was silently never tried. This binary is deliberately built
    so that's exactly what would happen to the old code, and confirms the
    new best-first search still finds and verifies the chain.
    """
    path = str(tmp_path / "beyond_breadth.exe")
    _write_beyond_old_breadth_binary(path)

    pool, img = _pool(path)
    touching = pool.shortlist_touching("rdi", max_insns=6)
    real_idx = next(i for i, g in enumerate(touching) if g.text == "mov rdi, r12 ; ret")
    assert real_idx >= 8, "test binary no longer exercises the old breadth cutoff"

    res = set_registers(pool, {"rdi": 0x1337})
    assert res.ok, res.log
    rep = verify_chain(img, res.chain, goal_regs={"rdi": 0x1337})
    assert rep.final_regs.get("rdi") == 0x1337


_DETERMINISM_SCRIPT = """
import sys
sys.path.insert(0, {repo_root!r})
from ropnroll.core import loader, scanner
from ropnroll.solve.chain import set_registers
from ropnroll.solve.pool import GadgetPool

img = loader.load(sys.argv[1])
gs = scanner.scan_image(img, scanner.ScanOptions(max_insns=6))
pool = GadgetPool(use_cache=False)
pool.add(img, gs)
res = set_registers(pool, {{"rdi": 0x1337}})
assert res.ok, res.log
print([w.value for w in res.chain.words])
"""


def test_indirect_solver_is_deterministic_across_hash_seeds(tmp_path):
    """Regression for the exact bug class fixed in commit 2f47a48 (solver
    non-determinism from PYTHONHASHSEED-sensitive set iteration): run the
    same search in two subprocesses with different hash seeds and require
    byte-identical results, not just "a" result.
    """
    path = str(tmp_path / "determinism.exe")
    _write_beyond_old_breadth_binary(path)

    import pathlib

    repo_root = str(pathlib.Path(__file__).resolve().parent.parent)
    script = _DETERMINISM_SCRIPT.format(repo_root=repo_root)

    outputs = []
    for seed in ("0", "1", "42"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", script, path],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        outputs.append(result.stdout.strip())
    assert len(set(outputs)) == 1, f"solver result varies by PYTHONHASHSEED: {outputs}"
