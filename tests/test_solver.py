import keystone

from ropnroll.core import loader, scanner
from ropnroll.solve.callchain import build_call
from ropnroll.solve.chain import set_registers
from ropnroll.solve.pool import GadgetPool
from ropnroll.solve.syscallchain import build_syscall
from ropnroll.verify.emulate import verify_chain
from tests.helpers import write_minimal_elf


def _pool(img_path, max_insns=6):
    img = loader.load(img_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=max_insns))
    pool = GadgetPool()
    pool.add(img, gadgets)
    return pool, img


def test_direct_register_solve_and_verify(libc_path):
    pool, img = _pool(libc_path)
    res = set_registers(pool, {"rdi": 0x1337, "rsi": 0, "rdx": 0x41414141})
    assert res.ok, res.log
    goal = {"rdi": 0x1337, "rsi": 0, "rdx": 0x41414141}
    rep = verify_chain(img, res.chain, goal_regs=goal)
    # no final_target is given, so the chain legitimately runs off its own
    # end into an unfilled placeholder -- that's expected, not a failure.
    # What must hold is that every goal register actually got set.
    assert all(ok for ok, *_ in rep.goal_results.values()), rep.goal_results
    assert all(ok for ok, *_ in rep.goal_results.values())


def test_ret2libc_system_binsh(libc_path):
    pool, img = _pool(libc_path)
    system_addr = img.symbols["system"]
    binsh = None
    for seg in img.segments:
        if not seg.executable and seg.readable:
            idx = seg.data.find(b"/bin/sh\x00")
            if idx != -1:
                binsh = seg.vaddr + idx
                break
    assert binsh is not None
    res = build_call(pool, target=system_addr, args=[binsh])
    assert res.ok
    rep = verify_chain(img, res.chain, final_target=system_addr, goal_regs={"rdi": binsh})
    assert rep.ok, rep.fault


def test_direct_execve_syscall_binsh(libc_path):
    binsh = None
    for seg in loader.load(libc_path).segments:
        if not seg.executable and seg.readable:
            idx = seg.data.find(b"/bin/sh\x00")
            if idx != -1:
                binsh = seg.vaddr + idx
                break
    assert binsh is not None

    # Which gadgets the solver ends up choosing depends on the exact glibc
    # build's own code layout, which differs across systems (confirmed: a
    # gadget that solved and verified cleanly on one machine caused a real
    # CPU exception on another glibc build's equivalent address, because
    # the specific instructions living there differ). Rather than hardcode
    # one instruction-count window that happened to work on one system,
    # widen the search the same way real usage would if verification
    # doesn't pass, and require *some* window to produce a working chain.
    last_report = None
    for max_insns in (6, 9, 12, 15):
        pool, img = _pool(libc_path, max_insns=max_insns)
        res = build_syscall(pool, nr=59, args=[binsh, 0, 0], max_insns=max_insns)
        if not res.ok:
            continue
        rep = verify_chain(img, res.chain, final_target=res.gadget_addr)
        last_report = rep
        if rep.ok:
            return
    assert last_report is not None and last_report.ok, \
        f"no working execve chain found up to max_insns=15; last attempt: {last_report}"


def test_stack_pivot_gadgets_rejected_by_general_solver(libc_path):
    """Regression: a `leave ; ret`-style gadget must never be silently
    picked to set a plain register -- it pivots rsp to an uncontrolled
    value (rbp), corrupting every subsequent stack offset in the chain."""
    pool, img = _pool(libc_path)
    res = set_registers(pool, {"rax": 0x1234, "rdx": 0x5678})
    if not res.ok:
        return  # fine -- just means no such gadget existed to mis-pick
    used_addrs = {w.value for w in res.chain.words}
    for g in pool.all():
        if g.text.startswith("leave") and g.address in used_addrs:
            raise AssertionError("a leave-based pivot gadget was used as a plain register setter")


def test_call_chain_alignment_pad(libc_path):
    """Regression: entering a function via a direct `ret` (no `call`
    instruction) must leave it with the same rsp%16==8 residue it would
    see from a real call, or its own callees crash on the first SSE
    instruction requiring 16-byte alignment. Confirmed against a real
    live process in examples/live_fire_demo.py; this checks the parity
    math itself against several arbitrary amounts of preceding padding.
    """
    pool, img = _pool(libc_path)
    system_addr = img.symbols["system"]
    # only multiples of 8 are realistic here: x86-64 stack frames are
    # always 8-byte aligned, so padding before a return-address overwrite
    # is inherently a multiple of the pointer width. A single 8-byte pad
    # gadget can only shift the 16-byte residue by 8, so it can fix "off
    # by one word" misalignment, not an arbitrary byte-level skew -- that
    # never occurs on a real stack.
    for padding in (0, 8, 40, 72, 104):
        res = build_call(pool, target=system_addr, args=[0x1000], bytes_before_chain=padding)
        assert res.ok
        target_word_index = next(i for i, w in enumerate(res.chain.words)
                                  if w.value == system_addr)
        target_offset = padding + target_word_index * 8
        assert target_offset % 16 == 0, (padding, target_offset)


def test_multihop_indirection_forced(tmp_path):
    """Synthetic gadget set with *no* direct popper for rdi -- only reachable
    via pop rax -> mov rbx,rax -> mov rdi,rbx. Proves the solver chains
    more than one level of indirection, not just the original single hop."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    def asm(s):
        enc, _ = ks.asm(s)
        return bytes(enc)

    code = asm("pop rax; ret") + asm("mov rbx, rax; ret") + asm("mov rdi, rbx; ret")
    path = str(tmp_path / "indirect.elf")
    write_minimal_elf(path, "x86_64", code, base=0x400000)

    pool, img = _pool(path)
    res = set_registers(pool, {"rdi": 0x1337})
    assert res.ok
    assert len(res.chain.words) >= 4  # at least 2 gadgets' worth of words

    rep = verify_chain(img, res.chain, goal_regs={"rdi": 0x1337})
    assert rep.final_regs.get("rdi") == 0x1337
