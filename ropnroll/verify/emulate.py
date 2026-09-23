"""
Concrete chain verification -- the "does this actually work" step almost
nothing else in this space does.

Everything upstream (the semantic engine, the solver) is built out of
*per-gadget* measurements and a model of how they compose. This module
throws that model away and just runs the assembled chain, for real, on an
emulated CPU with the target's actual memory mapped in. It can't prove a
chain works against the real, live target (ASLR base, exact DLL build,
stack layout may differ) but it proves the chain is *internally
consistent* -- every gadget decodes and behaves the way the solver assumed,
nothing double-clobbers a register you needed, and you find out now
instead of after firing it at a real target once.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import unicorn as uc

from ..core.archinfo import get_archinfo
from ..core.loader import Image
from ..solve.chain import Chain

STACK_ADDR_DEFAULT = 0x0000_7A00_1000_0000


def _align_down(x, a):
    return x & ~(a - 1)


@dataclass
class VerifyReport:
    ok: bool
    reached_target: bool
    fault: str | None = None
    fault_address: int | None = None
    last_gadget_context: str | None = None
    instructions_executed: int = 0
    final_regs: dict[str, int] = field(default_factory=dict)
    goal_results: dict[str, tuple] = field(
        default_factory=dict
    )  # reg -> (ok, expected, actual)
    trace: list[int] = field(default_factory=list)


def verify_chain(
    img: Image | list[Image],
    chain: Chain,
    *,
    final_target: int | None = None,
    goal_regs: dict[str, int] | None = None,
    initial_regs: dict[str, int] | None = None,
    stack_addr: int = STACK_ADDR_DEFAULT,
    max_insns: int = 20000,
    trace_limit: int = 64,
) -> VerifyReport:
    """`img` is normally the single binary a chain's gadgets came from, but
    a chain built with `call`/`syscall` against multiple `--binary` paths
    (e.g. gadgets from a target EXE calling into a function that only
    kernel32.dll exports) has code living in more than one module's address
    range -- pass the full list of images in that case, or this only maps
    one of them and the emulator faults the instant execution reaches the
    other."""
    imgs = [img] if isinstance(img, Image) else list(img)
    ai = get_archinfo(imgs[0].arch, imgs[0].little_endian)
    mu = uc.Uc(ai.uc_arch, ai.uc_mode)

    for im in imgs:
        for seg in im.segments:
            base = _align_down(seg.vaddr, 0x1000)
            end = (seg.vaddr + seg.size + 0xFFF) & ~0xFFF
            try:
                mu.mem_map(base, end - base)
            except uc.UcError:
                continue  # already mapped -- e.g. re-verifying, or an overlap with another image
            buf = bytearray(end - base)
            pad = seg.vaddr - base
            buf[pad : pad + seg.size] = seg.data
            mu.mem_write(base, bytes(buf))

    chain_bytes = chain.to_bytes(little_endian=imgs[0].little_endian)
    stack_size = max(0x10000, (len(chain_bytes) + 0x4000 + 0xFFF) & ~0xFFF)
    stack_base = _align_down(stack_addr, 0x1000)
    mu.mem_map(stack_base, stack_size)
    entry_sp = stack_base + 0x1000
    mu.mem_write(entry_sp, chain_bytes)

    for reg, val in (initial_regs or {}).items():
        const = ai.uc_reg_const.get(reg)
        if const is not None:
            mu.reg_write(const, val)
    mu.reg_write(ai.uc_reg_const[ai.sp_reg], entry_sp)

    trace: list[int] = []
    executed = [0]
    reached = [False]

    def on_code(muu, address, size, ud):
        executed[0] += 1
        if len(trace) < trace_limit:
            trace.append(address)
        if final_target is not None and address == final_target:
            reached[0] = True
            muu.emu_stop()
        elif executed[0] >= max_insns:
            muu.emu_stop()

    h = mu.hook_add(uc.UC_HOOK_CODE, on_code)
    fault = None
    fault_addr = None
    try:
        # entry point is the first gadget address, popped as if a ret just
        # landed here -- so PC = first word, SP = entry_sp + width.
        first_addr = chain.words[0].value
        mu.reg_write(ai.uc_reg_const[ai.ip_reg], first_addr)
        mu.reg_write(ai.uc_reg_const[ai.sp_reg], entry_sp + ai.reg_width)
        mu.emu_start(first_addr, 0, timeout=2_000_000)
    except uc.UcError as e:
        fault = e.args[0] if e.args else str(e)
        try:
            fault_addr = mu.reg_read(ai.uc_reg_const[ai.ip_reg])
        except Exception:
            fault_addr = None
    finally:
        mu.hook_del(h)

    final_regs = {}
    for reg, const in ai.uc_reg_const.items():
        try:
            final_regs[reg] = mu.reg_read(const)
        except Exception:
            pass

    goal_results = {}
    all_goals_ok = True
    for reg, want in (goal_regs or {}).items():
        got = final_regs.get(reg)
        ok = got is not None and got == want
        goal_results[reg] = (ok, want, got)
        all_goals_ok = all_goals_ok and ok

    context = None
    if fault_addr is not None:
        best = None
        for w in chain.words:
            if (
                w.value is not None
                and w.value <= fault_addr
                and (best is None or w.value > best.value)
            ):
                best = w
        context = best.label if best else None

    ok = (fault is None) and (final_target is None or reached[0]) and all_goals_ok
    return VerifyReport(
        ok=ok,
        reached_target=reached[0],
        fault=fault,
        fault_address=fault_addr,
        last_gadget_context=context,
        instructions_executed=executed[0],
        final_regs=final_regs,
        goal_results=goal_results,
        trace=trace,
    )
