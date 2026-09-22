"""Direct-syscall chains: set rax=nr, then the arg registers, then transfer
to a `syscall ; ret` gadget. Useful when libc's wrappers aren't reachable
(static binaries, seccomp-filtered libc calls, or when you just don't want
to deal with the PLT/GOT) -- go straight to the kernel."""
from __future__ import annotations

from dataclasses import dataclass

from ..core.gadget import Terminator
from .chain import Chain, SolveResult, set_registers
from .pool import GadgetPool

# Linux x86-64 syscall calling convention
_LINUX_X64_SYSCALL_ARGS = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
_LINUX_X86_SYSCALL_ARGS = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
_LINUX_ARM64_SYSCALL_ARGS = [f"x{i}" for i in range(6)]
_LINUX_ARM_SYSCALL_ARGS = [f"r{i}" for i in range(6)]


def _syscall_arg_regs(arch: str) -> list[str]:
    return {
        "x86_64": _LINUX_X64_SYSCALL_ARGS, "x86": _LINUX_X86_SYSCALL_ARGS,
        "arm64": _LINUX_ARM64_SYSCALL_ARGS, "arm": _LINUX_ARM_SYSCALL_ARGS,
    }.get(arch, _LINUX_X64_SYSCALL_ARGS)


def _syscall_num_reg(arch: str) -> str:
    return {"x86_64": "rax", "x86": "eax", "arm64": "x8", "arm": "r7"}.get(arch, "rax")


@dataclass
class SyscallResult:
    chain: Chain | None
    solve: SolveResult
    ok: bool
    gadget_addr: int | None


def build_syscall(pool: GadgetPool, nr: int, args: list[int], return_to: int | None = None,
                   avoid: set = frozenset(), max_insns: int = 6) -> SyscallResult:
    ai = pool.ai
    arg_regs = _syscall_arg_regs(ai.arch)
    if len(args) > len(arg_regs):
        raise ValueError(f"{ai.arch} syscalls take at most {len(arg_regs)} register args")

    sys_gadgets = pool.shortlist_terminator(Terminator.SYSCALL, max_insns=2)
    # prefer the tightest "syscall ; ret"-style gadget (exactly 2 insns:
    # the trap itself plus the ret that hands control back to our chain)
    sys_gadgets = [g for g in sys_gadgets if g.n_insns <= 2]
    if not sys_gadgets:
        return SyscallResult(chain=None, solve=SolveResult(None, {}, list(arg_regs) + ["<syscall gadget>"],
                              ["no syscall;ret-style gadget found"]), ok=False, gadget_addr=None)
    sys_gadget = sys_gadgets[0]

    targets = {_syscall_num_reg(ai.arch): nr}
    for i, v in enumerate(args):
        targets[arg_regs[i]] = v
    res = set_registers(pool, targets, avoid=avoid, max_insns=max_insns)
    if not res.ok or res.chain is None:
        return SyscallResult(chain=None, solve=res, ok=False, gadget_addr=None)
    chain = res.chain
    chain.set_last(sys_gadget.address, f"syscall gadget 0x{sys_gadget.address:x}: {sys_gadget.text}")
    if return_to is not None:
        chain.append_raw(return_to, f"return address after syscall 0x{return_to:x}")
    return SyscallResult(chain=chain, solve=res, ok=True, gadget_addr=sys_gadget.address)
