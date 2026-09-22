"""Build a ret2func / ret2libc-style chain: load the calling-convention
registers (or push stack args for cdecl/stdcall), then transfer control to
the target function address directly (classic "return into libc" -- the
callee's own `ret` is what would normally pop a return address, so we let
the caller decide what -- if anything -- goes there via Chain.set_last)."""
from __future__ import annotations

from dataclasses import dataclass

from ..core.archinfo import ArchInfo
from ..core.gadget import Terminator
from .chain import Chain, ChainWord, SolveResult, set_registers
from .pool import GadgetPool

# Microsoft x64 ABI: RCX, RDX, R8, R9 (not SysV's RDI/RSI/RDX/RCX/R8/R9),
# plus 32 bytes of caller-reserved "shadow space" on the stack immediately
# above the return address, which the callee's prologue may spill into.
_MS64_ARGS = ["rcx", "rdx", "r8", "r9"]
_MS64_SHADOW_SPACE = 0x20


@dataclass
class CallResult:
    chain: Chain | None
    solve: SolveResult
    ok: bool


def _arg_regs(ai: ArchInfo, os: str) -> list[str]:
    if ai.arch == "x86_64" and os == "windows":
        return _MS64_ARGS
    return ai.call_arg_regs


def build_call(pool: GadgetPool, target: int, args: list[int], return_to: int | None = None,
                avoid: set = frozenset(), max_insns: int = 6,
                bytes_before_chain: int | None = None) -> CallResult:
    """`bytes_before_chain`: how many bytes of payload precede this chain
    in the final buffer (e.g. the overflow padding before it starts) --
    when given, on x86-64 SysV this automatically inserts a single bare
    `ret` gadget if needed so `target` is entered with the same rsp%16==8
    residue it would see via a real `call` instruction. Without a `call`
    pushing a return address, a direct-`ret`-into-target chain built at the
    "wrong" parity will crash inside target's own callees the moment they
    use an SSE instruction that requires 16-byte-aligned rsp -- a classic,
    easy-to-miss ret2libc gotcha. Omit this if you don't know/care about
    what precedes the chain; the chain still works, it just isn't
    alignment-corrected.
    """
    ai = pool.ai
    arg_regs = _arg_regs(ai, pool.os)
    if arg_regs:
        if len(args) > len(arg_regs):
            raise ValueError(f"{ai.arch}/{pool.os} register-passed args max is {len(arg_regs)}, "
                              f"got {len(args)} (stack-spilled args not yet supported)")
        targets = {arg_regs[i]: v for i, v in enumerate(args)}
        res = set_registers(pool, targets, avoid=avoid, max_insns=max_insns)
        if not res.ok or res.chain is None:
            return CallResult(chain=None, solve=res, ok=False)
        chain = res.chain

        if bytes_before_chain is not None and ai.arch == "x86_64" and ai.reg_width == 8:
            target_word_offset = bytes_before_chain + (len(chain.words) - 1) * ai.reg_width
            if target_word_offset % 16 != 0:
                pads = [g for g in pool.shortlist_terminator(Terminator.RET, max_insns=1) if g.n_insns == 1]
                if pads:
                    chain.set_last(pads[0].address, f"alignment pad (bare ret) 0x{pads[0].address:x}")
                    chain.words.append(ChainWord(None, "-> next"))

        chain.set_last(target, f"call target 0x{target:x}")
        if ai.arch == "x86_64" and pool.os == "windows":
            for i in range(_MS64_SHADOW_SPACE // ai.reg_width):
                chain.append_raw(0, "MS x64 shadow space (callee may spill args here)")
        if return_to is not None:
            chain.append_raw(return_to, f"return address after call 0x{return_to:x}")
        return CallResult(chain=chain, solve=res, ok=True)
    else:
        # cdecl/stdcall (x86): arguments live on the stack, pushed right
        # before the target's own address (which itself sits where the
        # target's `ret` will look for its own return address).
        chain = Chain(ai=ai)
        chain.append_raw(target, f"call target 0x{target:x}")
        if return_to is not None:
            chain.append_raw(return_to, f"return address after call 0x{return_to:x}")
        else:
            chain.append_raw(0, "return address (unused placeholder)")
        for i, a in enumerate(args):
            chain.append_raw(a, f"stack arg[{i}] = 0x{a:x}")
        res = SolveResult(chain=chain, resolved={}, unresolved=[], log=["cdecl: args pushed on stack"])
        return CallResult(chain=chain, solve=res, ok=True)
