"""Build a ret2func-style chain: load the calling-convention registers (or
push stack args for cdecl/stdcall), then transfer control to the target
function address directly (classic "return into a DLL export" -- the
callee's own `ret` is what would normally pop a return address, so we let
the caller decide what -- if anything -- goes there via Chain.set_last)."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.archinfo import ArchInfo
from ..core.gadget import Terminator
from ..core.loader import Image
from .chain import Chain, ChainWord, SolveResult, _tag, set_registers
from .pool import GadgetPool

# Microsoft x64 ABI: RCX, RDX, R8, R9 (not SysV's RDI/RSI/RDX/RCX/R8/R9),
# plus 32 bytes of caller-reserved "shadow space" on the stack immediately
# above the return address, which the callee's prologue may spill into.
_MS64_ARGS = ["rcx", "rdx", "r8", "r9"]
_MS64_SHADOW_SPACE = 0x20

# CET shadow stack (/CETCOMPAT) checks every `ret` against a hardware-
# maintained copy of the call stack -- it is what actually decides whether a
# return-based chain can run at all, independent of any individual gadget.
# find_dispatchers (solve/jop.py) already steers JOP chains around CFG/CET-
# IBT; this is the same steering for the *other* half of the tool.
_CET_WARNING = (
    "target is CET shadow-stack compatible (/CETCOMPAT): a return-based ROP "
    "chain's `ret` instructions are checked against the hardware shadow stack "
    "and will fault as soon as one doesn't match what a real `call` pushed -- "
    "i.e. on the very first gadget here. Consider `ropnroll jop` (call/jmp-"
    "through-register chaining) instead; CET's shadow stack does not check those."
)

# A real `call` leaves rsp%16==8 at the callee's entry (rsp%16==0 right
# before `call`, then it pushes an 8-byte return address). This chain gets
# there via `ret`s instead, so nothing guarantees that residue -- without
# knowing how many bytes precede it in the actual payload, ropnroll can't
# correct it either. Landing at the wrong parity doesn't fault immediately;
# it faults later, inside the target (or anything it calls) the first time
# something spills an XMM register with a 16-byte-aligned `movaps`.
_ALIGNMENT_WARNING = (
    "no --bytes-before-chain given: this chain's stack-alignment residue at "
    "the call target was not corrected, and may not match what a real `call` "
    "would leave (rsp%16==8 at entry). Pass --bytes-before-chain (0 if this "
    "chain directly overwrites a saved return address) so ropnroll can pad "
    "it correctly."
)


@dataclass
class CallResult:
    chain: Chain | None
    solve: SolveResult
    ok: bool


def arg_regs(ai: ArchInfo, os: str) -> list[str]:
    """The calling-convention argument registers for `ai`'s arch under `os`
    -- exported (not just used internally by `build_call`) so callers that
    need to check what a chain *should* have set (e.g. `--verify`'s goal
    registers) use the same OS-aware answer instead of falling back to
    `ai.call_arg_regs`, which is SysV-only and wrong for x86-64 Windows."""
    if ai.arch == "x86_64" and os == "windows":
        return _MS64_ARGS
    return ai.call_arg_regs


def build_call(
    pool: GadgetPool,
    target: int,
    args: list[int],
    return_to: int | None = None,
    avoid: set = frozenset(),
    max_insns: int = 6,
    bytes_before_chain: int | None = None,
    target_module: str | None = None,
    img: Image | None = None,
) -> CallResult:
    """`bytes_before_chain`: how many bytes of payload precede this chain
    in the final buffer (e.g. the overflow padding before it starts) --
    when given, on x86-64 this automatically inserts a single bare `ret`
    gadget if needed so `target` is entered with the same rsp%16==8
    residue it would see via a real `call` instruction. Without a `call`
    pushing a return address, a direct-`ret`-into-target chain built at the
    "wrong" parity will crash inside target's own callees the moment they
    use an SSE instruction that requires 16-byte-aligned rsp -- a classic,
    easy-to-miss ret2libc gotcha. Omitting this leaves the chain
    alignment-uncorrected and adds a warning saying so (see
    `_ALIGNMENT_WARNING`); pass it (0 if this chain directly overwrites a
    saved return address) once you know what precedes the chain.

    `img`: the primary target Image, if you have one handy -- used only to
    warn (via the returned chain's `warnings`) when CET shadow stack would
    reject this return-based chain outright. Purely advisory; omitting it
    just means you don't get the warning.
    """
    ai = pool.ai
    argregs = arg_regs(ai, pool.os)
    if argregs:
        if len(args) > len(argregs):
            raise ValueError(
                f"{ai.arch}/{pool.os} register-passed args max is {len(argregs)}, "
                f"got {len(args)} (stack-spilled args not yet supported)"
            )
        targets = {argregs[i]: v for i, v in enumerate(args)}
        res = set_registers(pool, targets, avoid=avoid, max_insns=max_insns)
        if not res.ok or res.chain is None:
            return CallResult(chain=None, solve=res, ok=False)
        chain = res.chain

        if ai.arch == "x86_64" and ai.reg_width == 8:
            if bytes_before_chain is None:
                chain.warnings.append(_ALIGNMENT_WARNING)
            else:
                # Offset of the (not-yet-placed) target word from the start
                # of the actual return-address overwrite (bytes_before_chain
                # bytes before chain.words[0]). That overwritten slot is
                # itself always at an address ==8 (mod 16) -- it's where a
                # real `call` would have pushed its return address -- so the
                # target lands at the right rsp%16==8 residue only when
                # (target_word_offset + 8) % 16 == 8, i.e. target_word_offset
                # % 16 == 8. Any other residue needs one more 8-byte word to
                # flip the parity.
                #
                # `set_last` below overwrites the last word if there is one
                # (the open "-> next" placeholder every gadget block ends
                # with), or appends a new word 0 if the chain is empty (a
                # zero-argument call has no gadgets at all) -- mirror that
                # here rather than assuming a placeholder always exists.
                target_index = max(len(chain.words) - 1, 0)
                target_word_offset = bytes_before_chain + target_index * ai.reg_width
                if target_word_offset % 16 != 8:
                    # A gadget whose *only* instruction is the terminating
                    # `ret` itself (n_insns == 1, nothing preceding it) is
                    # exactly what we want here -- but the scanner never
                    # reports one: it deliberately skips the zero-length
                    # "start == end" case when walking back from a
                    # terminator (scanner.py's _scan_x86_offsets), since a
                    # gadget with no effect isn't useful for general
                    # scanning/searching. Every RET-terminated gadget still
                    # *contains* a standalone ret byte, though: the same
                    # "unintended gadget" byte-overlap technique the scanner
                    # itself relies on means the address of that gadget's
                    # own terminator instruction is just as valid an entry
                    # point as the gadget's head is.
                    rets = pool.shortlist_terminator(Terminator.RET)
                    if rets:
                        pad_insn = rets[0].insns[-1]
                        pad_addr = pad_insn.address
                        module, offset = _tag(pool, rets[0].module, pad_addr)
                        chain.set_last(
                            pad_addr,
                            f"alignment pad (bare ret) 0x{pad_addr:x}",
                            module=module,
                            offset=offset,
                        )
                        chain.words.append(ChainWord(None, "-> next"))

        t_module, t_offset = _tag(pool, target_module, target)
        chain.set_last(
            target, f"call target 0x{target:x}", module=t_module, offset=t_offset
        )
        if ai.arch == "x86_64" and pool.os == "windows":
            for i in range(_MS64_SHADOW_SPACE // ai.reg_width):
                chain.append_raw(0, "MS x64 shadow space (callee may spill args here)")
        if return_to is not None:
            chain.append_raw(return_to, f"return address after call 0x{return_to:x}")
        if img is not None and img.mitigations.get("cet"):
            chain.warnings.append(_CET_WARNING)
        return CallResult(chain=chain, solve=res, ok=True)
    else:
        # cdecl/stdcall (x86): arguments live on the stack, pushed right
        # before the target's own address (which itself sits where the
        # target's `ret` will look for its own return address).
        chain = Chain(ai=ai)
        t_module, t_offset = _tag(pool, target_module, target)
        chain.words.append(
            ChainWord(
                target, f"call target 0x{target:x}", module=t_module, offset=t_offset
            )
        )
        if return_to is not None:
            chain.append_raw(return_to, f"return address after call 0x{return_to:x}")
        else:
            chain.append_raw(0, "return address (unused placeholder)")
        for i, a in enumerate(args):
            chain.append_raw(a, f"stack arg[{i}] = 0x{a:x}")
        if img is not None and img.mitigations.get("cet"):
            chain.warnings.append(_CET_WARNING)
        res = SolveResult(
            chain=chain, resolved={}, unresolved=[], log=["cdecl: args pushed on stack"]
        )
        return CallResult(chain=chain, solve=res, ok=True)
