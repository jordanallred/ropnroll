"""
Gadget scanner: the syntactic layer.

Same core technique as Ropper / ROPgadget / the original "galileo" ROP
paper: for x86/x86-64 (variable-length ISA) walk every byte offset
backwards from every terminator instruction and keep any window that
disassembles cleanly straight through to that terminator. For
fixed-width ISAs (ARM/ARM64/MIPS) do the same thing at instruction
granularity instead of byte granularity.

This stage is deliberately "dumb" and fast -- it does not know what a
gadget *does*, only that it is a legally decodable instruction stream
ending in something that returns/jumps/syscalls. Semantic understanding
is added lazily on top by ropnroll.semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional

import capstone as cs

from .archinfo import ArchInfo, get_archinfo
from .gadget import Gadget, Terminator
from .loader import Image, Segment

_BAD_MNEMONICS = {
    # instructions we refuse to let appear *inside* a gadget body (privileged,
    # or themselves would have terminated an earlier/shorter gadget already).
    "hlt", "in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd",
    "iret", "iretd", "iretq", "ud2", "ud2b", "vmcall", "vmlaunch", "vmresume",
    "vmxoff", "cli", "sti", "lock",
}

_JUMP_MNEM = {"jmp"}
_CALL_MNEM = {"call"}
_COND_JUMP_PREFIXES = ("j",)  # jcc other than jmp - excluded from "clean" bodies by default


def _classify_x86(insn) -> Optional[Terminator]:
    m = insn.mnemonic
    if m == "ret" or m == "retf":
        return Terminator.RET if not insn.operands else Terminator.RET_IMM
    if m == "syscall" or m == "sysenter":
        return Terminator.SYSCALL
    if m == "int3":
        return None
    if m == "int" and insn.operands and insn.operands[0].type == cs.x86.X86_OP_IMM \
            and insn.operands[0].imm == 0x80:
        return Terminator.INT80
    if m in _JUMP_MNEM and insn.operands:
        op = insn.operands[0]
        if op.type == cs.x86.X86_OP_REG:
            return Terminator.JMP_REG
        if op.type == cs.x86.X86_OP_MEM:
            return Terminator.JMP_MEM
    if m in _CALL_MNEM and insn.operands:
        op = insn.operands[0]
        if op.type == cs.x86.X86_OP_REG:
            return Terminator.CALL_REG
        if op.type == cs.x86.X86_OP_MEM:
            return Terminator.CALL_MEM
    return None


def _classify_arm(insn) -> Optional[Terminator]:
    m = insn.mnemonic.split(".")[0]
    if m in ("bx", "blx") and insn.operands and insn.operands[0].type == cs.arm.ARM_OP_REG:
        return Terminator.CALL_REG if m == "blx" else Terminator.JMP_REG
    if m in ("svc", "swi"):
        return Terminator.SYSCALL
    if m == "pop" and any(o.type == cs.arm.ARM_OP_REG and o.reg == cs.arm.ARM_REG_PC
                           for o in insn.operands):
        return Terminator.RET
    return None


def _classify_arm64(insn) -> Optional[Terminator]:
    m = insn.mnemonic
    if m == "ret":
        return Terminator.RET
    if m in ("br", "blr") and insn.operands and insn.operands[0].type == cs.arm64.ARM64_OP_REG:
        return Terminator.CALL_REG if m == "blr" else Terminator.JMP_REG
    if m == "svc":
        return Terminator.SYSCALL
    return None


def _classify_mips(insn) -> Optional[Terminator]:
    m = insn.mnemonic
    if m in ("jr", "jalr") and insn.operands:
        return Terminator.CALL_REG if m == "jalr" else Terminator.JMP_REG
    if m == "syscall":
        return Terminator.SYSCALL
    return None


_CLASSIFIERS = {
    cs.CS_ARCH_X86: _classify_x86,
    cs.CS_ARCH_ARM: _classify_arm,
    cs.CS_ARCH_ARM64: _classify_arm64,
    cs.CS_ARCH_MIPS: _classify_mips,
}


def _is_bad_body_insn(insn, arch_cs: int) -> bool:
    if insn.mnemonic in _BAD_MNEMONICS:
        return True
    if not insn.mnemonic:
        return True
    if arch_cs == cs.CS_ARCH_X86:
        m = insn.mnemonic
        # conditional branches / loop-until instructions make the gadget's
        # control flow data-dependent, breaking the "always falls through
        # to the terminator" guarantee we rely on everywhere downstream.
        if m.startswith("j") and m != "jmp":
            return True
        if m in ("loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz"):
            return True
        # a write to a segment register (mov cs/ds/es/ss/fs/gs, ...) is
        # essentially never legitimate gadget content in real compiler
        # output -- when the byte-level scanner turns one up it's almost
        # always a misaligned decode landing on unrelated data, and its
        # real execution behavior is unpredictable (confirmed by the
        # verifier: one such gadget decoded and looked fine in isolation
        # but faulted with "invalid instruction" when actually run in
        # place against the real binary).
        if m == "mov" and insn.operands and insn.operands[0].type == cs.x86.X86_OP_REG:
            rname = insn.reg_name(insn.operands[0].reg)
            if rname in ("cs", "ds", "es", "ss", "fs", "gs"):
                return True
    return False


def _make_disassembler(ai: ArchInfo) -> cs.Cs:
    md = cs.Cs(ai.cs_arch, ai.cs_mode)
    md.detail = True
    return md


@dataclass
class ScanOptions:
    max_bytes: Optional[int] = None
    max_insns: Optional[int] = None
    rop: bool = True
    jop: bool = True
    sys: bool = True
    allow_cond_jump_terminators: bool = False
    bad_bytes: bytes = b""
    only_executable_segments: bool = True


def _wanted(term: Terminator, opts: ScanOptions) -> bool:
    if term in (Terminator.RET, Terminator.RET_IMM):
        return opts.rop
    if term in (Terminator.JMP_REG, Terminator.CALL_REG, Terminator.JMP_MEM, Terminator.CALL_MEM):
        return opts.jop
    if term in (Terminator.SYSCALL, Terminator.INT80):
        return opts.sys
    return False


def _has_bad_bytes(raw: bytes, bad: bytes) -> bool:
    if not bad:
        return False
    return any(b in raw for b in bad)


def _scan_segment_x86(seg: Segment, ai: ArchInfo, opts: ScanOptions, module: str) -> Iterator[Gadget]:
    md = _make_disassembler(ai)
    classify = _CLASSIFIERS[ai.cs_arch]
    data = seg.data
    n = len(data)
    max_bytes = opts.max_bytes or ai.max_gadget_bytes
    max_insns = opts.max_insns or ai.max_gadget_insns

    # Pass 1: linear disassembly to find every "naturally aligned" terminator.
    term_offsets: list[int] = []
    off = 0
    while off < n:
        chunk = data[off:off + 16]
        try:
            insn = next(md.disasm(chunk, seg.vaddr + off, count=1))
        except StopIteration:
            off += 1
            continue
        t = classify(insn)
        if t is not None and _wanted(t, opts):
            term_offsets.append(off)
        off += insn.size

    # Pass 2: also treat every raw occurrence of a terminator opcode byte as a
    # candidate end (this is what actually finds the "unintended" gadgets that
    # make x86 ROP possible -- a terminator hiding mid-instruction).
    if opts.rop:
        idx = data.find(b"\xc3")
        while idx != -1:
            term_offsets.append(idx)
            idx = data.find(b"\xc3", idx + 1)
    term_offsets = sorted(set(term_offsets))

    seen_bytes: set[bytes] = set()
    for end in term_offsets:
        # figure out how long the terminator instruction itself is
        try:
            term_insn = next(md.disasm(data[end:end + 16], seg.vaddr + end, count=1))
        except StopIteration:
            continue
        t = classify(term_insn)
        if t is None or not _wanted(t, opts):
            continue
        true_end = end + term_insn.size

        lo = max(0, end - max_bytes)
        for start in range(end, lo - 1, -1):
            if start == end:
                continue
            body = data[start:true_end]
            if _has_bad_bytes(body, opts.bad_bytes):
                continue
            insns = []
            o = start
            ok = True
            while o < true_end:
                try:
                    insn = next(md.disasm(data[o:o + 16], seg.vaddr + o, count=1))
                except StopIteration:
                    ok = False
                    break
                if o + insn.size > true_end:
                    ok = False
                    break
                if _is_bad_body_insn(insn, ai.cs_arch):
                    ok = False
                    break
                mid_term = classify(insn)
                # syscall/int0x80 don't divert control flow (the kernel
                # returns to the very next instruction), so unlike a
                # ret/jmp/call they're safe to have mid-body -- rejecting
                # them here would mean "syscall ; ret" could never be found
                # as a single gadget, only bare "syscall" ever would.
                diverts = mid_term not in (None, Terminator.SYSCALL, Terminator.INT80)
                if diverts and o + insn.size != true_end:
                    # an earlier terminator inside the window -> this start
                    # belongs to a *different*, shorter gadget, not this one
                    ok = False
                    break
                insns.append(insn)
                o += insn.size
                if len(insns) > max_insns:
                    ok = False
                    break
            if not ok or o != true_end or not insns:
                continue
            if len(insns) > max_insns:
                continue
            # the instruction that *actually* lands on true_end when decoded
            # forward from `start` must itself be the terminator -- landing
            # on the same offset by byte-overlap coincidence is not enough.
            if classify(insns[-1]) != t:
                continue
            raw = data[start:true_end]
            if raw in seen_bytes:
                continue
            seen_bytes.add(raw)
            text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
            yield Gadget(address=seg.vaddr + start, raw=raw, text=text, insns=insns,
                          terminator=t, module=module)


def _scan_segment_fixed_width(seg: Segment, ai: ArchInfo, opts: ScanOptions, module: str) -> Iterator[Gadget]:
    """ARM/ARM64/MIPS: every instruction is exactly `insn_alignment` bytes,
    so this is much simpler than the x86 byte-granular walk -- candidate
    gadget starts only need to be tried at aligned offsets."""
    md = _make_disassembler(ai)
    classify = _CLASSIFIERS[ai.cs_arch]
    step = ai.insn_alignment
    data = seg.data
    n = len(data)
    max_insns = opts.max_insns or ai.max_gadget_insns

    all_insns: dict[int, "cs.CsInsn"] = {}
    off = 0
    while off + step <= n:
        try:
            insn = next(md.disasm(data[off:off + step], seg.vaddr + off, count=1))
            all_insns[off] = insn
        except StopIteration:
            pass
        off += step

    term_offs = [o for o, ins in all_insns.items()
                 if classify(ins) is not None and _wanted(classify(ins), opts)]

    seen_bytes: set[bytes] = set()
    for end in term_offs:
        term_insn = all_insns[end]
        t = classify(term_insn)
        # MIPS-style branch delay slot: the instruction after jr/jalr/syscall
        # still executes, so it belongs *inside* the gadget.
        delay_slot = ai.arch.startswith("mips") and t in (Terminator.JMP_REG, Terminator.CALL_REG)
        true_end = end + step + (step if delay_slot else 0)
        if true_end > n:
            continue
        for start in range(end, max(-1, end - max_insns * step), -step):
            if start == end:
                continue
            insns = []
            ok = True
            o = start
            while o < true_end:
                insn = all_insns.get(o)
                if insn is None or _is_bad_body_insn(insn, ai.cs_arch):
                    ok = False
                    break
                if o != end and o != end + step and classify(insn) is not None:
                    ok = False
                    break
                insns.append(insn)
                o += step
            if not ok or not insns:
                continue
            # the instruction actually landing on true_end must itself be
            # the terminator, not just happen to end at the right offset
            # (mirrors the x86 byte-overlap check -- cheap defense in depth
            # even though fixed-width alignment makes this always hold).
            if classify(insns[-1]) != t:
                continue
            raw = data[start:true_end]
            if _has_bad_bytes(raw, opts.bad_bytes) or raw in seen_bytes:
                continue
            seen_bytes.add(raw)
            text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
            yield Gadget(address=seg.vaddr + start, raw=raw, text=text, insns=insns,
                         terminator=t, module=module)


def scan_image(img: Image, opts: Optional[ScanOptions] = None) -> list[Gadget]:
    opts = opts or ScanOptions()
    ai = get_archinfo(img.arch, img.little_endian)
    gadgets: list[Gadget] = []
    segs = img.executable_segments() if opts.only_executable_segments else img.segments
    for seg in segs:
        if ai.cs_arch == cs.CS_ARCH_X86:
            gadgets.extend(_scan_segment_x86(seg, ai, opts, module=img.path))
        else:
            gadgets.extend(_scan_segment_fixed_width(seg, ai, opts, module=img.path))
    gadgets.sort(key=lambda g: (g.address, g.size))
    return gadgets
