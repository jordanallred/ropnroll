"""
Empirical one-gadget discovery.

The standalone `one_gadget` tool works by hand-analyzing glibc *source* for
each release to find addresses that pop a shell if you just jump there with
the right (often "everything is NULL") register/stack state -- the magic
offsets and their constraint expressions are curated per glibc version.

This takes a different, more general approach that needs no version
database: find every place the binary's own code materializes a pointer to
a shell string (`"/bin/sh"`, `"/bin/bash"`, ...) into a register via a
rip-relative `lea` -- that's necessarily on the path system()/popen()/
posix_spawn() take internally -- and then *concretely emulate forward* from
each such point with a couple of candidate starting states (registers
zeroed; stack pointer valid and zeroed) to see whether an execve syscall
for that exact string address actually fires. Because this reuses the same
Unicorn machinery as chain verification, a hit is not a guess -- it is a
confirmed, concretely-observed shell-spawn from that address under that
starting state, hooked at the exact `syscall` instruction so the argument
registers are read at precisely the right moment.

Scoped to x86/x86-64 (rip-relative `lea` is how the string address gets
materialized there); will find fewer candidates than a curated per-version
database, but needs no database and works on any binary you hand it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import capstone as cs
import unicorn as uc
import unicorn.x86_const as ux86

from ..core.archinfo import get_archinfo
from ..core.loader import Image

_SHELL_STRINGS = [b"/bin/sh\x00", b"/bin/bash\x00", b"/bin/dash\x00"]
_EXECVE_NR = {"x86_64": 59, "x86": 11}
_SYS_NR_REG = {"x86_64": "rax", "x86": "eax"}
_ARG0_REG = {"x86_64": "rdi", "x86": "ebx"}


@dataclass
class OneGadgetCandidate:
    address: int
    string_addr: int
    string: bytes
    constraint: str            # human-readable description of the starting state that worked
    instructions_run: int


@dataclass
class OneGadgetReport:
    candidates: list[OneGadgetCandidate] = field(default_factory=list)
    searched_sites: int = 0


def _string_addr(img: Image, needle: bytes) -> Optional[int]:
    for seg in img.segments:
        if seg.readable:
            idx = seg.data.find(needle)
            if idx != -1:
                return seg.vaddr + idx
    return None


def _find_lea_string_refs(img: Image, target_addr: int) -> list[int]:
    """Every rip-relative `lea reg, [target_addr]` in the binary's own
    code -- i.e. every place it loads a pointer to that exact address."""
    ai = get_archinfo(img.arch, img.little_endian)
    md = cs.Cs(ai.cs_arch, ai.cs_mode)
    md.detail = True
    refs = []
    for seg in img.executable_segments():
        data = seg.data
        off = 0
        while off < len(data):
            try:
                insn = next(md.disasm(data[off:off + 16], seg.vaddr + off, count=1))
            except StopIteration:
                off += 1
                continue
            if insn.mnemonic == "lea" and len(insn.operands) > 1:
                mem = insn.operands[1].mem
                if mem.base != 0 and insn.reg_name(mem.base) == ai.ip_reg:
                    if insn.address + insn.size + mem.disp == target_addr:
                        refs.append(insn.address)
            off += insn.size
    return refs


def _map_image(mu: uc.Uc, img: Image):
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


def find_one_gadgets(img: Image, max_insns: int = 500, max_sites: int = 200) -> OneGadgetReport:
    if img.arch not in ("x86_64", "x86"):
        return OneGadgetReport()  # scoped to what we validate: see module docstring

    ai = get_archinfo(img.arch, img.little_endian)
    report = OneGadgetReport()

    sites: list[tuple[int, int, bytes]] = []  # (lea_addr, string_addr, string)
    for s in _SHELL_STRINGS:
        addr = _string_addr(img, s)
        if addr is None:
            continue
        for lea_addr in _find_lea_string_refs(img, addr):
            sites.append((lea_addr, addr, s))
    sites = sites[:max_sites]
    report.searched_sites = len(sites)
    if not sites:
        return report

    mu = uc.Uc(ai.uc_arch, ai.uc_mode)
    _map_image(mu, img)
    stack_base, stack_size = 0x0000_7C00_0000_0000, 0x40000
    mu.mem_map(stack_base, stack_size)
    stack_mid = stack_base + stack_size // 2

    sys_nr_reg, arg0_reg, execve_nr = _SYS_NR_REG[img.arch], _ARG0_REG[img.arch], _EXECVE_NR[img.arch]

    # a slab to hand out as fake mmap() return addresses -- modern glibc's
    # system()/popen() goes through posix_spawn, which mmaps a stack for a
    # helper thread before it ever gets to execve. Returning 0 there (as if
    # it were just "success") crashes the very next dereference; handing
    # back a real, growing, mapped address lets that code path continue.
    mmap_slab_base = 0x0000_7E00_0000_0000
    mmap_slab_size = 0x400000
    mu.mem_map(mmap_slab_base, mmap_slab_size)
    mmap_cursor = [mmap_slab_base]
    _NR_MMAP = 9

    for lea_addr, string_addr, s in sites:
        for env_name, sp_val in (("registers zeroed, NULL-filled stack", stack_mid),):
            for reg in ai.gpr:
                const = ai.uc_reg_const.get(reg)
                if const is not None:
                    mu.reg_write(const, 0)
            mu.reg_write(ai.uc_reg_const[ai.sp_reg], sp_val)
            mu.mem_write(stack_mid, b"\x00" * (stack_size // 2 - 0x1000))

            result = {}
            executed = [0]

            def on_syscall(muu, ud):
                try:
                    nr = muu.reg_read(ai.uc_reg_const[sys_nr_reg])
                    arg0 = muu.reg_read(ai.uc_reg_const[arg0_reg])
                except Exception:
                    muu.emu_stop()
                    return
                if nr == execve_nr:
                    result["nr"], result["arg0"] = nr, arg0
                    muu.emu_stop()
                    return
                # can't service any other syscall for real, but faking a
                # plausible return and skipping past the 2-byte `syscall`
                # instruction lets emulation keep walking the same code
                # path a real process would take (0 = "success"/"you are
                # the child" for clone/vfork/mprotect/etc; mmap needs an
                # actual valid pointer back, not 0, or the very next
                # dereference crashes).
                if nr == _NR_MMAP:
                    ret = mmap_cursor[0]
                    mmap_cursor[0] += 0x2000
                    muu.reg_write(ai.uc_reg_const[sys_nr_reg], ret)
                else:
                    muu.reg_write(ai.uc_reg_const[sys_nr_reg], 0)
                # NOTE: unlike UC_HOOK_CODE, this instruction-hook fires
                # with rip *already past* the 2-byte `syscall` opcode (this
                # hook type replaces the instruction's real effect rather
                # than previewing it) -- do not also advance rip here, or
                # it overshoots into the middle of the next instruction.

            def on_code(muu, address2, size, ud):
                executed[0] += 1
                if executed[0] >= max_insns:
                    muu.emu_stop()

            h1 = mu.hook_add(uc.UC_HOOK_INSN, on_syscall, aux1=ux86.UC_X86_INS_SYSCALL)
            h2 = mu.hook_add(uc.UC_HOOK_CODE, on_code)
            try:
                mu.emu_start(lea_addr, 0, timeout=500_000)
            except uc.UcError:
                pass
            finally:
                mu.hook_del(h1)
                mu.hook_del(h2)

            if result.get("nr") == execve_nr and result.get("arg0") == string_addr:
                report.candidates.append(OneGadgetCandidate(
                    address=lea_addr, string_addr=string_addr, string=s,
                    constraint=env_name, instructions_run=executed[0]))
                break
    return report
