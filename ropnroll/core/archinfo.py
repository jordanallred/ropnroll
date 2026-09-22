"""Per-architecture Capstone/Unicorn wiring and register tables."""
from __future__ import annotations

from dataclasses import dataclass

import capstone as cs
import unicorn as uc
import unicorn.x86_const as ux86
import unicorn.arm_const as uarm
import unicorn.arm64_const as uarm64
import unicorn.mips_const as umips

from .loader import ARCH_X86, ARCH_X86_64, ARCH_ARM, ARCH_ARM64, ARCH_MIPS, ARCH_MIPS64


@dataclass
class ArchInfo:
    arch: str
    bits: int
    cs_arch: int
    cs_mode: int
    uc_arch: int
    uc_mode: int
    sp_reg: str
    ip_reg: str
    gpr: list[str]                 # general purpose regs usable for semantic fitting
    call_arg_regs: list[str]       # argument-passing registers, in order (empty => stack-only)
    ret_reg: str
    reg_width: int                 # bytes
    uc_reg_const: dict[str, int]   # name -> unicorn constant
    max_gadget_bytes: int
    max_gadget_insns: int
    insn_alignment: int             # 1 for x86 (byte-granular), 4 for arm64/mips, 2 for thumb/arm-mixed


def _uc_x86_regmap():
    return {
        "rax": ux86.UC_X86_REG_RAX, "rbx": ux86.UC_X86_REG_RBX, "rcx": ux86.UC_X86_REG_RCX,
        "rdx": ux86.UC_X86_REG_RDX, "rsi": ux86.UC_X86_REG_RSI, "rdi": ux86.UC_X86_REG_RDI,
        "rbp": ux86.UC_X86_REG_RBP, "rsp": ux86.UC_X86_REG_RSP,
        "r8": ux86.UC_X86_REG_R8, "r9": ux86.UC_X86_REG_R9, "r10": ux86.UC_X86_REG_R10,
        "r11": ux86.UC_X86_REG_R11, "r12": ux86.UC_X86_REG_R12, "r13": ux86.UC_X86_REG_R13,
        "r14": ux86.UC_X86_REG_R14, "r15": ux86.UC_X86_REG_R15, "rip": ux86.UC_X86_REG_RIP,
        "eflags": ux86.UC_X86_REG_EFLAGS,
    }


def _uc_x86_32_regmap():
    return {
        "eax": ux86.UC_X86_REG_EAX, "ebx": ux86.UC_X86_REG_EBX, "ecx": ux86.UC_X86_REG_ECX,
        "edx": ux86.UC_X86_REG_EDX, "esi": ux86.UC_X86_REG_ESI, "edi": ux86.UC_X86_REG_EDI,
        "ebp": ux86.UC_X86_REG_EBP, "esp": ux86.UC_X86_REG_ESP, "eip": ux86.UC_X86_REG_EIP,
        "eflags": ux86.UC_X86_REG_EFLAGS,
    }


def _uc_arm_regmap():
    m = {f"r{i}": getattr(uarm, f"UC_ARM_REG_R{i}") for i in range(13)}
    m.update({"sp": uarm.UC_ARM_REG_SP, "lr": uarm.UC_ARM_REG_LR, "pc": uarm.UC_ARM_REG_PC,
              "cpsr": uarm.UC_ARM_REG_CPSR})
    return m


def _uc_arm64_regmap():
    m = {f"x{i}": getattr(uarm64, f"UC_ARM64_REG_X{i}") for i in range(29)}
    m.update({"sp": uarm64.UC_ARM64_REG_SP, "x29": uarm64.UC_ARM64_REG_X29,
              "x30": uarm64.UC_ARM64_REG_X30, "lr": uarm64.UC_ARM64_REG_X30,
              "pc": uarm64.UC_ARM64_REG_PC})
    return m


def _uc_mips_regmap():
    names = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
             "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
             "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
             "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"]
    m = {}
    for n in names:
        const = getattr(umips, f"UC_MIPS_REG_{n.upper()}", None)
        if const is not None:
            m[n] = const
    m["pc"] = umips.UC_MIPS_REG_PC
    return m


def get_archinfo(arch: str, little_endian: bool = True) -> ArchInfo:
    if arch == ARCH_X86_64:
        return ArchInfo(
            arch=arch, bits=64, cs_arch=cs.CS_ARCH_X86, cs_mode=cs.CS_MODE_64,
            uc_arch=uc.UC_ARCH_X86, uc_mode=uc.UC_MODE_64,
            sp_reg="rsp", ip_reg="rip",
            gpr=["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
            call_arg_regs=["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            ret_reg="rax", reg_width=8, uc_reg_const=_uc_x86_regmap(),
            max_gadget_bytes=24, max_gadget_insns=6, insn_alignment=1,
        )
    if arch == ARCH_X86:
        return ArchInfo(
            arch=arch, bits=32, cs_arch=cs.CS_ARCH_X86, cs_mode=cs.CS_MODE_32,
            uc_arch=uc.UC_ARCH_X86, uc_mode=uc.UC_MODE_32,
            sp_reg="esp", ip_reg="eip",
            gpr=["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
            call_arg_regs=[],  # cdecl/stdcall: stack-based
            ret_reg="eax", reg_width=4, uc_reg_const=_uc_x86_32_regmap(),
            max_gadget_bytes=20, max_gadget_insns=6, insn_alignment=1,
        )
    if arch == ARCH_ARM:
        mode = cs.CS_MODE_ARM if little_endian else (cs.CS_MODE_ARM | cs.CS_MODE_BIG_ENDIAN)
        return ArchInfo(
            arch=arch, bits=32, cs_arch=cs.CS_ARCH_ARM, cs_mode=mode,
            uc_arch=uc.UC_ARCH_ARM, uc_mode=uc.UC_MODE_ARM,
            sp_reg="sp", ip_reg="pc",
            gpr=[f"r{i}" for i in range(13)],
            call_arg_regs=["r0", "r1", "r2", "r3"],
            ret_reg="r0", reg_width=4, uc_reg_const=_uc_arm_regmap(),
            max_gadget_bytes=24, max_gadget_insns=6, insn_alignment=4,
        )
    if arch == ARCH_ARM64:
        return ArchInfo(
            arch=arch, bits=64, cs_arch=cs.CS_ARCH_ARM64, cs_mode=cs.CS_MODE_ARM,
            uc_arch=uc.UC_ARCH_ARM64, uc_mode=uc.UC_MODE_ARM,
            sp_reg="sp", ip_reg="pc",
            gpr=[f"x{i}" for i in range(29)],
            call_arg_regs=["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            ret_reg="x0", reg_width=8, uc_reg_const=_uc_arm64_regmap(),
            max_gadget_bytes=32, max_gadget_insns=6, insn_alignment=4,
        )
    if arch in (ARCH_MIPS, ARCH_MIPS64):
        bits = 64 if arch == ARCH_MIPS64 else 32
        cs_mode = (cs.CS_MODE_MIPS64 if bits == 64 else cs.CS_MODE_MIPS32)
        cs_mode |= (cs.CS_MODE_LITTLE_ENDIAN if little_endian else cs.CS_MODE_BIG_ENDIAN)
        uc_mode = (uc.UC_MODE_MIPS64 if bits == 64 else uc.UC_MODE_MIPS32)
        uc_mode |= (uc.UC_MODE_LITTLE_ENDIAN if little_endian else uc.UC_MODE_BIG_ENDIAN)
        return ArchInfo(
            arch=arch, bits=bits, cs_arch=cs.CS_ARCH_MIPS, cs_mode=cs_mode,
            uc_arch=uc.UC_ARCH_MIPS, uc_mode=uc_mode,
            sp_reg="sp", ip_reg="pc",
            gpr=["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
                 "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9"],
            call_arg_regs=["a0", "a1", "a2", "a3"],
            ret_reg="v0", reg_width=8 if bits == 64 else 4, uc_reg_const=_uc_mips_regmap(),
            max_gadget_bytes=32, max_gadget_insns=8, insn_alignment=4,
        )
    raise ValueError(f"no ArchInfo for arch={arch!r}")
