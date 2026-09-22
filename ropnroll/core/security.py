"""checksec-style mitigation report, extended with the bits that actually
matter for deciding a ROP/JOP strategy: syscall-gadget availability, and
Windows Control Flow Guard (the direct analog of Linux CET-IBT) since it
restricts which addresses a JOP dispatcher may legally land on."""
from __future__ import annotations

from dataclasses import dataclass

from .gadget import Gadget, Terminator
from .loader import Image


@dataclass
class SecurityReport:
    image: Image
    lines: list[tuple[str, str]]   # (label, value) pairs for display
    n_syscall_gadgets: int
    n_jop_gadgets: int
    n_cfg_targets: int


def build_report(img: Image, gadgets: list[Gadget]) -> SecurityReport:
    m = img.mitigations
    lines = [
        ("format", img.format), ("arch", f"{img.arch} ({img.bits}-bit)"),
        ("os / abi", img.os),
        ("PIE / ASLR-relocatable", "yes" if img.pie else "no"),
        ("NX / DEP", "yes" if m.get("nx") else "no"),
        ("stack canary", "yes" if m.get("canary") else "no (or stripped)"),
    ]
    if img.format == "ELF":
        relro = "full" if m.get("relro_full") else ("partial" if m.get("relro_partial") else "none")
        lines.append(("RELRO", relro))
        lines.append(("fortify (_chk symbols present)", "yes" if m.get("fortify") else "no"))
    if img.format == "PE":
        lines.append(("Control Flow Guard", "ENABLED -- JOP dispatch restricted to guard_cf table"
                       if m.get("cfg") else "not enabled"))
        if img.bits == 32:
            lines.append(("SafeSEH", "yes" if m.get("safeseh") else "no"))
        lines.append(("ASLR high-entropy (/HIGH_ENTROPY_VA)", "yes" if m.get("high_entropy_va") else "no"))

    n_sys = sum(1 for g in gadgets if g.terminator in (Terminator.SYSCALL, Terminator.INT80))
    n_jop = sum(1 for g in gadgets if g.terminator in
                (Terminator.JMP_REG, Terminator.CALL_REG, Terminator.JMP_MEM, Terminator.CALL_MEM))
    lines.append(("gadgets found", str(len(gadgets))))
    lines.append(("  syscall/int0x80 gadgets", str(n_sys)))
    lines.append(("  JOP-terminated gadgets", str(n_jop)))
    if img.cfg_valid_targets:
        lines.append(("  CFG-valid indirect-call targets", str(len(img.cfg_valid_targets))))

    return SecurityReport(image=img, lines=lines, n_syscall_gadgets=n_sys, n_jop_gadgets=n_jop,
                           n_cfg_targets=len(img.cfg_valid_targets))
