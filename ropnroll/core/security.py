"""checksec-style mitigation report, extended with the bits that actually
matter for deciding a ROP/JOP strategy: syscall-gadget availability, and
Control Flow Guard, since it restricts which addresses a JOP dispatcher may
legally land on."""

from __future__ import annotations

from dataclasses import dataclass

from .gadget import Gadget, Terminator
from .loader import Image


@dataclass
class SecurityReport:
    image: Image
    # (label, value, style) triples for display -- style is a Rich style name
    # ("green"/"yellow"/"red"/"bold red"/"dim"/"") reflecting how attacker-
    # friendly the row is, not how secure the binary is: an absent mitigation
    # is styled "green" here because it's an opportunity for this tool's user,
    # not a defensive win.
    lines: list[tuple[str, str, str]]
    n_syscall_gadgets: int
    n_jop_gadgets: int
    n_cfg_targets: int


def _mitigation(present: bool, yes: str = "yes", no: str = "no") -> tuple[str, str]:
    """A present mitigation works against the attacker (yellow); its absence
    is green -- an opportunity, not a defensive property."""
    return (yes, "yellow") if present else (no, "green")


def build_report(img: Image, gadgets: list[Gadget]) -> SecurityReport:
    m = img.mitigations
    pie_val, pie_style = _mitigation(img.pie)
    nx_val, nx_style = _mitigation(m.get("nx"))
    canary_val, canary_style = _mitigation(m.get("canary"), no="no (or stripped)")
    lines = [
        ("format", img.format, ""),
        ("arch", f"{img.arch} ({img.bits}-bit)", ""),
        ("PIE / ASLR-relocatable", pie_val, pie_style),
        ("NX / DEP", nx_val, nx_style),
        ("stack canary", canary_val, canary_style),
    ]
    # CET shadow stack validates return addresses in hardware -- it breaks
    # classic ROP outright, so report it first and unambiguously, in red
    # rather than the usual yellow.
    if m.get("cet"):
        lines.append(
            (
                "CET shadow stack (/CETCOMPAT)",
                "ENABLED -- return-address ROP defeated by hardware shadow stack",
                "bold red",
            )
        )
    else:
        lines.append(("CET shadow stack (/CETCOMPAT)", "not enabled", "green"))
    if m.get("xfg"):
        lines.append(
            (
                "Control Flow Guard",
                "XFG (eXtended Flow Guard) -- indirect-call targets type-checked",
                "red",
            )
        )
    elif m.get("cfg"):
        lines.append(
            (
                "Control Flow Guard",
                "ENABLED -- JOP dispatch restricted to guard_cf table",
                "yellow",
            )
        )
    else:
        lines.append(("Control Flow Guard", "not enabled", "green"))
    if img.bits == 32:
        safeseh_val, safeseh_style = _mitigation(m.get("safeseh"))
        lines.append(("SafeSEH", safeseh_val, safeseh_style))
    entropy_val, entropy_style = _mitigation(m.get("high_entropy_va"))
    lines.append(("ASLR high-entropy (/HIGH_ENTROPY_VA)", entropy_val, entropy_style))

    n_sys = sum(1 for g in gadgets if g.terminator == Terminator.SYSCALL)
    n_jop = sum(
        1
        for g in gadgets
        if g.terminator
        in (
            Terminator.JMP_REG,
            Terminator.CALL_REG,
            Terminator.JMP_MEM,
            Terminator.CALL_MEM,
        )
    )
    # gadget counts are an opportunity, not a threat -- style them green when
    # nonzero (usable) and dim when empty (this avenue is a dead end here).
    lines.append(("gadgets found", str(len(gadgets)), "green" if gadgets else "dim"))
    lines.append(("  syscall gadgets", str(n_sys), "green" if n_sys else "dim"))
    lines.append(("  JOP-terminated gadgets", str(n_jop), "green" if n_jop else "dim"))
    if img.cfg_valid_targets:
        lines.append(
            (
                "  CFG-valid indirect-call targets",
                str(len(img.cfg_valid_targets)),
                "green",
            )
        )

    return SecurityReport(
        image=img,
        lines=lines,
        n_syscall_gadgets=n_sys,
        n_jop_gadgets=n_jop,
        n_cfg_targets=len(img.cfg_valid_targets),
    )
