import re

from ropnroll.core import loader, scanner
from ropnroll.core.archinfo import get_archinfo
from ropnroll.semantics.effect import EKind
from ropnroll.semantics.engine import SemanticEngine


def _find(gadgets, pattern):
    rx = re.compile(pattern)
    for g in gadgets:
        if rx.match(g.text):
            return g
    raise AssertionError(f"no gadget matching {pattern!r}")


def test_pop_reg_is_load_from_stack(ntdll_path):
    img = loader.load(ntdll_path)
    ai = get_archinfo(img.arch, img.little_endian)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(jop=False, sys=False, max_insns=2))
    g = _find(gadgets, r"^pop rdi ; ret$")
    eff = SemanticEngine(img, ai).compute(g)
    assert eff.ok
    e = eff.reg_effects["rdi"]
    assert e.kind == EKind.LOAD
    assert e.src == "rsp"
    assert eff.sp_delta == 16  # own pop (8) + ret's pop (8)


def test_xor_self_is_const_zero(ntdll_path):
    img = loader.load(ntdll_path)
    ai = get_archinfo(img.arch, img.little_endian)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(jop=False, sys=False, max_insns=2))
    g = _find(gadgets, r"^xor eax, eax ; ret$")
    eff = SemanticEngine(img, ai).compute(g)
    assert eff.ok
    e = eff.reg_effects["rax"]
    assert e.kind == EKind.CONST
    assert e.c == 0


def test_32bit_write_zero_extends_on_x86_64(ntdll_path):
    """Regression: `inc edi` must be recognized as rdi += 1 (32-bit write,
    implicit zero-extend), not misfit as some unrelated constant."""
    img = loader.load(ntdll_path)
    ai = get_archinfo(img.arch, img.little_endian)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(jop=False, sys=False, max_insns=2))
    g = _find(gadgets, r"^inc edi ; ret$")
    eff = SemanticEngine(img, ai).compute(g)
    assert eff.ok
    e = eff.reg_effects["rdi"]
    assert e.kind == EKind.ADD
    assert e.src == "rdi"
    assert e.c == 1
    assert e.size == 4


def test_mov_reg_reg_is_copy(ntdll_path):
    img = loader.load(ntdll_path)
    ai = get_archinfo(img.arch, img.little_endian)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(jop=False, sys=False, max_insns=2))
    g = _find(gadgets, r"^mov rax, rcx ; ret$")
    eff = SemanticEngine(img, ai).compute(g)
    assert eff.ok
    e = eff.reg_effects["rax"]
    assert e.kind == EKind.COPY
    assert e.src == "rcx"
