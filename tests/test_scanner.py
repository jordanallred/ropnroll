from ropnroll.core import loader, scanner
from ropnroll.core.gadget import Terminator


def test_no_conditional_jumps_in_gadget_bodies(libc_path):
    img = loader.load(libc_path)
    opts = scanner.ScanOptions(max_insns=6)
    gadgets = scanner.scan_image(img, opts)
    assert len(gadgets) > 1000
    bad = [g for g in gadgets if any(
        insn.mnemonic.startswith("j") and insn.mnemonic != "jmp" for insn in g.insns[:-1])]
    assert bad == [], f"found {len(bad)} gadgets with a mid-body conditional jump"


def test_finds_common_gadgets(libc_path):
    img = loader.load(libc_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions())
    texts = {g.text for g in gadgets}
    assert "pop rdi ; ret" in texts
    assert "pop rsi ; ret" in texts
    assert "ret" in texts


def test_syscall_ret_found_as_single_gadget(libc_path):
    """Regression: `syscall` must not be treated as an always-terminating
    instruction, or `syscall ; ret` can never be found as one gadget."""
    img = loader.load(libc_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions())
    hits = [g for g in gadgets if g.text == "syscall ; ret"]
    assert hits, "syscall ; ret should be found as a single unit"


def test_terminator_classification_matches_last_instruction(libc_path):
    """Regression: a gadget's declared terminator type must match what the
    actually-decoded final instruction is, not just an offset coincidence."""
    img = loader.load(libc_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=8))
    for g in gadgets[:5000]:
        last = g.insns[-1]
        if g.terminator in (Terminator.RET, Terminator.RET_IMM):
            assert last.mnemonic in ("ret", "retf")
        elif g.terminator == Terminator.SYSCALL:
            assert last.mnemonic in ("syscall", "sysenter")


def test_pe_loading_64bit():
    img = loader.load("tests/fixtures/pe/cli-64.exe")
    assert img.format == "PE"
    assert img.arch == "x86_64"
    assert img.os == "windows"
    assert img.bits == 64
    gadgets = scanner.scan_image(img, scanner.ScanOptions())
    assert len(gadgets) > 100


def test_pe_loading_32bit():
    img = loader.load("tests/fixtures/pe/cli-32.exe")
    assert img.format == "PE"
    assert img.arch == "x86"
    assert img.bits == 32
    gadgets = scanner.scan_image(img, scanner.ScanOptions())
    assert len(gadgets) > 100
