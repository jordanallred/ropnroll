import keystone

from ropnroll.core import loader, scanner
from ropnroll.solve import jop
from ropnroll.solve.pool import GadgetPool
from tests.helpers import write_minimal_pe


def _dispatcher_pool(tmp_path):
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    def asm(s):
        enc, _ = ks.asm(s)
        return bytes(enc)

    # self-advancing dispatcher: bumps rbx by 8, then jumps through it --
    # exactly the "<advance dispatch-reg> ; jmp [dispatch-reg]" shape
    # find_dispatchers looks for.
    code = asm("add rbx, 8; jmp qword ptr [rbx]")
    path = str(tmp_path / "dispatcher.exe")
    write_minimal_pe(path, "x86_64", code, base=0x400000)

    img = loader.load(path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=6))
    pool = GadgetPool(use_cache=False)
    pool.add(img, gadgets)
    return pool, img


def test_find_dispatchers_baseline(tmp_path):
    # the x86 byte-level scanner also turns up longer "unintended" variants
    # that happen to land on the same jmp (e.g. with junk bytes decoded as a
    # leading no-op-ish instruction); sorted shortest-first, our exact
    # 2-instruction gadget should be the first result.
    pool, img = _dispatcher_pool(tmp_path)
    disp = jop.find_dispatchers(pool)
    assert len(disp) >= 1
    assert disp[0].reg == "rbx"
    assert disp[0].advance == 8
    assert disp[0].gadget.n_insns == 2


def test_find_dispatchers_excludes_cfg_invalid(tmp_path):
    pool, img = _dispatcher_pool(tmp_path)
    dispatcher_addr = jop.find_dispatchers(pool)[0].gadget.address

    img.mitigations["cfg"] = True
    img.cfg_valid_targets = {dispatcher_addr + 0x1000}  # deliberately excludes the real dispatcher
    assert jop.find_dispatchers(pool, img=img) == []

    img.cfg_valid_targets = {dispatcher_addr}
    disp = jop.find_dispatchers(pool, img=img)
    assert len(disp) == 1 and disp[0].gadget.address == dispatcher_addr


def test_find_dispatchers_excludes_cet_invalid(tmp_path):
    """Regression: _cet_ok existed but was never wired into find_dispatchers'
    filter, so a CET-IBT target that must land on `endbr*` was never
    actually excluded despite the module's own docstring claiming it was."""
    pool, img = _dispatcher_pool(tmp_path)
    img.mitigations["endbr_required"] = True
    # our dispatcher's gadget text starts with "add rbx, 8", not "endbr..."
    assert jop.find_dispatchers(pool, img=img) == []


def test_build_trampoline_reports_cfg_invalid_functional_targets(tmp_path):
    """Regression: build_trampoline never validated functional_targets against
    CFG/CET at all, despite the module docstring claiming both dispatcher
    *and* functional-gadget candidates are filtered."""
    pool, img = _dispatcher_pool(tmp_path)
    dispatcher = jop.find_dispatchers(pool)[0]

    img.mitigations["cfg"] = True
    img.cfg_valid_targets = {dispatcher.gadget.address}  # only the dispatcher itself is valid
    bad_addr = dispatcher.gadget.address + 0x2000

    tramp = jop.build_trampoline(pool, dispatcher, [dispatcher.gadget.address, bad_addr],
                                  table_addr=0x500000, img=img)
    assert any(f"0x{bad_addr:x}" in w for w in tramp.warnings)
    assert not any(f"0x{dispatcher.gadget.address:x}" in w for w in tramp.warnings)


def test_build_trampoline_no_img_no_warnings(tmp_path):
    """Without an Image, build_trampoline can't validate anything -- it
    should behave exactly as before (no warnings field surprises)."""
    pool, img = _dispatcher_pool(tmp_path)
    dispatcher = jop.find_dispatchers(pool)[0]
    tramp = jop.build_trampoline(pool, dispatcher, [dispatcher.gadget.address], table_addr=0x500000)
    assert tramp.warnings == []
