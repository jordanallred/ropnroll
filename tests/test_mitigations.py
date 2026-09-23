"""Regression tests for PE security-mitigation detection.

Three PE-specific signals matter to a ROP/JOP tool and are easy to get wrong:

* the /GS stack canary -- MSVC-linked PEs are almost always stripped of the
  COFF symbol table, so detection must fall back to the load configuration's
  SecurityCookie rather than __security_check_cookie / __stack_chk_fail symbols;
* XFG (eXtended Flow Guard) -- also sets GUARD_CF, so it is only distinguishable
  via the XFG_ENABLED guard flag and must not be reported as plain CFG;
* CET / hardware shadow stack (/CETCOMPAT) -- signalled by an extended-DLL-
  characteristics debug directory entry, wholly separate from the optional
  header's DllCharacteristics.

No MSVC toolchain with /guard:xfg or /CETCOMPAT is available in this
environment, so the positive fixtures for those two are synthesized from the
committed, stripped cli-64.exe: XFG by setting the flags through LIEF, CET by
repurposing the lone debug directory entry. Both are parsed back through the
same loader.load() path as everything else.
"""
import struct

import lief
import pytest

from ropnroll.core import loader, security, scanner

CLI64 = "tests/fixtures/pe/cli-64.exe"
CLI32 = "tests/fixtures/pe/cli-32.exe"


# --------------------------------------------------------------------------- #
# stack canary                                                                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", [CLI64, CLI32])
def test_canary_detected_via_load_config(path):
    b = lief.parse(path)
    # Precondition: the fixture is stripped, so the symbol-based check alone
    # would report no canary -- guards against a fixture that stops exercising
    # the load-config fallback.
    assert [s.name for s in b.symbols] == []
    assert b.has_configuration and b.load_configuration.security_cookie != 0

    img = loader.load(path)
    assert img.mitigations["canary"] is True


# --------------------------------------------------------------------------- #
# CET / XFG negative cases (stock fixtures have neither)                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", [CLI64, CLI32])
def test_cet_and_xfg_absent_by_default(path):
    img = loader.load(path)
    assert img.mitigations["cet"] is False
    assert img.mitigations["xfg"] is False


# --------------------------------------------------------------------------- #
# XFG positive case                                                           #
# --------------------------------------------------------------------------- #
@pytest.fixture
def xfg_pe(tmp_path):
    """cli-64.exe with GUARD_CF + XFG_ENABLED set through LIEF."""
    b = lief.parse(CLI64)
    oh = b.optional_header
    oh.dll_characteristics = (oh.dll_characteristics
                              | int(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.GUARD_CF))
    lc = b.load_configuration
    lc.guard_flags = int(lc.guard_flags) | int(lief.PE.LoadConfiguration.IMAGE_GUARD.XFG_ENABLED)
    out = tmp_path / "xfg-64.exe"
    b.write(str(out))
    return str(out)


def test_xfg_detected_and_distinct_from_cfg(xfg_pe):
    img = loader.load(xfg_pe)
    assert img.mitigations["xfg"] is True
    assert img.mitigations["cfg"] is True   # XFG also sets GUARD_CF

    report = security.build_report(img, scanner.scan_image(img, scanner.ScanOptions(max_insns=4)))
    cfg_line = {label: value for label, value, _ in report.lines}["Control Flow Guard"]
    assert "XFG" in cfg_line


# --------------------------------------------------------------------------- #
# CET positive case                                                           #
# --------------------------------------------------------------------------- #
@pytest.fixture
def cet_pe(tmp_path):
    """cli-64.exe with its sole debug directory entry repurposed into an
    EX_DLLCHARACTERISTICS entry whose payload sets CET_COMPAT."""
    d = bytearray(open(CLI64, "rb").read())
    pe = struct.unpack_from("<I", d, 0x3c)[0]
    coff = pe + 4
    nsec = struct.unpack_from("<H", d, coff + 2)[0]
    optsz = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    sec = opt + optsz

    def rva2off(rva):
        for i in range(nsec):
            b = sec + i * 40
            va = struct.unpack_from("<I", d, b + 12)[0]
            rawsz = struct.unpack_from("<I", d, b + 16)[0]
            rawptr = struct.unpack_from("<I", d, b + 20)[0]
            if va <= rva < va + rawsz:
                return rawptr + (rva - va)
        raise AssertionError("rva not mapped")

    datadir = opt + 0x6c + 4                 # after NumberOfRvaAndSizes
    dbg_rva, dbg_sz = struct.unpack_from("<II", d, datadir + 6 * 8)   # dir index 6 = debug
    assert dbg_sz >= 28, "fixture has no debug directory entry to repurpose"
    e = rva2off(dbg_rva)
    rawptr = struct.unpack_from("<I", d, e + 24)[0]
    struct.pack_into("<I", d, e + 12, 20)    # Type = IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
    struct.pack_into("<I", d, e + 16, 4)     # SizeOfData = 4
    struct.pack_into("<I", d, rawptr, 1)     # payload = CET_COMPAT (0x1)
    out = tmp_path / "cet-64.exe"
    out.write_bytes(d)
    return str(out)


def test_cet_detected(cet_pe):
    img = loader.load(cet_pe)
    assert img.mitigations["cet"] is True

    report = security.build_report(img, scanner.scan_image(img, scanner.ScanOptions(max_insns=4)))
    lines = {label: value for label, value, _ in report.lines}
    assert "ENABLED" in lines["CET shadow stack (/CETCOMPAT)"]
