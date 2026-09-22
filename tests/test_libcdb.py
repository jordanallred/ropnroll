import pytest

from ropnroll import libcdb
from ropnroll.core import loader


def test_identifies_real_libc_build(libc_path):
    img = loader.load(libc_path)
    offsets = {name: img.symbols[name] for name in ("system", "read", "printf") if name in img.symbols}
    if len(offsets) < 3:
        pytest.skip("test libc is missing expected symbols")
    try:
        matches = libcdb.identify(offsets)
    except ConnectionError:
        pytest.skip("libc.rip unreachable from this environment")
    assert matches, "expected at least one match for a real, unmodified system libc"
    assert matches[0].symbols.get("system") == offsets["system"]
    assert "str_bin_sh" in matches[0].symbols
