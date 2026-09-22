import pytest

from ropnroll.cli.main import _load_pool, _parse_base_overrides
from ropnroll.core import loader, scanner


def test_parse_base_overrides_basic():
    assert _parse_base_overrides(["a.dll=0x140000000", "b.dll=0x7ffb00000000"]) == {
        "a.dll": 0x140000000, "b.dll": 0x7ffb00000000,
    }


def test_parse_base_overrides_none_and_empty():
    assert _parse_base_overrides(None) == {}
    assert _parse_base_overrides([]) == {}


def test_parse_base_overrides_rejects_missing_address():
    with pytest.raises(ValueError):
        _parse_base_overrides(["a.dll"])


def test_load_pool_rebase_shifts_gadget_addresses():
    path = "tests/fixtures/pe/cli-64.exe"
    img = loader.load(path)
    old_base = img.image_base
    new_base = 0x7FFB00000000
    delta = new_base - old_base

    baseline, _ = _load_pool([path], scanner.ScanOptions(), use_cache=False)
    rebased, images = _load_pool([path], scanner.ScanOptions(), use_cache=False,
                                  base=[f"{path}={hex(new_base)}"])

    assert images[0].image_base == new_base
    baseline_addrs = sorted(g.address for g in baseline.all())
    rebased_addrs = sorted(g.address for g in rebased.all())
    assert baseline_addrs
    assert [a + delta for a in baseline_addrs] == rebased_addrs
