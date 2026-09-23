import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True, scope="session")
def _isolated_ropnroll_cache_dir(tmp_path_factory):
    """Every GadgetPool() in the test suite caches to disk by default (see
    core/cache.py); without this, running tests would read and write the
    developer's real ~/.cache/ropnroll instead of an isolated location."""
    os.environ["ROPNROLL_CACHE_DIR"] = str(tmp_path_factory.mktemp("ropnroll_cache"))


_NTDLL_CANDIDATES = [
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\SysWOW64\ntdll.dll",
]


@pytest.fixture(scope="session")
def ntdll_path() -> str:
    """A real, large, x86-64 PE with a genuine `syscall` instruction (its
    Zw*/Nt* wrappers) -- the Windows analog of using system libc for
    realistic large-binary gadget-scanning/semantics tests."""
    for c in _NTDLL_CANDIDATES:
        if Path(c).exists():
            return c
    pytest.skip("no ntdll.dll found")
