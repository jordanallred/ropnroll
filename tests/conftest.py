import glob
import os
import subprocess
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

_LIBC_CANDIDATES = [
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib64/libc.so.6",
]


@pytest.fixture(scope="session")
def libc_path() -> str:
    for c in _LIBC_CANDIDATES:
        if Path(c).exists():
            return c
    found = glob.glob("/lib/**/libc.so.6", recursive=True) or glob.glob("/usr/lib/**/libc.so.6", recursive=True)
    if found:
        return found[0]
    pytest.skip("no system libc.so.6 found")


@pytest.fixture(scope="session")
def vuln_nopie(tmp_path_factory) -> str:
    src = Path(__file__).resolve().parent / "fixtures" / "vuln.c"
    out = tmp_path_factory.mktemp("bin") / "vuln_nopie"
    try:
        subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-o", str(out), str(src)],
                        check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        pytest.skip(f"gcc unavailable or failed: {e}")
    return str(out)
