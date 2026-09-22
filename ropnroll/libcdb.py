"""
libc identification via libc.rip -- turn "I leaked one function's address"
into "here is the exact libc build, every symbol offset, and a download
link" in one call, instead of manually diffing candidate offsets by hand.

No API key, no extra dependency (stdlib `urllib` only). This is a network
call to a third-party service; nothing here happens unless the caller
explicitly asks for identification.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

_FIND_URL = "https://libc.rip/api/find"
_TIMEOUT = 15


@dataclass
class LibcMatch:
    id: str
    buildid: str
    symbols: dict[str, int] = field(default_factory=dict)
    download_url: str = ""


def identify(symbol_offsets: dict[str, int]) -> list[LibcMatch]:
    """`symbol_offsets`: {"system": 0x58750, ...} -- offsets *from the
    library's own base*, i.e. leaked_addr - leaked_libc_base, not raw
    leaked addresses. Two or three symbols is usually enough to pin down
    an exact build; one symbol alone will often return many candidates.
    """
    payload = json.dumps({"symbols": {k: hex(v) for k, v in symbol_offsets.items()}}).encode()
    req = urllib.request.Request(_FIND_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError) as e:
        raise ConnectionError(f"couldn't reach libc.rip: {e}") from e
    return [
        LibcMatch(id=d.get("id", ""), buildid=d.get("buildid", ""),
                  symbols={k: int(v, 16) for k, v in d.get("symbols", {}).items()},
                  download_url=d.get("download_url", ""))
        for d in data
    ]


def download(match: LibcMatch, dest_path: str) -> str:
    if not match.download_url:
        raise ValueError(f"{match.id} has no download_url")
    urllib.request.urlretrieve(match.download_url, dest_path)
    return dest_path
