"""Bad-character avoidance for chain payloads.

Distinct from `ScanOptions.bad_bytes` (scanner.py), which filters a
gadget's own *instruction encoding* at its fixed location in the binary --
irrelevant to whether a chain actually works, since those bytes are never
part of the attacker-controlled buffer. What actually breaks a real
exploit is a byte value that the delivery path (strcpy, a URL-decoder, a
size-prefixed-but-still-byte-sensitive parser, ...) treats specially --
and that only ever touches the *payload*: the gadget addresses, call
targets, and literal argument words a Chain writes into memory. This
module covers that: excluding gadgets whose own address is unusable from
candidate search, and flagging any payload word that still isn't clean
(typically a target address or literal argument the caller supplied
directly, which no alternate gadget choice can fix).
"""

from __future__ import annotations

import string

_HEX_DIGITS = set(string.hexdigits)


def parse_bad_chars(spec: str | None) -> frozenset[int]:
    """Accepts a hex byte spec with optional separators/escapes, e.g.
    "000a0d", "00,0a,0d", "00 0a 0d", or "\\x00\\x0a\\x0d"."""
    if not spec:
        return frozenset()
    cleaned = spec.replace("\\x", "").replace("0x", "")
    for sep in (",", " ", "-", ":"):
        cleaned = cleaned.replace(sep, "")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"bad-chars hex string has odd length: {spec!r}")
    try:
        return frozenset(bytes.fromhex(cleaned))
    except ValueError as e:
        raise ValueError(f"invalid bad-chars hex string {spec!r}: {e}") from e


def value_bad_bytes(
    value: int, width: int, bad: frozenset[int], little_endian: bool = True
) -> list[int]:
    """Which bytes of `bad` actually occur in `value`'s `width`-byte
    encoding, in the order they appear."""
    if not bad:
        return []
    mask = (1 << (width * 8)) - 1
    raw = (value & mask).to_bytes(width, "little" if little_endian else "big")
    seen = []
    for b in raw:
        if b in bad and b not in seen:
            seen.append(b)
    return seen


def has_bad_bytes(
    value: int, width: int, bad: frozenset[int], little_endian: bool = True
) -> bool:
    return bool(value_bad_bytes(value, width, bad, little_endian))


def chain_bad_char_warnings(chain, bad: frozenset[int]) -> list[str]:
    """Sweep every resolved word of an already-built Chain for bad bytes.
    Gadget addresses shouldn't turn any of these up (the solver excludes
    them from candidate search up front -- see GadgetPool.bad_chars), so a
    hit here is almost always a literal the caller supplied directly (a
    call target or argument), which needs a different value, not a
    different gadget."""
    if not bad:
        return []
    width = chain.ai.reg_width
    out = []
    for i, w in enumerate(chain.words):
        if w.value is None or w.module is not None:
            continue  # unresolved/symbolic word -- nothing concrete to check yet
        hits = value_bad_bytes(w.value, width, bad)
        if hits:
            hit_str = ", ".join(f"0x{b:02x}" for b in hits)
            out.append(
                f"+0x{i * width:04x}  0x{w.value:x} ({w.label}) contains bad byte(s) {hit_str}"
            )
    return out
