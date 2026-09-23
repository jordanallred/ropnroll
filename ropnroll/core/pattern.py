"""Cyclic pattern generation and crash-offset lookup -- the same tool as
Metasploit's pattern_create.rb/pattern_offset.rb or mona's `!mona pc`/`!mona
po`. Architecture- and binary-independent, and usually the very first thing
run in a stack-overflow exploit session: send `create`'s output as the
crash input, then feed whatever value a debugger shows in the clobbered
register (EIP/RIP, or any other) to `offset` to get back exactly how many
bytes of padding precede the data you control.
"""

from __future__ import annotations

import string

_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase
_DIGITS = string.digits

# 26 * 26 * 10 combinations, 3 bytes each -- the pattern repeats after this
# many bytes, same limit Metasploit/mona have. Long enough for any
# realistic stack/buffer overflow; `offset` only searches this first
# period because a match past it is inherently ambiguous.
PERIOD = len(_UPPER) * len(_LOWER) * len(_DIGITS) * 3


def create(length: int) -> bytes:
    """A `length`-byte buffer where every 3-byte window is unique for the
    first PERIOD bytes. Beyond that it wraps and repeats."""
    if length < 0:
        raise ValueError("length must be >= 0")
    out = bytearray()
    i = 0
    while len(out) < length:
        idx = i % (len(_UPPER) * len(_LOWER) * len(_DIGITS))
        u = _UPPER[idx // (len(_LOWER) * len(_DIGITS))]
        l = _LOWER[(idx // len(_DIGITS)) % len(_LOWER)]
        d = _DIGITS[idx % len(_DIGITS)]
        out += f"{u}{l}{d}".encode("ascii")
        i += 1
    return bytes(out[:length])


def _parse_needle(value: str, width: int | None, literal: bool) -> bytes:
    """By default `value` is the *integer* a debugger showed for a
    clobbered register -- packed little-endian, matching how those bytes
    actually sat in memory before being loaded. With `literal=True` it's
    instead a pattern substring (e.g. copied straight out of a memory
    dump) and matched as-is.

    Deliberately not auto-detected: the pattern's own alphabet includes
    a-f/A-F, so a perfectly ordinary substring like "6Ab7Ab" is *also*
    valid hex -- there is no reliable way to tell the two apart, so the
    caller has to say which one this is.
    """
    text = value.strip()
    if literal:
        return text.encode("latin-1")
    hexdigits = text[2:] if text.lower().startswith("0x") else text
    if not hexdigits or any(c not in string.hexdigits for c in hexdigits):
        raise ValueError(f"{value!r} is not a valid hex value -- pass literal=True "
                          f"to look it up as a literal pattern substring instead")
    if len(hexdigits) % 2 == 1:
        hexdigits = "0" + hexdigits
    n = int(hexdigits, 16)
    w = width or max(1, len(hexdigits) // 2)
    return n.to_bytes(w, "little")


def offset(value: str, width: int | None = None, literal: bool = False) -> int | None:
    """Byte offset of `value` within the first period of the cyclic
    pattern, or None if it doesn't appear there. Raises ValueError if
    `value` isn't valid hex and `literal` wasn't set."""
    needle = _parse_needle(value, width, literal)
    if not needle:
        return None
    haystack = create(PERIOD)
    idx = haystack.find(needle)
    return idx if idx >= 0 else None
