"""Emit an assembled Chain in whatever form you actually need next."""
from __future__ import annotations

import json

from ..solve.chain import Chain


def to_pwntools(chain: Chain, var_name: str = "payload", pack_call: str = "p64") -> str:
    lines = [f"{var_name} = flat("]
    for w in chain.words:
        val = "0x%x" % w.value if w.value is not None else "0x4141414141414141  # UNFILLED"
        comment = w.label.replace("\n", " ")
        lines.append(f"    {val},  # {comment}")
    lines.append(")")
    return "\n".join(lines)


def to_raw(chain: Chain, little_endian: bool = True) -> bytes:
    return chain.to_bytes(little_endian=little_endian)


def to_c_array(chain: Chain, var_name: str = "payload", little_endian: bool = True) -> str:
    raw = chain.to_bytes(little_endian=little_endian)
    body = ", ".join(f"0x{b:02x}" for b in raw)
    return f"unsigned char {var_name}[{len(raw)}] = {{ {body} }};"

def to_json(chain: Chain) -> str:
    return json.dumps([{"value": w.value, "label": w.label} for w in chain.words], indent=2)


def stack_layout(chain: Chain, base_label: str = "rsp+") -> str:
    """ASCII stack-layout visualizer -- every slot, offset, and why it's
    there, so you can eyeball a chain before you ever fire it."""
    w = chain.ai.reg_width
    lines = [f"  offset   value{' ' * (w * 2 - 3)}  purpose",
             f"  ------   {'-' * (w * 2)}  -------"]
    for i, word in enumerate(chain.words):
        off = i * w
        val = f"0x{word.value:0{w * 2}x}" if word.value is not None else "?" * (w * 2)
        lines.append(f"  +0x{off:04x}  {val}  {word.label}")
    return "\n".join(lines)
