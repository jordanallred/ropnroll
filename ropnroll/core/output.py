"""Emit an assembled Chain in whatever form you actually need next.

A chain built against a module whose real runtime base isn't known yet
(no leak, no --base) carries symbolic (module, offset) words instead of
baked addresses -- see ChainWord in solve/chain.py. A chain can also carry
words the caller explicitly marked PLACEHOLDER (see solve/chain.py) --
values it intends to resolve itself outside ropnroll entirely, e.g. a
pointer relative to the payload's own stack position. Every emit format
below has to make a deliberate choice about what to do with both: pwntools
/json stay symbolic (that's the whole point -- the exported script/data
resolves them once *it* has a leak or has patched the placeholder in),
while raw/c_array need real bytes on disk and refuse rather than silently
write a dev-time placeholder address, or the PLACEHOLDER sentinel itself,
into what looks like a finished payload.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..solve.chain import Chain, ChainWord


def _base_var(module: str) -> str:
    """A stable, readable identifier for a module's leaked base, e.g.
    "C:\\Windows\\System32\\kernel32.dll" -> "kernel32_base"."""
    stem = Path(module).stem or "module"
    ident = re.sub(r"\W+", "_", stem).strip("_") or "module"
    if ident[0].isdigit():
        ident = f"_{ident}"
    return f"{ident.lower()}_base"


def unresolved_modules(chain: Chain) -> list[str]:
    """Distinct modules this chain still has symbolic words for, in the
    order they first appear -- what a caller needs a leak for before the
    chain can produce real bytes."""
    seen: list[str] = []
    for w in chain.words:
        if w.module is not None and w.module not in seen:
            seen.append(w.module)
    return seen


def has_placeholders(chain: Chain) -> bool:
    """Whether any word was explicitly marked PLACEHOLDER by the caller --
    a value it intends to resolve itself, that ropnroll never had any way
    to fill in (see PLACEHOLDER in solve/chain.py)."""
    return any(w.placeholder for w in chain.words)


def _word_expr(w: ChainWord) -> str:
    if w.placeholder:
        return "0x%x" % w.value  # the PLACEHOLDER constant itself -- see comment
    if w.module is not None and w.offset is not None:
        var = _base_var(w.module)
        sign = "+" if w.offset >= 0 else "-"
        return f"{var} {sign} 0x{abs(w.offset):x}"
    if w.value is not None:
        return "0x%x" % w.value
    return "0x4141414141414141  # UNFILLED"


def to_pwntools(chain: Chain, var_name: str = "payload", pack_call: str = "p64") -> str:
    lines = []
    unresolved = unresolved_modules(chain)
    for m in unresolved:
        lines.append(
            f"{_base_var(m)} = 0  # TODO: leaked runtime base of {Path(m).name}"
        )
    if unresolved:
        lines.append("")
    lines.append(f"{var_name} = flat(")
    for w in chain.words:
        comment = w.label.replace("\n", " ")
        if w.placeholder:
            comment = f"PLACEHOLDER -- resolve outside ropnroll: {comment}"
        lines.append(f"    {_word_expr(w)},  # {comment}")
    lines.append(")")
    return "\n".join(lines)


def to_raw(chain: Chain, little_endian: bool = True) -> bytes:
    unresolved = unresolved_modules(chain)
    if unresolved:
        raise ValueError(
            "chain has unresolved symbolic addresses for: "
            + ", ".join(unresolved)
            + " -- raw bytes would bake in a dev-time placeholder address, not the real "
            "runtime one. Pass --base <module>=0xADDR for each once you have a leak, "
            "or use --emit pwntools/json to keep the chain symbolic."
        )
    if has_placeholders(chain):
        raise ValueError(
            "chain has a PLACEHOLDER word (see solve/chain.py) -- raw bytes would bake "
            "in that sentinel instead of the real value you intend to resolve yourself. "
            "Patch it in after export, or use --emit pwntools/json to keep it symbolic."
        )
    return chain.to_bytes(little_endian=little_endian)


def to_c_array(
    chain: Chain, var_name: str = "payload", little_endian: bool = True
) -> str:
    raw = to_raw(chain, little_endian=little_endian)  # same guard applies here
    body = ", ".join(f"0x{b:02x}" for b in raw)
    return f"unsigned char {var_name}[{len(raw)}] = {{ {body} }};"


def to_json(chain: Chain) -> str:
    """`value` is null whenever `module`/`offset` are set, or the word is a
    caller-marked PLACEHOLDER: a consumer resolving those itself must not
    also see a number in `value` that looks like a real resolved value but
    isn't one -- see the ChainWord docstring in solve/chain.py. `value` is
    only ever a number for a word that's actually resolved (or a plain
    literal, e.g. a stack fill). `placeholder: true` marks a word the
    caller explicitly asked to resolve itself (PLACEHOLDER in
    solve/chain.py) -- distinct from `module`/`offset`, which ropnroll
    could resolve for you given a leak."""
    return json.dumps(
        [
            {
                "value": None if (w.module is not None or w.placeholder) else w.value,
                "label": w.label,
                "module": w.module,
                "offset": w.offset,
                "placeholder": w.placeholder,
            }
            for w in chain.words
        ],
        indent=2,
    )


def stack_layout(chain: Chain, base_label: str = "rsp+") -> str:
    """ASCII stack-layout visualizer -- every slot, offset, and why it's
    there, so you can eyeball a chain before you ever fire it."""
    w = chain.ai.reg_width

    def _val_str(word: ChainWord) -> str:
        if word.placeholder:
            return "PLACEHOLDER"
        if word.module is not None and word.offset is not None:
            return _word_expr(word)
        if word.value is not None:
            return f"0x{word.value:0{w * 2}x}"
        return "?" * (w * 2)

    vals = [_val_str(word) for word in chain.words]
    # a symbolic "module_base + 0xoffset" expression can run much longer
    # than a fixed-width hex word, so size the column off the actual
    # longest value in *this* chain rather than assuming raw hex width --
    # otherwise mixing a resolved and an unresolved module in one chain
    # (a common two-binary `call` target/gadget-source split) staggers
    # every row after the first long one.
    val_width = max([len("value")] + [len(v) for v in vals])
    lines = [
        f"  offset   {'value'.ljust(val_width)}  purpose",
        f"  ------   {'-' * val_width}  -------",
    ]
    for i, (word, val) in enumerate(zip(chain.words, vals)):
        off = i * w
        lines.append(f"  +0x{off:04x}  {val.ljust(val_width)}  {word.label}")
    return "\n".join(lines)
