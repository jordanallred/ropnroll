"""
Symbolic-ish effect summaries for gadgets.

Instead of hand-writing an IL/lifter for every instruction of every
architecture (what most gadget tools with "semantic search" do), ropnroll
*measures* each gadget's behaviour by running it for real in Unicorn with
several carefully chosen input vectors and fitting a small closed-form
relation (constant / copy / affine / bitwise) to each output register and
memory write. If a relation fits every trial it is exact -- not a guess --
because affine, xor, and mask relations are fully determined by 2-3 points
and we verify against every trial, including edge cases (0 and all-ones)
that would break a spurious fit.

Anything that doesn't reduce to one of these closed forms (data-dependent
control flow can't occur -- the scanner already excludes it -- but things
like multiplies of two *variable* registers, or flag-dependent instructions
we don't model, can) is recorded as UNKNOWN with one concrete sample so the
gadget is still visible, just not usable as an exact primitive.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class EKind(Enum):
    CONST = auto()     # dst = c
    COPY = auto()       # dst = src              (add/scale with k=1,c=0)
    ADD = auto()         # dst = src + c
    SCALE = auto()        # dst = src * k + c
    AND = auto()           # dst = src & c
    OR = auto()              # dst = src | c
    XOR = auto()               # dst = src ^ c
    LOAD = auto()                # dst = mem[src * k + c]   (memory read)
    UNKNOWN = auto()


@dataclass
class RegEffect:
    kind: EKind
    src: Optional[str] = None
    k: int = 1
    c: int = 0
    size: int = 8
    sample: Optional[int] = None

    def mask(self) -> int:
        return (1 << (self.size * 8)) - 1

    def to_dict(self) -> dict:
        return {"kind": self.kind.name, "src": self.src, "k": self.k, "c": self.c,
                "size": self.size, "sample": self.sample}

    @staticmethod
    def from_dict(d: dict) -> "RegEffect":
        return RegEffect(kind=EKind[d["kind"]], src=d["src"], k=d["k"], c=d["c"],
                          size=d["size"], sample=d["sample"])

    def value_given(self, src_val: int) -> Optional[int]:
        m = self.mask()
        if self.kind == EKind.CONST:
            return self.c & m
        if self.kind in (EKind.COPY, EKind.ADD, EKind.SCALE):
            return (src_val * self.k + self.c) & m
        if self.kind == EKind.AND:
            return (src_val & self.c) & m
        if self.kind == EKind.OR:
            return (src_val | self.c) & m
        if self.kind == EKind.XOR:
            return (src_val ^ self.c) & m
        return None

    def solve_for_target(self, target: int) -> Optional[int]:
        """Return the required *source* register value to make this effect
        produce `target`, or None if not exactly solvable."""
        m = self.mask()
        target &= m
        width_bits = self.size * 8
        if self.kind == EKind.CONST:
            return None  # no source needed; caller checks target == self.c separately
        if self.kind in (EKind.COPY, EKind.ADD, EKind.SCALE):
            if self.k == 1:
                return (target - self.c) & m
            if self.k % 2 == 1:  # odd k has a modular inverse mod 2^n
                inv = pow(self.k, -1, 1 << width_bits)
                return (inv * ((target - self.c) & m)) & m
            return None  # non-invertible scale (e.g. shl) -- not exactly solvable in general
        if self.kind == EKind.XOR:
            return (target ^ self.c) & m
        if self.kind == EKind.AND:
            if (target & ~self.c) & m == 0:
                return target
            return None
        if self.kind == EKind.OR:
            if (self.c & ~target) & m == 0:
                return target
            return None
        return None

    def describe(self, dst: str) -> str:
        if self.kind == EKind.CONST:
            return f"{dst} = 0x{self.c & self.mask():x}"
        if self.kind == EKind.COPY:
            return f"{dst} = {self.src}"
        if self.kind == EKind.ADD:
            sign = "+" if self.c >= 0 else "-"
            return f"{dst} = {self.src} {sign} 0x{abs(self.c):x}" if self.c else f"{dst} = {self.src}"
        if self.kind == EKind.SCALE:
            return f"{dst} = {self.src}*{self.k} + 0x{self.c & self.mask():x}"
        if self.kind == EKind.AND:
            return f"{dst} = {self.src} & 0x{self.c & self.mask():x}"
        if self.kind == EKind.OR:
            return f"{dst} = {self.src} | 0x{self.c & self.mask():x}"
        if self.kind == EKind.XOR:
            return f"{dst} = {self.src} ^ 0x{self.c & self.mask():x}"
        if self.kind == EKind.LOAD:
            off = f"+0x{self.c:x}" if self.c else ""
            return f"{dst} = [{self.src}{off}]"
        return f"{dst} = ? (sample=0x{self.sample:x})" if self.sample is not None else f"{dst} = ?"


@dataclass
class MemEffect:
    addr: RegEffect          # how the written/read address is derived from a GPR
    value: Optional[RegEffect]  # how the stored value is derived (None for reads)
    size: int
    is_write: bool

    def describe(self) -> str:
        a = self.addr.describe("addr").split("= ", 1)[1]
        if self.is_write:
            v = self.value.describe("val").split("= ", 1)[1] if self.value else "?"
            return f"*({a}) = {v}"
        return f"read *({a})"

    def to_dict(self) -> dict:
        return {"addr": self.addr.to_dict(), "value": self.value.to_dict() if self.value else None,
                "size": self.size, "is_write": self.is_write}

    @staticmethod
    def from_dict(d: dict) -> "MemEffect":
        return MemEffect(addr=RegEffect.from_dict(d["addr"]),
                          value=RegEffect.from_dict(d["value"]) if d["value"] else None,
                          size=d["size"], is_write=d["is_write"])


@dataclass
class GadgetEffect:
    reg_effects: dict[str, RegEffect] = field(default_factory=dict)
    mem_writes: list[MemEffect] = field(default_factory=list)
    mem_reads: list[MemEffect] = field(default_factory=list)
    sp_delta: Optional[int] = None       # net stack-pointer change, if constant
    ok: bool = True                      # emulation completed without a hard fault
    notes: str = ""

    def clobbers(self) -> set[str]:
        return set(self.reg_effects.keys())

    def sets_exactly(self, reg: str) -> bool:
        eff = self.reg_effects.get(reg)
        return eff is not None and eff.kind != EKind.UNKNOWN

    def to_dict(self) -> dict:
        return {
            "reg_effects": {r: e.to_dict() for r, e in self.reg_effects.items()},
            "mem_writes": [m.to_dict() for m in self.mem_writes],
            "mem_reads": [m.to_dict() for m in self.mem_reads],
            "sp_delta": self.sp_delta,
            "ok": self.ok,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(d: dict) -> "GadgetEffect":
        return GadgetEffect(
            reg_effects={r: RegEffect.from_dict(e) for r, e in d["reg_effects"].items()},
            mem_writes=[MemEffect.from_dict(m) for m in d["mem_writes"]],
            mem_reads=[MemEffect.from_dict(m) for m in d["mem_reads"]],
            sp_delta=d["sp_delta"], ok=d["ok"], notes=d["notes"],
        )
