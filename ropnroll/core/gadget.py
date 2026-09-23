"""Core gadget representation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class Terminator(Enum):
    RET = auto()
    RET_IMM = auto()
    JMP_REG = auto()
    CALL_REG = auto()
    JMP_MEM = auto()
    CALL_MEM = auto()
    SYSCALL = auto()
    OTHER = auto()


@dataclass
class Gadget:
    address: int
    raw: bytes
    text: str  # "pop rdi ; ret"
    insns: list  # list of capstone CsInsn (kept for semantic lifting)
    terminator: Terminator
    module: str = ""  # which Image/module this came from (for multi-binary pools)

    @property
    def size(self) -> int:
        return len(self.raw)

    @property
    def n_insns(self) -> int:
        return len(self.insns)

    def __hash__(self):
        return hash((self.module, self.address))

    def __repr__(self):
        return f"<Gadget {self.module + '!' if self.module else ''}0x{self.address:x}: {self.text}>"
