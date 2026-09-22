"""
Unicorn-backed semantic engine.

Runs each gadget for real on an emulated CPU with several input vectors and
fits closed-form relations to the outputs (see effect.py for why). Because
this works off real CPU emulation rather than a hand-written IL, it is
correct-by-construction for every architecture Unicorn supports, including
flag/quirk behaviour we would otherwise have to model by hand.

Trial design, per gadget:
  * every register the gadget *reads* gets a "role":
      - 'sp'      -> the stack pointer; varied within the pre-mapped stack
                      region only (must always hold a valid address).
      - 'pointer' -> used as a memory base/index somewhere in the gadget;
                      given its own scratch lane so dereferences don't fault.
      - 'data'    -> pure value register; varied over a basis designed to
                      reveal copy / add / and / or / xor / scale relations.
  * for each candidate source register we run K trials that vary *only*
    that register (others held at a fixed baseline) and fit every output
    register + every memory write against it. First candidate that fits
    every trial wins; ties basically never happen because the basis
    includes 0 and all-ones, which pin down masks/consts uniquely.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import capstone as cs
import unicorn as uc

from ..core.archinfo import ArchInfo
from ..core.cache import EffectDiskCache
from ..core.gadget import Gadget
from ..core.loader import Image
from .effect import EKind, GadgetEffect, MemEffect, RegEffect

_MEM_OP_TYPE = {
    cs.CS_ARCH_X86: cs.x86.X86_OP_MEM,
    cs.CS_ARCH_ARM: cs.arm.ARM_OP_MEM,
    cs.CS_ARCH_ARM64: cs.arm64.ARM64_OP_MEM,
    cs.CS_ARCH_MIPS: cs.mips.MIPS_OP_MEM,
}


def _build_x86_subreg_map(bits: int) -> dict[str, str]:
    """Capstone reports whatever *sub*-register width an instruction
    actually touches (e.g. `xor eax, eax` reports EAX, not RAX). We need
    everything normalized to the architecture's canonical GPR name so a
    32-bit write is recognized as affecting the register we track."""
    groups64 = [
        ("rax", "eax", "ax", "al", "ah"), ("rbx", "ebx", "bx", "bl", "bh"),
        ("rcx", "ecx", "cx", "cl", "ch"), ("rdx", "edx", "dx", "dl", "dh"),
        ("rsi", "esi", "si", "sil", None), ("rdi", "edi", "di", "dil", None),
        ("rbp", "ebp", "bp", "bpl", None), ("rsp", "esp", "sp", "spl", None),
    ]
    groups32 = [(g[1], g[2], g[3], g[4]) for g in groups64]  # target = 32-bit form
    m: dict[str, str] = {}
    if bits == 64:
        for full, d32, d16, d8, d8h in groups64:
            for alt in (d32, d16, d8, d8h):
                if alt:
                    m[alt] = full
        for i in range(8, 16):
            full = f"r{i}"
            for suf in (f"r{i}d", f"r{i}w", f"r{i}b"):
                m[suf] = full
    else:
        for target, d16, d8, d8h in groups32:
            for alt in (d16, d8, d8h):
                if alt:
                    m[alt] = target
    return m


def _x86_reg_write_width(raw_name: str, bits: int) -> int:
    """Bytes actually written by a raw (un-normalized) x86 register name.

    A 32-bit write on x86-64 (e.g. `inc eax`) zero-extends and replaces the
    full 64-bit register; a 16/8-bit write merges into the existing value.
    We only need to get the *replacing* (32-bit on x86-64, native on x86)
    case exactly right -- it's the overwhelming majority of real gadgets --
    and conservatively fall back to full width otherwise (which just means
    those rarer 8/16-bit-only gadgets won't fit an exact relation and show
    up as UNKNOWN instead of something subtly wrong).
    """
    if bits != 64:
        return 4
    if raw_name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp") or \
            raw_name in (f"r{i}" for i in range(8, 16)):
        return 8
    if raw_name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp") or \
            raw_name in (f"r{i}d" for i in range(8, 16)):
        return 4
    return 8  # 16/8-bit sub-write: treat conservatively as full-width (merge, not replace)

_K_DATA_BASIS_TEMPLATE = [0x0, "ALLONES", 0x1111111111111111, 0x5A5A5A5A5A5A5A5A,
                          0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF]

STACK_SIZE = 0x8000
SCRATCH_LANE_SIZE = 0x1000
MAX_SCRATCH_LANES = 16

# Bumped whenever the trial/fitting logic below changes semantics, so a
# persisted EffectDiskCache from an older version is treated as cold instead
# of silently serving stale results (see core/cache.py).
SEMANTIC_ENGINE_VERSION = 1


def _align_down(x, a):
    return x & ~(a - 1)


def _fill_pattern(size: int) -> bytes:
    """Address-dependent (non-constant) filler for scratch/stack memory.

    Uniform zero-fill makes every memory read look identical regardless of
    address, which breaks the LOAD-effect detector's ability to tell *which*
    read actually feeds a destination register (see SemanticEngine.compute).
    A byte value that depends on its own offset fixes that for free.
    """
    return bytes(((i * 2654435761) >> 24) & 0xFF for i in range(size))


class SemanticEngine:
    def __init__(self, img: Image, ai: ArchInfo, disk_cache: Optional[EffectDiskCache] = None):
        self.img = img
        self.ai = ai
        self.width_bytes = ai.reg_width
        self.mask = (1 << (self.width_bytes * 8)) - 1
        self._cache: dict[bytes, GadgetEffect] = {}
        self._disk_cache = disk_cache
        self._subreg_map = _build_x86_subreg_map(ai.bits) if ai.cs_arch == cs.CS_ARCH_X86 else {}
        self.mu = uc.Uc(ai.uc_arch, ai.uc_mode)
        self._map_image()
        self._map_scratch()

    # ---- one-time memory setup -------------------------------------
    def _map_image(self):
        for seg in self.img.segments:
            base = _align_down(seg.vaddr, 0x1000)
            end = (seg.vaddr + seg.size + 0xFFF) & ~0xFFF
            size = end - base
            try:
                self.mu.mem_map(base, size)
            except uc.UcError:
                continue  # already mapped (overlapping segments)
            pad = seg.vaddr - base
            buf = bytearray(size)
            buf[pad:pad + seg.size] = seg.data
            self.mu.mem_write(base, bytes(buf))

    def _pick_free_region(self, size: int) -> int:
        candidates = [0x0000_7A00_0000_0000, 0x0000_6A00_0000_0000, 0x0000_5A00_0000_0000,
                      0x2000_0000, 0x6000_0000]
        occupied = [(_align_down(s.vaddr, 0x1000), (s.vaddr + s.size + 0xFFF) & ~0xFFF)
                    for s in self.img.segments]
        for c in candidates:
            if all(c + size <= lo or c >= hi for lo, hi in occupied):
                return c
        return candidates[0]

    def _map_scratch(self):
        stack_size = (STACK_SIZE + 0xFFF) & ~0xFFF
        self.stack_base = self._pick_free_region(stack_size)
        self.mu.mem_map(self.stack_base, stack_size)
        self.mu.mem_write(self.stack_base, _fill_pattern(stack_size))
        self.stack_mid = self.stack_base + stack_size // 2

        scratch_size = MAX_SCRATCH_LANES * SCRATCH_LANE_SIZE
        self.scratch_base = self._pick_free_region(scratch_size)
        if self.scratch_base == self.stack_base:
            self.scratch_base += stack_size + 0x10000
        self.mu.mem_map(self.scratch_base, scratch_size)
        self.mu.mem_write(self.scratch_base, _fill_pattern(scratch_size))

    def _lane(self, index: int) -> int:
        return self.scratch_base + (index % MAX_SCRATCH_LANES) * SCRATCH_LANE_SIZE + SCRATCH_LANE_SIZE // 2

    # ---- register role classification --------------------------------
    def _reg_name(self, insn, reg_id) -> Optional[str]:
        try:
            name = insn.reg_name(reg_id)
        except Exception:
            return None
        if not name:
            return None
        name = name.lower()
        return self._subreg_map.get(name, name)

    def _classify_gadget_regs(self, gadget: Gadget):
        read_regs: set[str] = set()
        written_regs: set[str] = set()
        pointer_regs: set[str] = set()
        write_width: dict[str, int] = {}
        gpr_set = set(self.ai.gpr) | {self.ai.sp_reg}
        is_x86 = self.ai.cs_arch == cs.CS_ARCH_X86

        for insn in gadget.insns:
            try:
                regs_read, regs_written = insn.regs_access()
            except Exception:
                regs_read, regs_written = [], []
            for r in regs_read:
                n = self._reg_name(insn, r)
                if n in gpr_set:
                    read_regs.add(n)
            for r in regs_written:
                n = self._reg_name(insn, r)
                if n in gpr_set:
                    written_regs.add(n)
                    if is_x86:
                        raw = (insn.reg_name(r) or "").lower()
                        write_width[n] = _x86_reg_write_width(raw, self.ai.bits)
            mem_type = _MEM_OP_TYPE.get(self.ai.cs_arch)
            for op in getattr(insn, "operands", []):
                mem = op.mem if (mem_type is not None and op.type == mem_type) else None
                if mem is not None:
                    for fld in ("base", "index"):
                        rid = getattr(mem, fld, 0)
                        if rid:
                            n = self._reg_name(insn, rid)
                            if n and n in gpr_set:
                                pointer_regs.add(n)
                                read_regs.add(n)
        written_regs.add(self.ai.sp_reg)
        read_regs.add(self.ai.sp_reg)
        pointer_regs.add(self.ai.sp_reg)
        write_width.setdefault(self.ai.sp_reg, self.width_bytes)
        return read_regs, written_regs, pointer_regs, write_width

    # ---- trial execution ----------------------------------------------
    def _basis_for(self, role: str, lane_index: int, variant: int) -> int:
        if role == "sp":
            return self.stack_mid + (variant * 8)
        if role == "pointer":
            return self._lane(lane_index) + (variant * 8)
        v = _K_DATA_BASIS_TEMPLATE[variant % len(_K_DATA_BASIS_TEMPLATE)]
        return self.mask if v == "ALLONES" else (v & self.mask)

    def _run_trial(self, gadget: Gadget, roles: dict[str, str], lane_of: dict[str, int],
                    varied_reg: Optional[str], variant: int, n_trials: int):
        ai = self.ai
        for reg, role in roles.items():
            if reg == varied_reg:
                val = self._basis_for(role, lane_of.get(reg, 0), variant)
            else:
                # fixed, distinguishable baseline per register/role
                val = self._basis_for(role, lane_of.get(reg, 0), 1)
            const = ai.uc_reg_const.get(reg)
            if const is not None:
                self.mu.reg_write(const, val & self.mask)

        sp_val = self._basis_for("sp", 0, 1) if varied_reg != ai.sp_reg else \
            self._basis_for("sp", 0, variant)
        self.mu.reg_write(ai.uc_reg_const[ai.sp_reg], sp_val)

        writes: list[tuple[int, int, int]] = []   # (addr, size, value)
        reads: list[tuple[int, int, int]] = []

        byteorder = "little" if self.img.little_endian else "big"

        def on_write(mu, access, address, size, value, ud):
            writes.append((address, size, value & ((1 << (8 * size)) - 1)))

        def on_read(mu, access, address, size, value, ud):
            # UC_HOOK_MEM_READ_AFTER is unsupported by this unicorn build, so
            # we hook the pre-read event and fetch the value ourselves --
            # memory hasn't changed by the time the instruction reads it.
            try:
                raw = mu.mem_read(address, size)
                reads.append((address, size, int.from_bytes(raw, byteorder)))
            except uc.UcError:
                pass

        h1 = self.mu.hook_add(uc.UC_HOOK_MEM_WRITE, on_write)
        h2 = self.mu.hook_add(uc.UC_HOOK_MEM_READ, on_read)

        # UC_HOOK_CODE fires *before* each instruction, so stopping as soon
        # as the counter reaches the gadget's instruction count would cut
        # off the terminator (ret/jmp/call) itself before it runs. Instead
        # we let it retire -- its effects (rsp pop, register writes) land
        # correctly -- and only emu_stop() once we're asked to fetch *past*
        # it. That next fetch almost always targets a bogus popped address
        # and raises UC_ERR_FETCH_*, which is the expected, benign way this
        # single-gadget sandbox run ends, not a real failure.
        budget = max(1, len(gadget.insns))
        executed = [0]

        def on_code(mu, address, size, ud):
            executed[0] += 1
            if executed[0] > budget:
                mu.emu_stop()

        h3 = self.mu.hook_add(uc.UC_HOOK_CODE, on_code)
        ok = True
        try:
            self.mu.emu_start(gadget.address, 0, timeout=200_000)
        except uc.UcError as e:
            benign = e.errno in (uc.UC_ERR_FETCH_UNMAPPED, uc.UC_ERR_FETCH_PROT,
                                  uc.UC_ERR_INSN_INVALID, uc.UC_ERR_EXCEPTION)
            ok = benign and executed[0] >= budget
        finally:
            self.mu.hook_del(h1)
            self.mu.hook_del(h2)
            self.mu.hook_del(h3)

        finals = {}
        if ok:
            for reg in roles:
                const = ai.uc_reg_const.get(reg)
                if const is not None:
                    finals[reg] = self.mu.reg_read(const) & self.mask
        return ok, finals, writes, reads

    # ---- affine fitting -------------------------------------------------
    @staticmethod
    def _fit(points: list[tuple[int, int]], width_bytes: int) -> Optional[tuple[EKind, int, int]]:
        """points = [(src_val, out_val), ...] -> (kind, k, c) or None."""
        if len(points) < 2:
            return None
        m = (1 << (width_bytes * 8)) - 1
        outs = {o for _, o in points}
        if len(outs) == 1:
            return EKind.CONST, 1, next(iter(outs))
        deltas = {((o - s) & m) for s, o in points}
        if len(deltas) == 1:
            d = next(iter(deltas))
            return (EKind.COPY if d == 0 else EKind.ADD), 1, d
        xors = {((o ^ s) & m) for s, o in points}
        if len(xors) == 1:
            return EKind.XOR, 1, next(iter(xors))
        ones = [o for s, o in points if s == m]
        if ones and all(o == (s & ones[0]) for s, o in points):
            return EKind.AND, 1, ones[0]
        zeros = [o for s, o in points if s == 0]
        if zeros and all(o == (s | zeros[0]) for s, o in points):
            return EKind.OR, 1, zeros[0]
        for k in (2, 3, 4, 5, 8, 9, -1, -2, -8):
            s0, o0 = points[0]
            c = (o0 - k * s0) & m
            if all(((k * s + c) & m) == o for s, o in points):
                return EKind.SCALE, k, c
        return None

    def _store(self, gadget: Gadget, eff: GadgetEffect) -> GadgetEffect:
        self._cache[gadget.raw] = eff
        if self._disk_cache is not None:
            self._disk_cache.put(gadget.raw, eff)
        return eff

    def compute(self, gadget: Gadget) -> GadgetEffect:
        cached = self._cache.get(gadget.raw)
        if cached is not None:
            return cached
        if self._disk_cache is not None:
            cached = self._disk_cache.get(gadget.raw)
            if cached is not None:
                self._cache[gadget.raw] = cached
                return cached

        read_regs, written_regs, pointer_regs, write_width = self._classify_gadget_regs(gadget)
        roles = {}
        lane_of = {}
        li = 0
        for r in read_regs | written_regs:
            if r == self.ai.sp_reg:
                roles[r] = "sp"
            elif r in pointer_regs:
                roles[r] = "pointer"
                lane_of[r] = li
                li += 1
            else:
                roles[r] = "data"

        n_variants = len(_K_DATA_BASIS_TEMPLATE)
        # deterministic order: when a tie between candidate source
        # registers is possible, iterating a set here would let Python's
        # per-process string-hash randomization silently pick a different
        # (still-correct, but different) attribution between runs.
        candidates = sorted(read_regs)

        # baseline trial (variant=1 for everyone) establishes fault-free sanity
        base_ok, base_finals, base_writes, base_reads = self._run_trial(
            gadget, roles, lane_of, varied_reg=None, variant=1, n_trials=1)

        if not base_ok:
            return self._store(gadget, GadgetEffect(ok=False, notes="baseline emulation faulted"))

        initial_sp = self._basis_for("sp", 0, 1)  # baseline trials use variant=1 for fixed regs
        sp_delta = base_finals.get(self.ai.sp_reg, 0) - initial_sp

        per_candidate_trials: dict[str, list[tuple[int, dict, list, list]]] = {}
        for cand in candidates:
            trials = []
            for variant in range(n_variants):
                src_val = self._basis_for(roles[cand], lane_of.get(cand, 0), variant)
                ok, finals, writes, reads = self._run_trial(
                    gadget, roles, lane_of, varied_reg=cand, variant=variant, n_trials=n_variants)
                if ok:
                    trials.append((src_val, finals, writes, reads))
            per_candidate_trials[cand] = trials

        reg_effects: dict[str, RegEffect] = {}
        for dst in written_regs:
            dst_width = write_width.get(dst, self.width_bytes)
            const_fallback: Optional[RegEffect] = None
            chosen: Optional[RegEffect] = None
            for cand in candidates:
                trials = per_candidate_trials.get(cand, [])
                if len(trials) < 3:
                    continue
                # mask the recorded output down to this write's real width so
                # a 32-bit-on-x86-64 write's implicit zero-extension doesn't
                # get compared against stale upper bits from a *different*
                # instruction earlier in the trial's final-state snapshot.
                dst_mask = (1 << (dst_width * 8)) - 1
                pts = [(s, f.get(dst, 0) & dst_mask) for s, f, _, _ in trials if dst in f]
                if len(pts) < 3:
                    continue
                fit = self._fit(pts, dst_width)
                if fit is None:
                    continue
                kind, k, c = fit
                eff = RegEffect(kind=kind, src=(None if kind == EKind.CONST else cand),
                                 k=k, c=c, size=dst_width)
                if kind == EKind.CONST:
                    if const_fallback is None:
                        const_fallback = eff
                    continue  # a real dependency elsewhere should win if one exists
                chosen = eff
                break  # first genuine (non-const) dependency found -- take it
            best = chosen or const_fallback
            if best is None:
                sample = base_finals.get(dst)
                best = RegEffect(kind=EKind.UNKNOWN, size=dst_width, sample=sample)
            reg_effects[dst] = best

        # memory writes: correlate the i-th write across a candidate's trials
        n_base_writes = len(base_writes)
        mem_writes: list[MemEffect] = []
        for wi in range(n_base_writes):
            addr_eff = None
            val_eff = None
            size = base_writes[wi][1]
            for cand in candidates:
                trials = per_candidate_trials.get(cand, [])
                usable = [(s, w) for s, f, w, r in trials if len(w) == n_base_writes]
                if len(usable) < 3:
                    continue
                addr_pts = [(s, w[wi][0]) for s, w in usable]
                val_pts = [(s, w[wi][2]) for s, w in usable]
                if addr_eff is None:
                    fit_a = self._fit(addr_pts, self.width_bytes)
                    if fit_a and fit_a[0] != EKind.CONST:
                        k, c = fit_a[1], fit_a[2]
                        addr_eff = RegEffect(kind=fit_a[0], src=cand, k=k, c=c, size=self.width_bytes)
                if val_eff is None:
                    fit_v = self._fit(val_pts, self.width_bytes)
                    if fit_v:
                        k, c = fit_v[1], fit_v[2]
                        val_eff = RegEffect(kind=fit_v[0], src=(None if fit_v[0] == EKind.CONST else cand),
                                             k=k, c=c, size=size)
            if addr_eff is None:
                addr_eff = RegEffect(kind=EKind.CONST, c=base_writes[wi][0], size=self.width_bytes)
            if val_eff is None:
                val_eff = RegEffect(kind=EKind.CONST, c=base_writes[wi][2], size=size)
            mem_writes.append(MemEffect(addr=addr_eff, value=val_eff, size=size, is_write=True))

        # memory reads -> also check for LOAD-into-register (dst == value read)
        n_base_reads = len(base_reads)
        mem_reads: list[MemEffect] = []
        for ri in range(n_base_reads):
            addr_eff = None
            size = base_reads[ri][1]
            for cand in candidates:
                trials = per_candidate_trials.get(cand, [])
                usable = [(s, r) for s, f, w, r in trials if len(r) == n_base_reads]
                if len(usable) < 3:
                    continue
                addr_pts = [(s, r[ri][0]) for s, r in usable]
                fit_a = self._fit(addr_pts, self.width_bytes)
                if fit_a and fit_a[0] != EKind.CONST:
                    addr_eff = RegEffect(kind=fit_a[0], src=cand, k=fit_a[1], c=fit_a[2], size=self.width_bytes)
                    break
            if addr_eff is None:
                addr_eff = RegEffect(kind=EKind.CONST, c=base_reads[ri][0], size=self.width_bytes)
            mem_reads.append(MemEffect(addr=addr_eff, value=None, size=size, is_write=False))
            # does some destination register simply equal this read's value in every trial?
            for cand in candidates:
                trials = per_candidate_trials.get(cand, [])
                usable = [(f, r) for s, f, w, r in trials if len(r) == n_base_reads]
                if len(usable) < 3:
                    continue
                for dst in list(written_regs):
                    if reg_effects.get(dst) is not None and reg_effects[dst].kind == EKind.LOAD:
                        continue  # first matching read wins; don't let a later one clobber it
                    if all(dst in f and f[dst] == r[ri][2] for f, r in usable):
                        reg_effects[dst] = RegEffect(kind=EKind.LOAD, src=addr_eff.src or "const",
                                                      k=addr_eff.k, c=addr_eff.c, size=size)

        eff = GadgetEffect(reg_effects=reg_effects, mem_writes=mem_writes, mem_reads=mem_reads,
                            sp_delta=sp_delta, ok=True)
        return self._store(gadget, eff)
