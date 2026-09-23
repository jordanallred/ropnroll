#!/usr/bin/env python3
"""Benchmark ropnroll's gadget scanner against ROPgadget and ropper on the
same binary: raw gadget count and wall-clock scan time, like-for-like.

This only measures the syntactic scanning layer all three tools share.
ropnroll's semantic layer (emulation-verified register/memory effects,
chain synthesis) has no equivalent in the other two tools, so there's
nothing to compare it against here -- pass --semantic-sample to report
that dimension for ropnroll alone instead of pretending it's a fair
three-way number.

The tools do not search to the same default depth, so raw gadget counts
are not directly comparable out of the box:
  - ropnroll's --max-insns is an instruction count (default 6).
  - ROPgadget's --depth is a byte count (default 10).
  - ropper searches to a fixed internal depth per architecture.
Use --max-insns / --ropgadget-depth to align them approximately if you
want a closer apples-to-apples run; this script reports whatever each
tool's own default finds unless you override it, since "what do you get
running each tool normally" is usually the more useful number.

Usage:
    python3 benchmarks/compare_gadget_finders.py --binary /path/to/file.dll
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _time_it(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def bench_ropnroll(binary: str, max_insns: int) -> tuple[int, float]:
    from ropnroll.core import loader, scanner

    def run():
        img = loader.load(binary)
        return scanner.scan_image(img, scanner.ScanOptions(max_insns=max_insns), use_cache=False)

    gadgets, elapsed = _time_it(run)
    return len(gadgets), elapsed


def bench_ropnroll_semantic_sample(binary: str, max_insns: int, sample_size: int):
    """How many of the first `sample_size` scanned gadgets get an exact,
    emulation-verified register effect -- the thing neither ROPgadget nor
    ropper attempt at all, so it's reported on its own rather than as a
    fourth column next to counts that mean something different."""
    from ropnroll.core import loader, scanner
    from ropnroll.core.archinfo import get_archinfo
    from ropnroll.semantics.engine import SemanticEngine

    img = loader.load(binary)
    ai = get_archinfo(img.arch, img.little_endian)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=max_insns))[:sample_size]
    engine = SemanticEngine(img, ai, disk_cache=None)

    def run():
        classified = 0
        for g in gadgets:
            eff = engine.compute(g)
            if eff.ok and any(e.kind.name != "UNKNOWN" for e in eff.reg_effects.values()):
                classified += 1
        return classified

    classified, elapsed = _time_it(run)
    return len(gadgets), classified, elapsed


def _find_ropper() -> str | None:
    found = shutil.which("ropper")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "ropper"
    return str(local) if local.exists() else None


def _find_ropgadget() -> list[str] | None:
    """Locate a way to invoke ROPgadget.

    On Windows, pip/uv installs ROPgadget's console script as a shebang
    file with no .exe wrapper (its setup.py uses scripts=, not the
    console_scripts entry-point ropper uses), so it has no extension
    shutil.which recognizes via PATHEXT and "ROPgadget" is invisible on
    PATH even when it's installed. Fall back to invoking the importable
    `ropgadget` module directly, which works the same on every platform.
    """
    found = shutil.which("ROPgadget")
    if found:
        return [found]
    local = Path.home() / ".local" / "bin" / "ROPgadget"
    if local.exists():
        return [str(local)]
    try:
        import ropgadget  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-c", "import ropgadget; ropgadget.main()"]


def bench_subprocess(cmd: list[str], count_pattern: str) -> tuple[int | None, float]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    m = re.search(count_pattern, proc.stdout) or re.search(count_pattern, proc.stderr)
    return (int(m.group(1)) if m else None), elapsed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="path to the target binary")
    ap.add_argument("--max-insns", type=int, default=6, help="ropnroll's instruction-count depth")
    ap.add_argument("--ropgadget-depth", type=int, default=10, help="ROPgadget's --depth (bytes)")
    ap.add_argument("--tools", default="ropnroll,ropgadget,ropper",
                     help="comma-separated subset to run")
    ap.add_argument("--semantic-sample", type=int, default=0,
                     help="also report ropnroll's semantic classification rate over the first N gadgets")
    args = ap.parse_args()

    if not Path(args.binary).exists():
        raise SystemExit(f"no such file: {args.binary}")

    tools = set(args.tools.split(","))
    rows: list[tuple[str, int | None, float]] = []

    if "ropnroll" in tools:
        count, elapsed = bench_ropnroll(args.binary, args.max_insns)
        rows.append((f"ropnroll (max-insns={args.max_insns})", count, elapsed))

    if "ropgadget" in tools:
        ropgadget_cmd = _find_ropgadget()
        if ropgadget_cmd:
            count, elapsed = bench_subprocess(
                ropgadget_cmd + ["--binary", args.binary, "--depth", str(args.ropgadget_depth)],
                r"Unique gadgets found:\s*(\d+)")
            rows.append((f"ROPgadget (depth={args.ropgadget_depth})", count, elapsed))
        else:
            print("ROPgadget not found, skipping")

    if "ropper" in tools:
        ropper_bin = _find_ropper()
        if ropper_bin:
            count, elapsed = bench_subprocess([ropper_bin, "--file", args.binary, "--nocolor"],
                                               r"(\d+) gadgets found")
            rows.append(("ropper", count, elapsed))
        else:
            print("ropper not found, skipping")

    print()
    print(f"{'tool':<28} {'gadgets':>10} {'time (s)':>10}")
    for name, count, elapsed in rows:
        print(f"{name:<28} {count if count is not None else '?':>10} {elapsed:>10.2f}")

    if args.semantic_sample:
        n, classified, elapsed = bench_ropnroll_semantic_sample(
            args.binary, args.max_insns, args.semantic_sample)
        print()
        print(f"ropnroll semantic classification (sample of {n}, no other tool has an equivalent):")
        print(f"  {classified}/{n} gadgets got an exact, emulation-verified register effect "
              f"({elapsed:.2f}s)")


if __name__ == "__main__":
    main()
