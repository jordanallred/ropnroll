# Gadget-finder benchmarks

`compare_gadget_finders.py` runs ropnroll, [ROPgadget](https://github.com/JonathanSalwan/ROPgadget),
and [ropper](https://github.com/sashs/Ropper) against the same binary and reports raw gadget
count and wall-clock scan time. Nothing here is committed to the repo except the script and
these results -- see "Target binary" below for why.

```bash
python3 benchmarks/compare_gadget_finders.py --binary /path/to/target.dll --semantic-sample 1000
```

## Target binary

This machine has no real Windows install (no Wine, no system DLLs), so the first run uses the
best available stand-in: **`msdia140.dll`** from the Visual Studio / DIA SDK, pulled in here as
a dependency of an installed tool (`angr`'s `pyxdia` package). It's a genuine Microsoft-compiled
PE32+ binary, not a toy test fixture -- just not a core OS DLL like `kernel32.dll`/`ntdll.dll`.
The file itself is **not** included in this repo (Microsoft's copyright); only the script and
the numbers below are.

If you have a real system DLL (`kernel32.dll`, `ntdll.dll`, or whatever you actually target),
point `--binary` at it instead for a more representative run -- do not commit the binary itself
to this repo.

| | |
|---|---|
| File | `msdia140.dll` |
| SHA-256 | `3de9d7ec815abaaa58939cf5b39f7dfc9a3e95030460c553db316a1a094ab6d9` |
| Size | 1,893,424 bytes |
| Format | PE32+, x86-64, 7 sections |

## Environment

- Python 3.12.3
- ropnroll (this branch, post scanner memoization/parallelism)
- ROPgadget v7.7
- Ropper 1.13.13
- 12 CPU cores available (`--jobs` defaults to auto-detect)

## Results

```
tool                            gadgets   time (s)
ropnroll (max-insns=6)            80842       6.96
ROPgadget (depth=10)              87764       2.18
ropper                            62171       5.37

ropnroll semantic classification (sample of 1000, no other tool has an equivalent):
  604/1000 gadgets got an exact, emulation-verified register effect (1.58s)
```

**History**: the first run of this benchmark measured ropnroll at **18.51s** on this same
binary -- 8x slower than ROPgadget and 3.2x slower than ropper. Two fixes closed most of that
gap, in order:

1. **Memoizing per-offset disassembly** (`ropnroll/core/scanner.py`): the scanner's backward
   byte-walk was re-disassembling the same byte offsets repeatedly across heavily overlapping
   candidate windows (measured 3.89M capstone calls against ~1.4M executable bytes in the
   target). Caching each offset's decode result within a segment is exact -- decoding at a
   fixed byte offset is a pure function of the bytes there -- and cut this to **~11s** with a
   verified bit-identical gadget set.
2. **Parallelizing across worker processes**: terminator offsets are now split across
   `ProcessPoolExecutor` workers (`--jobs`, auto-detected by default). Getting this right
   required a real fix, not just splitting the work: deduping byte-identical gadgets found by
   different workers must pick the same (lowest) address every time regardless of worker count
   or scheduling order, or the *set* of reported addresses becomes non-deterministic across
   machines with different core counts -- caught by comparing `--jobs 1` against `--jobs 8`
   output during development, now a permanent regression test
   (`test_parallel_scan_matches_serial` in `tests/test_scanner.py`). With that fixed: **~7s**.

ropnroll is still the slowest of the three (~3.2x ROPgadget, ~1.3x ropper), but the gap to
ropper in particular is now small enough that the remaining difference is more plausibly
"different algorithm constants" than "doing meaningfully more redundant work."

## Reading these numbers honestly

**The three gadget counts aren't directly comparable** -- each tool defaults to a different
search depth (ropnroll: 6 instructions; ROPgadget: 10 bytes; ropper: its own fixed per-arch
depth), so a raw count difference partly reflects "searched deeper/shallower," not just
"found more/fewer gadgets in the same haystack." Use `--max-insns`/`--ropgadget-depth` to
align them if you want a tighter comparison; the numbers above are each tool's own default,
since "what do you get running it normally" is usually the more honest question.

**The semantic number has no baseline to compare against** -- neither ROPgadget nor ropper
attempt emulation-verified effect classification at all, so 604/1000 isn't "better than X,"
it's ropnroll's only differentiator, measured on its own. The other ~40% are gadgets whose
behavior didn't reduce to one of the closed-form relations `ropnroll/semantics/effect.py`
models (flag-dependent instructions, non-invertible scales, etc.) -- expected, not a bug.

**Parallelism helps most on larger binaries with more CPU cores** -- on a small binary
(a few KB) the scanner stays serial by design (`_PARALLEL_MIN_BYTES` in `scanner.py`) since
process-pool startup would cost more than it saves; this benchmark's 1.9MB target and 12 cores
are a reasonably representative "worth it" case, but the speedup will vary with both binary
size and available cores -- notably, process creation is heavier on Windows (spawn) than the
Linux (fork) semantics this was measured under, so the real-world win on a Windows workstation
may differ from the number above even though the implementation is written to be spawn-safe.

## Next steps this suggests

The remaining ~3.2x gap to ROPgadget is likely the per-instruction cost of capstone's
`detail=True` mode (needed for register/operand classification) rather than redundant work --
worth profiling directly rather than assumed. A cheaper two-tier disassembly (skip full detail
for instructions that don't need operand inspection) was considered but not attempted here: the
most common case that needs detail (`mov` to a segment register, the safety check that rejects
gadgets misdecoding into privileged instructions) is also one of the most common mnemonics in
real code, which limits how much a "detail only when needed" split would actually save.
