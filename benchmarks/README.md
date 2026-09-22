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
- ropnroll (this branch, post cache/A*-solver changes)
- ROPgadget v7.7
- Ropper 1.13.13

## Results

```
tool                            gadgets   time (s)
ropnroll (max-insns=6)            80842      18.51
ROPgadget (depth=10)              87764       2.32
ropper                            62171       5.83

ropnroll semantic classification (sample of 1000, no other tool has an equivalent):
  604/1000 gadgets got an exact, emulation-verified register effect (1.78s)
```

## Reading these numbers honestly

**Raw scan speed: ropnroll is the slowest of the three here (~8x ROPgadget, ~3x ropper).**
That's the headline finding, not a footnote. ropnroll's x86 scanner walks every byte offset
backward from every terminator instruction and disassembles the whole candidate window each
time (`ropnroll/core/scanner.py`); ROPgadget and ropper both use cheaper search strategies. On
a 1.9MB real-world DLL that gap is nearly 20 seconds versus ~2-6 seconds, and it will only get
worse on a full system DLL like `ntdll.dll`, which is several times larger. This is the most
concrete, actionable target if the goal is "awesome on Windows" -- gadget scanning is the very
first thing every command in the tool does, so this cost is paid on every single invocation,
even before the persistent effect cache (which only helps the *semantic* layer, not this one)
can do anything for you.

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

## Next steps this suggests

Scanner speed is the natural next focus for the Windows push: profile
`ropnroll/core/scanner.py`'s x86 backward walk, and look at whether the per-offset
re-disassembly can be memoized/pruned (e.g. reusing partial disassembly across overlapping
windows) without weakening the "unintended gadget" byte-level search that's specifically what
makes x86 ROP scanning valuable in the first place.
