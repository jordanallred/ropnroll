# ropnroll

ropnroll is a command-line tool and Python library for finding return-oriented
programming (ROP) and jump-oriented programming (JOP) gadgets in **Windows PE
binaries** (EXE/DLL, x86/x86-64/ARM64). It supports instruction-pattern and
semantic searches, builds function-call chains against the MS x64/cdecl/
stdcall calling conventions, and can check generated chains with Unicorn
emulation.

Use it to inspect PE mitigations (DEP, ASLR, CFG, XFG, CET, SafeSEH), find
gadgets with specific register effects, and assemble chains for Windows
exploit-development research and CTF challenges.

## Why ropnroll

Most gadget tools infer a gadget's effect from a hand-written instruction model.
ropnroll instead *measures* it: every gadget runs for real on an emulated CPU
(Unicorn) with several input vectors, and a closed-form relation (constant,
copy, affine, bitwise) is fit to the outputs. If a relation fits every trial,
it's exact, not a guess -- and it's correct by construction for every
architecture Unicorn supports, including quirks a hand-rolled model would miss.

Chain synthesis uses a best-first (A*) search over candidate gadgets rather
than a fixed-width traversal, so it isn't limited to only the first few
shortest candidates at each step -- within its depth and work bounds, it finds
a minimum-gadget chain instead of giving up on one that a narrower search would
miss. Repeated analysis of the same binary (the normal workflow while building
an exploit) is backed by a persistent on-disk cache, so the second and later
`search`/`call` invocation against the same target is fast; see `--no-cache`
and `ROPNROLL_CACHE_DIR` below if you need to bypass or relocate it.

## Installation

Requires **Python 3.10 or newer**. Install from PyPI in a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install ropnroll
ropnroll --help
```

Capstone, LIEF, Unicorn, and Rich are installed automatically. ropnroll
itself is a pure analysis tool (it never executes target code on the host),
so it also runs fine from Linux/macOS if you're cross-analyzing a PE -- but
Windows is the only platform it targets and tests against.

If you use uv, you can run the CLI without a persistent installation:

```bash
uvx ropnroll --help
```

## Quick start

Replace `./target` with the path to a binary you want to inspect.

```bash
# Report a PE's mitigations: DEP, ASLR, stack canary, CFG/XFG, CET, SafeSEH.
ropnroll security ./target.exe

# List up to 20 gadgets.
ropnroll scan ./target.exe --limit 20

# Find x86-64 gadgets by instruction text.
ropnroll scan ./target.exe --regex 'pop rcx'

# Find x86-64 gadgets by their effect on registers.
ropnroll search ./target.exe --query 'rcx=rax+8'
```

`scan` prints gadget addresses and disassembly. `search` uses emulation to infer
register effects; the query above asks for a gadget that sets `rdi` to `rax + 8`.
Matches depend on the instructions available in your binary.

Run `ropnroll <command> --help` for command options.

## Commands

| Command | Purpose |
| --- | --- |
| `security` | Report a PE's mitigations. |
| `scan` | List gadgets, optionally filtered by an instruction regex. |
| `search` | Search for register or memory effects using semantic queries. |
| `pivot` | Find stack-pivot gadgets. |
| `jop` | Find JOP dispatcher gadgets. |
| `call` | Build a chain that calls a function by symbol or address. |

### Build and export a chain

For a binary that contains a suitable exported symbol and gadgets:

```bash
ropnroll call ./target.exe --target ExitProcess --args 0 --verify --emit json --out chain.json
```

`--target` accepts a symbol name or numeric address. `--args` accepts
comma-separated integers. `--verify` prints an emulation report; inspect that
report before using the output. Export formats are `json`, `raw`, `c`, and
`pwntools`. Use `--out` to save a payload separately from console diagnostics.

You can pool gadgets from multiple binaries:

```bash
ropnroll search ./target.exe ./kernel32.dll --query 'rcx=rax+8'
```

`call`, `pivot`, and `jop` also accept multiple paths. Addresses come from the
loaded images and reflect each file's own preferred base -- pass `--base
path=0xaddr` (repeatable) to override a specific binary's base with a leaked
runtime address instead, e.g. for an ASLR-relocated DLL:

```bash
ropnroll call ./target.exe ./kernel32.dll --base kernel32.dll=0x7ffb2a3c0000 \
  --target VirtualProtect --args 0x140001000,0x1000,0x40,0x140002000
```

Loading `kernel32.dll` alongside the target is what makes `--target
VirtualProtect` resolve at all: the CLI only resolves symbol names against a
binary's own *exports*, not another binary's imports, so a function the
target merely calls (rather than defines) must come from a binary that
actually exports it. Pointer arguments (like `VirtualProtect`'s output
parameter above) must refer to valid memory in the intended target; nothing
here allocates scratch space for you.

For x86-64, `call` accepts `--bytes-before-chain N` (bytes of payload
preceding the chain in your final buffer) to automatically correct stack
alignment for the call instruction, matching what a real `call` would have
left behind -- entering a function at the wrong 16-byte parity is a common,
easy-to-miss way a chain crashes inside the callee's own SSE instructions.

### Caching

Semantic effects (the expensive part -- several Unicorn runs per gadget) are
cached on disk per binary, keyed by its content hash, so repeated commands
against the same target reuse prior analysis instead of redoing it. Pass
`--no-cache` to any command to bypass the cache for that run. The cache lives
under `%LOCALAPPDATA%\ropnroll` by default; set `ROPNROLL_CACHE_DIR` to
relocate it.

## Supported targets and limitations

| Target | Scope |
| --- | --- |
| Windows x86-64 PE (EXE/DLL) | Primary target for scanning, semantic analysis, chain building, and verification. |
| Windows x86 PE (32-bit) | Loading, mitigation reporting (incl. SafeSEH), and scanning; cdecl/stdcall calling-convention support is implemented. |
| Windows ARM64 PE | Scanner and semantic-engine implementation; not covered by real-binary architecture tests. |
| ELF, Mach-O, other architectures | Unsupported -- ropnroll only reads PE. |

- Semantic effects are inferred from a finite set of emulation trials, not
  formally proved for every possible input.
- Chain search (a best-first/A* search over candidate gadgets) has depth and
  work limits; within those bounds it finds a minimum-gadget chain if one
  exists, but a gadget-poor pool can still exhaust the budget without one.
- Chain verification uses the first supplied image; it does not fully validate
  chains spanning multiple images or guarantee success in a live process.
- Raw gadget-scan speed still trails ROPgadget (not ropper, closely) on large
  real-world binaries, though a scanner rewrite closed most of a former 3-8x
  gap; see [`benchmarks/`](benchmarks/) for measured numbers and honest notes
  on where the remaining gap is. Scanning parallelizes across CPU cores by
  default (`--jobs` to control worker count; `--jobs 1` to disable).

## Development

```powershell
git clone https://github.com/jordanallred/ropnroll.git
cd ropnroll
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m pytest -q
```

Several tests scan `C:\Windows\System32\ntdll.dll` as a realistic, large PE
fixture; they skip automatically off Windows. The repository also includes
small, purpose-built PE fixtures under `tests/fixtures/pe/` for loader and
scanner tests.

## Help and contributions

Report bugs or suggest improvements in
[GitHub Issues](https://github.com/jordanallred/ropnroll/issues).
For bug reports, include the command, full error output, Python and ropnroll
versions, and the target's architecture and file format. Include a minimal
reproducer when possible.

Pull requests are welcome. Include relevant tests for behavior changes and run
the test suite before submitting.
